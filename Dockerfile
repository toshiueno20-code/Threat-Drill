# ThreatDrill Gatekeeper - Cloud Run Dockerfile
#
# Multi-stage build: builder stage compiles native wheels (gcc/g++),
# runtime stage contains only what the app needs at execution time.

# ── Stage 1: build Python dependencies ───────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==2.3.2

COPY pyproject.toml poetry.lock* ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main


# ── Stage 2: runtime ─────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Cloud Run provides PORT env var (default 8080).
# PLAYWRIGHT_BROWSERS_PATH : shared Chromium path readable by non-root user.
# NPM_CONFIG_CACHE / XDG_CACHE_HOME : redirect caches to writable /tmp
#   (Cloud Run 2nd-gen execution environment mounts the filesystem read-only
#    except for /tmp).
ENV PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    NPM_CONFIG_CACHE=/tmp/.npm \
    XDG_CACHE_HOME=/tmp/.cache

# Default Node.js LTS version – override with --build-arg NODE_VERSION=x.y.z
ARG NODE_VERSION=20.18.0

# Runtime system packages
# ─ git            : GitPython needs it to clone repositories at runtime
# ─ ca-certificates: outbound HTTPS
# ─ curl / tar     : healthcheck & Node.js binary install
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    curl \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (architecture-aware so the same Dockerfile works on
# amd64 Cloud Build *and* arm64 local builds on Apple Silicon).
RUN ARCH="$(dpkg --print-architecture)" \
    && case "${ARCH}" in arm64|aarch64) NODE_ARCH=arm64 ;; *) NODE_ARCH=x64 ;; esac \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.gz" \
       -o /tmp/node.tgz \
    && tar -xzf /tmp/node.tgz -C /usr/local --strip-components=1 \
    && rm /tmp/node.tgz \
    && node --version && npm --version

# Copy pre-built Python packages from builder (no gcc/g++/poetry in final image)
COPY --from=builder /usr/local/lib/python3.11/site-packages/ \
                    /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Playwright Chromium + its OS-level dependencies (as root)
RUN mkdir -p "${PLAYWRIGHT_BROWSERS_PATH}" \
    && python -m playwright install --with-deps chromium

# Application code
COPY . .

EXPOSE 8080

# Non-root user with writable cache directories
RUN useradd -m -u 1000 threatdrill \
    && chown -R threatdrill:threatdrill /app "${PLAYWRIGHT_BROWSERS_PATH}" \
    && mkdir -p /tmp/.npm /tmp/.cache \
    && chown -R threatdrill:threatdrill /tmp/.npm /tmp/.cache

USER threatdrill

# Docker-level healthcheck (Cloud Run ignores this but useful for local docker run)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request as u;u.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8080\")}/health',timeout=5).read()"

# `exec` replaces the shell process so uvicorn becomes PID 1 and receives
# SIGTERM directly from Cloud Run, enabling graceful shutdown.
CMD exec uvicorn gatekeeper.app.main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8080} \
    --workers 1
