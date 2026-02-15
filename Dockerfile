# ThreatDrill Gatekeeper - Cloud Run Dockerfile

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    # Make sure globally-installed npm CLIs are available to the non-root runtime user.
    PATH=/usr/local/bin:$PATH \
    # Default to the installed CLI to avoid slow/flaky runtime `npx @playwright/mcp@...` downloads on Cloud Run.
    PLAYWRIGHT_MCP_COMMAND=playwright-mcp \
    PLAYWRIGHT_MCP_ARGS="--headless --isolated --output-dir .playwright-mcp"

ARG NODE_VERSION=20.19.4
ARG PLAYWRIGHT_MCP_VERSION=0.0.68

# System packages:
# - build tools for wheels (uvicorn[standard] deps, etc.)
# - git is required by GitPython (used by static_analyzer) to clone repositories at runtime
# - curl/ca-certificates used by build steps and healthcheck
# - node/npm/npx is used when enabling the optional Gemini Playwright MCP path
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    ca-certificates \
    curl \
    tar \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz" -o /tmp/node.tgz \
    && tar -xzf /tmp/node.tgz -C /usr/local --strip-components=1 \
    && rm -f /tmp/node.tgz \
    && node --version \
    && npm --version

# Avoid slow runtime `npx @playwright/mcp@...` downloads on Cloud Run by installing the MCP CLI at build time.
RUN npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" \
    && playwright-mcp --help >/dev/null \
    && npm cache clean --force

# Poetry (match poetry.lock / pyproject.toml features like `package-mode`)
RUN pip install poetry==2.3.2

# Install dependencies first for better Docker layer caching
COPY pyproject.toml poetry.lock* ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Install Playwright browser binaries (Chromium) + OS deps at build time
RUN mkdir -p "${PLAYWRIGHT_BROWSERS_PATH}" \
    && python -m playwright install --with-deps chromium

# Copy application code
COPY . .

EXPOSE 8080

# Run as non-root
RUN useradd -m -u 1000 threatdrill \
    && chown -R threatdrill:threatdrill /app "${PLAYWRIGHT_BROWSERS_PATH}"
USER threatdrill

# Optional: Docker healthcheck (Cloud Run doesn't require it)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; port=os.environ.get('PORT','8080'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=5).read()"

# Cloud Run sets PORT=8080 by default. Use exec-form so uvicorn is PID 1 (better signal handling on Cloud Run).
# If you need multi-worker, set it explicitly here (Playwright-heavy workloads are usually happier with 1 worker).
CMD ["uvicorn", "gatekeeper.app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
