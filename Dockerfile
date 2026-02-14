# ThreatDrill Gatekeeper - Cloud Run Dockerfile

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    # Install Playwright browsers into a shared path so a non-root user can run them.
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# System packages:
# - build tools for wheels (uvicorn[standard] deps, etc.)
# - curl/ca-certificates used by build steps and healthcheck
# - nodejs/npm is used when enabling the optional Gemini Playwright MCP path (npx @playwright/mcp@latest)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    ca-certificates \
    curl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

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
