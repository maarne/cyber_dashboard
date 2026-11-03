# ============================================================
# CyberDash — Production Multi-Stage / Hardened Dockerfile
# ============================================================
FROM python:3.11-slim-bookworm AS base
ARG INSTALL_ASSET_NETWORK_TOOLS=false

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    APP_DATA_DIR="/app/data" \
    DATABASE_PATH="/app/data/cyber_dashboard.db"

WORKDIR /app

# Apply latest Debian security updates and remove package manager caches
RUN apt-get update && \
    apt-get upgrade -y && \
    if [ "$INSTALL_ASSET_NETWORK_TOOLS" = "true" ]; then \
      apt-get install -y --no-install-recommends curl iputils-ping nmap && \
      chmod u-s,g-s /usr/bin/ping && \
      python3 -c "import os; p='/usr/bin/ping'; a='security.capability'; os.removexattr(p,a) if a in os.listxattr(p) else None"; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# Install and upgrade Python dependencies with modern secure build tooling
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip "setuptools>=83.0.0" "wheel>=0.46.2" && \
    pip install --no-cache-dir --only-binary=:all: -r requirements.txt && \
    pip install --no-cache-dir --upgrade "msgpack>=1.2.1" "jaraco.context>=6.1.0"

# Copy application source code
COPY app ./app
COPY scripts ./scripts

# Create a non-root user and persistent data folders for security
RUN groupadd -g 10001 cyberdash && \
    useradd -u 10001 -g cyberdash -s /bin/bash -m cyberdash && \
    mkdir -p /app/data /home/data /home/cyberdash/data && \
    chown -R cyberdash:cyberdash /app /home/data /home/cyberdash && \
    chmod -R 700 /app/data /home/data /home/cyberdash/data

USER cyberdash

# Native Python healthcheck (avoids installing curl and 30+ dependent OS packages)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

EXPOSE 8000

# Run with Gunicorn + Uvicorn workers for production concurrency
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "app.main:app"]
