# ============================================================
# CyberDash — Production Multi-Stage / Hardened Dockerfile
# ============================================================
FROM python:3.11-slim-bookworm AS base

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    DATABASE_PATH="/app/data/cyber_dashboard.db"

WORKDIR /app

# Apply latest Debian security updates and remove package manager caches
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

# Install and upgrade Python dependencies with modern secure build tooling
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip "setuptools>=83.0.0" "wheel>=0.46.2" && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir --upgrade "msgpack>=1.2.1" "jaraco.context>=6.1.0"

# Copy application source code
COPY app ./app

# Create a non-root user and persistent data folder for security
RUN groupadd -g 10001 cyberdash && \
    useradd -u 10001 -g cyberdash -s /bin/bash -m cyberdash && \
    mkdir -p /app/data && \
    chown -R cyberdash:cyberdash /app

USER cyberdash

# Native Python healthcheck (avoids installing curl and 30+ dependent OS packages)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

EXPOSE 8000

# Run with Gunicorn + Uvicorn workers for production concurrency
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "app.main:app"]
