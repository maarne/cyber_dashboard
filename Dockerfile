# ============================================================
# CyberDash — Production Multi-Stage / Hardened Dockerfile
# ============================================================
FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    DATABASE_PATH="/app/data/cyber_dashboard.db"

WORKDIR /app

# Install minimal OS dependencies for cryptography and sqlite
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (leverages Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app ./app

# Create a non-root user and persistent data folder for security
RUN groupadd -g 10001 cyberdash && \
    useradd -u 10001 -g cyberdash -s /bin/bash -m cyberdash && \
    mkdir -p /app/data && \
    chown -R cyberdash:cyberdash /app

USER cyberdash

# Health check to ensure the container is alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

EXPOSE 8000

# Run with Gunicorn + Uvicorn workers for production concurrency
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "app.main:app"]
