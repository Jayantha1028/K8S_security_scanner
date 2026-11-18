# Multi-Stage Hardened Containerfile for Kubernetes Native Security Scanner
# Base: Debian 12 Bookworm Slim (Standard glibc, eliminating musl DNS quirks)
# Security: Runs Non-Root (UID 10001), Read-Only Code, Minimal Attack Surface

FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final Hardened Runtime Stage
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="k8s-native-scanner" \
      org.opencontainers.image.description="Enterprise Pure-Python Kubernetes CNAPP & Fleet Controller" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . /app

# Create non-root unprivileged service user and strictly lock down permissions:
# - Application code is made strictly read-only (555: r-x r-x r-x)
# - Shell access for user is disabled (/bin/false)
# - Home directory is /nonexistent (-M)
# - Temp directory /tmp has full permissions for ephemeral scratch operations
RUN groupadd -g 10001 secagent && \
    useradd -u 10001 -g secagent -d /nonexistent -s /bin/false -M secagent && \
    chmod -R 555 /app && \
    chmod 777 /tmp

USER 10001:10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PATH="/app/bin:${PATH}" \
    TMPDIR=/tmp

# Container Healthcheck (verifies Python runtime without external curl/wget)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python3", "-c", "import sys; sys.exit(0)"]

ENTRYPOINT ["python3", "/app/cli.py"]
CMD ["agent", "--watch", "--interval", "60"]
