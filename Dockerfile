# Multi-Stage Hardened Containerfile for Kubernetes Native Security Scanner
# Base: Debian 12 Bookworm Slim (Standard glibc, eliminating musl DNS quirks)
# Security: Runs Non-Root (UID 10001), Minimal Attack Surface

FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final Runtime Stage
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

# Create non-root unprivileged service user and harden permissions
RUN groupadd -g 10001 secagent && \
    useradd -u 10001 -g secagent -s /bin/false -M secagent && \
    chmod -R 755 /app && \
    chmod +x /app/bin/k8s-native-scan /app/cli.py

USER 10001:10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/app/bin:${PATH}"

ENTRYPOINT ["python3", "/app/cli.py"]
CMD ["agent", "--watch", "--interval", "60"]
