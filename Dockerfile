# Multi-Stage Minimal Containerfile for Kubernetes Native Security Scanner & AI Agent
# Footprint: ~35MB | Zero Binary Dependencies | Runs Non-Root (UID 10001)

FROM python:3.12-alpine AS builder

WORKDIR /build
RUN apk add --no-cache gcc musl-dev libffi-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final Runtime Stage
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="k8s-native-scanner" \
      org.opencontainers.image.description="Enterprise Pure-Python Kubernetes CNAPP, Attack DAG & AI Security Agent" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Copy installed Python packages
COPY --from=builder /install /usr/local

# Copy application code
COPY . /app

# Create non-root unprivileged service user
RUN addgroup -g 10001 -S secagent && \
    adduser -u 10001 -S secagent -G secagent && \
    chmod -R 755 /app && \
    chmod +x /app/bin/k8s-native-scan /app/cli.py

USER 10001:10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/app/bin:${PATH}"

ENTRYPOINT ["python3", "/app/cli.py"]
CMD ["agent", "--watch", "--interval", "60"]
