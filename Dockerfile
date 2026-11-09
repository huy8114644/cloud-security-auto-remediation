# Multi-stage Build for Maximum Security
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Stage 2: Hardened Runtime (Non-root user, minimal footprint)
FROM python:3.12-slim-bookworm AS runner

WORKDIR /app

# Create non-root system user
RUN groupadd -g 10001 secops && \
    useradd -u 10001 -g secops -s /bin/false -m secops

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY src/ /app/src/

USER 10001:10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "-m", "src.main"]

