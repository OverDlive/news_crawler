############################ 1️⃣ Builder stage ############################
FROM python:3.12-slim AS builder

# Prevent prompts and enable consistent, reproducible builds
ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Copy only files needed to resolve dependencies — maximises cache‑efficiency
COPY pyproject.toml .

RUN pip install --upgrade pip && \
    pip install pdm-backend pdm python-dateutil && \
    pdm lock --prod && \
    pdm export --prod --without-hashes -o requirements.txt

############################ 2️⃣ Production stage #########################
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

# Optional: create non‑root user (comment out if you need root for ipset)
RUN adduser --disabled-password --gecos '' secbot
WORKDIR /app
USER secbot

# Copy dependency lockfile first to leverage Docker layer cache
COPY --from=builder /build/requirements.txt .
COPY --from=builder /build/pdm.lock .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy application code
COPY src/ src/

# Default command
CMD ["python", "-m", "secbot.main"]