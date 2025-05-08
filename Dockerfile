############################ 1️⃣ Builder stage ############################
FROM python:3.12-slim AS builder

# Prevent prompts and enable consistent, reproducible builds
ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Copy only files needed to resolve dependencies — maximises cache‑efficiency
COPY pyproject.toml .

RUN apt-get update && apt-get install -y ca-certificates \
    && pip install --upgrade pip pdm-backend pdm python-dateutil pydantic-settings \
    && pdm lock --prod \
    && pdm export --prod --without-hashes -o requirements.txt
############################ 2️⃣ Production stage #########################
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

ENV LANG=ko_KR.UTF-8 \
    LC_ALL=ko_KR.UTF-8

# Install system CA bundle so TLS verification works
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wget && \
    wget -qO /usr/local/share/ca-certificates/isrg-r3.pem \
        https://letsencrypt.org/certs/lets-encrypt-r3.pem && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install ko_KR.UTF-8 locale so BeautifulSoup / requests can decode Korean pages
RUN apt-get update && \
    apt-get install -y --no-install-recommends locales && \
    sed -i '/ko_KR.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen ko_KR.UTF-8 && \
    rm -rf /var/lib/apt/lists/*

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