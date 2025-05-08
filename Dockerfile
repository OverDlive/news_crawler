FROM python:3.12-slim AS base
WORKDIR /app
COPY pyproject.toml .
RUN pip install --upgrade pip && pip install -r <(pip install --dry-run -r pyproject.toml)
COPY src/ src/
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "secbot.main"]