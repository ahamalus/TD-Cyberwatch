# syntax=docker/dockerfile:1
# TrustData CyberWatch backend (API, workers, scheduler share this image)
FROM python:3.12-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# psycopg[binary] bundles libpq; backups run pg_dump inside the db container.
RUN groupadd --system --gid 10001 cyberwatch \
 && useradd --system --uid 10001 --gid cyberwatch --home /app --shell /usr/sbin/nologin cyberwatch
WORKDIR /app
COPY requirements.txt requirements.lock ./
# Optional: behind a TLS-intercepting proxy, pass its CA without baking it in:
#   docker build --secret id=extra_ca,src=/path/ca.pem ...
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install -r requirements.txt
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
RUN mkdir -p /var/lib/cyberwatch/storage && chown -R cyberwatch:cyberwatch /var/lib/cyberwatch
USER cyberwatch
ENV CW_STORAGE_DIR=/var/lib/cyberwatch/storage
EXPOSE 8000
# Default: API. Workers/scheduler override the command in docker-compose.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--workers", "2"]
