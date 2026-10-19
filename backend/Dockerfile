# TrustData CyberWatch backend (API, workers, scheduler share this image)
FROM python:3.12-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 ca-certificates postgresql-client \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 cyberwatch \
 && useradd --system --uid 10001 --gid cyberwatch --home /app --shell /usr/sbin/nologin cyberwatch
WORKDIR /app
COPY requirements.txt requirements.lock ./
RUN pip install -r requirements.txt
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
RUN mkdir -p /var/lib/cyberwatch/storage && chown -R cyberwatch:cyberwatch /var/lib/cyberwatch
USER cyberwatch
ENV CW_STORAGE_DIR=/var/lib/cyberwatch/storage
EXPOSE 8000
# Default: API. Workers/scheduler override the command in docker-compose.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--workers", "2"]
