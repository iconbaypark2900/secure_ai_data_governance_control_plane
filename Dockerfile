# Build the UI first, so the API image can serve it without a second container.
FROM node:22-alpine AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM python:3.13-slim AS runtime

# Fail fast and log immediately: a buffered stdout in a container means the
# logs from a crash arrive after the crash, or not at all.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY control_plane ./control_plane
RUN pip install --no-cache-dir .

# The SDK and the reference enforcement point ship in the same image, so the
# proxy runs from it without needing a volume mount. Compose still mounts them
# in development, for reload.
COPY sdk ./sdk
RUN pip install --no-cache-dir ./sdk/python
COPY pep ./pep

COPY alembic.ini ./
COPY migrations ./migrations
COPY scripts ./scripts
COPY seed ./seed
COPY --from=ui /ui/dist ./ui/dist

# An unprivileged user, and a home it can actually write to.
RUN useradd --create-home --uid 10001 control && chown -R control:control /app
USER control

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8000/v1/health || exit 1

# Classification is CPU-bound and only partially releases the GIL, so one worker
# is one core however many requests arrive. WEB_CONCURRENCY is uvicorn's own
# variable; leaving it unset keeps the single-process behaviour that is easier to
# debug, and setting it is how a deployment gets more than one core's worth.
CMD ["sh", "-c", "exec uvicorn control_plane.main:app --host 0.0.0.0 --port 8000 ${WEB_CONCURRENCY:+--workers $WEB_CONCURRENCY}"]
