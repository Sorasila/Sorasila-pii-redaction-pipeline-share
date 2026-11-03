# Reference image for the PII redaction service (POST /redact).
#
# An example for the platform team: adapt the base image, user and registry to
# the platform's rules. The image holds code only. Every setting and secret
# (LLM_PROXY_*, PII_SERVICE_*) comes from the environment at run time; never
# copy .env into the image (.dockerignore keeps it out of the build context).
#
#   docker build -t pii-redaction-service .
#   docker run --rm -p 8080:8080 --env-file <env file outside the image> pii-redaction-service
#
# A request can take many minutes (the service waits for the LLM proxy), so the
# platform's stop grace period must be longer than
# PII_SERVICE_REQUEST_DEADLINE_SECONDS (default 7200), or requests in progress
# are killed on deploy: Compose stop_grace_period, Kubernetes
# terminationGracePeriodSeconds.

# Pin by digest in production (python:3.13-slim@sha256:...).
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Exact versions come from constraints.txt, which requirements.txt loads.
COPY requirements.txt constraints.txt ./
RUN pip install -r requirements.txt

COPY pii_pipeline ./pii_pipeline

# The service writes no files: it runs as an unprivileged user and works on a
# read-only root filesystem.
RUN useradd --system --uid 10001 --no-create-home app
USER 10001

EXPOSE 8080

# For Docker and Compose; Kubernetes uses its own probes on the same paths
# (liveness GET /healthz, readiness GET /readyz).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=4).status == 200 else 1)"]

# One process per container; scale with replicas. The process already serves
# many requests at once because it mostly waits for the LLM proxy.
CMD ["uvicorn", "pii_pipeline.service:create_service_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
