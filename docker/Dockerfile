# syntax=docker/dockerfile:1.7
#
# LG-SOTF application image: one image, four process roles
# (lg-sotf api | worker | scheduler | migrate). See docs/deployment.md.
#
#   docker build -f docker/Dockerfile -t lg-sotf:dev .
#
# Build arguments:
#   BASE_IMAGE  Python runtime base. Override to use a registry mirror or a
#               digest-pinned image, e.g.
#               --build-arg BASE_IMAGE=mirror.gcr.io/library/python:3.11-slim
#               --build-arg BASE_IMAGE=python:3.11-slim@sha256:<digest>
#   VERSION, REVISION, CREATED   OCI label values (set by CI).
#
# Behind a TLS-intercepting proxy, pass its CA bundle as a build secret so pip
# can verify PyPI; it is never written into an image layer:
#   docker build --secret id=build_ca,src=/path/to/ca-bundle.crt ...

ARG BASE_IMAGE=python:3.11-slim

# ---------------------------------------------------------------------------
# Builder: resolve the pinned dependency set into a virtualenv and install the
# application wheel into it. Nothing from this stage but /opt/venv is shipped.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ONLY_BINARY=:all: \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

RUN python -m venv /opt/venv

WORKDIR /build

# Dependencies first so source edits do not invalidate this layer. Every
# runtime dependency is pinned in requirements.txt; only binary wheels are
# accepted, so the builder needs no compiler. dumb-init (static binary shipped
# as a wheel) is PID 1: it forwards signals and reaps zombies.
COPY requirements.txt ./
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; \
    pip install --upgrade "pip==25.2" \
 && pip install -r requirements.txt "dumb-init==1.2.5.post1"

# Build the application wheel with a pinned backend and install it without
# pulling any further dependency.
COPY pyproject.toml setup.py README.md LICENSE ./
COPY src/lg_sotf ./src/lg_sotf
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; \
    python -m venv /tmp/buildenv \
 && /tmp/buildenv/bin/pip install --disable-pip-version-check "setuptools==80.9.0" "wheel==0.45.1" \
 && /tmp/buildenv/bin/pip wheel --no-deps --no-build-isolation -w /dist . \
 && pip install --no-deps /dist/lg_sotf-*.whl \
 && pip check \
 && python -m compileall -q /opt/venv/lib \
 && lg-sotf version \
 && pip uninstall -y -q pip setuptools \
 && rm -rf /tmp/buildenv /dist

# ---------------------------------------------------------------------------
# Runtime: slim base, no build tools, no package manager use, non-root,
# read-only-root friendly (only /tmp needs to be writable).
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS runtime

ARG VERSION=1.0.0
ARG REVISION=unknown
ARG CREATED=unknown
ARG SOURCE=https://github.com/gapilongo/SOC

LABEL org.opencontainers.image.title="lg-sotf" \
      org.opencontainers.image.description="Multi-tenant AI triage and investigation platform for security alerts" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="LG-SOTF"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    TMPDIR=/tmp

# Fixed numeric ids so Kubernetes runAsNonRoot can verify the user.
RUN groupadd --system --gid 10001 lgsotf \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin lgsotf \
 && mkdir -p /app \
 && chown root:root /app \
 && chmod 0755 /app

COPY --from=builder /opt/venv /opt/venv
# Non-secret reference configs (select one with LG_SOTF_CONFIG_FILE). The
# development/testing files hold published placeholder keys that
# staging/production refuse.
COPY configs /app/configs
COPY docker/healthcheck.py /usr/local/lib/lg-sotf/healthcheck.py

WORKDIR /app
USER 10001:10001

# API port and the worker/scheduler health+metrics port.
EXPOSE 8000 9100

STOPSIGNAL SIGTERM

# Probes the role's own health endpoint (api :8000/healthz, worker and
# scheduler :9100/healthz); one-shot commands report healthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "/usr/local/lib/lg-sotf/healthcheck.py"]

ENTRYPOINT ["dumb-init", "--", "lg-sotf"]
CMD ["api"]
