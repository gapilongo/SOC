# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# LG-SOTF application image: one image, four process roles
# (lg-sotf api | worker | scheduler | migrate). See docs/deployment.md.
#
#   docker build -f docker/Dockerfile -t lg-sotf:dev .
#
# Build arguments:
#   BASE_IMAGE  Python runtime base. Empty (the default) builds from the
#               digest-pinned python-base stage below; set it to use a registry
#               mirror, ideally pinned by the same digest, e.g.
#               --build-arg BASE_IMAGE=mirror.gcr.io/library/python:3.11-slim@sha256:<digest>
#   VERSION, REVISION, CREATED   OCI label values (set by CI).
#
# Behind a TLS-intercepting proxy, pass its CA bundle as a build secret so pip
# can verify PyPI; it is never written into an image layer:
#   docker build --secret id=build_ca,src=/path/to/ca-bundle.crt ...

ARG BASE_IMAGE=

# The base image, pinned by digest (tag kept for readability; Dependabot bumps
# both). Only pulled when BASE_IMAGE is empty.
FROM python:3.11-slim@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79 AS python-base

# ---------------------------------------------------------------------------
# Builder: install the hash-locked dependency set into a virtualenv and the
# application wheel on top. Nothing from this stage but /opt/venv is shipped.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE:-python-base} AS builder

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
# package is pinned with the SHA-256 of each of its files (--require-hashes:
# a changed or substituted file on the index fails the build); only binary
# wheels are accepted, so the builder needs no compiler.
# docker/requirements-build.txt: pip and setuptools (to build the application
# wheel, removed below) and dumb-init (static binary shipped as a wheel), PID 1:
# it forwards signals and reaps zombies.
COPY requirements.txt docker/requirements-build.txt ./
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; \
    pip install --require-hashes -r requirements-build.txt \
 && pip install --require-hashes -r requirements.txt

# Build the application wheel with the pinned backend and install it without
# pulling any further dependency.
COPY pyproject.toml setup.py README.md LICENSE ./
COPY src/lg_sotf ./src/lg_sotf
RUN pip wheel --no-deps --no-build-isolation -w /dist . \
 && pip install --no-deps /dist/lg_sotf-*.whl \
 && pip check \
 && python -m compileall -q /opt/venv/lib \
 && lg-sotf version \
 && pip uninstall -y -q pip setuptools \
 && rm -rf /dist

# ---------------------------------------------------------------------------
# Runtime: slim base, no build tools, no package manager use, non-root,
# read-only-root friendly (only /tmp needs to be writable).
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE:-python-base} AS runtime

ARG VERSION=0.2.0
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
# The base image's own pip/setuptools/wheel (the app runs from /opt/venv and never
# installs anything) and its setuid/setgid bits are removed: nothing for image
# scanners to flag and nothing for the unprivileged user to escalate through.
RUN groupadd --system --gid 10001 lgsotf \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin lgsotf \
 && mkdir -p /app \
 && chown root:root /app \
 && chmod 0755 /app \
 && /usr/local/bin/python -m pip uninstall -y -q pip setuptools wheel \
 && rm -rf /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc* /usr/local/bin/2to3* \
        /usr/local/lib/python3*/ensurepip \
 && find / -xdev -type f -perm /6000 -exec chmod a-s {} + \
 && ! find / -xdev -type f -perm /6000 | grep -q .

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
