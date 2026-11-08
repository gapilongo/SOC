# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# LG-SOTF analyst web app: static build served by unprivileged nginx.
#
#   docker build -t lg-sotf-frontend:dev src/lg_front
#
# Build arguments (empty, the default, builds from the digest-pinned node-base
# and nginx-base stages below; set them to use a registry mirror, ideally
# pinned by the same digests):
#   NODE_IMAGE   Node.js build image (e.g. mirror.gcr.io/library/node:22-alpine@sha256:<digest>).
#   NGINX_IMAGE  Runtime image; must be an nginx-unprivileged variant (runs as
#                a non-root user and listens on 8080).
#
# Behind a TLS-intercepting proxy, pass its CA bundle as a build secret so npm
# can verify the registry; it is never written into an image layer:
#   docker build --secret id=build_ca,src=/path/to/ca-bundle.crt ...
#
# Runtime configuration comes from environment variables, turned into
# /config.js and the Content-Security-Policy at container start (see
# docker/entrypoint.sh), so one image serves every environment. The build
# embeds no URLs and no secrets.

ARG NODE_IMAGE=
ARG NGINX_IMAGE=

# Base images, pinned by digest (tags kept for readability; Dependabot bumps
# both). Each is only pulled when its override above is empty. The runtime is
# the -slim variant: nginx and busybox only, no curl, libxml2 or image libraries.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS node-base
FROM nginxinc/nginx-unprivileged:1.31-alpine-slim@sha256:a8cb0f33d51fa107c96fd2bd3a71aaf564ec131e9d2bdf8700944f0ed8b170d7 AS nginx-base

# ---------------------------------------------------------------------------
# Build: install the locked dependency set, type-check and bundle. The output
# is static files, so this stage runs on the build host's own platform even in
# a multi-arch build (no emulated npm/vite for linux/arm64).
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE:-node-base} AS build
ENV CI=true \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/build_ca; fi; \
    npm ci --ignore-scripts
COPY . .
RUN npm run build \
 && rm -f dist/config.js \
 && test -f dist/index.html \
 && ! grep -Eq '<script>|<script[^>]*>[^<]' dist/index.html

# ---------------------------------------------------------------------------
# Runtime: static files only; nginx runs as a non-root user and writes
# nothing outside /tmp, so the root filesystem can be mounted read-only.
# ---------------------------------------------------------------------------
FROM ${NGINX_IMAGE:-nginx-base} AS runtime

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="lg-sotf-frontend" \
      org.opencontainers.image.description="LG-SOTF analyst web app" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT"

USER root
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/* /docker-entrypoint.d
COPY --chmod=0644 docker/nginx.conf /etc/nginx/nginx.conf
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/lg-sotf-frontend-entrypoint
COPY --from=build /app/dist /usr/share/nginx/html
# Static content is root-owned and read-only for the server user.
RUN chown -R root:root /usr/share/nginx/html \
 && chmod -R a+rX,go-w /usr/share/nginx/html

# nginx-unprivileged's user (uid 101); any non-root uid works as long as
# /tmp is writable (Kubernetes runAsUser, compose tmpfs).
USER 101
EXPOSE 8080
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/lg-sotf-frontend-entrypoint"]
CMD ["nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]
