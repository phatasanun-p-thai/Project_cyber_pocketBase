# syntax=docker/dockerfile:1

# ---------------------------------------------------------------- build stage
FROM alpine:3.21 AS downloader

# Pin the release and let buildx fill TARGETARCH in (amd64 / arm64 / ...).
# A hard coded default here silently shipped an amd64 binary to arm64 hosts.
ARG PB_VERSION=0.40.4
ARG TARGETARCH

RUN apk add --no-cache curl unzip

RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64|arm64|armv6) ;; \
      *) echo "unsupported TARGETARCH: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/pb.zip \
      "https://github.com/pocketbase/pocketbase/releases/download/v${PB_VERSION}/pocketbase_${PB_VERSION}_linux_${arch}.zip"; \
    unzip -q /tmp/pb.zip -d /tmp/pb; \
    chmod +x /tmp/pb/pocketbase; \
    /tmp/pb/pocketbase --version

# ----------------------------------------------------------------- run stage
FROM alpine:3.21

# ca-certificates for SMTP/TLS, tzdata so log timestamps match the wall clock,
# su-exec to drop privileges only after the entrypoint fixed the data dir,
# curl for the entrypoint to seed the mailer settings over the API.
RUN apk add --no-cache ca-certificates tzdata wget curl su-exec

COPY --from=downloader /tmp/pb/pocketbase /usr/local/bin/pocketbase

# These are PocketBase's defaults for a binary in /app - the paths are derived
# from the executable location, not the working directory.
WORKDIR /app
COPY pb_hooks/ /app/pb_hooks/
COPY pb_migrations/ /app/pb_migrations/
COPY pb_public/ /app/pb_public/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN adduser -D -H -u 10001 pocketbase \
  && mkdir -p /app/pb_data \
  && chown -R pocketbase:pocketbase /app \
  && chmod +x /usr/local/bin/entrypoint.sh

VOLUME /app/pb_data
EXPOSE 8090

# NOTE: the healthcheck lives here only. docker-compose.yaml deliberately does
# not repeat it, otherwise `depends_on: service_healthy` would read a second,
# possibly diverging definition.
#
# /api/health is the cheap unauthenticated readiness probe; the `wget` that is
# installed in the run stage exists for exactly this. The port is hard coded to
# the in-container one on purpose - it must not follow POCKETBASE_PORT, which is
# the *host* side of the published port in docker-compose.yaml.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:8090/api/health" || exit 1

# Entrypoint still needs root to chown a host bind mount, then drops to
# `pocketbase` via su-exec before exec'ing the server.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]