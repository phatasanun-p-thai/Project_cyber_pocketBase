# syntax=docker/dockerfile:1

# ---------------------------------------------------------------- build stage
FROM alpine:3.21 AS downloader

ARG PB_VERSION=0.40.4
ARG TARGETARCH=amd64

RUN apk add --no-cache curl unzip

RUN curl -fsSL -o /tmp/pb.zip \
      "https://github.com/pocketbase/pocketbase/releases/download/v${PB_VERSION}/pocketbase_${PB_VERSION}_linux_${TARGETARCH}.zip" \
 && unzip -q /tmp/pb.zip -d /tmp/pb \
 && chmod +x /tmp/pb/pocketbase

# ----------------------------------------------------------------- run stage
FROM alpine:3.21

# ca-certificates สำหรับต่อ SMTP/TLS, tzdata เพื่อให้เวลาใน log เป็นเวลาไทย
RUN apk add --no-cache ca-certificates tzdata wget

COPY --from=downloader /tmp/pb/pocketbase /usr/local/bin/pocketbase

# โฟลเดอร์เหล่านี้คือค่า default ของ PocketBase เมื่อ binary อยู่ที่ /app
# (PocketBase อ้างอิง path จากโฟลเดอร์ของ executable ไม่ใช่ working directory)
WORKDIR /app
COPY pb_hooks/ /app/pb_hooks/
COPY pb_migrations/ /app/pb_migrations/
COPY index.html /app/pb_public/index.html
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# สร้าง user ธรรมดา + เตรียม pb_data ให้เป็นของ user นี้
# (named volume จะสืบทอด ownership จากตรงนี้ตอนถูกสร้างครั้งแรก)
RUN adduser -D -H -u 10001 pocketbase \
 && mkdir -p /app/pb_data \
 && chown -R pocketbase:pocketbase /app \
 && chmod +x /usr/local/bin/entrypoint.sh

USER pocketbase
VOLUME /app/pb_data
EXPOSE 8090

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD wget -qO- http://127.0.0.1:8090/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
