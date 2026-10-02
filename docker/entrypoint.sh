#!/bin/sh
# สร้าง/อัปเดต superuser ครั้งแรกจาก env (upsert = idempotent จึงปลอดภัยที่จะรันทุกครั้งที่ start)
# แล้ว exec เป็น PID 1 เพื่อให้ `docker stop` ส่งสัญญาณถึง PocketBase ตรง ๆ
set -e

PB_DIR="${PB_DATA_DIR:-/app/pb_data}"

# รันเป็น root เพื่อแก้สิทธิ์ให้ data dir แล้วค่อย su-exec ลดสิทธิ์
# จำเป็นเพราะ compose bind-mount ./pb_data ซึ่งบน Linux จะเป็นของ host
# และผู้ใช้ใน container (uid 10001) เขียนไม่ได้ -> superuser upsert พัง
DOWN_UID="${PUID:-10001}"
if [ "$(id -u)" = "0" ]; then
    mkdir -p "$PB_DIR"
    chown -R "${DOWN_UID}:${DOWN_UID}" "$PB_DIR" 2>/dev/null || \
        echo "[entrypoint] warning: could not chown $PB_DIR, continuing"

    if [ -n "${SUPERUSER_EMAIL}" ] && [ -n "${SUPERUSER_PASSWORD}" ]; then
        echo "[entrypoint] ensuring superuser ${SUPERUSER_EMAIL}"
        su-exec "${DOWN_UID}" pocketbase superuser upsert \
            "${SUPERUSER_EMAIL}" "${SUPERUSER_PASSWORD}" --dir "$PB_DIR"
    else
        echo "[entrypoint] SUPERUSER_EMAIL/PASSWORD not set - skipping superuser upsert"
    fi

    echo "[entrypoint] starting as uid ${DOWN_UID}: pocketbase $*"
    exec su-exec "${DOWN_UID}" pocketbase "$@"
fi

# ไม่มี root (เช่นรันใน environment ที่ drop caps ตั้งแต่ build) -> รันตรง ๆ
if [ -n "${SUPERUSER_EMAIL}" ] && [ -n "${SUPERUSER_PASSWORD}" ]; then
    echo "[entrypoint] ensuring superuser ${SUPERUSER_EMAIL}"
    pocketbase superuser upsert "${SUPERUSER_EMAIL}" "${SUPERUSER_PASSWORD}" --dir "$PB_DIR"
fi

echo "[entrypoint] starting: pocketbase $*"
exec pocketbase "$@"