#!/bin/sh
# สร้าง superuser ครั้งแรกจาก env (upsert = idempotent จึงปลอดภัยที่จะรันทุกครั้งที่ start)
# แล้ว exec เป็น PID 1 เพื่อให้ docker stop ส่งสัญญาณถึง PocketBase ตรง ๆ
set -e

if [ -n "${SUPERUSER_EMAIL}" ] && [ -n "${SUPERUSER_PASSWORD}" ]; then
    echo "[entrypoint] ensuring superuser ${SUPERUSER_EMAIL}"
    pocketbase superuser upsert "${SUPERUSER_EMAIL}" "${SUPERUSER_PASSWORD}" --dir /app/pb_data
fi

echo "[entrypoint] starting: pocketbase $*"
exec pocketbase "$@"
