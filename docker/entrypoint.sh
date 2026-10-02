#!/bin/sh
# สร้าง/อัปเดต superuser ครั้งแรกจาก env (upsert = idempotent จึงปลอดภัยที่จะรันทุกครั้งที่ start)
# แล้ว seed ค่า SMTP ลงใน PocketBase settings ผ่าน API เพราะ PocketBase 0.40
# ไม่มี flag --smtpHost อีกแล้ว และ JS hook ก็เขียน settings ไม่ได้
#
# PocketBase ต้องรันเป็น background process เพื่อให้มีช่วงเวลาที่จะ seed ได้ จึงไม่
# สามารถ exec เป็น PID 1 ได้อีก - trap จึงทำหน้าที่ forward SIGTERM ต่อไปหา child
# แทน (ถ้าไม่ทำ `docker stop` จะรอครบ 10 วินาทีแล้วค่อย SIGKILL)
set -e

PB_DIR="${PB_DATA_DIR:-/app/pb_data}"
PB_HOST="${PB_SEED_HOST:-127.0.0.1}"
PB_PORT="${PB_SEED_PORT:-8090}"
DOWN_UID="${PUID:-10001}"

upsert_superuser() {
    if [ -n "${SUPERUSER_EMAIL}" ] && [ -n "${SUPERUSER_PASSWORD}" ]; then
        echo "[entrypoint] ensuring superuser ${SUPERUSER_EMAIL}"
        pocketbase superuser upsert \
            "${SUPERUSER_EMAIL}" "${SUPERUSER_PASSWORD}" --dir "$PB_DIR"
    else
        echo "[entrypoint] SUPERUSER_EMAIL/PASSWORD not set - skipping superuser upsert"
    fi
}

# PocketBase 0.40 เก็บค่า mailer ใน settings record ซึ่งเขียนจาก JS hook ไม่ได้
# (_settings เป็น system collection และ $app ไม่มี saveSettings) ทางเดียวคือ
# PATCH /api/settings ด้วย superuser token - สองอย่างที่ง่ายจะพลาด:
#   1. token ของ superuser ต้องส่งเป็น JWT เปล่า ๆ ถ้าใส่ prefix "Token " จะได้ 401
#   2. endpoint คือ PATCH ไม่ใช่ PUT (PUT ได้ 404)
seed_mailer() {
    if [ -z "${SMTP_HOST}" ] || [ -z "${SMTP_USER}" ] || [ -z "${SMTP_PASS}" ]; then
        echo "[entrypoint] SMTP_HOST/SMTP_USER/SMTP_PASS not set - skipping mailer seed"
        return 0
    fi
    if [ -z "${SUPERUSER_EMAIL}" ] || [ -z "${SUPERUSER_PASSWORD}" ]; then
        echo "[entrypoint] no superuser credentials - cannot seed mailer"
        return 0
    fi

    token=$(curl -fsS -X POST "http://${PB_HOST}:${PB_PORT}/api/collections/_superusers/auth-with-password" \
        -H 'Content-Type: application/json' \
        -d "{\"identity\":\"${SUPERUSER_EMAIL}\",\"password\":\"${SUPERUSER_PASSWORD}\"}" \
        2>/dev/null | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

    if [ -z "${token}" ]; then
        echo "[entrypoint] warning: could not obtain superuser token - mailer left unconfigured"
        return 0
    fi

    port="${SMTP_PORT:-587}"
    # tls=true คือ implicit TLS (465 เท่านั้น) ส่วน 587 คือ STARTTLS
    # ซึ่ง PocketBase เจอจาก tls=false เอง - ตั้ง true ที่ 587 แล้วทุกฉบับจะ fail
    if [ "${port}" = "465" ] || [ "${SMTP_TLS:-}" = "implicit" ]; then
        tls=true
    else
        tls=false
    fi
    from="${SMTP_FROM:-${SMTP_USER}}"

    code=$(curl -s -o /dev/null -w '%{http_code}' -X PATCH "http://${PB_HOST}:${PB_PORT}/api/settings" \
        -H "Authorization: ${token}" \
        -H 'Content-Type: application/json' \
        -d "{\"smtp\":{\"enabled\":true,\"host\":\"${SMTP_HOST}\",\"port\":${port},\"username\":\"${SMTP_USER}\",\"password\":\"${SMTP_PASS}\",\"tls\":${tls},\"authMethod\":\"PLAIN\"},\"meta\":{\"senderAddress\":\"${from}\"}}")

    if [ "${code}" = "200" ]; then
        echo "[entrypoint] mailer configured from SMTP_* env (${SMTP_HOST}:${port})"
    else
        echo "[entrypoint] warning: PATCH /api/settings returned ${code} - alerts will not be sent"
    fi
}

# รันเป็น root เพื่อแก้สิทธิ์ให้ data dir แล้วค่อย su-exec ลดสิทธิ์
# จำเป็นเพราะ compose bind-mount ./pb_data ซึ่งบน Linux จะเป็นของ host
# และผู้ใช้ใน container (uid 10001) เขียนไม่ได้ -> superuser upsert พัง
if [ "$(id -u)" = "0" ]; then
    mkdir -p "$PB_DIR"
    chown -R "${DOWN_UID}:${DOWN_UID}" "$PB_DIR" 2>/dev/null || \
        echo "[entrypoint] warning: could not chown $PB_DIR, continuing"

    upsert_superuser

    echo "[entrypoint] starting as uid ${DOWN_UID}: pocketbase $*"
    su-exec "${DOWN_UID}" pocketbase "$@" &
    pb_pid=$!
else
    upsert_superuser

    echo "[entrypoint] starting: pocketbase $*"
    pocketbase "$@" &
    pb_pid=$!
fi

# `docker stop` ส่ง SIGTERM มาที่ shell (PID 1) ไม่ใช่ PocketBase ตอนนี้
# จึงต้อง forward เอง ไม่งั้น `docker stop` จะรอ timeout 10 วินาทีแล้ว SIGKILL
trap 'kill -TERM "${pb_pid}" 2>/dev/null' TERM INT

# รอให้ server ตอบก่อน seed (migration ต้องเสร็จก่อน)
i=0
while [ "$i" -lt 60 ]; do
    if curl -fsS -o /dev/null "http://${PB_HOST}:${PB_PORT}/api/health" 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
seed_mailer

wait "${pb_pid}"