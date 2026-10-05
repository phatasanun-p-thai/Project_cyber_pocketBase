นายธนกฤต ณ. พัทลุง 006-8<br>
นางสาวกัญจนพร กระจาดแก้ว 005-0<br>
นายพรรษนันท์ เปี่ยมยานนท์ 002-7<br>


# PocketBase Security Monitor (SIEM)

SIEM เล็ก ๆ บน PocketBase — ดักจับการโจมตีที่ผ่าน REST API ทุก request แล้วบันทึกลง
collection `attack_logs` พร้อมส่งอีเมลแจ้งเตือนเมื่อเจอเคสระดับ high / critical

| ส่วน | ที่อยู่ |
| --- | --- |
| Middlehook ตรวจจับ | `pb_hooks/main.pb.js` |
| Dev helper ดึง reset token | `pb_hooks/dev_reset_token.pb.js` |
| Schema + API rules | `pb_migrations/` |
| หน้าแดชบอร์ด (Tailwind ไม่มี build step) | `pb_public/index.html` |
| Docker | `Dockerfile`, `docker-compose.yaml`, `docker/entrypoint.sh` |
| สคริปต์เปิดใช้งาน | `start.ps1` |
| ชุดทดสอบการโจมตี | `test.http` |

## เริ่มใช้งานแบบ Docker (แนะนำ)

ครั้งแรกสร้างไฟล์ env (ทำแค่ครั้งเดียว) ค่าพอร์ตและ superuser จะถูกอ่านจากไฟล์นี้

```bash
cp .env.example .env      # Windows: Copy-Item .env.example .env
# แก้ค่าใน .env อย่างน้อย SUPERUSER_EMAIL / SUPERUSER_PASSWORD
```

จากนั้นทุกครั้งที่จะเปิดใช้งาน:

```powershell
.\start.ps1               # สตาร์ท + รอให้พร้อม + เปิดเบราว์เซอร์ให้เอง
```

| ตัวเลือก | ทำอะไร |
| --- | --- |
| (ไม่ใส่) | ใช้ image ที่ build ไว้แล้ว เร็วที่สุด เหมาะกับการแค่เปิดดูข้อมูล |
| `-Build` | build image ใหม่ ใช้หลังแก้ `pb_public/` หรือ `pb_hooks/` |
| `-NoOpen` | รันแล้วพิมพ์ URL อย่างเดียว ไม่เปิดเบราว์เซอร์ |
| `-TimeoutSec` | จำนวนวินาทีที่ยอมรอ (ค่าเริ่มต้น 60) |

สคริปต์อ่าน `POCKETBASE_PORT` จาก `.env` มาประกอบ URL ให้เอง จึงไม่ต้องแก้ที่ใหนเพิ่ม

เทียบเทียบกับการรันเอง: `.\start.ps1 -NoOpen` คือ `docker compose up -d` + เปิด
<http://127.0.0.1:8090> แล้ว Sign in ด้วยบัญชี superuser

> ไฟล์ `start.ps1` ต้องมี **UTF-8 with BOM** — PowerShell 5.1 (ค่าเริ่มต้นบน Windows)
> อ่านไฟล์ที่ไม่มี BOM เป็น ANSI แล้วข้อความไทยจะกลายเป็นอักขระยึกเยิ้ ถ้าแก้ไฟล์นี้
> ให้บันทึกกลับเป็น UTF-8 with BOM

- port ถูก publish ไว้ที่ `127.0.0.1` **เท่านั้น** (`POCKETBASE_PORT` เปลี่ยนได้)
  ถ้าจะเปิดออกนอกเครื่อง ต้องมี reverse proxy ที่มี TLS + auth ตั้งไว้ข้างหน้าเสมอ
  admin UI ของ PocketBase และแดชบอร์ดนี้ไม่มี authentication นอกเหนือจากตัว login
- `SUPERUSER_EMAIL` / `SUPERUSER_PASSWORD` ถูก `superuser upsert` ทุกครั้งที่ container
  start (idempotent) ดู `docker/entrypoint.sh`
- healthcheck อยู่ใน `Dockerfile` เท่านั้น `compose` ไม่นิยามซ้ำ

## เริ่มใช้งานแบบ local (ไม่มี Docker)

PocketBase ต้องอยู่ในโฟลเดอร์เดียวกับ `pb_hooks/`, `pb_migrations/`, `pb_public/`
เพราะ path ทั้งหลาย derive จากตำแหน่งไฟล์ executable (ไม่ใช่ working directory)

```bash
# 1.2x ขึ้นไป (arm64 / armv6 ต้องเลือก asset ให้ตรงสถาปัตยกรรมเอง)
curl -fsSL -o pocketbase.zip \
  https://github.com/pocketbase/pocketbase/releases/download/v0.40.4/pocketbase_0.40.4_linux_amd64.zip
unzip -q pocketbase.zip && rm pocketbase.zip

# สร้าง superuser
./pocketbase superuser upsert you@example.com 'your-password'   # Windows: .\pocketbase.exe ...

# รัน (รันครั้งแรกจะสร้าง pb_data/ และ pb_data/types.d.ts ให้เอง)
./pocketbase serve
```

> `pocketbase migrate up` จะ**ไม่**สร้าง `pb_data/types.d.ts` — ไฟล์นี้ถูก generate
> ตอน `serve` เท่านั้น ถ้า editor บอกว่า `pb_hooks/main.pb.js` อ้างไฟล์ที่หาไม่เจอ
> ให้รัน server สักครั้งก่อน

## ทดสอบว่า hook ทำงาน

เปิด `test.http` ด้วย VS Code REST Client / IntelliJ HTTP Client แล้วยิงตามลำดับ

1. `.\start.ps1` (หรือ `./pocketbase serve` ถ้ารันแบบไม่มี Docker)
2. เปิด <http://127.0.0.1:8090> → Sign in ด้วย superuser แล้วเปิดแดชบอร์ดค้างไว้
3. ยิง **STEP 1** ครั้งแรก 1 ครั้งต่อ instance ที่ยังสะอาด (สมัคร victim + attacker)
4. ยิง **STEP 2 / 3 / 4** ทีละ request แล้วดูแดชบอร์ด

หัวไฟล์ `test.http` มีตารางผลลัพธ์ที่คาดหวังอยู่แล้ว **ตรงกับพฤติกรรมจริง** ณ ปัจจุบัน
ถ้าแก้ `classify()` ใน hook ต้องแก้ตารางนั้นตามด้วย ไม่งั้นเอกสารจะโกหกตัวเอง

## ทำไมถึงต้องมี dev_reset_token.pb.js

PocketBase **ไม่เก็บ reset token ไว้ในฐานข้อมูลเลย** ยืนยันจาก schema จริง:

```sql
-- pb_data/data.db
CREATE TABLE `_superusers` (created, email, emailVisibility, id,
                            password, tokenKey, updated, verified)
-- ไม่มี passwordResetToken และไม่มีตาราง _password_reset_tokens
```

ตั้งแต่ v0.23 token ถูกทำเป็น **stateless JWT** ผูกกับ `TokenConfig.secretKey`
ฝั่ง server ยืนยันจากลายเซ็นอย่างเดียว ไม่ต้องมี state ให้เก็บ ผลคือ

- `POST /api/collections/{c}/request-password-reset` ตอบ **204 No Content ว่างเปล่า**
  จึงไม่มี token ให้ดู และหา token จากที่ไหนไม่ได้
- อ่าน record ด้วย `$app` หรือด้วย superuser token ก็ไม่มี (REST API ยิ่งเป็นไปได้
  เพราะ `PublicExport()` กรอง field พวกนี้ออกอีกชั้น)
- ตัว token มีอยู่ที่เดียวคือในลิงก์ในอีเมล
  `/_/#/auth/confirm-password-reset/<JWT>`

และบนเครื่อง lab อีเมล `example.com` ส่งไม่ถึงอยู่แล้ว เพราะโดเมนนี้มี
null MX record (RFC 7505) คือปฏิเสธอีเมลทุกชนิด ตรวจได้ด้วย
`Resolve-DnsName example.com -Type MX` ได้ `NameExchange = "."`
(ต่างจาก `example.com couldn't be found` ซึ่งเป็นอีเเรอร์ของกรณีที่โดเมน
ไม่มี MX เลย)

ข้อที่ทำให้ debug ยากที่สุด: Gmail ตอบ `250 OK` ตอนรับ `DATA` แล้วค่อย
bounce ทีหลังแบบ async → **PocketBase ไม่ log error ใดๆ** ใน `docker logs`
ทั้งที่ไม่มีใครได้รับอีเมล ต้องไปเช็ค MX เองถึงจะรู้ว่าไม่ใช่ปัญหา
SMTP credentials วิธีเช็คว่าเป็นปัญหา SMTP จริงไหม คือยิง
`STARTTLS` + `AUTH PLAIN` แล้วดูว่าได้ `2352.7.0 Accepted` หรือไม่

`dev_reset_token.pb.js` จึงแอบจับ token ตรงจุดที่ยังมีชีวิตอยู่ คือ hook
`onMailerRecordPasswordResetSend` (ยิง **ก่อน** SMTP ส่งจริง จึงทำงานได้แม้ผู้รับ
จะ bounce) แล้วเก็บลง `$app.store()` ซึ่งเป็น in-memory store ระดับ app ข้าม request
ได้ แต่หายเมื่อ restart

เปิดใช้ผ่าน route ที่ผูก `$apis.requireSuperuserAuth()`:

```
GET  /api/dev/password-reset-token?collection=users&email=victim@example.com
POST /api/dev/delete-auth-record?collection=users&email=newuser@example.com
```

ถ้ายังไม่เคยยิง `request-password-reset` route แรกจะ**ส่งอีเมล reset ให้เอง**
ก่อน (`autoTrigger`) จึงคลิกครั้งเดียวได้ token เลย ไม่ต้องยิง 2 คำขอ ใส่
`?trigger=0` ได้ถ้าอยากบังคับให้ยิงตามลำดับจริง

route ที่สองมีไว้เพราะ `POST /api/collections/users/records` ตอบ
**400 `validation_not_unique`** ทันทีที่ยิงซ้ำด้วยอีเมลเดิม (email มี unique
index) ถ้าไม่มี route นี้ การสมัครผู้ใช้ซ้ำในเครื่องเดิมต้องไปแก้ชื่ออีเมลทุกครั้ง
ตัว route ลบได้เฉพาะ `users` — `_superusers` ถูกกันไว้โดยตั้งใจ กันไม่ให้ลบ
บัญชีแอดมินทิ้งผ่าน helper

| ข้อควรรู้ | |
| --- | --- |
| token หมดอายุ | ตาม `settings.passwordResetToken.expiresIn` — ถ้า confirm แล้วได้ 400 ให้ขอใหม่ |
| แก้ไฟล์นี้แล้ว | ต้อง `.\start.ps1 -Build` (Docker copy `pb_hooks/` เข้า image) |
| `enabled = true` | ค่าในไฟล์ตอนนี้ (lab ต้องใช้ เพราะอีเมล `example.com` bounce) ถ้าแก้เป็น `false` route จะตอบ 404 — fresh clone ที่ไม่อยากเปิดช่องรั่วควรแก้เป็น false ก่อน commit |
| ก่อนขึ้น production | **ลบไฟล์นี้ทิ้ง** |

## hook ตรวจอะไรบ้าง

| attack_type | เงื่อนไข |
| --- | --- |
| `PRIVILEGE_ESCALATION` | write ที่สำเร็จ และ body มี field สิทธิ์พิเศษ (`role`, `isadmin`, ...) |
| `MASS_ASSIGNMENT` | เหมือนข้างบนแต่ถูกปฏิเสธ |
| `BOLA_IDOR` | write/read ที่กระทบ record ของคนอื่น รวมถึง 404 ที่กติกา API rule ซ่อน record ไว้ |
| `UNAUTHENTICATED_WRITE` | write ที่ไม่มี token และไม่ใช่การสมัครสมาชิก |
| `UNAUTHENTICATED_ACCESS` / `FORBIDDEN_ACCESS` | 401 / 403 |
| `AUTH_FAILURE` | login ผิดรหัส |
| `BRUTE_FORCE` | `AUTH_FAILURE` จาก IP เดียวกันครบ 5 ครั้งใน 2 นาที (critical) |
| `INJECTION_PROBE` | SQLi / XSS marker ใน query string หรือ body |
| `RATE_LIMIT_HIT` | 429 |

ทุกค่าปรับได้ที่ object `SEC` ด้านบนของ `pb_hooks/main.pb.js`

### ข้อควรรู้เรื่อง hook

- hook เป็น **ผู้สังเกตการณ์เท่านั้น** ไม่ block คำขอใด ๆ ชั้นความปลอดภัยจริงอยู่ที่
  API rules ใน migrations
- **อย่าย้าย helper ออกไปนอก callback ของ `routerUse`** PocketBase รัน hook ผ่าน
  goja runtime แบบ pooled และเรียก middleware จาก source ที่ถูก serialize ไว้
  ตัวแปรระดับไฟล์จึง out of scope ตอน callback ทำงาน และจะกลายเป็น
  `ReferenceError` ที่ PocketBase รายงานเป็น HTTP 400 ทั้งระบบ
- `trustProxyHeader: false` ไว้เพราะ `e.realIP()` เชื่อ header `X-Forwarded-For` ที่
  spoof ได้ง่าย ถ้าวางหลัง reverse proxy ที่เขียน header นี้ให้เที่ยวจริงค่อยเปิด
- ตัวนับ brute force อ่านกลับจาก DB ทุกครั้ง ไม่พึ่ง state ใน memory ล้วน การ restart
  PocketBase จึงไม่ทำให้ทั้งระบบตื่นตัวพร้อมกัน

## collection

- **`attack_logs`** — ล็อก **superuser เท่านั้น** (rule เป็น `null`) ไม่ว่าจะ list, view,
  create, update, delete การเปิด self-service ไว้ให้ผู้ใช้ทั่วไปอ่าน incident ทั้งหมด
  เป็นช่องรั่วที่เคยเกิดขึ้นและถูกแก้ใน migration `1790640001`
  hook เขียนผ่าน `$app.save()` ซึ่งข้าม API rules
- **`users`** — auth collection สำหรับเป็นเหยื่อของ `test.http` สร้างใน
  `1790640002` เปิด self-registration ไว้เพื่อให้ทดสอบได้ ถ้าขึ้น production ต้อง
  เปลี่ยน `createRule` เป็น `null` และตัด field สิทธิ์พิเศษออก (ดูคอมเมนต์ในไฟล์)

### กฎ PocketBase ที่มักเข้าใจผิด

```
null  = ให้ superuser อย่างเดียว   <- ล็อก
""    = สาธารณะ / ไม่ต้องล็อกอิน  <- เปิดโล่ง
```

## อีเมลแจ้งเตือน

จะส่งเมื่อ severity เป็น `high` หรือ `critical` เท่านั้น ตั้งค่าใน `.env`:

| ตัวแปร | หมายเหตุ |
| --- | --- |
| `SMTP_HOST` | ว่าง = ปิดการส่งอีเมล (hook จะ log ว่าไม่ได้ตั้งค่า) |
| `SMTP_PORT` | `465` = SMTPS / `587` = STARTTLS |
| `SMTP_TLS` | ค่า `implicit` บังคับ TLS ตรง (ค่าปริยายคือปล่อยให้ client ต่อรอง) |
| `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Gmail ต้องใช้ App Password |
| `ALERT_EMAIL` | ผู้รับอีเมล ถ้าเว้นว่างจะส่งไปที่อีเมล superuser คนแรก |

### ทำไมต้องมีขั้นตอน seed

PocketBase 0.40 **ไม่ได้อ่าน `SMTP_*` จาก environment เอง** และ JS hook ก็เขียนค่า mailer
ไม่ได้ (`_settings` เป็น system collection, `$app` ไม่มี `saveSettings()`) ค่า mailerจึงถูกเก็บ
ใน settings record ที่แก้ได้จาก Settings > Mailer หรือ REST API เท่านั้น

`docker/entrypoint.sh` จึงเป็นตัวแทน: หลัง server ตอบ `/api/health` แล้ว มันจะ auth เป็น
superuser แล้ว `PATCH /api/settings` เพื่อ seed ค่าจาก `SMTP_*` **ทุกครั้งที่ container start**
(rotate รหัสใน `.env` แล้ว restart ก็ได้ผลใหม่โดยไม่ต้องแตะ UI) ดู log เพื่อยืนยันว่าสำเร็จ:

```
[entrypoint] mailer configured from SMTP_* env (smtp.gmail.com:587)
[security] alert email sent to you@example.com (CRITICAL BRUTE_FORCE)
```

จุดที่ง่ายจะพลาดในการ seed เอง (เคยเจอแล้วระหว่างทดสอบ) — ถ้าเขียนเองต้องระวังสองข้อนี้:

1. **token ของ superuser ต้องส่งเป็น JWT เปล่า ๆ** คือ `Authorization: <jwt>` ไม่ใช่
   `Authorization: Token <jwt>` — ใส่ prefix แล้วได้ `401` ทั้งที่ token นั้นถูกต้อง
   (endpoint อื่นที่ใช้กฎจะผ่าน เพราะ superuser ถูก bypass rule)
2. **method คือ `PATCH` ไม่ใช่ `PUT`** (`PUT` ได้ `404`)

ยืนยันว่า settings ถูกบันทึกแล้วด้วย `GET /api/settings` (สังเกตว่า `smtp.password` จะ
กลับมาเป็นค่าว่างเสมอ เพราะ PocketBase redact ไว้ ไม่ได้แปลว่ารหัสหาย)

มี cooldown 2 นาทีต่อ incident และเพดาน 10 ฉบับ / 10 นาทีต่อผู้รับ กันใช้บัญชี SMTP
เป็น mail bomb

> รหัสผ่าน SMTP อยู่ใน `.env` ซึ่งถูก gitignore และถูกล้างออกจาก git history แล้ว
> ถ้าเคย paste ค่าไว้ในที่สาธารณะ (เช่น issue/แชต) ให้ revoke App Password นั้นแล้วสร้างใหม่

## โครงสร้างโฟลเดอร์

```
pb_hooks/main.pb.js     middleware ตรวจจับทั้งหมด
pb_hooks/dev_reset_token.pb.js
                        DEV ONLY - GET /api/dev/password-reset-token
                        ดูหัวข้อ "ทำไมถึงต้องมี dev_reset_token.pb.js"
pb_migrations/          1790640000 attack_logs
                        1790640001 ล็อก attack_logs ให้ superuser
                        1790640002 users (เหยื่อสำหรับ test.http)
pb_public/index.html    แดชบอร์ด realtime
pb_data/                ฐานข้อมูลจริง + types.d.ts (gitignored)
start.ps1               สตาร์ท + เปิดเบราว์เซอร์
test.http               ชุดทดสอบการโจมตี
```

`pb_data/` คือฐานข้อมูลจริงที่ `docker-compose.yaml` mount เข้าไป **มีแค่ที่เดียว**
ถ้าเคยเจอโฟลเดอร์ `data-pb/` แปลว่าเป็นข้อมูลชุดเก่าที่ไม่ได้ถูกใช้ — ลบทิ้งได้

## ก่อนขึ้น production

- [ ] เปลี่ยน `SUPERUSER_PASSWORD` เป็นค่าสุ่มยาว ๆ และอย่า commit `.env`
- [ ] ลบ `pb_hooks/dev_reset_token.pb.js` ทิ้ง แล้ว rebuild image
      (มันเปิด reset token ให้ superuser อ่านได้ แม้จะผูก auth ไว้แล้ว)
- [ ] ตั้ง `ALERT_EMAIL` เป็นกล่องจดหมายที่ใครมีเวลาอ่านจริง ไม่ใช่
      `admin@example.com` (ไม่งั้นอีเมลถูกส่งแล้วไม่มีใครเห็น)
- [ ] เปลี่ยน `users.createRule` เป็น `null` ถ้าไม่ต้องการ self-service
- [ ] ตัด field สิทธิ์พิเศษออกจาก schema หรือป้องกันด้วย validation hook
- [ ] ตั้ง reverse proxy ที่มี TLS ต่อหน้า อย่าออก port 8090 ตรง ๆ
- [ ] ตั้ง `SEC.trustProxyHeader = true` **เฉพาะเมื่อ** reverse proxy เขียน
      `X-Forwarded-For` ให้เที่ยวจริง
- [ ] สำรอง `pb_data/` และกำหนดว่าจะเก็บ incident นานแค่ไหน (ตอนนี้ไม่มีการล้างอัตโนมัติ)
- [ ] ตรวจว่าเข้า `cdn.tailwindcss.com` จากเน็ตภายนอกได้ ถ้าไม่ได้ให้ self-host
      Tailwind แล้วเพิ่ม CSP
