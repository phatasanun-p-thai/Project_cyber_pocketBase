// PocketBase generates this file on first `serve` (not on `migrate up`), and
// pb_data/ is gitignored - so a fresh clone has no types.d.ts yet and your
// editor will flag the reference as missing. Run the server once to create it:
//     ./pocketbase serve          (Windows: .\pocketbase.exe serve)
/// <reference path="../pb_data/types.d.ts" />

// ============================================================================
//  pb_hooks/dev_reset_token.pb.js
// ----------------------------------------------------------------------------
//  DEV ONLY - ดึง password-reset token โดยไม่ต้องอ่านอีเมลจริง
// ----------------------------------------------------------------------------
//  ทำไมต้องมีไฟล์นี้
//
//  1) PocketBase 0.40 **ไม่เก็บ reset token ไว้ในฐานข้อมูลเลย**
//     ยืนยันจาก schema จริงใน pb_data/data.db:
//         CREATE TABLE `_superusers` (created, email, emailVisibility, id,
//                                      password, tokenKey, updated, verified)
//     ไม่มีคอลัมน์ `passwordResetToken` และก็ไม่มีตาราง `_password_reset_tokens`
//     เหตุผล: ตั้งแต่ v0.23 token ถูกทำเป็น **stateless signed token** ผูกกับ
//     TokenConfig.secretKey - ฝั่ง server ยืนยัน token ได้จากลายเซ็นอย่างเดียว
//     ไม่ต้องมี state ให้เก็บ ดังนั้นการอ่าน record ด้วย `$app` หรือด้วย
//     superuser token ก็ไม่มีทางได้ token กลับมา (ผ่าน REST API ยิ่งเป็นไปได้
//     เพราะ `PublicExport()` กรอง field พวกนี้ออกอีกชั้น)
//
//  2) เครื่อง lab นี้ใช้อีเมล `example.com` ซึ่งมี null MX record (ปฏิเสธอีเมล
//     ทุกชนิด) Gmail จึง bounce กลับมาเป็น
//         "Your message wasn't delivered to admin@example.com because the
//          domain example.com couldn't be found."
//     ผลคือยิงหัวข้อ forgot / reset password ต่อไม่ได้ เพราะไม่มีทางรู้ token
//
//  วิธีที่ใช้
//  โฟกัสที่ `onMailerRecordPasswordResetSend` ซึ่ง PocketBase เรียก "ก่อนส่ง"
//  อีเมลจริง แปลว่ามันยังทำงานแม้ Gmail จะ bounce ตัว token อยู่ในลิงก์
//  ภายใน `e.message.html` เราแค่ regex ดึงออกมาเก็บลง `$app.store()` ซึ่งเป็น
//  in-memory store ระดับ app (ข้าม request ได้ แต่หายเมื่อ restart) แล้วเสิรอร์
//  route ไว้ให้เรียกดึงกลับผ่าน REST ได้ตรงๆ
//
//  route ที่เสิรอร์ไว้ (ทุกตัวผูก `$apis.requireSuperuserAuth()`)
//    POST /api/dev/forgot-password        -> ส่งอีเมล reset + คืน token ในคำตอบเดียว
//    GET  /api/dev/password-reset-token  -> อ่าน token ที่จับได้ล่าสุด (ไม่ส่งซ้ำ)
//    POST /api/dev/delete-auth-record    -> ลบผู้ใช้ทดสอบเพื่อให้ register ซ้ำได้
//
//  ---------------------------------------------------------------------------
//  ⚠ ระวังเรื่องความปลอดภัย
//  ---------------------------------------------------------------------------
//  นี่คือช่องรั่วโดยตั้งใจ (reset token = เข้าบัญชีได้โดยไม่ต้องรู้รหัสเดิม)
//  จึงปิดไว้สองชั้น:
//    1.  route ผูก `$apis.requireSuperuserAuth()` -> บังคับ token ของ superuser
//    2.  `enabled` ต้องเป็น true (ค่าในไฟล์นี้ตั้งไว้ true เพื่อให้ lab ที่ใช้
//        example.com ใช้งานได้ทันที) - fresh clone ที่ต้องการค่าเริ่มต้นที่ปิด
//        ช่องรั่ว ให้แก้บรรทัด enabled เป็น false ก่อน commit
//    ตั้ง headerValue เพิ่มได้อีกชั้นถ้าอยากให้ต้องส่ง header ถูกต้องด้วย
//
//  ก่อนขึ้น production ต้อง **ลบไฟล์นี้ทิ้ง** ดูรายการใน README หัวข้อ
//  "ก่อนขึ้น production"
//
//  ---------------------------------------------------------------------------
//  STRUCTURE WARNING (เหมือนใน main.pb.js)
//  ---------------------------------------------------------------------------
//  PocketBase รัน JS hook ผ่าน goja runtime แบบ pooled -> ตัวแปรระดับไฟล์
//  out of scope ตอน callback ทำงาน กลายเป็น ReferenceError ที่ PocketBase
//  รายงานเป็น HTTP 400 ทั้งระบบ -> ต้องประกาศทุกอย่างไว้ INSIDE callback
// ============================================================================

// ---------------------------------------------------------------------------
//  จุดเดียวที่ token ยังมีชีวิตอยู่: ก่อน PocketBase ส่งอีเมลออกไป
// ---------------------------------------------------------------------------
onMailerRecordPasswordResetSend((e) => {
    // เหตุการณ์นี้ยิงก่อน SMTP ส่งจริง -> ทำงานแม้ผู้รับจะ bounce
    const record = e.record;
    const message = e.message;
    if (!record || !message) {
        return;
    }

// PocketBase 0.40 ฝัง token ลงในลิงก์แบบ path ไม่ใช่ query string:
    //   <adminURL>/_/#/auth/confirm-password-reset/<JWT>
    // (ยืนยันจาก log จริง - รุ่นเก่ากว่าใช้ ?token=<token> จึงต้องรองรับทั้งสองแบบ)
    // ตัว token เป็น JWT จึงมี `.` อยู่ในชื่อ ต้องอยู่ใน char class
    const html = String(message.html || "");
    const text = String(message.text || "");
    const PATTERNS = [
        /confirm-password-reset\/([A-Za-z0-9_\-.]+)/,
        /[?&]token=([A-Za-z0-9_\-.]+)/,
    ];
    let found = null;
    for (let i = 0; i < PATTERNS.length && !found; i++) {
        found = PATTERNS[i].exec(html) || PATTERNS[i].exec(text);
    }

    if (!found) {
        console.log(
            "[dev-reset-token] no token found in the reset mail body - " +
            "the link format may have changed again; dump html here to inspect"
        );
        return;
    }

    const collection = record.collection().name;
    const key = "dev_reset_token::" + collection + "::" + record.email();
    $app.store().set(key, {
        token: found[1],
        recordId: record.id,
        collection: collection,
        email: record.email(),
        // เก็บเวลาไว้ให้ debug ได้ว่า token เก่าแค่ไหน
        capturedAt: new Date().toISOString(),
    });

    console.log(
        "[dev-reset-token] captured for " + collection + " / " + record.email()
    );
});

// ---------------------------------------------------------------------------
//  Route ให้ REST Client ดึง token ที่จับได้
// ---------------------------------------------------------------------------
routerAdd(
    "GET",
    "/api/dev/password-reset-token",
    (e) => {
        // ------------------------------------------------------------ config
        const SEC = {
            // ค่าเริ่มต้น false -> fresh clone จะได้ 404 จนกว่าจะแก้เป็น true
            enabled: false,
            // ชั้นที่สอง (ถ้าอยากบังคับ) เว้นว่าง = ไม่ตรวจ header
            headerName: "X-Dev-Reset-Token",
            headerValue: "",
            allowedCollections: ["users"],
            // ส่งอีเมล reset เองถ้ายังไม่มี token ที่จับได้ ทำให้ยิงครั้งเดียว
            // ได้ token เลย ไม่ต้องพึ่งว่าเคยยิง request-password-reset มาก่อน
            // ปิดไว้ถ้าอยากบังคับให้ทดสอบตามลำดับจริง (ใส่ ?trigger=0 ได้)
            autoTrigger: true,
        };

        if (!SEC.enabled) {
            return e.json(404, {
                ok: false,
                error: "dev reset-token endpoint is disabled (set enabled = true in pb_hooks/dev_reset_token.pb.js)",
            });
        }

        // requestInfo() คืน dict เปล่า ๆ (_TygojaDict) ไม่ใช่ url.Values
        // จึงต้องอ่านด้วย q.collection ไม่ใช่ q.get("collection")
        // (การใช้ .get() จะ throw TypeError -> PocketBase ตอบ 400 ทั้งชุด)
        const info = e.requestInfo();
        const q = info.query || {};

        if (SEC.headerValue &&
            (info.headers || {})[SEC.headerName.toLowerCase()] !== SEC.headerValue) {
            return e.json(403, {
                ok: false,
                error: "missing or wrong " + SEC.headerName + " header",
            });
        }

        const collection = String(q.collection || "users").trim();
        const email = String(q.email || "").trim();

        if (SEC.allowedCollections.indexOf(collection) === -1) {
            return e.json(400, {
                ok: false,
                error: "collection must be one of: " + SEC.allowedCollections.join(", "),
            });
        }

        if (email === "") {
            return e.json(400, {
                ok: false,
                error: "missing required query param: email",
                hint: "GET /api/dev/password-reset-token?collection=users&email=victim@example.com",
            });
        }

        const key = "dev_reset_token::" + collection + "::" + email;
        let entry = $app.store().get(key);

        // ------------------------------------------------- ยังไม่มี token ไหม
        // ปกติ request-password-reset จะตอบ 204 No Content เปล่า ๆ ไม่มี body
        // ให้ดู token ไม่ได้ (นั่นคือพฤติกรรมถูกต้องของ PocketBase ไม่ใช่บั๊ก)
        // -> ถ้ายังไม่มี ให้ส่งอีเมลเองเพื่อให้ hook ข้างบนจับ token ใหม่
        if (!entry && SEC.autoTrigger && String(q.trigger || "1") !== "0") {
            try {
                const record = $app.findAuthRecordByEmail(collection, email);
                // เรียกตรงนี้จะ trigger onMailerRecordPasswordResetSend แบบ
                // synchronous -> พอคืนกลับมา store ต้องมีค่าใหม่แล้ว
                $mails.sendRecordPasswordReset($app, record);
                entry = $app.store().get(key);
            } catch (err) {
                return e.json(502, {
                    ok: false,
                    error: "could not trigger a reset mail: " + String(err),
                });
            }
        }

        if (!entry) {
            return e.json(404, {
                ok: false,
                error: "no captured reset token for " + collection + " / " + email,
                hint: "run POST /api/collections/" + collection +
                    "/request-password-reset first, then re-run this request " +
                    "(or drop ?trigger=0 to let this endpoint trigger it itself)",
            });
        }

        return e.json(200, {
            ok: true,
            collection: collection,
            email: email,
            recordId: entry.recordId,
            token: entry.token,
            capturedAt: entry.capturedAt,
            note: "token นี้หมดอายุตาม settings.passwordResetToken.expiresIn - ถ้า confirm แล้ว 400 ให้ขอใหม่",
        });
    },
    $apis.requireSuperuserAuth()
);

// ---------------------------------------------------------------------------
//  Route "ลืมรหัสผ่าน" แบบคลิกเดียวจบ -> ได้ token มาใช้ต่อทันที
// ---------------------------------------------------------------------------
//  ทำไมต้องมี นอกเหนือจาก `request-password-reset` ปกติ
//  route ปกติตอบ **204 No Content เปล่า ๆ** โดยดีไซน์ของ PocketBase เอง เพราะ
//  token เป็น JWT ที่ฝังอยู่ในลิงก์ในอีเมล ไม่มีทางดึงกลับมาทาง REST API ได้
//  (ดูหัวข้อ "ทำไมต้องมีไฟล์นี้" ด้านบน) แถวอีเมล `example.com` ก็ส่งไม่ถึง
//
//  route นี้จึงรวม 3 ขั้นตอนไว้ใน request เดียว
//      หา record -> ส่งอีเมล reset -> อ่าน token ที่ hook ข้างบนจับได้กลับมา
//  ผลคือ test.http ยิงขั้นตอน "forgot password" ครั้งเดียวแล้วเอาค่า `token`
//  ไปวางใน `confirm-password-reset` ต่อได้เลย
//
//  ต่างจาก GET /api/dev/password-reset-token ยังไง
//  - route นี้ **ส่งอีเมลใหม่ทุกครั้ง** เพื่อให้ได้ token ที่ยังไม่ถูกใช้
//    (ถ้ายิงซ้ำหลัง confirm ไปแล้ว store ยังเก็บ token เก่าไว้ การยิงซ้ำแบบนี้
//    จึงเป็นวิธีที่ถูกต้องในการ "ขอ token ใหม่")
//  - GET ตัวเดิมจะ **ไม่ส่งอีเมลซ้ำ** ถ้ามี token อยู่แล้ว เหมาะกับการยิง
//    `request-password-reset` ปกติแล้วค่อยมาอ่าน token ตามลำดับจริง
// ---------------------------------------------------------------------------
routerAdd(
    "POST",
    "/api/dev/forgot-password",
    (e) => {
        const SEC = {
            enabled: false,
            allowedCollections: ["users"],
        };

        if (!SEC.enabled) {
            return e.json(404, {
                ok: false,
                error: "dev forgot-password endpoint is disabled (set enabled = true in pb_hooks/dev_reset_token.pb.js)",
            });
        }

        const info = e.requestInfo();
        const q = info.query || {};
        const collection = String(q.collection || "users").trim();
        const email = String(q.email || "").trim();

        if (SEC.allowedCollections.indexOf(collection) === -1) {
            return e.json(400, {
                ok: false,
                error: "collection must be one of: " + SEC.allowedCollections.join(", "),
            });
        }

        if (email === "") {
            return e.json(400, {
                ok: false,
                error: "missing required query param: email",
                hint: "POST /api/dev/forgot-password?collection=users&email=victim@example.com",
            });
        }

        let record;
        try {
            record = $app.findAuthRecordByEmail(collection, email);
        } catch (err) {
            // route นี้ผูก superuser auth ไว้แล้ว จึงตอบ 404 ตรง ๆ ได้โดยไม่ต้อง
            // กังวลเรื่อง user enumeration ของผู้ใช้ทั่วไป
            // (request-password-reset ปกติตอบ 204 เสมอเพื่อไม่ให้ตรวจว่าอีเมล
            //  มีอยู่จริงไหม)
            return e.json(404, {
                ok: false,
                error: "no auth record for " + collection + " / " + email,
            });
        }

        // ยิงอีเมล reset -> hook ข้างบนจับ token เก็บลง store
        // ข้อสำคัญ: ต่อให้ send จะพังก็ต้องอ่าน store ต่อ เพราะ hook ทำงาน "ก่อน"
        // SMTP ส่งจริง (ตามที่อธิบายไว้ด้านบน) -> ถ้า mailer ยังไม่ได้ตั้งค่าแล้ว
        // throw ตรงนี้ เรายังเอา token ไป confirm-password-reset ต่อได้
        let mailError = "";
        try {
            $mails.sendRecordPasswordReset($app, record);
        } catch (err) {
            mailError = String(err);
        }

        const key = "dev_reset_token::" + collection + "::" + email;
        const entry = $app.store().get(key);

        if (!entry) {
            return e.json(502, {
                ok: false,
                error:
                    "reset mail was sent but no token was captured - the link " +
                    "format inside the mail body may have changed again",
                mailError: mailError,
            });
        }

        return e.json(200, {
            ok: true,
            collection: collection,
            email: email,
            recordId: entry.recordId,
            token: entry.token,
            confirmPath: "/_/#/auth/confirm-password-reset/" + entry.token,
            capturedAt: entry.capturedAt,
            mailSent: mailError === "",
            mailError: mailError,
            note:
                "เอาค่า token นี้ไปใส่ใน POST /api/collections/" + collection +
                "/confirm-password-reset ได้เลย - ใช้ได้ครั้งเดียว " +
                "และหมดอายุตาม settings.passwordResetToken.expiresIn",
        });
    },
    $apis.requireSuperuserAuth()
);

// ---------------------------------------------------------------------------
//  Route ลบผู้ใช้ทดสอบ - ทำให้ยิง register ซ้ำได้
// ---------------------------------------------------------------------------
//  ทำไมต้องมี
//  `POST /api/collections/users/records` ตอบ 400 validation_not_unique ทันทีที่
//  ยิงซ้ำด้วยอีเมลเดิม เพราะ email มี unique index ทำให้สมัครซ้ำในเครื่องเดิม
//  ไม่ได้ ต้องไปแก้ชื่อ email ในไฟล์ทดสอบทุกครั้ง
//  route นี้แก้ให้เป็น "ลบแล้วสมัครใหม่" ได้ใน 2 คลิก แทนที่จะแก้ไฟล์
//
//  ข้อจำกัด: ลบได้เฉพาะ record ที่ยังถูกผูกกับ collection ที่อยู่ใน allowlist
//  และ `_superusers` ไม่อยู่ในรายการ - กันไว้ไม่ให้ลบบัญชีแอดมินทิ้งโดยพลาด
// ---------------------------------------------------------------------------
routerAdd(
    "POST",
    "/api/dev/delete-auth-record",
    (e) => {
        const SEC = {
            enabled: false,
            // ตั้งใจไม่รวม _superusers - token ของ superuser ไม่อยู่ใน allowlist
            allowedCollections: ["users"],
        };

        if (!SEC.enabled) {
            return e.json(404, {
                ok: false,
                error: "dev delete endpoint is disabled (set enabled = true)",
            });
        }

        const info = e.requestInfo();
        const q = info.query || {};
        const collection = String(q.collection || "users").trim();
        const email = String(q.email || "").trim();

        if (SEC.allowedCollections.indexOf(collection) === -1) {
            return e.json(400, {
                ok: false,
                error: "collection must be one of: " + SEC.allowedCollections.join(", "),
                note: "_superusers is intentionally not deletable through this helper",
            });
        }

        if (email === "") {
            return e.json(400, {
                ok: false,
                error: "missing required query param: email",
            });
        }

        let record;
        try {
            record = $app.findAuthRecordByEmail(collection, email);
        } catch (err) {
            // ไม่มีอยู่แล้ว = สำเร็จในเชิงผลลัพธ์ (idempotent) ตอนนี้ register ได้แล้ว
            return e.json(200, {
                ok: true,
                deleted: false,
                collection: collection,
                email: email,
                note: "no such record - nothing to delete, you can register this email now",
            });
        }

        const id = record.id;
        try {
            $app.delete(record);
        } catch (err) {
            return e.json(500, {
                ok: false,
                error: "delete failed: " + String(err),
            });
        }

        return e.json(200, {
            ok: true,
            deleted: true,
            collection: collection,
            email: email,
            recordId: id,
            note: "record removed - you can register this email again",
        });
    },
    $apis.requireSuperuserAuth()
);
