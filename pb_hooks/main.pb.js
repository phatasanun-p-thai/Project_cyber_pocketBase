// PocketBase generates this file on first `serve` (not on `migrate up`), and
// pb_data/ is gitignored - so a fresh clone has no types.d.ts yet and your
// editor will flag the reference as missing. Run the server once to create it:
//     ./pocketbase serve          (Windows: .\pocketbase.exe serve)
/// <reference path="../pb_data/types.d.ts" />

// ============================================================================
//  PocketBase Security Monitor  -  pb_hooks/security.pb.js
// ----------------------------------------------------------------------------
//  A single global router middleware intercepts every matched API route and
//  inspects the outcome:
//
//    * privileged fields in an ACCEPTED body    -> privilege escalation
//    * 401 / 403 / 404 responses  -> unauthenticated or unauthorised access
//    * write requests on a concrete record id  -> possible BOLA / IDOR
//    * bodies containing privileged fields      -> mass assignment / privilege
//                                                  escalation attempt
//    * SQLi / XSS markers in the query or body  -> injection probing
//    * repeated failed logins from one IP       -> brute force
//
//  Every incident is persisted into the `attack_logs` collection and, when the
//  severity is high or critical, an alert email is dispatched to the admin
//  through the PocketBase Mailer API.
//
//  NOTES
//  - The middleware is a pure observer: it never changes the API response.
//  - Superuser traffic is ignored so the monitoring dashboard (and the
//    `$app.save()` writes below) can never trigger themselves.
//  - The module level Maps are shared across requests (PocketBase reuses a
//    non-forkable VM for the request lifecycle). If they ever get reset, the
//    only effect is that throttles/cooldowns stop applying - never a missed
//    detection, because the brute force counter is read back from the DB.
// ============================================================================

// ============================================================================
//  STRUCTURE WARNING - read before editing
//  Everything below is nested INSIDE the `routerUse` callback on purpose.
//  PocketBase runs JS hooks through a pooled goja runtime and invokes the
//  registered middleware from its serialised source, so free variables from
//  the file top level (isIgnored, report, SEC, ...) are out of scope by the
//  time the callback executes. They fail with
//      ReferenceError: isIgnored is not defined
//  which PocketBase surfaces as a blanket HTTP 400 on *every* request.
//  Keeping the helpers inside the callback keeps them in the closure of the
//  function that actually runs.
// ----------------------------------------------------------------------------

routerUse(((e) => {
const SEC = {
    // -------------------------------------------------------------- storage
    logsCollection: "attack_logs",

    // ---------------------------------------------------------------- mail
    // Leave empty to fall back to the email of the first _superusers record.
    adminEmail: "",
    // Severities that trigger an alert email.
    alertSeverities: ["high", "critical"],
    // Minimum gap between two alert emails for the same incident key.
    emailCooldownMs: 2 * 60 * 1000,
    // Hard cap on alert emails per rolling window, per recipient. Protects the
    // SMTP account from being used as a mail bomb by an attacker who rotates
    // the request path/IP to defeat `emailCooldownMs`.
    emailBurstLimit: 10,
    emailBurstWindowMs: 10 * 60 * 1000,

    // --------------------------------------------------------- brute force
    // N failed logins from the same IP within the window == brute force.
    bruteForceThreshold: 5,
    bruteForceWindowMs: 2 * 60 * 1000,

    // ---------------------------------------------------------------- misc
    // 0 disables the per incident de-duplication (every hit is logged).
    logCooldownMs: 0,
    maxPayloadLen: 4000,
    // Keep false when PocketBase is exposed directly - e.realIP() trusts the
    // X-Forwarded-For / X-Real-IP headers and is trivially spoofable.
    trustProxyHeader: false,
    // Skip the obvious read-only endpoints so a crawler or a browser prefetch
    // cannot flood `attack_logs` with 404 noise.
    // A trailing `*` matches by prefix.
    ignorePaths: ["/api/health", "/api/realtime*", "/api/settings", "/api/logs"],
    ignoreMethods: ["HEAD", "OPTIONS"],

    // ------------------------------------------------------- field lookups
    // Writing one of these through the public API is treated as an attempt to
    // grant yourself privileges. Tune the list to match your own schema.
    // NOTE: `verified` is deliberately absent - it is a legit self-service field
    // on an auth record (e-mail confirmation) and flagging it made every normal
    // sign-up report as MASS_ASSIGNMENT.
    privilegedFields: [
        "role",
        "permissions",
        "isadmin",
        "superuser",
        "isstaff",
        "tokenkey",
    ],
    // First of these found on the body / on the targeted record is reported as
    // the victim of the attack.
    ownerFields: ["owner", "author", "user", "user_id", "userid", "created_by"],
    // Never store these in the log payload.
    secretFields: [
        "password",
        "passwordconfirm",
        "oldpassword",
        "newpassword",
        "token",
        "secret",
        "tokenkey",
    ],
};

const WRITE_METHODS = ["POST", "PATCH", "PUT", "DELETE"];

/** /api/collections/{collection}/records[/{recordId}] */
const RECORD_PATH_RE = /^\/api\/collections\/([^\/]+)\/records(?:\/([^\/?]+))?/;

/**
 * /api/collections/{collection}/auth-with-password|auth-with-otp
 *
 * `auth-refresh` is intentionally excluded: an expired/rotated token makes
 * every dashboard poll answer 401, which used to be counted as a failed
 * password attempt and could push a normal user over the brute force
 * threshold.
 */
const AUTH_PATH_RE = /^\/api\/collections\/[^\/]+\/(auth-with-password|auth-with-otp)$/;

/** SQLi / XSS heuristics - deliberately broad, false positives are logged as
 *  "injection probe" and never block the request. */
const INJECTION_RE = new RegExp(
    "(union\\s+(all\\s+)?select\\b)" + // UNION [ALL] SELECT
    "|(<\\s*script\\b)" + // <script
    "|(javascript\\s*:)" + // javascript:
    "|(on(error|load|click|mouseover)\\s*=)" + // inline event handler
    "|(;\\s*(drop|delete|truncate|alter|insert)\\s+)" + // stacked query
    "|(\\bor\\s+['\"]?\\d+['\"]?\\s*=)" + // OR 1=1
    "|(\\bsleep\\s*\\(\\s*\\d)" + // sleep()
    "|(benchmark\\s*\\()",
    "i"
);

// Throttle bookkeeping (shared per process, see the NOTES block on top).
const cooldowns = new Map();
// Alert e-mail budget, per recipient: [timestamps...] inside the burst window.
const mailBudget = new Map();
let adminEmailCache = "";
let adminEmailResolved = false;

// ============================================================================
//  Middleware
// ============================================================================

    if (isIgnored(e)) {
        e.next();
        return;
    }

    // Denied requests bubble up as a thrown ApiError, so the status code has to
    // be read from the error itself - e.status() is still 0 at that point.
    try {
        e.next();
    } catch (err) {
        const status = errorStatus(err);
        if (status > 0) {
            report(e, status, errorMessage(err));
        }
        throw err;
    }

    report(e, e.status(), "");

function isIgnored(e) {
    const path = e.request.url.path || "";

    if (SEC.ignoreMethods.indexOf((e.request.method || "").toUpperCase()) !== -1) {
        return true;
    }

    for (let i = 0; i < SEC.ignorePaths.length; i++) {
        // The SSE stream is a long lived request and is never an attack, so it
        // is matched by prefix; everything else by exact path.
        if (SEC.ignorePaths[i].indexOf("*") !== -1) {
            const prefix = SEC.ignorePaths[i].slice(0, -1);
            if (path.indexOf(prefix) === 0) {
                return true;
            }
        } else if (path === SEC.ignorePaths[i]) {
            return true;
        }
    }

    // Ignore the admin/dashboard traffic, otherwise every dashboard poll would
    // generate a new incident.
    try {
        if (e.hasSuperuserAuth()) {
            return true;
        }
    } catch (err) {
        // noop - not being able to resolve the auth state is not fatal here
    }

    return false;
}

// ============================================================================
//  Detection
// ============================================================================

/**
 * Classify and persist.
 *
 * `status < 400` does NOT mean "safe": a mass assignment that actually
 * escalated a user to admin answers 200 and is far worse than a 403 that was
 * rejected. The successful-request verdicts are therefore the ones that run
 * first and can outrank the error-based ones.
 */
function report(e, status, errMsg) {
    try {
        const ctx = buildContext(e, status, errMsg);
        const verdict = classify(ctx);
        if (!verdict) {
            return;
        }
        handleVerdict(ctx, verdict);
    } catch (err) {
        // Never let the monitoring break the actual API response.
        console.log("[security] failed to inspect request:", err);
    }
}

function buildContext(e, status, errMsg) {
    const info = e.requestInfo();
    const path = e.request.url.path || "";
    const matched = RECORD_PATH_RE.exec(path);

    return {
        method: (info.method || "GET").toUpperCase(),
        path: path,
        rawQuery: e.request.url.rawQuery || "",
        status: status,
        errMsg: errMsg,
        ip: clientIP(e),
        body: toPlainObject(info.body),
        auth: info.auth || null,
        actor: recordLabel(info.auth),
        userAgent: (info.headers && info.headers["user-agent"]) || "",
        collection: matched ? matched[1] : "",
        recordId: matched && matched[2] ? matched[2] : "",
    };
}

function classify(ctx) {
    const method = ctx.method;
    const isWrite = WRITE_METHODS.indexOf(method) !== -1;
    const failed = ctx.status >= 400;

    if (ctx.status === 429) {
        return { type: "RATE_LIMIT_HIT", severity: "low" };
    }

    // ------------------------------------------------------ success paths
    // Checked before the error based verdicts below: a request that was
    // *allowed* through is the interesting case.
    const privileged = privilegedHits(ctx.body);
    if (privileged.length > 0 && isWrite) {
        return {
            type: failed ? "MASS_ASSIGNMENT" : "PRIVILEGE_ESCALATION",
            severity: !failed ? "critical" : ctx.auth ? "high" : "critical",
            note: failed
                ? "rejected privileged fields: " + privileged.join(", ")
                : "ACCEPTED privileged fields: " + privileged.join(", "),
        };
    }

    if (!failed) {
        // Everything below classifies a rejection; a 2xx write against another
        // user's record is a successful BOLA, which PocketBase only reports as
        // a 404 when an API rule hides it. Reaching here means the rules let it
        // through, so it is only worth a row when someone else owns the record.
        if (ctx.recordId && ctx.actor && !ownsRecord(ctx)) {
            return {
                type: "BOLA_IDOR",
                severity: "high",
                note: method + " on " + ctx.path + " succeeded on a foreign record",
            };
        }
        return null;
    }

    // -------------------------------------------------------- error paths
    //
    // ORDER MATTERS: the injection probe is evaluated BEFORE the auth path
    // check. A login attempt carrying `'`/`OR 1=1`/`union select` is an
    // injection probe, and it used to be swallowed by AUTH_PATH_RE - which
    // also fed it into the brute force counter, so an attacker could raise a
    // CRITICAL brute force alert against a victim just by sending XSS/SQLi
    // payloads at /auth-with-password.
    const probe = injectionProbe(ctx.rawQuery, ctx.body);
    if (probe) {
        return {
            type: "INJECTION_PROBE",
            severity: "high",
            note: "matched " + probe,
        };
    }

    // เข้ามาถึงที่นี่แปลว่าเป็นการ login ล้มเหลวที่ "ปกติ" ไม่ใช่ payload แปลก ๆ
    if (AUTH_PATH_RE.test(ctx.path)) {
        return { type: "AUTH_FAILURE", severity: "low" };
    }

    // A write against a concrete record while carrying no credentials at all.
    if (!ctx.auth && isWrite && ctx.recordId) {
        return {
            type: "UNAUTHENTICATED_WRITE",
            severity: "high",
            note: "no auth token supplied for " + method + " " + ctx.path,
        };
    }

    // PocketBase answers 404 (not 403) when a rule hides a record, so both are
    // treated as a horizontal/vertical privilege violation.
    if (ctx.recordId && (ctx.status === 403 || ctx.status === 404)) {
        return {
            type: "BOLA_IDOR",
            severity: ctx.status === 404 && method === "GET" ? "medium" : "high",
            note:
                method +
                " on " +
                ctx.collection +
                "/" +
                ctx.recordId +
                " rejected with " +
                ctx.status,
        };
    }

    // Anonymous writes to a regular collection are rejected by the API rules,
    // but an anonymous POST to an auth collection is the normal self
    // registration flow and must not be reported.
    if (!ctx.auth && isWrite && !isSelfRegistration(ctx)) {
        return {
            type: "UNAUTHENTICATED_WRITE",
            severity: "medium",
            note: method + " " + ctx.path,
        };
    }

    if (ctx.status === 401) {
        return { type: "UNAUTHENTICATED_ACCESS", severity: "medium" };
    }

    if (ctx.status === 403) {
        return { type: "FORBIDDEN_ACCESS", severity: "low" };
    }

    return null;
}

function handleVerdict(ctx, verdict) {
    if (verdict.type !== "AUTH_FAILURE") {
        writeIncident(ctx, verdict, verdict.note || "");
        return;
    }

    // A single bad password is noise; a burst of them is a brute force run.
    const failures = countRecentAuthFailures(ctx.ip) + 1; // + this request
    writeIncident(ctx, verdict, "failed login #" + failures + " from this IP");

    if (failures >= SEC.bruteForceThreshold) {
        writeIncident(ctx, {
            type: "BRUTE_FORCE",
            severity: "critical",
            note:
                failures +
                " failed logins in " +
                Math.round(SEC.bruteForceWindowMs / 1000) +
                "s",
        });
    }
}

function injectionProbe(rawQuery, body) {
    if (hasInjectionMarker(rawQuery)) {
        return "the request query string";
    }

    // Attackers url-encode their payloads, so also test the decoded form.
    let decoded = "";
    try {
        decoded = decodeURIComponent(rawQuery || "");
    } catch (err) {
        decoded = rawQuery || "";
    }
    if (decoded !== rawQuery && hasInjectionMarker(decoded)) {
        return "the url decoded query string";
    }

    let serialized = "";
    try {
        serialized = JSON.stringify(body || {});
    } catch (err) {
        serialized = "";
    }
    if (hasInjectionMarker(serialized)) {
        return "the request body";
    }

    return "";
}

function hasInjectionMarker(text) {
    return Boolean(text) && INJECTION_RE.test(text);
}

/**
 * True when the authenticated caller is the record itself or its owner.
 *
 * The id comparison has to go through the auth record's own `id`. `ctx.actor`
 * is a human label (the e-mail for an auth record) produced by recordLabel(),
 * so passing it to findRecordById() looks a record up by e-mail and always
 * throws - which made every self-service read (`GET /records/<own id>`) report
 * as a high severity BOLA on a "foreign" record.
 *
 * Used only to decide whether a *successful* write deserves a row, so it stays
 * conservative: anything it cannot prove returns false and the write gets
 * logged. False positives on reads are preferable to blind spots here.
 */
function ownsRecord(ctx) {
    // Fast path: the caller is the record they just read or wrote.
    try {
        const selfId = ctx.auth && String(ctx.auth.id || "");
        if (selfId && selfId === String(ctx.recordId)) {
            return true;
        }
    } catch (err) {
        // not an auth record, or the id is not exposed
    }

    // Otherwise the caller may still own the record through an owner field.
    const owner = ctx.actor;
    if (!owner || owner === "anonymous") {
        return false;
    }

    for (let i = 0; i < SEC.ownerFields.length; i++) {
        const field = SEC.ownerFields[i];
        if (ctx.body && ctx.body[field] && String(ctx.body[field]) === owner) {
            return true;
        }
    }

    return false;
}

/** An anonymous `POST /api/collections/{auth}/records` is a signup, not an attack. */
function isSelfRegistration(ctx) {
    if (ctx.method !== "POST" || ctx.recordId || !ctx.collection) {
        return false;
    }
    try {
        return $app.findCollectionByNameOrId(ctx.collection).type === "auth";
    } catch (err) {
        return false;
    }
}

function privilegedHits(body) {
    const hits = [];
    if (!body || typeof body !== "object") {
        return hits;
    }
    const keys = Object.keys(body);
    for (let i = 0; i < keys.length; i++) {
        if (SEC.privilegedFields.indexOf(keys[i].toLowerCase()) !== -1) {
            hits.push(keys[i]);
        }
    }
    return hits;
}

/** Number of AUTH_FAILURE rows already stored for this IP in the window. */
function countRecentAuthFailures(ip) {
    try {
        const since = sqlDate(Date.now() - SEC.bruteForceWindowMs);
        const records = $app.findRecordsByFilter(
            SEC.logsCollection,
            "ip = {:ip} && attack_type = 'AUTH_FAILURE' && created >= {:since}",
            "-created",
            SEC.bruteForceThreshold,
            0,
            { ip: ip, since: since }
        );
        return records.length;
    } catch (err) {
        return 0;
    }
}

// ============================================================================
//  Persistence
// ============================================================================

function writeIncident(ctx, verdict, note) {
    const key =
        verdict.type + "|" + ctx.ip + "|" + ctx.method + "|" + ctx.path;
    if (!allowOnce(key, SEC.logCooldownMs)) {
        return null;
    }

    const payload = buildPayload(ctx, verdict, note);
    const record = saveIncident(ctx, verdict, payload);

    console.log(
        "[security] " +
            verdict.severity.toUpperCase() +
            " " +
            verdict.type +
            " | ip=" +
            ctx.ip +
            " | " +
            ctx.method +
            " " +
            ctx.path
    );

    if (SEC.alertSeverities.indexOf(verdict.severity) !== -1) {
        const recipient = resolveAdminEmail();
        if (allowOnce("mail:" + key, SEC.emailCooldownMs) && takeMailBudget(recipient)) {
            sendSecurityAlert(ctx, verdict, payload, record, recipient);
        } else {
            console.log(
                "[security] alert e-mail suppressed (cooldown or burst budget) for " + key
            );
        }
    }

    return record;
}

/**
 * Rolling-window cap on alert e-mails. `emailCooldownMs` alone is keyed by
 * type|ip|method|path, so an attacker who varies the path (or spoofs the ip
 * once trustProxyHeader is on) can still force one mail per hit.
 */
function takeMailBudget(recipient) {
    if (!recipient) {
        return false;
    }

    const now = Date.now();
    const key = recipient.toLowerCase();
    const sent = (mailBudget.get(key) || []).filter(function (at) {
        return now - at < SEC.emailBurstWindowMs;
    });

    if (sent.length >= SEC.emailBurstLimit) {
        mailBudget.set(key, sent);
        return false;
    }

    sent.push(now);
    mailBudget.set(key, sent);
    return true;
}

function saveIncident(ctx, verdict, payload) {
    let collection;
    try {
        collection = $app.findCollectionByNameOrId(SEC.logsCollection);
    } catch (err) {
        console.log(
            "[security] collection \"" +
                SEC.logsCollection +
                "\" not found - run the migration in pb_migrations first"
        );
        return null;
    }

    const record = new Record(collection);

    setField(record, "ip", ctx.ip);
    setField(record, "target_user", resolveTargetUser(ctx));
    setField(record, "attack_type", verdict.type);
    setField(record, "severity", verdict.severity);
    setField(record, "payload", payload);
    // Optional extras - skipped silently when the collection was created
    // manually with only the five required fields.
    setField(record, "method", ctx.method);
    setField(record, "endpoint", ctx.path);
    setField(record, "status_code", ctx.status);
    setField(record, "actor", ctx.actor);
    setField(record, "user_agent", ctx.userAgent.slice(0, 300));

    try {
        $app.save(record);
    } catch (err) {
        console.log("[security] could not store the incident:", err);
        return null;
    }

    return record;
}

/** Write a value only when the target collection actually declares the field. */
function setField(record, key, value) {
    try {
        record.set(key, value);
    } catch (err) {
        // field not defined in the collection - nothing to do
    }
}

/**
 * Best effort "who is being attacked" resolution:
 *   1. an owner/author field present in the request body
 *   2. the owner of the record the attacker tried to reach
 *   3. the authenticated caller
 *   4. the identity submitted on a login attempt
 */
function resolveTargetUser(ctx) {
    if (ctx.body && typeof ctx.body === "object") {
        for (let i = 0; i < SEC.ownerFields.length; i++) {
            const value = ctx.body[SEC.ownerFields[i]];
            if (value) {
                return String(value);
            }
        }
    }

    if (ctx.recordId && ctx.collection) {
        try {
            const record = $app.findRecordById(ctx.collection, ctx.recordId);
            for (let i = 0; i < SEC.ownerFields.length; i++) {
                const value = record.get(SEC.ownerFields[i]);
                if (value) {
                    return String(value);
                }
            }
            if (record.id) {
                return String(record.id);
            }
        } catch (err) {
            // record does not exist or the collection is gone
        }
    }

    if (ctx.actor && ctx.actor !== "anonymous") {
        return ctx.actor;
    }

    if (ctx.body && typeof ctx.body === "object") {
        if (ctx.body.identity) {
            return String(ctx.body.identity);
        }
        if (ctx.body.email) {
            return String(ctx.body.email);
        }
    }

    return "unknown";
}

function buildPayload(ctx, verdict, note) {
    const data = {
        note: note || "",
        endpoint: ctx.path,
        method: ctx.method,
        // ctx.errMsg can carry a raw PocketBase validation message, which may
        // echo the submitted value back. Keep it, but bounded.
        status: ctx.status,
        actor: ctx.actor,
        collection: ctx.collection || "",
        target_record: ctx.recordId || "",
        error: ctx.errMsg || "",
        query: ctx.rawQuery,
        body: redact(ctx.body, 0),
        user_agent: ctx.userAgent,
    };

    let out;
    try {
        out = JSON.stringify(data);
    } catch (err) {
        out = JSON.stringify({ note: note || "", endpoint: ctx.path });
    }

    if (out.length > SEC.maxPayloadLen) {
        out = out.slice(0, SEC.maxPayloadLen) + "...[truncated]";
    }

    return out;
}

/** Recursively strips secrets and bounds the size of the logged structure. */
function redact(value, depth) {
    if (value === null || value === undefined) {
        return null;
    }
    if (depth > 4) {
        return "[max depth reached]";
    }
    if (Array.isArray(value)) {
        const list = [];
        for (let i = 0; i < value.length && i < 20; i++) {
            list.push(redact(value[i], depth + 1));
        }
        return list;
    }
    if (typeof value === "number" || typeof value === "boolean") {
        return value;
    }
    if (typeof value !== "object") {
        const str = String(value);
        return str.length > 200 ? str.slice(0, 200) + "..." : str;
    }

    const keys = Object.keys(value);
    const out = {};
    for (let i = 0; i < keys.length && i < 30; i++) {
        const key = keys[i];
        out[key] = isSecret(key)
            ? "[redacted]"
            : redact(value[key], depth + 1);
    }
    return out;
}

function isSecret(key) {
    const lower = String(key).toLowerCase();
    for (let i = 0; i < SEC.secretFields.length; i++) {
        if (lower.indexOf(SEC.secretFields[i]) !== -1) {
            return true;
        }
    }
    return false;
}

// ============================================================================
//  Mailer
// ============================================================================

function sendSecurityAlert(ctx, verdict, payload, record, to) {
    if (!to) {
        console.log(
            "[security] no admin email available - set SEC.adminEmail or create a _superusers account"
        );
        return;
    }

    if (!mailerConfigured()) {
        console.log(
            "[security] mailer is not configured - no email sent. " +
                "PocketBase 0.40 reads SMTP only from the stored app settings " +
                "(superuser UI > Settings > Mailer, or PATCH /api/settings); " +
                "SMTP_* env vars are NOT picked up by $app.newMailClient(). " +
                "The docker entrypoint seeds them from the environment on boot."
        );
    }

    const sender = senderAddress();

    const targetUser = record ? record.get("target_user") : "unknown";
    const subject =
        "[" +
        verdict.severity.toUpperCase() +
        "] " +
        verdict.type +
        " detected - " +
        ctx.method +
        " " +
        ctx.path;

    const details = [
        ["Attack type", verdict.type],
        ["Severity", verdict.severity],
        ["Attacker IP", ctx.ip],
        ["Actor", ctx.actor],
        ["Target user", String(targetUser)],
        ["Endpoint", ctx.method + " " + ctx.path],
        ["Response status", String(ctx.status)],
        ["Time", new Date().toISOString()],
    ];

    let rows = "";
    let text = "";
    for (let i = 0; i < details.length; i++) {
        rows +=
            "<tr><td style=\"padding:4px 12px 4px 0;color:#64748b;vertical-align:top\">" +
            escapeHtml(details[i][0]) +
            "</td><td style=\"padding:4px 0;font-family:monospace\">" +
            escapeHtml(details[i][1]) +
            "</td></tr>";
        text += details[i][0] + ": " + details[i][1] + "\n";
    }

    // Logged incidents are untrusted input: the body is escaped for the HTML
    // part below and never interpolated raw, but the plain text part is what
    // most mobile clients render, so it is kept free of control characters.
    const safeText = collapseControlChars(payload);
    const safeError = collapseControlChars(ctx.errMsg || "");

    const message = new MailerMessage({
        from: { address: sender, name: "PocketBase Security Bot" },
        to: [{ address: to }],
        subject: subject,
        text:
            "Security incident detected.\n\n" +
            text +
            "\nPayload:\n" +
            safeText +
            "\n",
        html:
            '<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:640px">' +
            '<div style="background:' +
            (verdict.severity === "critical" ? "#dc2626" : "#ea580c") +
            ';color:#fff;padding:12px 16px;border-radius:8px 8px 0 0;font-weight:700">' +
            escapeHtml(subject) +
            "</div>" +
            '<div style="border:1px solid #e2e8f0;border-top:0;border-radius:0 0 8px 8px;padding:16px">' +
            '<table style="width:100%;font-size:14px;border-collapse:collapse">' +
            rows +
            "</table>" +
            '<pre style="background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all">' +
            escapeHtml(payload) +
            "</pre>" +
            '<p style="color:#64748b;font-size:12px">Log id: ' +
            (record ? escapeHtml(record.id) : "n/a") +
            "</p>" +
            "</div></div>",
    });

    try {
        newAlertMailClient().send(message);
        console.log(
            "[security] alert email sent to " +
                to +
                " (" +
                verdict.severity.toUpperCase() +
                " " +
                verdict.type +
                ")"
        );
    } catch (err) {
        console.log("[security] failed to send the alert email:", err);
    }
}

function resolveAdminEmail() {
    if (SEC.adminEmail) {
        return SEC.adminEmail;
    }
    // ALERT_EMAIL wins over the first superuser: the superuser is usually an
    // internal address (admin@example.com) that nobody reads, so alerts would
    // be delivered and never seen.
    const fromEnv = envSettings().ALERT_EMAIL;
    if (fromEnv) {
        return fromEnv;
    }
    if (adminEmailResolved) {
        return adminEmailCache;
    }

    try {
        const superusers = $app.findAllRecords("_superusers");
        for (let i = 0; i < superusers.length; i++) {
            const email = recordEmail(superusers[i]);
            if (email) {
                adminEmailCache = email;
                break;
            }
        }
    } catch (err) {
        console.log("[security] could not resolve a superuser email:", err);
    }

    // only cache a positive result, so a superuser created later is picked up
    if (adminEmailCache) {
        adminEmailResolved = true;
    }

    return adminEmailCache;
}

// ============================================================================
//  Helpers
// ============================================================================

/** PocketBase stores dates as `YYYY-MM-DD HH:MM:SS.sssZ` text. */
function sqlDate(ms) {
    return (
        new Date(ms).toISOString().slice(0, 19).replace("T", " ") + ".000Z"
    );
}

function clientIP(e) {
    try {
        const ip = SEC.trustProxyHeader ? e.realIP() : e.remoteIP();
        return ip || "unknown";
    } catch (err) {
        return "unknown";
    }
}

function allowOnce(key, ms) {
    if (!ms || ms <= 0) {
        return true;
    }
    const now = Date.now();
    const last = cooldowns.get(key);
    if (last !== undefined && now - last < ms) {
        return false;
    }
    cooldowns.set(key, now);

    // Hard cap: an attacker rotating the ip/path would otherwise grow this map
    // without bound for the lifetime of the process.
    if (cooldowns.size > 2000) {
        cooldowns.forEach(function (value, k) {
            if (now - value > ms * 20) {
                cooldowns.delete(k);
            }
        });
        // still oversized (everything is fresh) -> drop the oldest quarter
        if (cooldowns.size > 2000) {
            const keys = Array.from(cooldowns.keys()).sort(function (a, b) {
                return cooldowns.get(a) - cooldowns.get(b);
            });
            for (let i = 0; i < keys.length / 4; i++) {
                cooldowns.delete(keys[i]);
            }
        }
    }

    return true;
}

/** A denied route throws a Go ApiError wrapped in a goja GoError. */
function errorStatus(err) {
    const candidates = [err, err ? err.value : null];
    for (let i = 0; i < candidates.length; i++) {
        const candidate = candidates[i];
        if (!candidate) {
            continue;
        }
        const status = Number(candidate.status || candidate.statusCode);
        if (status >= 100 && status < 600) {
            return status;
        }
    }
    return 0;
}

function errorMessage(err) {
    const candidate = err && err.value ? err.value : err;
    const message = (candidate && candidate.message) || (err && err.message) || "";
    return String(message).slice(0, 500);
}

function recordEmail(record) {
    if (!record) {
        return "";
    }
    try {
        if (typeof record.email === "function") {
            return record.email() || "";
        }
    } catch (err) {
        // not an auth record
    }
    try {
        return String(record.get("email") || "");
    } catch (err) {
        return "";
    }
}

function recordLabel(record) {
    if (!record) {
        return "anonymous";
    }
    const email = recordEmail(record);
    if (email) {
        return email;
    }
    try {
        return String(record.get("id") || "unknown");
    } catch (err) {
        return "unknown";
    }
}

/** Go maps (request body / query) come through as tygoja objects. */
function toPlainObject(value) {
    if (!value) {
        return {};
    }
    try {
        return JSON.parse(JSON.stringify(value));
    } catch (err) {
        return {};
    }
}

/**
 * Strips C0 control characters (except tab/newline) so a payload cannot forge
 * extra lines in the plain text part of the alert mail - the classic
 * "header/body split" trick when the address itself is attacker influenced.
 */
function collapseControlChars(value) {
    // eslint-disable-next-line no-control-regex
    return String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "?");
}

function escapeHtml(value) {
    return String(value === null || value === undefined ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// ============================================================================
//  Mailer used for the alert emails
//  PocketBase 0.40 removed the `--smtpHost`/`--senderAddress` serve flags and
//  the JSVM binding is `newMailClient(): mailer.Mailer` - it takes NO arguments
//  and always builds the client from the stored app settings. Passing a custom
//  settings object is silently ignored, which made every alert fall back to
//  sendmail and fail with "failed to locate a sendmail executable path".
//  `_settings` is a system collection that cannot be written from JS either,
//  so the mailer must be configured through Settings > Mailer (superuser UI)
//  or `PATCH /api/settings`. The docker entrypoint seeds it from SMTP_* on boot.
//  These helpers must stay INSIDE the routerUse callback - see the STRUCTURE
//  WARNING at the top of this file.
// ============================================================================

/** True when a real SMTP transport is configured (not sendmail). */
function mailerConfigured() {
    try {
        const smtp = $app.settings().smtp;
        return !!(smtp && smtp.enabled && smtp.host && smtp.host !== "smtp.example.com");
    } catch (err) {
        return false;
    }
}

/** The From address. Must match the configured mailer or Gmail rejects it. */
function senderAddress() {
    try {
        const configured = $app.settings().meta.senderAddress;
        if (configured) {
            return configured;
        }
    } catch (err) {
        // fall through to the env fallback
    }
    const env = envSettings();
    return env.SMTP_FROM || env.SMTP_USER || "security@localhost";
}

function envSettings() {
    return (typeof process !== "undefined" && process.env) || {};
}

/**
 * PocketBase 0.40: no arguments. Everything (host, port, credentials, TLS,
 * sender) comes from the stored settings.
 */
function newAlertMailClient() {
    return $app.newMailClient();
}

}));
