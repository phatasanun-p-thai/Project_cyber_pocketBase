// pb_migrations/1790640001_lock_attack_logs_to_superusers.js
//
// Security fix: `attack_logs` used to be readable by ANY authenticated record
// (`@request.auth.id != ""`). Since sign-up is open on an auth collection, an
// attacker could create one throwaway user and then read every incident the
// SIEM had collected, including attacker IPs, target accounts, user agents and
// the request payloads.
//
// Rule used here: no non-superuser may touch the collection at all. A superuser
// bypasses API rules in PocketBase, so the monitoring dashboard (which signs in
// as `_superusers`) keeps working untouched, and the hook keeps writing through
// `$app.save()` which also bypasses rules.
//
// Realtime events are filtered per collection by the same list rule, so a
// normal user should not receive `attack_logs` events. NOTE: the SSE
// *handshake* still answers 200 for any valid token (superuser or not) -
// PocketBase rejects the subscription, not the connection - so "the SSE
// stream connected" is not evidence of a leak.

migrate(
    (app) => {
        let collection;
        try {
            collection = app.findCollectionByNameOrId("attack_logs");
        } catch (err) {
            // the init migration has not run yet (or was rolled back)
            return;
        }

        // RULE SEMANTICS (easy to get backwards):
        //   null = "superuser only"  <-- what we want
        //   ""   = "public / guest"  <-- what the old code effectively had
        // Setting an empty string here would have made the log world readable,
        // which is the exact bug this migration fixes.
        collection.listRule = null;
        collection.viewRule = null;
        // Incidents are written by the hook via `$app.save()` and are immutable
        // from the outside.
        collection.createRule = null;
        collection.updateRule = null;
        collection.deleteRule = null;

        // `created` is what the dashboard sorts and filters on, `ip` is what the
        // brute force counter and the dashboard group by.
        collection.indexes = [
            "CREATE INDEX IF NOT EXISTS idx_attack_logs_created ON attack_logs (created)",
            "CREATE INDEX IF NOT EXISTS idx_attack_logs_ip ON attack_logs (ip)",
            "CREATE INDEX IF NOT EXISTS idx_attack_logs_type_created ON attack_logs (attack_type, created)",
            "CREATE INDEX IF NOT EXISTS idx_attack_logs_severity_created ON attack_logs (severity, created)",
        ];

        app.save(collection);
    },
    (app) => {
        let collection;
        try {
            collection = app.findCollectionByNameOrId("attack_logs");
        } catch (err) {
            return;
        }

        // เดิม down() คืนค่า rule แบบ `@request.auth.id != ""` ตามสถานะก่อนหน้า
        // ซึ่งแปลว่า rollback migration นี้ = เปิดช่องโหว่เดิมกลับมา โดยไม่ได้เตือนใคร
        // ความปลอดภัยชนะความสามารถในการย้อนกลับอยู่ดีกว่า -> คง rule แบบล็อกไว้
        // (ถ้าอยากได้พฤติกรรมเดิมค่อยแก้ใน migration ใหม่ที่มีเหตุผลรองรับ)
        collection.listRule = null;
        collection.viewRule = null;
        collection.createRule = null;
        collection.updateRule = null;
        collection.deleteRule = null;

        // คืน index ชุดเดิม (เผื่อ down() ถูกเรียกหลังจากมี migration ที่แตะ index)
        collection.indexes = [
            "CREATE INDEX IF NOT EXISTS idx_attack_logs_created ON attack_logs (created)",
            "CREATE INDEX IF NOT EXISTS idx_attack_logs_ip ON attack_logs (ip)",
        ];

        app.save(collection);
    }
);