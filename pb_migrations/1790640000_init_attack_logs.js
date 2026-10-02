// pb_migrations/1790640000_init_attack_logs.js
//
// Creates the collection consumed by pb_hooks/main.pb.js.
// The hook writes with `$app.save()`, so the API rules below only govern what
// clients (i.e. the realtime dashboard) are allowed to read.

migrate(
    (app) => {
        // already created (e.g. through the Dashboard) -> keep the existing one
        try {
            app.findCollectionByNameOrId("attack_logs");
            return;
        } catch (err) {
            // not found, safe to create
        }

        const collection = new Collection({
            name: "attack_logs",
            type: "base",

            // SUPERUSER ONLY -> the rule must be `null`.
            //
            // PocketBase rule semantics, easy to get backwards:
            //   null = superuser only   <- locked
            //   ""   = public / guest   <- anyone, even anonymous
            //
            // These were originally `@request.auth.id != ""`, which any throwaway
            // sign-up could satisfy and then read the whole incident history.
            // Migration 1790640001 re-applies the locked rules for databases that
            // already ran this one.
            listRule: null,
            viewRule: null,

            // incidents are immutable from the outside: the hook uses
            // `$app.save()` which bypasses the API rules
            createRule: null,
            updateRule: null,
            deleteRule: null,

            fields: [
                {
                    type: "text",
                    name: "ip",
                    required: true,
                    max: 100,
                },
                {
                    type: "text",
                    name: "target_user",
                    required: true,
                    max: 200,
                },
                {
                    type: "text",
                    name: "attack_type",
                    required: true,
                    max: 60,
                },
                {
                    type: "select",
                    name: "severity",
                    required: true,
                    maxSelect: 1,
                    values: ["low", "medium", "high", "critical"],
                },
                {
                    // the sanitised request snapshot (JSON text, truncated by
                    // the hook - kept as text so a cut payload still saves)
                    type: "text",
                    name: "payload",
                    max: 8000,
                },
                {
                    type: "text",
                    name: "actor",
                    max: 200,
                },
                {
                    type: "text",
                    name: "method",
                    max: 10,
                },
                {
                    type: "text",
                    name: "endpoint",
                    max: 300,
                },
                {
                    type: "number",
                    name: "status_code",
                    onlyInt: true,
                    min: 0,
                    max: 599,
                },
                {
                    type: "text",
                    name: "user_agent",
                    max: 300,
                },

                // system fields: when a collection is declared through a
                // migration, `created`/`updated` are NOT added implicitly
                // (unlike the Dashboard). `created` is also the column the
                // dashboard sorts on, so it is required.
                {
                    type: "autodate",
                    name: "created",
                    onCreate: true,
                    onUpdate: false,
                    required: true,
                    system: true,
                },
                {
                    type: "autodate",
                    name: "updated",
                    onCreate: true,
                    onUpdate: true,
                    required: true,
                    system: true,
                },
            ],

            indexes: [
                "CREATE INDEX idx_attack_logs_created ON attack_logs (created)",
                "CREATE INDEX idx_attack_logs_ip ON attack_logs (ip)",
                "CREATE INDEX idx_attack_logs_type_created ON attack_logs (attack_type, created)",
                "CREATE INDEX idx_attack_logs_severity_created ON attack_logs (severity, created)",
            ],
        });

        app.save(collection);
    },
    (app) => {
        const collection = app.findCollectionByNameOrId("attack_logs");
        app.delete(collection);
    }
);
