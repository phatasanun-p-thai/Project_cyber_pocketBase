// pb_migrations/1790640000_init_attack_logs.js
//
// Creates the collection consumed by pb_hooks/security.js.
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

            // readable by any authenticated user, and by every superuser
            listRule: '@request.auth.id != ""',
            viewRule: '@request.auth.id != ""',

            // incidents are immutable from the outside: the hook uses
            // `$app.save()` which bypasses the API rules
            createRule: "",
            updateRule: "",
            deleteRule: "",

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
            ],
        });

        app.save(collection);
    },
    (app) => {
        const collection = app.findCollectionByNameOrId("attack_logs");
        app.delete(collection);
    }
);
