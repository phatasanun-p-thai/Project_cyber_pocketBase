// pb_migrations/1790640002_init_users.js
//
// สร้าง `users` auth collection ซึ่ง test.http ใช้เป็นเหยื่อ แต่ก่อนหน้านี้ไม่มี
// migration ไหนสร้างมัน -> instance ใหม่ทุกตัวจะไม่มี collection นี้ และ STEP 1
// (`POST /api/collections/users/records`) จะตอบ 404 ทั้งชุด ทำให้ยืนยันว่า
// hook ทำงานถูกต้องไม่ได้เลย
//
// ทุกอย่างในไฟล์นี้ถูกออกแบบมาให้ test.http คาดผลได้ตามนี้:
//
//   1.1/1.2 สมัครผู้ใช้ไม่มี token   -> createRule = ""  (สมัครสมาชิกได้)
//                                       และ hook จะไม่ log เพราะ isSelfRegistration()
//   2.x   login ผิดรหัส              -> AUTH_PATH_RE จับได้ที่ auth-with-password
//   3.1   PATCH record คนอื่น ไม่มี token -> updateRule ไม่ผ่าน -> 4xx -> MASS_ASSIGNMENT
//   3.2   PATCH record คนอื่น มี token    -> updateRule ไม่ผ่าน -> 4xx -> MASS_ASSIGNMENT
//   3.3   DELETE record คนอื่น มี token  -> deleteRule ไม่ผ่าน -> 4xx -> BOLA_IDOR
//   3.4   GET record คนอื่น                -> viewRule  ไม่ผ่าน -> 404 -> BOLA_IDOR
//   4.1   อ่าน attack_logs                -> collection นั้นล็อก superuser-only แยกต่างหาก
//
// ---------------------------------------------------------------------------
//  ทำไมไม่มี field `role`
// ---------------------------------------------------------------------------
//  `role` อยู่ใน SEC.privilegedFields ของ hook เพื่อจับ mass assignment แต่
//  **ไม่** ใส่ field นี้ใน schema ตั้งใจ เพราะ createRule เปิดให้สมัครสมาชิกได้
//  (ตามข้อ 1.1 ข้างบน) และ PocketBase ไม่มีกลไก filter field ผ่าน API rule ->
//  ถ้าใส่ `role` ไว้ ผู้ใช้ทั่วไปจะ `POST {role:"admin"}` แล้วได้สิทธิ์ admin
//  ไปจริง ๆ ซึ่งเป็นช่องโหว่ที่ใช้งานจริง ไม่ใช่แค่ log
//
//  การทดสอบ mass assignment ยังทำงานครบอยู่ดี เพราะ hook ตรวจ **request body**
//  ไม่ใช่ record ที่บันทึกลงฐานข้อมูล -> ยิด role แล้ว PocketBase ทิ้ง field ที่ไม่รู้จัก
//  แต่ hook ยังเห็น key ใน body และรายงานตามปกติ
//
//  ถ้าอยากเปิดเคส privilege escalation จริง (ใช้เฉพาะ lab ที่ตั้งใจให้เปราะ):
//    1. เพิ่ม field `role` (select: user|admin) ผ่าน Dashboard หรือ migration
//    2. ปิด createRule เป็น null ไม่ให้สมัครเอง แล้วค่อยแก้ role ผ่าน superuser
//       เท่านั้น - มิฉะนั้นช่องโหว่จะเปิดให้คนทั่วไปโดยอัตโนมัติ
// ---------------------------------------------------------------------------

migrate(
    (app) => {
        // สร้างผ่าน Dashboard ไปแล้ว -> อย่าแตะ ให้ schema ที่ทำไว้เอง
        try {
            app.findCollectionByNameOrId("users");
            return;
        } catch (err) {
            // not found, safe to create
        }

        const collection = new Collection({
            name: "users",
            type: "auth",

            // --------------------------------------------------------- API rules
            // ค่าเริ่มต้นของ PocketBase สำหรับ auth collection (Users)
            // ปรับตามต้องการจริงได้ แต่อย่าลืมว่าทุกค่านี้คือชั้นความปลอดภัย
            // ชั้นเดียว - hook ใน pb_hooks/main.pb.js เป็นแค่ผู้สังเกตการณ์ ไม่ได้กันอะไร

            // เห็นเฉพาะแถวของตัวเอง
            listRule: "id = @request.auth.id",
            viewRule: "id = @request.auth.id",

            // "" = สมัครสมาชิกได้โดยไม่ต้องล็อกอิน (test.http STEP 1 ต้องการแบบนี้)
            // เปลี่ยนเป็น null เพื่อปิดการสมัครสมาชิกเมื่อขึ้น production
            createRule: "",

            // แก้ได้เฉพาะตัวเองเท่านั้น
            // (PocketBase จะ normalise เป็น `id = @request.auth.id` ให้อยู่แล้ว)
            updateRule: "@request.auth.id = @request.data.id",

            deleteRule: "id = @request.auth.id",

            // ----------------------------------------------------------- fields
            // ฟิลด์ของ auth collection ต้องประกาศเองทุกตัว เพราะการสร้างผ่าน
            // migration ไม่ได้เติม system field ให้อัตโนมัติเหมือนที่ Dashboard
            // ทำ (เหมือนกรณี created/updated ใน 1790640000_init_attack_logs.js)
            //
            // ข้อควรรู้: PocketBase normalise ฟิลด์ชุดมาตรฐานของ auth collection
            // ทุกครั้งที่ `app.save()` - ค่าที่ประกาศไว้ข้างล่างบางตัวจึงถูกเขียนทับ
            // ทดสอบแล้วว่าเขียนทับทั้งตอนสร้างและตอน save ซ้ำ ดังนั้นไฟล์นี้จะไม่ประกาศ
            // ค่าที่จะถูกทิ้ง เพื่อไม่ให้ผู้อ่านเข้าใจผิดว่าบังคับใช้งานอยู่:
            //
            //   name        -> max กลับเป็น 255 เสมอ
            //   avatar      -> maxSize กลับเป็น 0 (ไม่จำกัดขนาด) และ mimeTypes ถูก
            //                   เติม image/svg+xml เข้ามาเอง
            //   verified    -> required กลับเป็น false
            //   created/updated -> system กลับเป็น false
            //
            // ถ้าต้องจำกัดขนาดไฟล์ avatar ต้องทำที่ชั้นอื่น (reverse proxy / disk quota)
            // เพราะ PocketBase ไม่ให้ migration คุมได้
            fields: [
                {
                    type: "text",
                    name: "name",
                    required: false,
                },
                {
                    type: "file",
                    name: "avatar",
                    maxSelect: 1,
                },
                {
                    type: "authEmail",
                    name: "email",
                    required: true,
                    exceptEmailDomains: [],
                    onlyDomains: [],
                },
                {
                    type: "bool",
                    name: "verified",
                },
                {
                    type: "authPassword",
                    name: "password",
                    required: true,
                    // ความยาวขั้นต่ำของรหัสผ่าน เก็บไว้ตามนี้ได้จริง (ทดสอบแล้ว
                    // ต่างจาก max/maxSize ของ text/file ที่ถูก normalize ทิ้ง)
                    min: 8,
                    cost: 10,
                },
                {
                    type: "authTokenKey",
                    name: "tokenKey",
                },
                {
                    // จำเป็นเพราะหน้าแดชบอร์ดเรียงตาม created และกรองด้วย created
                    type: "autodate",
                    name: "created",
                    onCreate: true,
                    onUpdate: false,
                    required: true,
                },
                {
                    type: "autodate",
                    name: "updated",
                    onCreate: true,
                    onUpdate: true,
                    required: true,
                },
            ],
            // ไม่ประกาศ indexes: PocketBase เพิ่ม unique index บน tokenKey/email ให้เอง
            // อยู่แล้ว และ hook ไม่ได้ query `users` โดยตรงเลย
        });

        app.save(collection);
    },
    (app) => {
        let collection;
        try {
            collection = app.findCollectionByNameOrId("users");
        } catch (err) {
            return;
        }
        app.delete(collection);
    }
);