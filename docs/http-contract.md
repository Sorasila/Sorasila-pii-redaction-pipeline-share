# HTTP contract: raw Markdown and multipart delivery

ข้อตกลงนี้ยึด Handoff revised ข้อ 3 และ 4.1 (`Handoff.revised.md`, เอกสารส่วนตัว ไม่อยู่ใน repo)
และคำยืนยันผู้ใช้วันที่ 2026-10-02: รับ raw string, รอผลใน request เดียว
และใช้ multipart ตามข้อ 3 ข้อความ Markdown ต้องไม่มี JSON wrapper หรือ PII mapping ปนอยู่

## Request

Adapter ใช้ `POST /redact` โดยรับ body เป็นข้อความ Markdown UTF-8 โดยตรง
รองรับ `Content-Type: text/plain; charset=utf-8` หรือ
`Content-Type: text/markdown; charset=utf-8` ไม่รับ `application/json`
และไม่ดึงข้อความจาก object เช่น `{"text": "..."}`

ตัวอย่าง body แบบ synthetic ซึ่งส่งเป็นข้อความล้วน:

```text
ชื่อ นายทดสอบ
คดีหมายเลขดำที่ 1/2569
```

แต่ละ request จบในตัวเอง ไม่รวม session หรือข้อความจาก requests อื่น
จำกัดต้นฉบับที่ 2000 Unicode codepoints (เพิ่มจาก 1000 เมื่อ 2026-10-05) ก่อน NFC normalization และอ่าน body
ไม่เกิน 8000 UTF-8 bytes (4 bytes ต่อ code point) ทั้งสองเงื่อนไขต้องผ่าน ตัวอักษรในที่นี้ไม่ใช่ bytes,
UTF-16 code units, grapheme clusters หรือ LLM tokens
ไม่ตัดข้อความที่เกินเกณฑ์และไม่แยกส่ง LLM เพิ่มโดยอัตโนมัติ
เก็บ whitespace/newlines ของข้อความไว้ตาม core contract

Caller ต้องผ่าน authentication ที่ deployment กำหนดก่อนอ่าน body/เรียก core
Factory ไม่เลือก credential หรือเปิด anonymous access ให้เอง
Caller รอการประมวลผลและ independent verification ทั้งสองชุดใน request เดิม
จนได้ final response ไม่มี `202 Accepted` หรือ polling flow

## Container probes

`GET /healthz` ตอบ `200 {"status": "ok"}` เมื่อ process ยังทำงาน และ `GET /readyz` ตอบ
`200 {"status": "ready"}` เมื่อเปิด LLM client แล้วพร้อมรับ request (`503 {"status": "not_ready"}`
ก่อนเริ่มเสร็จและระหว่างปิด) ไม่ต้องใช้ token ไม่รับเอกสาร ไม่เรียก LLM proxy หรือที่เก็บ manifest
และไม่เขียน request log; method อื่นได้ `405` พร้อม `Allow: GET`; path จริงที่ระบบ deploy ใช้ยังต้องตกลงกับ dev

## Successful response

หลัง verification ผ่านครบจึงประกอบ response ใน memory แล้วตอบ HTTP 200 พร้อม header
`X-Document-Id` (ตรงกับ log ของ request; ไม่มี PII)

**ค่าเริ่มต้น (ตัดสิน 2026-10-16): body คือ Markdown ที่ redact แล้วโดยตรง**
`Content-Type: text/markdown; charset=utf-8` ไม่มี metadata ไม่มี manifest ไม่มี PII ออกจาก service

เมื่อตั้ง `PII_SERVICE_RETURN_METADATA=true` ตอบ `Content-Type: multipart/form-data; boundary=<generated-boundary>`
ที่มี `redacted_md` + `metadata`; เมื่อตั้ง `PII_SERVICE_RETURN_MANIFEST=true` เพิ่ม `pii_manifest`
(และ metadata ด้วยเสมอ เพราะ manifest ผูกกับ metadata) สำหรับผู้เรียกที่ต้องโยง placeholder กลับไปหาค่าจริง; ต้องมี encryptor:

| Part name | Filename | Content-Type | Body |
| --- | --- | --- | --- |
| `redacted_md` | `redacted.md` | `text/markdown; charset=utf-8` | UTF-8 Markdown ที่ redact แล้วโดยตรง |
| `pii_manifest` | `pii_manifest.json` | `application/json` | Encrypted manifest ใน JWE JSON envelope ตาม adapter ที่กำหนด (เฉพาะเมื่อเปิด `PII_SERVICE_RETURN_MANIFEST`) |
| `metadata` | — | `application/json` | IDs/version/hash/time ที่ไม่มีค่า PII (เฉพาะเมื่อเปิด `PII_SERVICE_RETURN_METADATA` หรือ `PII_SERVICE_RETURN_MANIFEST`) |

`redacted_md` ใช้ bytes ของข้อความที่ core คืนมาโดยตรง ไม่ผ่าน `json.dumps()`
ไม่มี quotes/escape characters จาก JSON serialization และไม่มี mapping ต่อท้าย
CRLF สำหรับแบ่ง MIME parts เป็น framing ภายนอก ไม่เพิ่มหรือเปลี่ยน newlines ในข้อความ
ใช้ชื่อ parts/filenames คงที่ ไม่ใส่ค่า PII ใน headers
Boundary ต้องไม่ชน payload ของส่วนใดส่วนหนึ่ง
รูปแบบการแยกส่วนเป็น [multipart/form-data ตาม RFC 7578](https://www.rfc-editor.org/rfc/rfc7578)

Manifest ก่อนเข้ารหัสมีเฉพาะ `document_id` และ `entries` แต่ละ entry มี
`placeholder`, `pii_type`, `occurrence_index`, `original_value`, `redacted_at`
Counter เริ่มที่ 1 แยกตาม canonical type และต้องตรงกับ placeholders ในข้อความ
Metadata มี `document_id`, `detector_version`, `delivery_id`,
`redacted_md_sha256`, `created_at` Hash คำนวณจาก exact UTF-8 bytes ของ Markdown part
JSON Schema ที่ใช้อ้างอิง/validate ฝั่งผู้รับ: [pii-manifest.schema.json](pii-manifest.schema.json)
(manifest หลังถอดรหัส) และ [metadata.schema.json](metadata.schema.json)
`tests/test_delivery_schemas.py` ตรวจว่า output จริงของ `prepare_delivery` ผ่านทั้งสอง schema
และ enum ของ `pii_type` ตรงกับ canonical vocabulary ทุกครั้งที่รัน test suite

ตัวประกอบ package ต้องได้รับ trusted synchronous encryptor จริงจาก deployment ไม่มี plaintext
fallback และไม่มี test cipher เป็นค่าเริ่มต้น Serializer รองรับ flattened JWE JSON profile
`RSA-OAEP-256` + `A256GCM` (12-byte IV, 16-byte authentication tag) เท่านั้น
Profile นี้เป็นขอบเขต adapter ที่เตรียมไว้ ไม่ใช่ผลทดสอบ cryptography หรือการยืนยัน key ของระบบจริง Envelope เป็น
[JWE JSON serialization ตาม RFC 7516](https://www.rfc-editor.org/rfc/rfc7516#section-7.2)
เพื่อให้ manifest ยังคงเป็นไฟล์ JSON ได้ ข้อกำหนด public-key encryption,
TLS/mTLS, trusted endpoint และการปิด body logging ของเอกสารแม่ยังคงเดิม
Canonical metadata bytes ผูกเป็น additional authenticated data ของ manifest
ผู้รับต้องตรวจ AAD/hash/IDs และ decrypt ด้วย key ที่กำหนดก่อนใช้งาน mapping
การตรวจ envelope shape ใน serializer ไม่ใช่หลักฐานว่า encryption implementation ถูกต้อง

Response และ errors ใช้ `Cache-Control: no-store` และ `X-Content-Type-Options: nosniff`
ห้าม log request body, response parts, original values, anchors หรือ manifest

## Errors and deadlines

ไม่ส่ง Markdown หรือ manifest บางส่วนเมื่อขั้นใดล้มเหลว Error response มีเฉพาะ
fixed error code และ safe IDs ตามที่ adapter กำหนด ไม่ส่ง input/model/error details กลับ

| HTTP status | เงื่อนไข |
| --- | --- |
| 400 | Body/UTF-8/header ไม่ถูกต้อง หรือข้อความว่าง |
| 401 | Authentication ไม่ผ่าน |
| 413 | เกิน character/byte limit |
| 415 | Content-Type/charset ไม่รองรับ |
| 502 | Detection, verification หรือ package/encryption ล้มเหลว |
| 504 | เกิน whole-request deadline ที่ deployment กำหนด |
| (499) | ผู้เรียกตัดการเชื่อมต่อระหว่างประมวลผล: service หยุดงานทันที ปิด LLM request ที่ค้าง ไม่ลองใหม่และไม่เก็บ manifest; ไม่มีใครได้รับ response นี้ ใช้แค่ใน log |

Whole-request deadline ต้องกำหนดชัดเจนและครอบ auth/body/core/package
แยกจาก per-proxy-call deadline ใน `LlmProxySettings` การยกเลิก request ต้องไม่
ทำให้ส่ง partial response ค่า deadline ของ frontend/gateway ต้องรองรับเวลานี้
งาน synchronous ภายใน serializer/encryptor ตรวจเวลาหลังกลับมาได้ แต่ไม่อ้างว่า interrupt CPU work ได้

## Composition and remaining integration

`create_app()` เป็น factory ที่ต้องได้รับ trusted `LlmDocumentProcessor` + `RecoveryPolicy` (ประมวลผลผ่าน automatic recovery เส้นทางเดียว),
rule detectors และ rule verification checker (synchronous), authentication callback, synchronous `encrypt_manifest` (หรือ `None` เมื่อไม่ส่งและไม่เก็บ manifest) และ finite positive request deadline; `return_manifest` เลือกว่าจะใส่ส่วน `pii_manifest` หรือไม่
API เรียก fixed `prepare_delivery()` ภายในเอง ไม่มี public callback ที่นำ body ที่สร้างเองมาข้าม serializer ได้
แยก lifecycle/ownership ของ LLM client และ window planners ไว้กับ caller
ไม่มี `.env` loading, dummy rule lanes, guessed token budget หรือ live calls ตอน import

`pii_pipeline.service.create_service_app` (รันด้วย `uvicorn --factory`) คือ composition ที่ใช้ทดสอบตอนนี้:
rule lane `detect_thai_rule_pii` ทั้ง detection และ rule verification, LLM lane พร้อม automatic recovery,
หนึ่ง window ต่อ request, deadline `PII_SERVICE_REQUEST_DEADLINE_SECONDS` (ค่าเริ่มต้น 1200 วินาที)
และ Bearer token ชั่วคราว `PII_SERVICE_API_TOKEN` จนกว่าจะตกลงวิธี authentication กับ dev
ค่าเริ่มต้น `PII_SERVICE_RETURN_METADATA=false` และ `PII_SERVICE_RETURN_MANIFEST=false` ตอบแค่ Markdown ที่ redact แล้ว ไม่สร้าง manifest และไม่ต้องมี encryptor; เมื่อเปิดส่ง (หรือเปิดที่เก็บ manifest) ระหว่างที่ยังไม่มี encryptor จริง service เริ่มได้เฉพาะเมื่อตั้ง `PII_SERVICE_ALLOW_UNENCRYPTED_TEST_MANIFEST=true`
ซึ่ง `pii_manifest` เป็น envelope รูป JWE ที่มี `kid` `UNENCRYPTED-TEST-ONLY` และ `ciphertext` คือ manifest แบบ **plaintext**
ใช้กับเครื่องทดสอบเท่านั้น ไม่ใช่ plaintext fallback ของ production

Adapter log หนึ่งบรรทัดต่อ request: `document_id`, status, เวลา, จำนวน LLM calls แยกตาม role
(`llm_calls`, `by_role`), จำนวน HTTP request ที่ส่งถึง proxy จริง (`http_attempts`) และเวลา/ผลของแต่ละครั้ง (`attempt_seconds`), เหตุของ call ส่วนเกิน
(`repairs`, `blank_resends`, `verification_retries`, `residual_rounds`, `merge_selections`), งบ recovery,
event สุดท้าย และสายของ exception (ชื่อ class, reason code และข้อความคงที่ของ package นี้เท่านั้น)
ไม่มีข้อความเอกสาร ค่า PII หรือข้อความ error จากภายนอก

Operator ยังต้องกำหนด ingress authentication จริง, real encryptor/recipient keys,
production rule policy, proxy token/window budgets และ effective gateway deadline
ก่อนรันกับระบบจริง ชุด ASGI/MIME tests ใช้ fake dependencies เพื่อทดสอบ contract
ไม่ใช่ผล production LLM/encryption/deployment

ผู้ใช้แจ้งข้อมูลทีม dev วันที่ 2026-10-02: ระบบหลักเรียก container นี้เป็น service
แล้วรับ multipart ใน HTTP response เดิม ผู้เรียกเป็นผู้รับผล ไม่มี separate outbound
POST/callback/acknowledgement endpoint Response200ยืนยันการประมวลผล/ประกอบผลสำเร็จ
ไม่ใช่หลักฐานว่าผู้เรียกจัดเก็บแล้ว Request retryเป็นหน้าที่ผู้เรียก; optional request
idempotency/status/quarantine/storage/alerts และ Dockerยังต้องผูก operational contract

ผู้ใช้เลื่อน encryption design ไว้ก่อน ข้อมูล JWE profile/AAD ด้านบนเป็นข้อเท็จจริง
ของ prototype serializer ไม่ใช่การเลือก crypto design ที่อนุมัติแล้ว ไม่ออกแบบ
algorithm/keys/real encryptor ต่อในรอบนี้ โหมดทดสอบของ service ที่ต้องเปิดด้วย flag ข้างบน
ไม่ใช่การเลือก crypto design และห้ามใช้กับระบบจริง
รายการข้อมูลที่ขอจาก dev อยู่ใน [DEV_REQUIREMENTS_CHECKLIST.md](DEV_REQUIREMENTS_CHECKLIST.md)
