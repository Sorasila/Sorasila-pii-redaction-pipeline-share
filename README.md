# PII Redaction Service: การรันและตั้งค่าใน Docker

Service รับข้อความ Markdown ภาษาไทยที่ได้จาก OCR (ไม่เกิน 2000 ตัวอักษรต่อ request)
หา PII แล้วแทนด้วย placeholder เช่น `[PII_NAME_1]` ตรวจซ้ำว่าไม่เหลือ PII
แล้วตอบข้อความที่ปิดแล้วกลับไปใน request เดิม ถ้าตรวจไม่ผ่านจะตอบ error เสมอ
ไม่มีผลบางส่วนหลุดออกไป

เอกสารนี้สำหรับทีมที่นำ service ขึ้น container รายละเอียดอื่น:
[สัญญา HTTP](docs/http-contract.md) ·
[การทำงานและขอบเขต PII](docs/OVERVIEW.md) ·
[รันบนเครื่องโดยไม่ใช้ Docker](docs/SETUP_AND_USAGE.md)

> สถานะ: prototype ที่ผ่านเทสต์อัตโนมัติ (core 1303, harness 79) และทดสอบกับ LLM
> เครื่องทดสอบแล้ว **Dockerfile และตัวอย่าง Compose/Kubernetes ด้านล่างเป็นตัวอย่างอ้างอิง
> ยังไม่ได้ทดสอบบนแพลตฟอร์มจริง** ปรับตามกติกาของแพลตฟอร์มได้

---

## 1. ข้อมูลของ container โดยสรุป

| หัวข้อ | ค่า |
| --- | --- |
| Base image | `python:3.13-slim` (ทดสอบแล้วทั้ง Python 3.12 และ 3.13) |
| ไลบรารี | `pip install -r requirements.txt` ซึ่งล็อกเวอร์ชันทั้งหมดผ่าน [constraints.txt](constraints.txt) |
| โค้ดที่อยู่ใน image | โฟลเดอร์ `pii_pipeline/` เท่านั้น |
| คำสั่งเปิด | `uvicorn pii_pipeline.service:create_service_app --factory --host 0.0.0.0 --port 8080` |
| พอร์ต | `8080` (HTTP) |
| User | ไม่ใช่ root (uid `10001`) |
| ไฟล์ / volume / database | **ไม่มี** service ไม่เขียนไฟล์ ใช้ root filesystem แบบอ่านอย่างเดียวได้ |
| ค่าตั้ง | environment variable ทั้งหมด (ข้อ 3) ไม่ต้องมีไฟล์ `.env` ใน container |
| Health check | `GET /healthz` (liveness), `GET /readyz` (readiness) ไม่ต้องใช้ token |
| หน้าทดลอง API | Swagger ที่ `/docs` เปิดด้วย `PII_SERVICE_ENABLE_DOCS=true` (ค่าเริ่มต้นปิด) |
| Log | stdout/stderr บรรทัดเดียวต่อ request ไม่มีข้อความเอกสารหรือค่า PII |
| Network ขาออก | HTTPS ไปที่ LLM proxy เท่านั้น |
| Process | 1 process ต่อ container แล้ว scale ด้วยจำนวน replica (process เดียวรับได้หลาย request พร้อมกัน เพราะเวลาเกือบทั้งหมดคือรอ LLM) |

---

## 2. Build และรันแบบเร็ว

```bash
docker build -t pii-redaction-service .
```

สร้างไฟล์ค่าตั้ง **นอก repo และนอก image** เช่น `/srv/pii-redaction/service.env`
(ตัวอย่างในข้อ 3.3) จำกัดสิทธิ์อ่านเฉพาะผู้ดูแล แล้วรัน:

```bash
docker run --rm -p 8080:8080 --env-file /srv/pii-redaction/service.env --read-only --stop-timeout 1500 pii-redaction-service
```

เช็คว่าพร้อม:

```bash
curl -s http://127.0.0.1:8080/readyz
```

ได้ `{"status":"ready"}` แปลว่าพร้อมรับงาน ส่งหน้าทดสอบ (ข้อมูลสังเคราะห์ใน `samples/synthetic/`):

```bash
curl -s -X POST -H "Content-Type: text/markdown; charset=utf-8" -H "Authorization: Bearer $PII_SERVICE_API_TOKEN" --data-binary @samples/synthetic/page-3.md -D - http://127.0.0.1:8080/redact
```

ได้ HTTP 200 พร้อม body เป็น Markdown ที่ปิด PII แล้ว และ header `X-Document-Id`
**request หนึ่งใช้เวลาหลายนาที** บนเครื่อง LLM ทดสอบ (ดูข้อ 5)

---

## 3. การตั้งค่า (environment variables)

Service อ่านค่าจาก environment ของ container ถ้าค่าที่จำเป็นขาดหรือผิด service
จะไม่ยอมเปิด และแสดงชื่อค่าที่ผิดใน log (ข้อ 8)

### 3.1 ค่าที่ต้องตั้ง

| ตัวแปร | ชนิด | ความหมาย |
| --- | --- | --- |
| `LLM_PROXY_BASE_URL` | ค่าตั้ง | URL ของ LLM proxy (service เรียก `POST /structured-output`) |
| `LLM_PROXY_API_KEY` | **ค่าลับ** | Bearer key ของ proxy ขอจากทีมที่ดูแล proxy |
| `PII_SERVICE_API_TOKEN` | **ค่าลับ** | token ที่ผู้เรียกต้องส่งใน `Authorization: Bearer <token>` อย่างน้อย 32 ตัวอักษรแบบสุ่ม เป็นวิธีชั่วคราวจนกว่าจะตกลง authentication จริง |

### 3.2 ค่าที่ปรับได้

| ตัวแปร | ค่าเริ่มต้น | ใช้เมื่อ |
| --- | --- | --- |
| `PII_SERVICE_REQUEST_DEADLINE_SECONDS` | `1200` | เวลาสูงสุดต่อ request ครบแล้วตอบ 504 ต้องไม่ยาวกว่า timeout ของ gateway (ข้อ 5) |
| `LLM_PROXY_VERIFY_TLS` | `true` | ตั้ง `false` **เฉพาะ** เมื่อใช้ข้อยกเว้น TLS ของ proxy ที่อนุมัติไว้ (ไม่ตรวจ certificate ของ proxy; ยังเป็น HTTPS) |
| `LLM_PROXY_CA_BUNDLE` | ไม่ตั้ง | path ของไฟล์ CA ภายในองค์กร (mount ไฟล์เข้า container แบบอ่านอย่างเดียว) ใช้แทนการปิด TLS |
| `LLM_PROXY_READ_TIMEOUT_SECONDS` | `300` | รอคำตอบจาก proxy ต่อครั้ง |
| `LLM_PROXY_REQUEST_DEADLINE_SECONDS` | `600` | เวลาสูงสุดต่อการเรียก LLM หนึ่งครั้ง รวมการลองใหม่ |
| `LLM_PROXY_MAX_RETRIES` | `2` | ลองใหม่เมื่อ proxy ตอบ 502/503/504 หรือการเชื่อมต่อหลุด (0–2) |
| `LLM_PROXY_CONNECT_TIMEOUT_SECONDS`, `..._WRITE_...`, `..._POOL_...` | `10`, `30`, `10` | timeout ย่อยต่อครั้ง |
| `PII_SERVICE_RETURN_METADATA` | `false` | `true` = ตอบ multipart `redacted_md` + `metadata` แทนข้อความล้วน |
| `PII_SERVICE_ENABLE_DOCS` | `false` | `true` = เปิดหน้า Swagger ที่ `/docs` ให้ลองเรียก API (ข้อ 6.1) แนะนำเฉพาะเครื่องทดสอบ/staging |
| `PII_SERVICE_DOCS_USERNAME`, `PII_SERVICE_DOCS_PASSWORD` | ไม่ตั้ง | **ค่าลับ (รหัสผ่าน)** ล็อกอินในหน้า Swagger เพื่อรับ token ชั่วคราว ต้องตั้งคู่กัน รหัสผ่านอย่างน้อย 12 ตัว ใช้ได้เฉพาะเมื่อเปิด docs (ข้อ 6.1) |
| `PII_SERVICE_DOCS_TOKEN_TTL_SECONDS` | `3600` | อายุของ token ที่ได้จากการล็อกอิน (สูงสุด 86400) |
| `UVICORN_ROOT_PATH` | ไม่ตั้ง | path นำหน้าเมื่อเรียกผ่าน gateway เช่น `/pii` (ข้อ 6.2) |

### 3.3 ตัวอย่างไฟล์ค่าตั้ง (ค่าปลอม)

```text
LLM_PROXY_BASE_URL=https://llm-proxy.example.internal:9001
LLM_PROXY_API_KEY=<ใส่จาก secret store>
PII_SERVICE_API_TOKEN=<สุ่มใหม่ อย่างน้อย 32 ตัว>
PII_SERVICE_REQUEST_DEADLINE_SECONDS=1200
# LLM_PROXY_VERIFY_TLS=false        # เฉพาะเมื่อใช้ข้อยกเว้น TLS
# LLM_PROXY_CA_BUNDLE=/run/certs/internal-ca.pem
```

สุ่ม token ได้ด้วย `python -c "import secrets; print(secrets.token_urlsafe(32))"`
รายชื่อค่าทั้งหมดอยู่ใน [.env.example](.env.example)

### 3.4 ค่าลับเก็บที่ไหน

- **ห้าม** copy `.env` หรือค่าลับเข้า image และห้าม commit ลง git
  ([.dockerignore](.dockerignore) อนุญาตแค่ `requirements.txt`, `constraints.txt`, `pii_pipeline/`
  ไฟล์อื่นเข้า image ไม่ได้)
- Docker Compose: `env_file` ที่อยู่บนเซิร์ฟเวอร์ หรือ Docker secrets
- Kubernetes: `LLM_PROXY_API_KEY`, `PII_SERVICE_API_TOKEN` ใน Secret ส่วนค่าอื่นใน ConfigMap
- ใช้ token ของ production แยกจากเครื่องทดสอบเสมอ

### 3.5 ค่าที่ไม่ต้องตั้งใน production

| ตัวแปร | เหตุผล |
| --- | --- |
| `PII_SERVICE_RETURN_MANIFEST` | ส่งค่า PII จริงกลับไปใน response ต้องรอการออกแบบการเข้ารหัสและการอนุญาตด้านข้อมูลก่อน |
| `PII_SERVICE_ALLOW_UNENCRYPTED_TEST_MANIFEST` | โหมดทดสอบที่ manifest **ไม่เข้ารหัส** ใช้กับเครื่องทดสอบเท่านั้น |
| `PII_SERVICE_ENABLE_DOCS`, `PII_SERVICE_DOCS_USERNAME`, `PII_SERVICE_DOCS_PASSWORD` | หน้า Swagger และการล็อกอิน มีไว้ให้ลองบนเครื่องทดสอบ/staging |
| `PII_STORE_URL`, `PII_STORE_TOKEN` | ที่เก็บ manifest เตรียมไว้สำหรับอนาคต production ตั้งใจไม่เก็บ PII |
| `LLM_PROXY_MODEL` | รับได้ค่าเดียวคือ `qwen/qwen3.6-27b` (ค่าเริ่มต้น) |

---

## 4. ตัวอย่างการ deploy

### 4.1 Docker Compose

```yaml
services:
  pii-redaction:
    image: pii-redaction-service:latest
    ports:
      - "8080:8080"
    env_file:
      - /srv/pii-redaction/service.env   # อยู่บนเซิร์ฟเวอร์ ไม่อยู่ใน repo หรือ image
    read_only: true
    stop_grace_period: 25m               # ยาวกว่า PII_SERVICE_REQUEST_DEADLINE_SECONDS
    restart: unless-stopped
```

Health check ใช้ `HEALTHCHECK` ที่อยู่ใน Dockerfile แล้ว (เรียก `/readyz` ทุก 30 วินาที)

### 4.2 Kubernetes (ส่วนที่เกี่ยวข้อง)

```yaml
spec:
  terminationGracePeriodSeconds: 1500    # ยาวกว่า PII_SERVICE_REQUEST_DEADLINE_SECONDS
  containers:
    - name: pii-redaction
      image: <registry>/pii-redaction-service:<tag>
      ports:
        - containerPort: 8080
      envFrom:
        - configMapRef: { name: pii-redaction-config }
        - secretRef: { name: pii-redaction-secrets }
      livenessProbe:
        httpGet: { path: /healthz, port: 8080 }
        periodSeconds: 30
      readinessProbe:
        httpGet: { path: /readyz, port: 8080 }
        periodSeconds: 10
      securityContext:
        runAsNonRoot: true
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
```

ยังไม่มีตัวเลข CPU/RAM ที่วัดแล้ว ตัว service ใช้ทรัพยากรน้อยเพราะส่วนใหญ่รอ LLM
แนะนำวัดจากการใช้งานจริงก่อนตั้ง limit

---

## 5. Timeout และ request ที่ใช้เวลานาน (สำคัญ)

- **request หนึ่งใช้เวลาหลายนาที** บนเครื่อง LLM ทดสอบ: ปกติ 1–6 นาที ช้าสุดที่วัดได้ราว
  20 นาที เวลาเกือบทั้งหมดคือรอ LLM (ต้องวัดซ้ำบนเครื่อง LLM production)
- **ทุกชั้นระหว่างผู้เรียกกับ container** (HTTP client, gateway, reverse proxy, ingress,
  load balancer) ต้องรอได้นานกว่า `PII_SERVICE_REQUEST_DEADLINE_SECONDS` หลายตัวมี
  ค่าเริ่มต้นแค่ 60 วินาที ชั้นที่สั้นที่สุดจะตัด request ก่อน
- **เวลาปิด container** (`stop_grace_period`, `terminationGracePeriodSeconds`,
  `docker run --stop-timeout`) ต้องยาวกว่า deadline ไม่อย่างนั้นตอน deploy หรือ
  scale down งานที่กำลังทำจะถูกตัดกลางทาง ระหว่างปิด `/readyz` ตอบ 503
  เพื่อให้หยุดส่งงานใหม่เข้ามา
- **ถ้าผู้เรียกตัดการเชื่อมต่อ** service หยุดงานหน้านั้นทันที ยกเลิกการเรียก LLM
  ที่ค้าง ไม่ลองใหม่ (log ขึ้น `status=499`)
- ถ้าผู้เรียก retry อัตโนมัติ งานจะถูกส่งไปที่ LLM ซ้ำ ควรตั้ง retry เฉพาะ 502/504
  และเว้นระยะ

---

## 6. API โดยย่อ

```text
POST /redact
Content-Type: text/markdown; charset=utf-8   (หรือ text/plain; charset=utf-8)
Authorization: Bearer <PII_SERVICE_API_TOKEN>
body: ข้อความ UTF-8 ดิบ ไม่เกิน 2000 ตัวอักษร (Unicode code point) ไม่ห่อด้วย JSON
```

| ผล | สิ่งที่ได้ |
| --- | --- |
| 200 (ค่าเริ่มต้น) | body = Markdown ที่ปิด PII แล้ว (`text/markdown; charset=utf-8`) + header `X-Document-Id` |
| 200 (`PII_SERVICE_RETURN_METADATA=true`) | `multipart/form-data`: `redacted_md` + `metadata` (ID, เวอร์ชัน, SHA-256 ของข้อความ, เวลา) |
| 400 / 401 / 413 / 415 | JSON `{"error": "..."}` (มี `document_id` ด้วยเมื่อเริ่มประมวลผลแล้ว): input ผิด, token ผิด, ยาวเกิน, Content-Type ไม่รองรับ |
| 502 | `processing_failed`: ตรวจจับหรือตรวจซ้ำไม่ผ่าน (รวมกรณี LLM ใช้งานไม่ได้) |
| 504 | `request_timeout`: ครบ `PII_SERVICE_REQUEST_DEADLINE_SECONDS` |

- เอกสารยาวกว่า 2000 ตัวอักษร ผู้เรียกต้องแบ่งเป็นหลาย request
  (ตัวช่วย: `tools/split_md_pages.py`) แต่ละ request อิสระ placeholder นับใหม่ทุก request
- `X-Document-Id` และ `document_id` ใน error ตรงกับ log ใช้ติดตามปัญหา
- รายละเอียดเต็ม: [docs/http-contract.md](docs/http-contract.md)

### 6.1 ลองเรียก API จากหน้า Swagger

ตั้ง `PII_SERVICE_ENABLE_DOCS=true` แล้วเปิด `http://<host>:8080/docs` ในเบราว์เซอร์

1. กด **Authorize** แล้วเลือกทางใดทางหนึ่ง
   - **ล็อกอิน (ถ้าเปิดไว้):** ส่วน *docsLogin* กรอก `username` และ `password` (ค่าที่ตั้งใน `PII_SERVICE_DOCS_USERNAME` / `PII_SERVICE_DOCS_PASSWORD`) ช่อง client_id/client_secret เว้นว่าง แล้วกด **Authorize** หน้าเว็บจะขอ token ชั่วคราวจาก `POST /token` แล้วใช้ให้เองจนหมดอายุ (ค่าเริ่ม 1 ชั่วโมง; หมดแล้วกด Logout แล้วล็อกอินใหม่)
   - **ใส่ token เอง:** ส่วน *bearerAuth* ใส่ค่า `PII_SERVICE_API_TOKEN` (ไม่ต้องพิมพ์คำว่า `Bearer`)
2. เปิด `POST /redact` กด **Try it out** แก้ข้อความในช่อง body (มีตัวอย่างสังเคราะห์ให้) แล้วกด **Execute**
3. รอผล (หลายนาทีบนเครื่อง LLM ทดสอบ) ผลอยู่ที่ช่อง *Server response* พร้อม header `x-document-id`

- เปิดหน้า `/docs` และ `/openapi.json` ได้โดยไม่ต้องใช้ token แต่การเรียก `/redact` จากหน้านี้ยังต้องใช้ token เสมอ
- **การล็อกอิน (`POST /token`)** เปิดเมื่อตั้ง `PII_SERVICE_ENABLE_DOCS=true` **และ** ตั้งทั้ง `PII_SERVICE_DOCS_USERNAME` กับ `PII_SERVICE_DOCS_PASSWORD` (ยาวอย่างน้อย 12 ตัว) token ที่ได้เป็นของชั่วคราว ไม่ใช่ `PII_SERVICE_API_TOKEN` ตัวจริง และใช้ไม่ได้ทันทีถ้าเปลี่ยน `PII_SERVICE_API_TOKEN`; ล็อกอินผิดได้ `400 invalid_grant` (รอ 1 วินาทีต่อครั้ง กันการเดารหัส) และ log ขึ้น `docs login failed` โดยไม่บันทึก username/password
- ไม่มีระบบล็อกบัญชีเมื่อเดารหัสผิดหลายครั้ง ให้ใช้รหัสผ่านยาวและเปิดเฉพาะเครื่องทดสอบ/staging ที่จำกัดเครือข่าย
- หน้า Swagger โหลดไฟล์หน้าเว็บจาก `cdn.jsdelivr.net` เบราว์เซอร์ที่เปิดต้องออกอินเทอร์เน็ตได้ (ตัว service ไม่ต้อง)
- **ใช้ข้อความสังเคราะห์เท่านั้น** เอกสารจริงที่วางในหน้านี้จะผ่านเบราว์เซอร์และอาจถูกบันทึกในประวัติของเครื่อง
- ค่าเริ่มต้นปิด เพื่อไม่ให้ production เปิดหน้า docs โดยไม่ตั้งใจ

### 6.2 Swagger ใน Docker

ไม่ต้องแก้โค้ดหรือ Dockerfile ตั้งค่าผ่าน environment ของ container เหมือนค่าอื่น

```bash
docker run --rm -p 8080:8080 --env-file /srv/pii-redaction/service.env -e PII_SERVICE_ENABLE_DOCS=true pii-redaction-service
```

แล้วเปิด `http://<เครื่องที่รัน container>:8080/docs` ปุ่ม Execute ยิงไปที่ host และพอร์ตเดียวกับหน้าเว็บเอง

| สถานการณ์ | ต้องทำ |
| --- | --- |
| เครื่องทดสอบหรือ staging | ตั้ง `PII_SERVICE_ENABLE_DOCS=true` (Compose: `environment:` หรือ `env_file`; Kubernetes: ConfigMap) |
| production | ไม่ต้องตั้ง (ค่าเริ่มต้นปิด) |
| เรียกผ่าน gateway ที่มี **path นำหน้า** เช่น `https://gateway.example/pii/docs` | ตั้ง `UVICORN_ROOT_PATH=/pii` ให้ container แล้วให้ gateway ตัด `/pii` ออกก่อนส่งต่อ หน้า Swagger จะโหลด `/pii/openapi.json` และ Execute จะยิงไป `/pii/redact` (ถ้าไม่ตั้ง หน้าจะหา schema ไม่เจอ) |
| เรียกตรงที่ container หรือ path ไม่มีตัวนำหน้า | ไม่ต้องตั้งอะไรเพิ่ม |
| gateway มี timeout สั้นกว่าเวลาประมวลผล | Execute จะได้ 504 หรือ error จาก gateway เหมือนระบบหลัก (ข้อ 5) |
| gateway ตรวจ authentication เองหรือแก้ header | ต้องให้ header `Authorization: Bearer ...` จาก Swagger ผ่านไปถึง service |
| เบราว์เซอร์ของผู้ใช้ออกอินเทอร์เน็ตไม่ได้ | หน้า `/docs` ขาวเปล่า เพราะไฟล์หน้าเว็บของ Swagger โหลดจาก `cdn.jsdelivr.net` (container ไม่ต้องออกเน็ต) |

- token ที่ใส่ใน **Authorize** คือ `PII_SERVICE_API_TOKEN` ของ container นั้น ขอจากผู้ดูแลระบบ
- `/docs` และ `/openapi.json` เปิดดูได้โดยไม่ต้องใช้ token (เห็นแค่รูปแบบ API) ถ้า staging เข้าถึงได้จากวงกว้าง ควรจำกัดเครือข่ายที่เข้า `/docs` ได้
- Execute ที่ `POST /redact` **เรียก LLM จริง** ใช้เวลาหลายนาที และใช้เครื่อง LLM ร่วมกับผู้ใช้อื่น ใช้ข้อความสังเคราะห์เท่านั้น
- ข้อผิดพลาดที่ตอบทันทีโดยไม่เรียก LLM: token ผิด (401), body ว่าง (400), ยาวเกิน 2000 ตัวอักษร (413)

---

## 7. Log

ทุก request (ยกเว้น `/healthz`, `/readyz`) เขียน log หนึ่งบรรทัดทาง stderr ชื่อ logger
`pii_pipeline.http_api` เช่น

```text
INFO redact document_id=… status=200 seconds=188.8 llm_calls=2 by_role=detection:1,verification:1 http_attempts=2 attempt_seconds=detection:125,verification:64 ... last_event=FINAL_VERIFIED residual=- selections=- reason=-
```

- `status`, `seconds`: ผลและเวลา; `reason`: สาเหตุเมื่อไม่สำเร็จ (ชื่อ error และรหัสคงที่)
- `llm_calls`, `attempt_seconds`: เรียก LLM กี่ครั้ง แต่ละครั้งใช้กี่วินาที
- `repairs`, `repair_reasons`: หน้านั้นต้องให้ LLM ทำ detection ใหม่กี่ครั้ง และเพราะอะไร เช่น `value_not_found:1` (LLM ตอบค่าที่หาในต้นฉบับไม่เจอ), `detection_unavailable:1` (เรียก LLM ไม่สำเร็จ); `-` = ไม่มี
- **ไม่มีข้อความเอกสาร ค่า PII หรือข้อความ error จากภายนอก**
- ต้อง**ปิดการบันทึก request/response body** ที่ gateway, APM และ reverse proxy ทุกชั้น
  เพราะ body มีข้อความต้นฉบับที่มี PII

ความหมายของทุกช่อง: [docs/OVERVIEW.md](docs/OVERVIEW.md) (หัวข้อ Configuration)

---

## 8. แก้ปัญหาที่พบบ่อย

| อาการ | สาเหตุและวิธีแก้ |
| --- | --- |
| container ปิดทันที log ขึ้น `api_token ... Field required` | ไม่ได้ตั้ง `PII_SERVICE_API_TOKEN` |
| `api_token ... at least 32` หรือ `still the example value` | token สั้นเกินไป หรือยังเป็นค่าตัวอย่าง ให้สุ่มใหม่ |
| `LlmProxySettings ... base_url ... Field required` | ไม่ได้ตั้ง `LLM_PROXY_BASE_URL` / `LLM_PROXY_API_KEY` |
| `No manifest encryptor is configured` | ตั้ง `PII_SERVICE_RETURN_MANIFEST=true` ไว้ ให้เอาออก (ข้อ 3.5) |
| เรียกจากนอก container ไม่ได้ | service ต้องฟังที่ `0.0.0.0` (ค่าใน Dockerfile) ไม่ใช่ `127.0.0.1` |
| `/readyz` ตอบ 503 | กำลังเริ่มหรือกำลังปิด รอสักครู่ |
| `/docs` ได้ `{"error":"not_found"}` | ยังไม่ได้ตั้ง `PII_SERVICE_ENABLE_DOCS=true` |
| Authorize แบบล็อกอินขึ้น error / `invalid_grant` | username หรือ password ไม่ตรงกับ `PII_SERVICE_DOCS_USERNAME` / `PII_SERVICE_DOCS_PASSWORD` |
| ไม่มีส่วน *docsLogin* ในหน้า Authorize | ยังไม่ได้ตั้ง username/password คู่กัน หรือไม่ได้เปิด docs (log ตอนเริ่มบอกสถานะการล็อกอิน) |
| ล็อกอินแล้วใช้ได้สักพักกลายเป็น 401 | token ชั่วคราวหมดอายุ กด Logout แล้วล็อกอินใหม่ |
| หน้า `/docs` ขาวเปล่า | เบราว์เซอร์โหลดไฟล์จาก `cdn.jsdelivr.net` ไม่ได้ (เครือข่ายปิดอินเทอร์เน็ต) |
| ทุก request ได้ 401 | token ใน header ไม่ตรงกับ `PII_SERVICE_API_TOKEN` |
| 502 และ `reason` มี `LlmProxyTransportError` | ต่อ proxy ไม่ได้ (network, URL, certificate) |
| 502 และ `reason` มี `VerificationError` | ตรวจซ้ำแล้วยังเจอ PII หรือ LLM ใช้งานไม่ได้ช่วงนั้น ส่งใหม่ได้ |
| ผู้เรียกได้ timeout ก่อน service ตอบ | ชั้นใดชั้นหนึ่งระหว่างทางมี timeout สั้นกว่า deadline (ข้อ 5) |

---

## 9. สำหรับนักพัฒนา

รันเทสต์ (ไม่เรียก LLM ไม่อ่าน `.env` จริง):

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
```

- `tests/` ใช้ข้อมูลสังเคราะห์ทั้งหมด มี replay ของคำตอบ proxy ที่บันทึกไว้
  (`tests/replay/`) ตรวจว่าทุก request, response และ log ไม่เปลี่ยน
- เปิด service บนเครื่องโดยไม่ใช้ Docker และส่งไฟล์ทดสอบด้วย `tools/redact_client.py`:
  [docs/SETUP_AND_USAGE.md](docs/SETUP_AND_USAGE.md)
- การทำงานภายใน ขอบเขต PII ที่ตกลงไว้ และ module map: [docs/OVERVIEW.md](docs/OVERVIEW.md)

## ข้อควรระวังด้านข้อมูล

- body ของ request มีข้อความต้นฉบับที่มี PII ห้ามบันทึกที่ชั้นใดๆ
- เอกสารจริง ค่าลับ และผลลัพธ์จริงต้องไม่อยู่ใน repo หรือ image
- ข้อยกเว้น TLS (`LLM_PROXY_VERIFY_TLS=false`) ใช้ได้เฉพาะการเชื่อมต่อไปที่ LLM proxy
  และยังต้องระบุผู้รับผิดชอบความเสี่ยงและวันทบทวนสำหรับ production
