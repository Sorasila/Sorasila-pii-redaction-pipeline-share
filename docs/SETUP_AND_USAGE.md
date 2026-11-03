# คู่มือติดตั้งและใช้งาน PII Redaction Pipeline

คู่มือนี้สำหรับคนที่เพิ่ง clone repo มาเพื่อลองรัน service บนเครื่องตัวเอง ส่งเอกสาร Markdown เข้าไป
แล้วได้ข้อความที่ปกปิด PII แล้ว พร้อมรายการค่าที่ถูกปกปิด รายละเอียดเชิงเทคนิคอยู่ใน [README](../README.md)

> **สถานะ:** เป็น prototype สำหรับทดสอบ ไม่ใช่ระบบ production manifest ที่ได้ยังไม่ได้เข้ารหัส
> และ LLM ที่ใช้เป็นเครื่องทดสอบที่ใช้ร่วมกับงานอื่น จึงช้าและผลแต่ละรอบอาจต่างกันเล็กน้อย

---

## วิธีรันแบบย่อ

**ครั้งแรก:** ทำข้อ 3 (ติดตั้ง) และข้อ 4 (ตั้งค่า `.env`) ก่อนหนึ่งครั้ง

**ทุกครั้งที่ใช้งาน:** เปิด PowerShell 2 หน้าต่างที่โฟลเดอร์ repo

| หน้าต่าง | ทำอะไร | คำสั่ง |
| --- | --- | --- |
| 1 | เปิด service แล้วเปิดค้างไว้ | `.venv\Scripts\python.exe -m uvicorn pii_pipeline.service:create_service_app --factory --host 127.0.0.1 --port 8080` |
| 2 | ส่งเอกสาร รอผล | `.venv\Scripts\python.exe tools\redact_client.py <ไฟล์ .md> --output-dir <โฟลเดอร์ผลนอก repo>` |

ตัวอย่างหน้าต่างที่ 2 กับหน้าทดสอบที่ให้มา:

```powershell
.venv\Scripts\python.exe tools\redact_client.py samples\synthetic\page-*.md --output-dir ..\redact-out
```

เสร็จแล้วดูผลใน `..\redact-out` (ข้อ 6.2) และปิด service ด้วย `Ctrl+C` ในหน้าต่างที่ 1
รายละเอียดแต่ละขั้นอยู่ในข้อ 5 และ 6 ถ้าติดปัญหาดูข้อ 8

---

## 1. ภาพรวม

```text
ไฟล์ .md (ทั้งหน้า ค่าเริ่มต้นไม่เกิน 10000 ตัวอักษร)
   │  tools/redact_client.py ส่งทีละหน้า
   ▼
service บนเครื่องคุณ (POST /redact)  ──►  LLM proxy (ต้องเข้าถึงได้)
   │  rule + LLM ตรวจหา PII → ปกปิด → ตรวจซ้ำ
   ▼
โฟลเดอร์ผล: <ชื่อไฟล์>.redacted.md, .manifest.json, .metadata.json
```

- **rule** จับค่าที่มีคำกำกับชัด เช่น เลขคดี โฉนด เลขประจำตัวประชาชน โทรศัพท์ อีเมล ได้ผลเหมือนเดิมทุกครั้ง
- **LLM** จับชื่อ ที่อยู่ และนิติบุคคล
- **ตรวจซ้ำ (verification)** ทุกหน้าก่อนส่งผล ถ้ายังเหลือ PII จะไม่ส่งผลแบบครึ่งๆ กลางๆ แต่ตอบ error แทน

---

## 2. สิ่งที่ต้องมี

| รายการ | รายละเอียด |
| --- | --- |
| Windows + PowerShell | คำสั่งในคู่มือเป็นของ PowerShell (macOS/Linux ดูข้อ 9) |
| Python 3.12 ขึ้นไป | เช็คด้วย `py --version` หรือ `python --version` |
| Git | และสิทธิ์เข้า repo `Sorasila/PII-redaction-pipeline` (repo เป็น private ต้องให้เจ้าของเชิญก่อน) |
| เข้าถึง LLM proxy ได้ | อยู่ใน network เดียวกัน หรือต่อ VPN ที่เข้าถึง proxy ได้ |
| `LLM_PROXY_BASE_URL` และ `LLM_PROXY_API_KEY` | ขอจากเจ้าของ repo หรือ dev **ผ่านช่องทางที่ปลอดภัยเท่านั้น** ห้ามส่งทาง git หรือแชตทั่วไป |

---

## 3. ติดตั้ง (ทำครั้งเดียว)

**3.1 clone repo** แล้วเข้าโฟลเดอร์

```powershell
git clone https://github.com/Sorasila/PII-redaction-pipeline.git
```

```powershell
cd PII-redaction-pipeline
```

**3.2 สร้าง virtual environment และติดตั้งแพ็กเกจ**

```powershell
py -m venv .venv
```

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

ถ้าไม่มีคำสั่ง `py` ให้ใช้ `python -m venv .venv` แทน

**3.3 ตรวจว่าติดตั้งถูกต้อง** ขั้นนี้ไม่ต้องใช้ key และไม่เรียก LLM

```powershell
.venv\Scripts\python.exe -m pytest -q
```

ต้องขึ้นว่า `passed` ทั้งหมด ไม่มี `failed`

---

## 4. ตั้งค่า `.env` (ทำครั้งเดียว)

**4.1 สร้างค่าตั้งเริ่มต้น**

```powershell
.venv\Scripts\python.exe tools\setup_service_env.py
```

script จะ

- สร้าง `.env` จาก `.env.example` ถ้ายังไม่มี
- สร้าง `PII_SERVICE_API_TOKEN` แบบสุ่ม (รหัสที่ client ใช้เรียก service)
- เปิด `PII_SERVICE_ALLOW_UNENCRYPTED_TEST_MANIFEST=true` (โหมดทดสอบ manifest ไม่เข้ารหัส)
- เปิด `PII_SERVICE_RETURN_MANIFEST=true` ให้ผลลัพธ์มีไฟล์ manifest ไว้เทียบกับค่าที่ควรถูกปกปิด (ค่าเริ่มต้นของ service คือตอบแค่ข้อความที่ปิดแล้ว: ได้แค่ redacted.md)
- แสดงเฉพาะชื่อค่า ไม่แสดงค่าจริง และบอกว่าค่าไหนยังต้องใส่เอง (`TODO: …`)

**4.2 ใส่ค่าของ LLM proxy** เปิด `.env` ด้วย editor แล้วแก้ 2 บรรทัดนี้เป็นค่าจริงที่ได้รับมา

```text
LLM_PROXY_BASE_URL=https://<ที่อยู่ proxy>
LLM_PROXY_API_KEY=<key ที่ได้รับ>
```

ถ้า proxy ยังใช้ certificate ที่ตรวจไม่ผ่าน (ข้อยกเว้นที่อนุมัติไว้เฉพาะ proxy นี้) ให้เพิ่ม

```text
LLM_PROXY_VERIFY_TLS=false
```

**4.3 ค่าที่ปรับได้ (ไม่บังคับ)**

| ค่า | ค่าเริ่มต้น | ใช้เมื่อ |
| --- | --- | --- |
| `PII_SERVICE_REQUEST_DEADLINE_SECONDS` | `7200` | เวลาสูงสุดต่อหน้า (2 ชั่วโมง) ตั้งไว้ยาวเพื่อรอ LLM ทำทั้งหน้าจนเสร็จ ลดลงได้ถ้าไม่อยากรอนาน |
| `PII_SERVICE_MAX_SOURCE_CHARACTERS` | `10000` | ความยาวสูงสุดของหน้าที่รับ ทั้งหน้าส่งให้ LLM ในครั้งเดียว หน้ายิ่งยาวยิ่งใช้เวลานาน |
| `LLM_PROXY_READ_TIMEOUT_SECONDS` | `1800` | เวลารอคำตอบจาก LLM ต่อครั้ง (30 นาที) |
| `LLM_PROXY_MAX_RETRIES` | `2` | จำนวนครั้งที่ลองส่งซ้ำเมื่อ proxy ตอบ 502/503/504 |

`.env` ถูก git ignore ไว้แล้ว **ห้ามส่งไฟล์นี้หรือค่าในไฟล์ให้ใคร**

---

## 5. รัน: เปิด service (หน้าต่างที่ 1)

เปิด PowerShell **หน้าต่างที่ 1** ที่โฟลเดอร์ repo แล้วรัน

```powershell
.venv\Scripts\python.exe -m uvicorn pii_pipeline.service:create_service_app --factory --host 127.0.0.1 --port 8080
```

พร้อมใช้เมื่อเห็นบรรทัดนี้ (คำเตือนเรื่อง manifest ไม่เข้ารหัสเป็นเรื่องปกติในโหมดทดสอบ)

```text
INFO:     Uvicorn running on http://127.0.0.1:8080 (Press CTRL+C to quit)
```

**เปิดหน้าต่างนี้ค้างไว้ตลอดที่ใช้งาน** ปิด service ด้วย `Ctrl+C`
ถ้าแก้ `.env` ต้องปิดแล้วเปิด service ใหม่ เพราะ service อ่าน `.env` ตอนเริ่มเท่านั้น

เช็คว่า service พร้อมจากอีกหน้าต่างได้ (ได้ `{"status":"ready"}` = พร้อม, ได้ `not_ready` = กำลังเริ่มหรือกำลังปิด, เชื่อมต่อไม่ได้ = ยังไม่เปิด)

```powershell
curl.exe -s http://127.0.0.1:8080/readyz
```

---

## 6. รัน: ส่งเอกสารและดูผล (หน้าต่างที่ 2)

### 6.1 ลองกับหน้าทดสอบที่ให้มา

เปิด PowerShell **หน้าต่างที่ 2** ที่โฟลเดอร์ repo

```powershell
.venv\Scripts\python.exe tools\redact_client.py samples\synthetic\page-*.md --output-dir ..\redact-out
```

- `samples\synthetic\` มีหน้าทดสอบ 3 หน้า ข้อมูลทั้งหมดแต่งขึ้น ไม่ใช่บุคคลหรือคดีจริง
- `--output-dir` คือโฟลเดอร์เก็บผล **ต้องอยู่นอก repo** (client ไม่ยอมเขียนลงโฟลเดอร์ที่เป็น git repo)
- แต่ละหน้าใช้เวลา 1 ถึงหลายนาที หน้าที่ยาวใช้เวลานานขึ้น แล้วแต่ความเร็วของเครื่อง LLM ช่วงนั้น

ระหว่างรัน หน้าต่างที่ 2 แสดงผลทีละหน้า เช่น

```text
{"file": "page-1.md", "status": "VERIFIED", "hash_ok": true, "manifest": "plaintext_test", "entries_by_type": {...}, "seconds": 182.4}
Done: 3/3 verified. Results in C:\...\redact-out
```

### 6.2 ไฟล์ผลลัพธ์

| ไฟล์ | เนื้อหา |
| --- | --- |
| `<ชื่อ>.redacted.md` | ข้อความที่ปกปิดแล้ว ค่า PII ถูกแทนด้วย placeholder เช่น `[PII_NAME_1]`, `[PII_ADDRESS_2]` |
| `<ชื่อ>.manifest.json` | รายการ placeholder → ค่าจริง **มี PII จริง** (ในโหมดทดสอบไม่ได้เข้ารหัส) มีเฉพาะเมื่อ `PII_SERVICE_RETURN_MANIFEST=true` |
| `<ชื่อ>.metadata.json` | `document_id`, เวอร์ชัน, hash ของ redacted.md, เวลา ไม่มี PII มีเฉพาะเมื่อเปิด `PII_SERVICE_RETURN_METADATA` หรือ `PII_SERVICE_RETURN_MANIFEST` (ค่าเริ่มต้นได้แค่ redacted.md; `document_id` อยู่ใน `summary.json`) |
| `<ชื่อ>.error.json` | มีเฉพาะหน้าที่ไม่สำเร็จ บอก HTTP status, รหัส error และ `document_id` |
| `summary.json` | สรุปทุกหน้า: สถานะ เวลา จำนวนค่าแต่ละชนิด |

`hash_ok: true` แปลว่า redacted.md ที่ได้ตรงกับ hash ใน metadata ทุกไบต์

เทียบผลของหน้าทดสอบกับรายการที่ควรถูกปกปิดได้ที่ [samples/synthetic/README.md](../samples/synthetic/README.md)

### 6.3 ใช้กับเอกสารของตัวเอง

- ไฟล์ต้องเป็น Markdown หรือข้อความ UTF-8 **หน้าละไม่เกิน `PII_SERVICE_MAX_SOURCE_CHARACTERS` (ค่าเริ่มต้น 10000) ตัวอักษร**
  (นับแบบ Unicode code point) ส่งทั้งหน้าได้เลยไม่ต้องแบ่ง ไฟล์ที่ยาวกว่านี้ client จะข้ามพร้อมเหตุผล `too_long_<จำนวน>_code_points` โดยไม่ส่ง
- เอกสารที่ยาวเกินค่านี้ต้องแบ่งเป็นหลายไฟล์ก่อน ควรตัดที่ย่อหน้าหรือบรรทัด ไม่ตัดกลางชื่อหรือที่อยู่
  ใช้ `tools\split_md_pages.py` แบ่งให้ได้ (ตัดที่บรรทัดว่างก่อน แล้วท้ายบรรทัด แล้วช่องว่าง ตัดกลางคำเป็นทางสุดท้าย; ต่อไฟล์กลับได้เท่าต้นฉบับทุกตัวอักษร):
  ```powershell
  .venv\Scripts\python.exe tools\split_md_pages.py <เอกสาร.md> --output-dir ..\my-doc
  ```
  โฟลเดอร์ผลต้องเป็นโฟลเดอร์ใหม่นอก repo; หน้าจอแสดงแค่จำนวน ถ้าเตือนว่าตัดกลางคำ ให้ดูรอยต่อนั้นก่อนส่ง
  แต่ละไฟล์เป็น request อิสระ placeholder จึงนับใหม่ทุกไฟล์ (`[PII_NAME_1]` ของคนละไฟล์ไม่ใช่ค่าเดียวกัน)
- ส่งหลายไฟล์ได้ด้วย wildcard เช่น `..\my-doc\page-*.md`
- **เอกสารจริงและโฟลเดอร์ผลต้องอยู่นอก repo เสมอ** และห้ามส่งต่อ

---

## 7. อ่าน log ของ service

หน้าต่างที่ 1 แสดง 1 บรรทัดต่อ 1 หน้า ไม่มีข้อความเอกสารหรือค่า PII เช่น

```text
INFO redact document_id=… status=200 seconds=182.4 ... last_event=FINAL_VERIFIED residual=- reason=-
WARNING redact document_id=… status=502 seconds=801.7 ... residual=findings:ADDRESS;rules:no;candidates:0;... reason=VerificationError("Residual recovery made no progress")
```

- `status=200` สำเร็จ, `502` ประมวลผลไม่สำเร็จ, `504` หมดเวลา, `499` ผู้เรียกตัดการเชื่อมต่อก่อนได้ผล (เช่นกด Ctrl+C ที่ client) service จึงหยุดงานหน้านั้นทันที
- `reason=` บอกสาเหตุเมื่อไม่สำเร็จ ใช้ `document_id` จับคู่กับ `<ชื่อ>.error.json`
- `attempt_seconds=` เวลาของแต่ละครั้งที่ยิงไปที่ proxy ตามลำดับ เช่น `detection:142` = ได้คำตอบใน 142 วินาที, `detection:timeout@300` = รอครบ read timeout แล้วไม่ได้คำตอบ, `cut@` = ถูกตัดเพราะครบเวลาของ call; ใช้ดูว่าควรตั้ง `LLM_PROXY_READ_TIMEOUT_SECONDS` เท่าไร
- `residual=` เป็น `-` ถ้าไม่ต้องตามเก็บค่าที่หลุด ถ้ามีจะบอกชนิดที่ตัวตรวจเจอและรูปร่างค่าที่ LLM ตอบกลับ (ไม่มีค่าจริง)
- ความหมายของตัวเลขอื่นในบรรทัด ดู README หัวข้อ "Running the service"

---

## 8. ปัญหาที่พบบ่อย

| อาการ | สาเหตุ / วิธีแก้ |
| --- | --- |
| service เริ่มไม่ได้ ขึ้น `[Errno 10048] error while attempting to bind on address ('127.0.0.1', 8080)` | มี service ตัวเก่าเปิดค้างอยู่ ใช้ตัวเดิมต่อได้ หรือกด Ctrl+C ในหน้าต่างเดิม (หา PID ด้วย `Get-NetTCPConnection -LocalPort 8080`) แล้วเปิดใหม่ |
| `client:ConnectError` ทุกหน้าภายใน 2 วินาที | service ไม่ได้เปิด หรือหน้าต่างที่ 1 ถูกปิด เปิดตามข้อ 5 |
| `http_status: 401` | token ไม่ตรงกัน ถ้าแก้ `.env` หลังเปิด service ให้ปิดแล้วเปิดใหม่ |
| service เริ่มไม่ได้ ขึ้น `ValidationError` เรื่อง token | ยังไม่ได้รันข้อ 4.1 หรือ token ยังเป็นค่าตัวอย่าง |
| service เริ่มไม่ได้ ขึ้น `No manifest encryptor is configured` | ยังไม่ได้เปิดโหมดทดสอบ รันข้อ 4.1 |
| `502` และ log มี `LlmProxyTransportError` | เข้าถึง proxy ไม่ได้: เช็ค VPN/network และ `LLM_PROXY_BASE_URL` |
| `502` และ log มี `VerificationError` | ตรวจซ้ำแล้วยังเจอ PII หรือ LLM ใช้งานไม่ได้ช่วงนั้น ลองส่งหน้านั้นใหม่ |
| `504` หรือ `request_timeout` | เครื่อง LLM ช้าจนหมดเวลา (ค่าเริ่มต้น 2 ชั่วโมง) ลองใหม่ หรือเพิ่ม `PII_SERVICE_REQUEST_DEADLINE_SECONDS` (ข้อ 4.3) |
| `413` หรือ `too_long_<จำนวน>_code_points` | หน้ายาวเกิน `PII_SERVICE_MAX_SOURCE_CHARACTERS` เพิ่มค่านี้ใน `.env` (แล้วเปิด service ใหม่) หรือแบ่งไฟล์ด้วย `tools\split_md_pages.py` |
| `STOPPED: the output folder is inside a Git repository` | เลือก `--output-dir` ที่อยู่นอก repo เช่น `..\redact-out` |
| `STOPPED: results for <ชื่อ> already exist` | ใช้โฟลเดอร์ผลใหม่ หรือลบผลเก่าของหน้านั้น |
| port 8080 ถูกใช้อยู่ | เปิด service ด้วย `--port 8081` แล้วเพิ่ม `--url http://127.0.0.1:8081/redact` ตอนส่ง |
| ช้ามาก | ปกติของเครื่อง LLM ทดสอบ ถ้าหลายคนใช้พร้อมกันจะช้าลงอีก ควรแจ้ง dev ก่อนรันจำนวนมาก |

ระหว่างรันชุดยาว ให้เสียบปลั๊กและตั้งเครื่องไม่ให้ sleep เพราะ connection ที่รอ LLM อยู่จะหลุด

---

## 9. macOS / Linux

ใช้คำสั่งเดียวกันโดยเปลี่ยน path ของ Python และตัวคั่น path

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python tools/setup_service_env.py
.venv/bin/python -m uvicorn pii_pipeline.service:create_service_app --factory --host 127.0.0.1 --port 8080
.venv/bin/python tools/redact_client.py samples/synthetic/page-*.md --output-dir ../redact-out
```

---

## 10. ข้อควรระวังด้านข้อมูล

- `.manifest.json` มีค่า PII จริงโดยไม่เข้ารหัส เก็บโฟลเดอร์ผลไว้ในเครื่องตัวเองเท่านั้น ลบเมื่อไม่ใช้
- ห้าม commit เอกสารจริง ผลลัพธ์ หรือ `.env` เข้า git
- ห้ามคัดลอกข้อความเอกสารหรือค่า PII ลงแชต issue หรือ log ที่แชร์กัน
- โหมดทดสอบ (manifest ไม่เข้ารหัส) ใช้กับเครื่องทดสอบเท่านั้น ห้ามใช้กับระบบจริง
