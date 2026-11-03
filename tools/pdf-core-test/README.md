# pdf-core-test: เครื่องมือทดสอบ processing core กับเอกสารจริง

เครื่องมือ (test harness) สำหรับรัน processing core ของ repo นี้ (`../..`) กับเอกสารจริงแบบควบคุมได้ เรียก core ตัวเดียวกับ production ผ่าน `process_markdown_with_recovery_async` พร้อมเพดาน call/เวลา และรายงานผลแบบ safe JSON ที่ไม่มี PII

ไม่ใช่ service สำหรับ production: ไม่มี HTTP ingress ไม่สร้าง multipart ไม่ export PII manifest service จริงอยู่ที่ `pii_pipeline/service/app.py` (ประกอบ `pii_pipeline/service/http.py`) ถ้าต้องการทดสอบผ่าน HTTP ให้ใช้ `tools/redact_client.py` ตาม README หลัก

## สถานะปัจจุบัน (2026-10-09)

| หัวข้อ | สถานะ |
| --- | --- |
| ตำแหน่ง | `tools/pdf-core-test/` ใน repo หลัก (ย้ายมาจาก `../pdf-core-test` วันที่ 2026-10-05) |
| Core ที่ใช้ | detection `pii-detection-v18`, verification `pii-verification-v11`, `automatic-recovery-v3` พร้อม forced conflict resolution, initial legal-option selection, reserved recovery calls, near-copy location (ช่องว่าง/แก้ OCR/ต่อข้ามเส้นแบ่งหน้า) และการส่งซ้ำเมื่อได้คำตอบว่าง |
| Rule lane | `detect_thai_rule_pii` ทั้ง rule detection และ rule verification: CASE_NUMBER, TITLE_DEED_NUMBER, LAND_PARCEL_NUMBER, OFFICIAL_LETTER_NUMBER, ID_NUMBER, PHONE, FAX, BANK_ACCOUNT_NUMBER, PASSPORT_NUMBER, EMAIL |
| Tests | harness 79 passed; core 1303 passed (Python 3.12 และ 3.13) |
| Live | วัดบนเครื่อง LLM ทดสอบที่ช้า ต้องวัดซ้ำเมื่อใช้เครื่อง LLM production ได้ |

## สิ่งที่ต้องมี

- **Python ที่ใช้รัน:** `.venv` ของ repo (ตั้งตาม README หลัก) แล้วติดตั้งแพ็กเกจเพิ่มของ harness:

  ```powershell
  .venv\Scripts\python.exe -m pip install -r tools/pdf-core-test/requirements.txt
  ```

  `pypdf` อ่าน PDF, `pdfplumber` เป็น extractor ทางเลือก (`--extractor pdfplumber`), `reportlab` กับ `Pillow` ใช้ใน tests เท่านั้น
  `run.ps1` ใช้ Python ใน `.venv` ให้อัตโนมัติ ถ้าต้องการใช้ Python ตัวอื่นให้ตั้ง `PDF_CORE_TEST_PYTHON` เป็น path ของ python.exe
- **Settings ของ LLM proxy:** อ่านจาก `../../.env` (เปลี่ยนได้ด้วย `--settings-file`) ไม่ต้องใส่ credentials ใน command line หรือ chat

ถ้า PowerShell ไม่ให้รัน `run.ps1` ให้เรียก Python กับ `pdf_to_pipeline.py` โดยตรงจาก root ของ repo ไม่ต้องเปลี่ยน execution policy

```powershell
.venv\Scripts\python.exe tools\pdf-core-test\pdf_to_pipeline.py --help
```

## หลักความปลอดภัย

- **Work directory ต้องอยู่นอก Git และนอกโฟลเดอร์ code** script ปฏิเสธเองถ้าไม่เป็นเช่นนั้น เช่น โฟลเดอร์ `local-core-test-data` ที่อยู่ข้าง repo (ไม่ใช่ข้างใน)
- เอกสารจริงเก็บไว้นอก repo ส่วน `inputs/`, `cases/` และ `*.pdf` ในโฟลเดอร์นี้ถูก ignore ไว้กันพลาด
- คำสั่งที่ส่งข้อมูลไป LLM proxy ต้องใส่ `--allow-proxy-upload` เสมอ
- Terminal/report แสดงเฉพาะ status, counts, types, timing และ reason codes ไม่มีค่า PII, source, raw response, header หรือ exception message ห้ามคัดลอกข้อความเอกสารลง chat

## ขั้นตอนการใช้งาน

### 1. เตรียมเอกสาร (ไม่เรียก LLM)

**Markdown (เส้นทางหลัก):**

```powershell
.\run.ps1 prepare-md --markdown '<นอก repo>\inputs\sample.md' --work-dir '<นอก repo>\md-case-new' --window-chars 5000 --max-windows 100 --boundary line --overlap-blocks 2
```

- ได้ `source.raw.md`, `source.md` (NFC), `pages.json` และ `detection-windows.json` ใน work dir ใหม่ (ห้ามมีอยู่ก่อน)
- ถ้าต้องการจำลอง request ขนาด production ให้ใช้ `--window-chars 2000 --overlap-blocks 0` เพราะ production รับไม่เกิน 2000 ตัวอักษร (ประมาณ 1 หน้า) ต่อ request และแต่ละ request เป็นอิสระ
- ถ้ามีบรรทัดยาวเกิน `--window-chars` จะได้ `planning_error: BLOCK_EXCEEDS_WINDOW` แก้ได้โดยเขียน `windows` ใน `detection-windows.json` เอง (ช่วง `[start,end)` ของ NFC source ที่เรียงต่อกันครบ แต่ละช่วงไม่เกิน cap) แล้วตั้ง `planning_error` เป็น `null` ห้ามแก้ source หรือ source hash ตรวจด้วย `validate_ranges` ของ script ได้

**PDF (ไม่ใช่เส้นทาง production):** `prepare --pdf <file>` ใช้ text layer ผ่าน `pypdf` (หรือ `--extractor pdfplumber`) ไม่ทำ OCR ใหม่ หน้า scan ต้อง OCR เองแล้วส่ง `--page-text-dir` (ไฟล์ `0001.txt`, `0002.txt`, …) PDF ที่เข้ารหัสใช้ `--ask-password`

### 2. ตรวจและยืนยัน windows (คนตรวจ)

```powershell
.\run.ps1 review --work-dir '<work-dir>' --confirm-pages-and-boundaries
```

`--confirm-pages-and-boundaries` คือการยืนยันว่า**คนตรวจรอยต่อของ windows แล้ว** ว่าไม่ตัดชื่อ/ที่อยู่/เลขกลางค่า ไม่ควรให้ agent ยืนยันแทน หน้า PDF ที่ไม่มี text เป็น `OCR_REQUIRED` ใช้ `--blank-pages` เฉพาะหน้าว่างจริง

### 3. รัน core กับ LLM จริง

**ทีละ window (scoped)** ใช้ทดสอบ request ขนาด production หรือวินิจฉัย window ที่มีปัญหา ไม่ publish ผล:

```powershell
.\run.ps1 run-core --work-dir '<work-dir>' --window-number 32 --allow-proxy-upload --use-thinking false --max-calls 8 --max-recovery-calls 4 --max-residual-rounds 1 --max-verification-windows 2 --run-deadline-seconds 1200
```

**ทั้งเอกสาร** (core test เท่านั้น production ไม่รับเอกสารยาว) ค่าที่ใช้ล่าสุด:

```powershell
.\run.ps1 run-core --work-dir '<work-dir>' --allow-proxy-upload --use-thinking false --max-calls 144 --max-verification-windows 40 --run-deadline-seconds 7200 --max-recovery-calls 4 --reserved-recovery-calls 2 --max-residual-rounds 1
```

| Flag | ความหมาย |
| --- | --- |
| `--max-calls` | เพดาน proxy requests จริงทั้งหมด (รวม selection/repair/retry) |
| `--max-verification-windows` | เพดาน verification windows ที่วางบน redacted text |
| `--run-deadline-seconds` | deadline ของทั้ง run (ต่อ request ยังมี read timeout 1800s และ request deadline 3600s จาก settings) |
| `--max-recovery-calls` | role calls เพิ่มสำหรับ repair/selection/retry/residual (default 4) |
| `--reserved-recovery-calls` | ส่วนของ recovery ที่ initial window repairs ใช้ไม่ได้ เก็บไว้ให้ document merge/verification retry/residual (default 0 = ใช้ร่วมแบบเดิม) |
| `--max-residual-rounds` | รอบแก้ residual หลัง final verification (0–2, default 1) |
| `--window-number` | รันเฉพาะ window นั้นเป็น scope อิสระ |
| `--use-thinking` | `false` (default) หรือ `true` สำหรับ detection |

ผลลัพธ์:

- `CORE_VERIFIED` (ทั้งเอกสาร): เขียน `<work-dir>\results\run-<id>\redacted.md` และ `summary.json` (safe) เฉพาะเมื่อ rules AND LLM verification ผ่านทั้งหมด ไม่มี manifest export
- `CORE_WINDOW_VERIFIED` (scoped): ผ่านแต่ไม่เขียนไฟล์
- `STOPPED`: ไม่เขียนผลบางส่วน report มี `error_code`, `stage`, จำนวน requests, recovery counts และ `calls` trace

### 4. คำสั่งวินิจฉัยเพิ่มเติม

- `inspect-detection --window-number N`: strict probe ของ detection หนึ่ง window (ไม่มี recovery/redaction/verification) ไม่ใช่การยอมรับ flow
- `export-swagger --window-number N`: export context/prompt/json_schema ของ window ไปที่ `<work-dir>\swagger-inputs\<export_id>` เพื่อทดสอบเองใน Swagger ไม่เรียก proxy ไม่อ่าน credentials

## อ่าน progress และ report

Terminal แสดง JSON ทีละบรรทัด (flush ทันที):

| กลุ่ม | Events |
| --- | --- |
| Run | `RUN_SETTINGS`, `CORE_STARTED`, `RECOVERY_STARTED` (มี `max_recovery_calls`/`reserved_recovery_calls`) |
| Call | `CALL_STARTED`, `CALL_WAITING` (ทุก 30s), `CALL_FINISHED` |
| Proxy request | `PROXY_REQUEST_STARTED` (role/ขนาด/timeouts), `PROXY_REQUEST_FINISHED` (`elapsed_seconds`, `outcome` = `HTTP_<code>` หรือ `READ_TIMEOUT` ฯลฯ) |
| Detection | `DETECTION_WINDOW_STARTED`, `DETECTION_WINDOW_OUTCOME`, `WINDOW_REPAIR_SKIPPED`, `DETECTION_WINDOW_REJECTED` |
| Conflict | `CONFLICT_GROUPS_PLANNED`, `CONFLICT_MERGE_PLANNED`, `CONFLICT_SELECTION_FORCED`, `CONFLICT_SELECTION_STARTED/FINISHED` |
| Verification | `VERIFICATION_PLANNED`, `VERIFICATION_WINDOW_STARTED`, `VERIFICATION_RETRY`, `RESIDUAL_RECOVERY_STARTED`, `FINAL_VERIFIED` |

ใน `calls` ของ report แต่ละ call มี `role`, `status` (`SUCCESS`, `DETECTION_ISSUES` + `reason_codes`, `RESIDUAL_DETECTED`, `PROXY_TRANSPORT_ERROR` + `transport_kind`), `proxy_request_timings` และสำหรับ verify มี `finding_types` (ชนิด PII ที่ verification flag ไม่มีค่า)

Error codes ที่พบบ่อย: `PROXY_TRANSPORT_ERROR` (เช่น READ_TIMEOUT เมื่อครบ read timeout ซึ่งตอนนี้คือ 1800s), `DETECTION_MERGE_REJECTED` + `reason_code` (เช่น `conflict_recovery_limit`), `RESIDUAL_NOT_RESOLVED` (stage `residual_recovery`: verification ยังพบ PII หลังรอบแก้), `CALL_CAP_EXCEEDED`, `WHOLE_RUN_TIMEOUT` `CALL_WAITING` หมายถึง client ยังรอ ไม่พิสูจน์สถานะฝั่ง proxy

`CORE_VERIFIED` ไม่รับรองความครบถ้วนของ PII ทั้งไฟล์ ยังต้องให้คนตรวจ `redacted.md` เพื่อประเมิน miss/false positive

## Tests

รันจาก root ของ repo ด้วย `.venv` (ไม่ใช้ network/credentials/ไฟล์จริง ใช้ synthetic PDFs และ HTTPX MockTransport):

```powershell
.venv\Scripts\python.exe -m pytest tools/pdf-core-test/tests -q -p no:cacheprovider --basetemp ..\_pdf_core_test_tmp
```

`--basetemp` ใช้ directory นอก repo เพื่อเลี่ยงปัญหา Windows temp permission ลบ directory นั้นได้หลังรันเสร็จ Core suite รันแยกจาก root ของ repo (`python -m pytest -q`) และ root `pytest.ini` จำกัดให้เก็บเฉพาะ `tests/` ของ core เมื่อแก้ core ควรรันทั้งสองชุด

## Scripts วินิจฉัยแบบ private

อยู่ในเครื่องผู้ดูแลที่ `local-core-test-data/scripts/` ข้าง repo (นอก Git ไม่ได้มากับการ clone) stdout มีแต่ types/counts/booleans ค่าจริงเขียนลง `<work-dir>\diagnostics\` เท่านั้น

| Script | ใช้ทำอะไร |
| --- | --- |
| `split_md_pages.py <input.md> --output-dir <new> [--max-chars 10000]` | แบ่งเอกสาร `.md` ทั้งฉบับเป็นไฟล์ละไม่เกิน `--max-chars` ตัวอักษร (ค่าเริ่มต้น 10000 เท่ากับ service, 1 request) ตัดที่ย่อหน้า → บรรทัด → ช่องว่าง ต่อกลับได้ต้นฉบับตรงตัว เขียน `index.json` (offsets/จุดตัด ไม่มีเนื้อหา) ปฏิเสธโฟลเดอร์ที่อยู่ใน Git |
| `diag_window_copy.py <window> [attempts] [repair]` | ตรวจว่า candidate ที่ `value_not_found` ต่างจาก source แบบไหน (whitespace/NFKC/คำนำหน้า/รูปนามแฝง) |
| `diag_window22.py` | รัน pipeline เต็มของ window เดียวแล้วเขียน `redacted_markdown` + `entries` ให้คนตรวจ |
| `diag_window22_verify_recall.py` | วัดว่า verification จับ PII ที่ตั้งใจคืนค่าไว้ได้หรือไม่ |
| `diag_window32.py`, `diag_window32_copy.py` | การวินิจฉัย window 32 รุ่นแรก (ถูกแทนด้วย `diag_window_copy.py`) |

## เอกสารที่เกี่ยวข้อง

การทำงานของ pipeline และขอบเขต PII: [docs/OVERVIEW.md](../../docs/OVERVIEW.md); สัญญา HTTP: [docs/http-contract.md](../../docs/http-contract.md)
