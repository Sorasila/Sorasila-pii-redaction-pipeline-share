# แนวทางนำ PDF จริงมาทดสอบ processing core

สถานะ 2026-10-09: harness อยู่ใน repo ที่ [tools/pdf-core-test](../tools/pdf-core-test/README.md) (ดู [DESIGN.md](../tools/pdf-core-test/DESIGN.md)) ingress limit คือ 2000 Unicode code points ต่อ request (ประมาณหนึ่งหน้า) และได้รันเอกสารจริงกับ LLM ทดสอบแล้ว ทั้งผ่าน core โดยตรงและผ่าน service แบบหน้าละหนึ่ง request ผลและบันทึกอยู่ในเอกสารส่วนตัวนอก repo เอกสารนี้เก็บแนวทาง extraction/OCR และ accuracy evaluation ประกอบ ซึ่งยังใช้ได้ (human accuracy evaluation ยังไม่ได้ทำ)

## ขอบเขต

Pipeline ปัจจุบันรับ raw UTF-8 Markdown; `/redact` ไม่รับ application/pdf จึงเตรียม PDF เป็นข้อความ/Markdown ก่อนทดสอบ ไม่เปลี่ยน request/response contract ของระบบหลัก ผลของ redaction เป็น Markdown ไม่ใช่ PDF ที่ปกปิดข้อมูลแล้ว ต้นฉบับ PDF ยังมี PII ตามเดิม

ช่วงรอ dev แนะนำทดสอบที่ processing core (detection → deterministic redaction → independent verification) ก่อน ไม่อ้างว่าเป็น live HTTP multipart delivery ที่ครบ production เพราะ ingress authentication/real encryptor/deployment ยัง pending และผู้ใช้เลื่อน encryption design ไว้

## ขั้นเตรียมและตรวจสอบ

1. เริ่มจากตัวอย่างเล็ก เช่น 1–3 หน้า ใช้สำเนาทดสอบที่ผู้ใช้เลือก ตรวจแต่ละหน้าว่ามี text layer, scan-only หรือ mixed content ข้อความที่เลือก/copyได้อาจมาจาก OCR layer จึงยังต้องเทียบภาพจริง
2. PDF ที่มี text layer ดึงข้อความด้วย local extractor เช่น pypdf/pdfplumber; หน้า scan/image-only ใช้ OCR ที่รองรับไทย หากทีมมี OCR ที่จะใช้จริง ควรใช้ output จากระบบนั้นเพื่อให้ test inputสะท้อน production ถ้า outputเป็นtext/JSON จึงปรับเป็นMarkdownก่อนcore ไม่เลือกOCRengine/endpointแทนทีมโดยเดา
3. Render/ดูหน้าที่เกี่ยวข้องแล้วเทียบ extracted text/OCR กับ PDF: ชื่อ/นามสกุล, เลขคดี/ปี, เลขที่ดิน/โฉนด, ที่อยู่, ตาราง/ลำดับคอลัมน์/ช่องว่าง ห้ามถือ extracted textเป็นlayout ground truth และไม่ซ่อมค่าที่OCRผิดเงียบ ๆ
4. แยกผลประเมินสองระดับ: (a) OCRดึงPIIมาครบและอ่านถูกหรือไม่ (b) coreปกปิดค่าที่ปรากฏในMarkdownครบหรือไม่ PIIที่ตกก่อนเข้าcoreต้องบันทึกเป็นextraction/OCR miss แยกจากcore miss; end-to-end coverageต้องรวมทั้งสองขั้น
5. กำหนด expected PII/types/exact ranges บนข้อความ Markdown NFCที่จะทดสอบจากการตรวจด้วยคน **ก่อน** เรียกLLM รวม negative fieldsที่ไม่ควรปกปิด เก็บข้อความทดสอบนั้นคงที่ ไม่ใช้ modeloutputสร้างoracle ไม่เปลี่ยนspansให้ผ่าน
6. เริ่มด้วยบล็อกข้อความครบfield/paragraphไม่เกิน2000Unicodecodepointsของsource หากทดสอบHTTPภายหลัง ใช้requestอิสระและcounters/IDsแยกrequest ไม่ตัดทุก2000แบบตายตัวที่อาจผ่าชื่อ/ที่อยู่กลางค่า ไม่เหมาว่าหนึ่งหน้าPDF≤2000 chars หากfieldหรือcontextใหญ่เกินเกณฑ์ให้ทบทวนcaseก่อน ไม่แอบเพิ่มsession/limit
7. หากทดสอบหลายwindowsบนcoreภายหลัง ต้องมีexplicittrustedplans/fullcoverage/frozenper-windoworacles ตรวจlocal→documentoffsets/dedup และวางverificationใหม่บนredactedtextเช่นhybridcheckpointเดิม ไม่เลือกautomatictokenplannerก่อนรู้proxylimits
8. Runtestทีละcaseด้วยprofile/budgetที่กำหนดและหยุดreviewเมื่อguard/oracle/transportผิด เทียบredactedtext/manifestentriesในขอบเขตที่ควบคุมสิทธิ์ รายงานชนิด/count/scope/เวลาและmiss/falsepositive โดยไม่echoค่าPII/anchors/body/tokenลงconsole/chat/log

## สิ่งที่ต้องมีเพื่อเริ่มกับไฟล์จริง

- PDFตัวอย่างและหน้าที่ต้องการทดสอบ ซึ่งผู้ใช้เลือกและเก็บในพื้นที่ทดสอบส่วนตัว ไม่ต้องส่งให้ Codex
- ถ้ามีOCRเดิม ระบุได้เฉพาะชื่อระบบ/output format; ผู้ใช้เก็บและเทียบMarkdown/ข้อความกับPDFเอง ไม่ส่งข้อความหรือcredentials
- ผู้ใช้ตรวจconversion/OCRและwindow boundariesก่อนlive; detailed expectedPII/negativefieldsเป็นขั้นวัดaccuracyเพิ่มเติม ไม่เป็นprerequisiteของconverter/corebridge ไม่ให้Codexเปิดเอกสารจริงหรือpasteค่าจริงในhandoff
- ระบุเมื่อจะให้รันreal-PII LLMtestและใช้approvedproxyใด ไม่ถือsynthetic-only livecheckpointเดิมเป็นผลทดสอบของเอกสารจริง ไม่ส่งไปOCR/LLMendpointใหม่โดยอัตโนมัติ
- RawPDF/OCR text/mappingถือเป็นข้อมูลอ่อนไหว จัดเก็บเฉพาะพื้นที่ทดสอบที่ควบคุมสิทธิ์ตามนโยบาย ไม่commitเข้าGitหรือส่งbodyไปAPM/errorlogs และไม่ใช้testfakeencryptorกับproductionหรือเอกสารจริง

## หลักฐานและข้อจำกัด

[pypdf text extraction documentation](https://pypdf.readthedocs.io/en/stable/user/extract-text.html) อธิบายความต่างของtext-layer/scanned/OCRedPDF และข้อจำกัดของตาราง/whitespace; pypdfไม่ทำOCRหรืออ่านตัวอักษรในimages การดึงtextสำเร็จอย่างเดียวจึงไม่รับรองว่าPIIบนภาพถูกนำเข้ามาครบ

ข้อเสนอข้างต้นเพิ่มขั้นเตรียมtestinput ไม่เพิ่มPDFroute, PDFredaction, OCRproductionservice หรือcrypto design ข้อตกลงraw2000/synchronous/สามmultipartpartsใน`Handoff.revised.md` (เอกสารส่วนตัว ไม่อยู่ใน repo)ยังเดิม ส่วนข้อมูลที่จะถามdevอยู่ใน[DEV_REQUIREMENTS_CHECKLIST.md](DEV_REQUIREMENTS_CHECKLIST.md)
