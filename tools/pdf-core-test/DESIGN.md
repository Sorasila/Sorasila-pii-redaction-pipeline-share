# Design: PDF หลายหน้า → Markdown → processing core

Automatic recovery v3 is implemented (2026-10-04). Conflict selection now uses service-generated legal nonoverlapping option sets; the model returns one enumerated option ID per required group key. Every option preserves configured mandatory rules and finalized replacements. Original source spans, contextual NOT_PII, shared budgets and fresh final rules AND LLM verification remain. Generation has fixed group/span/option/work bounds; invalid or unavailable choices stop safely. **1359 combined tests passed / 19.77s**; Ruff check/format core56/standalone4 files and tracked diff check passed. Historical full v2 stopped at prepared20: conflict_selection_rejected / 2680.564s / 33 requests / verification0, because independent ID/type votes selected overlapping spans. Current scoped/full live status and resume point are recorded only in the learning handoff (`LEARNING_HANDOFF.md`, เอกสารส่วนตัว ไม่อยู่ใน repo). See [conflict design](CONFLICT_RECONCILIATION_DESIGN.md).

Current contract, 2026-10-03: detection v9 removes anchors and preserves non-PII occurrences through service-generated IDs plus contextual selection for repeated values. See [current design](NO_ANCHOR_DETECTION_DESIGN.md) and revised handoff §4.7. Earlier v8 anchor results and unique-value bypass proposals below are historical, superseded evidence. Live results and the current next step are recorded in the learning handoff (`LEARNING_HANDOFF.md`, เอกสารส่วนตัว ไม่อยู่ใน repo).


Implementation checkpoint 2026-10-03: standalone bridgeเรียกactualcorev9ตามrequirementเลิกanchor/เก็บnon-PII occurrences Reviewed document118327characters/28windows ผ่านpreflight Source-copy/occurrence-ID/physicalrequest/timeouts diagnosticsคงstrictguards Core1163/standalone72gatesเป็นofflineevidence ประวัติlive/สถานะล่าสุด/ขั้นกลับมาต่อให้ดู `LEARNING_HANDOFF.md` (เอกสารส่วนตัว ไม่อยู่ใน repo) และคำสั่งใน [NO_ANCHOR_DETECTION_DESIGN.md](NO_ANCHOR_DETECTION_DESIGN.md) ไม่รวมisolatedprobepassesเป็นwhole-documentaccuracy ไม่มีresume/cache

ผลanchorerrors/requestauditก่อนหน้านี้เป็นประวัติใน `PIPELINE_CONTRACT_REVIEW.md` (ลบแล้ว 2026-10-05) ข้อเสนอunique-valuebypassถูกsupersede ไม่ใช่currentworkpendingapproval

## เป้าหมาย

Current implementation is above; live status is maintained in the learning handoff. Historical1317 merge-diagnostics and v2/1338 checkpoints precede the current v3/1359 gate. Exact failed spans from the earlier confidential invocation were not persisted. No manifest export, source/window-plan, ingress/multipart or encryption change.

รับ PDF **หนึ่งไฟล์ทุกหน้า** แปลงเป็น UTF-8 Markdown แล้วส่งเข้า processing core ที่มีอยู่เพื่อทดสอบ detection → redaction → independent verification ให้ได้ redacted Markdown ของเอกสารทั้งไฟล์และรายงานผล

งานหลักคือ conversion และ adapter สำหรับเรียก pipeline ไม่บังคับให้ทำ expected PII ทุกตำแหน่งก่อนเริ่มใช้งาน script การตรวจด้วยคน/expected PII เป็นขั้นประเมินความแม่นยำเพิ่มเติม การรันครบและ verification ผ่านไม่ใช่หลักฐานว่าไม่มี PII ตกหล่นทุกกรณี

## โครงสร้าง script ที่เสนอ

ไฟล์ `pdf_to_pipeline.py` มีคำสั่ง prepare/review/run-core เพื่อให้ตรวจข้อความก่อนส่งเข้า LLM:

| คำสั่ง | หน้าที่ | Network |
| --- | --- | --- |
| `prepare` | อ่านทุกหน้า, extract text, สร้าง Markdown ทั้งไฟล์, page index และร่าง detection windows | ไม่เรียก LLM; local extraction เท่านั้น |
| `prepare-md` | รับ UTF-8 Markdown ทั้งไฟล์โดยตรงเป็นหนึ่ง document review unit ไม่อ้าง PDF page count | ไม่เรียก LLM |
| `review` | ผู้ใช้ยืนยันว่าตรวจทุกหน้าและ window boundaries แล้ว; blank pages ต้องระบุเอง | ไม่เรียก LLM |
| `run-core` | อ่าน Markdown/แผนที่ผู้ใช้ตรวจแล้ว เรียก actual core และเขียนผลหลัง verification ผ่านครบ | ใช้ LLM proxy จาก trusted settings เดิม |

คำสั่งพร้อมใช้ตาม README ไม่เพิ่ม PDF ingress route หรือ production OCR service เก็บ script/design/tests แยกจากโปรเจคหลักตามคำขอผู้ใช้

Flow: `input.pdf` → `prepare` → `source.md` + `pages.json` + `detection-windows.json` → ผู้ใช้ตรวจในเครื่อง → `run-core` → `redacted.md` + `summary.json`

## 1. อ่าน PDF ทุกหน้าและสร้าง Markdown

- ใช้ local text extractor ที่มีใน runtime สำหรับ PDF ที่มี text layer เก็บข้อความตามลำดับหน้าและรักษาเลข/ช่องว่าง/line breaks ไม่ใช้ LLM เพื่อแปลง PDF หรือเขียนข้อความใหม่
- ข้อความธรรมดาที่ extract ได้เป็น Markdown input ได้ ไม่จำเป็นต้องสร้างหัวข้อ/ตารางจากการเดา layout ไม่มีการซ่อม OCR values หรือรวมคอลัมน์เงียบ ๆ
- เก็บ mapping page → source ranges ใน `pages.json` แยกจากข้อความที่ส่งเข้า detector ไม่แทรกชื่อไฟล์/document title หรือ page labels ที่ script สร้างลงใน semantic input
- นิยามการต่อหน้า/newline ให้คงที่และเก็บไว้ใน conversion version; เก็บ raw extracted source และ NFC view ในพื้นที่ส่วนตัว เพื่อให้ offsets และขอบเขตหน้าตรวจย้อนกลับได้
- ตรวจทุกหน้า หากหน้าใดไม่มี text ให้รายงาน `OCR_REQUIRED` และหยุดก่อน `run-core` ไม่ข้ามหน้านั้นแล้วอ้างว่าทดสอบทั้งไฟล์ หากเป็นหน้าว่างจริง ผู้ใช้ต้องระบุไว้ใน page review
- PDF แบบ mixed อาจมีทั้ง text และ PII ในรูปภาพ การมีข้อความไม่พิสูจน์ว่าครบ ต้องให้ผู้ใช้ตรวจเทียบทุกหน้าก่อน live run
- หากต้องใช้ OCR ให้รับ output ของ OCR ที่ทีมใช้เป็น conversion input แทน ยังไม่เลือก/เรียก OCR endpoint ใหม่ PDF password errors/extraction errors ต้องหยุดและรายงาน safe code ไม่ใส่ password หรือ source ใน log

## 2. PDF หลายหน้าและขีดจำกัด 1000 ตัวอักษร

**ขีดจำกัด 1000 source code points อยู่ที่ HTTP ingress; `process_markdown_async` ไม่ได้มี universal document-length limit** ดังนั้น test script รอบนี้ส่ง Markdown ทั้งเอกสารเข้า core หนึ่งครั้ง แล้วให้ semantic/verification lanes ทำงานหลาย windows ไม่ตัดเป็นหลายเอกสารหรือหลาย HTTP requests โดยอัตโนมัติ

ข้อดีของการใช้ document เดียว: รวม document offsets/dedup จาก overlapping windows ก่อน redaction ได้ และ placeholder counters เรียงทั้งเอกสาร ไม่เกิด `[PII_NAME_1]` หลายชุดจากคนละ request

Detection window plan ต้องเป็น explicit trusted ranges บน NFC source และครอบทุกอักขระ รวมส่วนต่อหน้า ไม่ใช้หนึ่งหน้าเท่ากับหนึ่ง window และไม่ตัดทุก 1000 ตัวอักษรแบบตายตัว

`prepare` เสนอขอบเขต paragraph พร้อม overlap หรือ opt-in line boundaries ให้ผู้ใช้ตรวจ ไม่รับรอง semantic recall/automatic production splitter ต้องตรวจชื่อ/ที่อยู่/field ที่ต่อข้ามหน้าและข้าม window หากมี block ใหญ่เกิน budget ให้หยุดเพื่อปรับแผน ไม่ฝืนตัดกลางค่า

Window length/overlap/max windows เป็น test parameters ที่ระบุล่วงหน้า ไม่ถือว่า 1000 characters เท่ากับ token capacity และไม่เปลี่ยน production defaults หากกำหนด context/output budget ที่เหมาะสมไม่ได้ ให้เตรียม conversion ได้แต่ยังไม่ run live

Verification ต้องวาง windows **ใหม่บน actual redacted Markdown** โดย trusted test planner ที่กำหนดไว้ ตรวจ full coverage ก่อนเรียก verification role ห้าม reuse original offsets เพราะ placeholders เปลี่ยนความยาว

หากจะทดสอบผ่าน HTTP API ในอนาคต ต้องออกแบบการแบ่ง ≤1000 ต่อ request และรวมผล/manifest ที่ counters แยก request ต่างหาก รอบนี้เลือก core โดยตรงเพื่อทดสอบ PDF ทั้งไฟล์ และไม่ติดงาน auth/real encryptor/server deployment ที่ยัง pending

## 3. เรียก pipeline เดิม

`run-core` ใช้ composition เดิม ไม่สร้าง redaction logic อีกชุด:

1. โหลด trusted `LlmProxySettings` หลังตรวจ conversion/window plan แล้ว เปิด `LlmProxyClient` ด้วย async lifecycle
2. สร้าง `LlmDocumentProcessor` ด้วย frozen detection plan และ verification planner ที่ตรวจ source/full coverage
3. สร้าง `AsyncPipelineComponents`: opt-in `detect_thai_labeled_numbers`, semantic detector ของ processor, independent numeric rule checker บน redacted text และ fresh LLM verifier
4. เรียก `process_markdown_async(markdown, components)` **หนึ่งครั้งสำหรับ document นี้** Core รวม matches และ deterministic redaction จากทั้งเอกสารก่อน verification
5. เมื่อทุก gate ผ่านจึงเขียน `redacted.md` และ summary หาก detection/schema/occurrence-selection/conflict/verification/transport ผิด ให้หยุดโดยไม่เขียน partial redacted output หรือ manifest

ใช้ sequential windows, retry 0, explicit max windows/max total calls และ whole-run deadline ที่ implement ใน script แล้ว ไม่ใช่ per-role deadline เดิม ตรวจ verification cap ก่อนเริ่ม role เพื่อกัน output expansion ทำให้จำนวน calls เพิ่มไม่จำกัด ไม่มี auto-resume/retry ที่ซ่อน call count

Observability อยู่ในstandalone wrapper: JSONprogressต่อcallพร้อมordinal/role/inputlength/status/elapsed และheartbeatทุก30วินาทีระหว่างรอ ใช้captured terminal streamเพื่อคงการปิดlibrarystdout/stderr/logs รายงานresponse reason codes/รายละเอียดผ่านallowlistจากcoreเท่านั้น ไม่dumpข้อความexception/causes/response/source/anchor จัดcategoryของwindow planning/aggregation, detection merge/redaction และindependent verificationตามboundaryที่สังเกตได้ ไม่เดาสาเหตุจากgenericerror Failureคืนsafe traceในterminalเท่านั้น ไม่publishpartialผลหรือfailurefile Heartbeatไม่พิสูจน์remote progress และrerunเริ่มใหม่ทั้งdocument

ผลrealrunที่ผู้ใช้แชร์ล่าสุด:4detectionwindowsผ่านlocalparser; window5(4923characters) rejectinvalid_response_shapeหลัง103.63s รวม253.433s ยังไม่เริ่มverification ไม่ใช่HTTP504หรือanchorerror เพิ่มstandaloneclient subclassเพื่อเก็บเพียงallowlistedtop-levelshape(counts/flags)ก่อนparser โดยไม่เก็บrawresponse และมีinspect-detectionสำหรับselectedreviewedwindowหนึ่งcall/retry0/requestdeadlineเดิม ไม่มีredaction/verification/publication/cache/resume ไม่เปลี่ยนผลfailedrunหรือผ่อนparsercontract ขั้นถัดไปผู้ใช้probewindow5เองเพื่อแยกmissingcandidates/extrakeys ผลใหม่อาจต่างจากเดิม

ผลbaselineprobeที่ผู้ใช้แชร์ถัดมา:window5(4923chars)62.707s มีcandidateskeyเดียว/15candidates แต่candidate7ORGANIZATIONanchor_not_found Value9charsพบตรงunique; anchor26charsมีvalueแต่ไม่พบในsourceและwhitespacecomparisonfalse Promptv8ระบุuniquevalueให้usevalueasanchorแล้วแต่responseไม่ทำตาม ยังไม่ยืนยันclassificationหรืออักขระที่คลาดเคลื่อน และshapeผ่านรอบนี้ไม่แก้หลักฐานshapefailedรอบก่อน เพิ่มopt-inanchor-focus-v1ย้ำกฎเดิมต้นpromptv8เฉพาะinspect-detection บันทึกprofile/baseversion ไม่มีparserfallback/repair/no silent candidate dropping ไม่มีผลต่อrun-core/productionprompt ผลprofileระบุด้านล่าง

ผลprofileanchor-focus-v1ต่อมา:227.7s/invalid_response_shape;key_count1/unexpected1/candidatesfalse/requiredfalse ไม่มีknownhas_pii/findings จึงไม่promoteprofileและไม่ถือว่าปัญหาanchorแก้แล้ว ยังไม่ทราบชื่อ/ชนิดค่าของkeyนั้น เพิ่มเฉพาะfixedallowlistfieldtags/counts/sole-valueJSONtype/nestedcandidatesflag และschemaecho/requestcontractflagsในstandaloneclient ไม่มีrawresponsepersistence/no repair/rename/wrappingผล ดู `PROXY_CONTRACT_CHECK.md` (ลบแล้ว 2026-10-05) สำหรับประเด็นdev ตรวจpath/logsก่อนเลือกcontrolledprobeถัดไป ยังไม่มีliveผลdiagnosticsชุดใหม่ ไม่เพิ่มtimeoutsหรือretryอัตโนมัติ

ตรวจฝั่งเราหลังผู้ใช้ทัก: scriptใช้hardcodedthinkingtrueตามhistoricalmanualprofile แต่ผู้ใช้ยืนยันSwaggerfalse จึงทดลองpromptเร็วเกินไปก่อนrequestparity แก้run-core/inspectdefaultfalseพร้อมexplicitCLIflagและlogactualvalue ไม่เปลี่ยนcore/defaultproductionconfig มีexport-swaggerofflineเพื่อส่งออกrealreviewedwindow/prompt/schema/publicparametersในprivateworkdirโดยไม่อ่าน.env/สร้างsecret/เรียกnetwork ใช้actualclient_build_formแบบmodel-onlyserializationcontext แล้วHTTPXRequest+parse_qsตรวจทุกfield/schemaexactroundtrip ตัวexportไม่ใช่liveLLMpassและไม่เก็บrawencodedbody/Authorization ขั้นต่อไปเปลี่ยนเฉพาะthinkingจากbaselineprobeเดิมและเทียบSwaggerทุกfieldเดียวกัน

Coverage ของ numeric rules มีเพียง CASE_NUMBER/TITLE_DEED_NUMBER/LAND_PARCEL_NUMBER ไม่ใช่ general NAME/ADDRESS NER ต้องระบุ test profile นี้ใน summary และไม่ใช้ callback ที่คืน `False` เสมอเพื่อทำให้ core ผ่าน

## 4. ผลลัพธ์และข้อมูล confidential

| Output | วัตถุประสงค์ |
| --- | --- |
| `source.md` | ผู้ใช้ตรวจ conversion/OCR กับ PDF ก่อน test |
| `pages.json` | conversion/page review/หน้าใดต้อง OCR และ ranges สำหรับตรวจในเครื่อง |
| `detection-windows.json` | ranges/budgets ที่ตรวจแล้วและตรึงก่อน live |
| `redacted.md` | ผลทั้ง document หลัง core verification ผ่าน; ผู้ใช้ตรวจ PII ตกหล่นเพิ่มเติม |
| `summary.json` | page/window/call counts, versions, rule coverage, counts ตาม type, elapsed time และ safe result/error code |

ทั้งหมดเก็บใน output directory ส่วนตัวนอก Git ที่ผู้ใช้เลือก ไม่อ่านหรือเผยแพร่ให้ Codex โดยอัตโนมัติ แม้ redacted file ก็ยังถือเป็น confidential เพราะอาจมีข้อมูลอื่นหรือ residual PII ไม่ echo source/values/anchors/path/headers/body/secrets ลง terminal

PII mapping อยู่ใน memory ตาม core เดิม **ยังไม่ export manifest ลง disk** เพราะงาน encryption เลื่อนไว้ script นี้จึงไม่ได้สร้าง multipart package หรือผลลัพธ์ครบ delivery contract ฝั่ง API หากต้องการทดสอบ manifest/encryption ให้เป็นขั้นต่อไป

PDF อยู่ในเครื่อง แต่ `run-core` ส่งข้อความจาก Markdown และ redacted text ไป proxy เดิม ผู้ใช้รันกับ proxy ที่อนุญาตให้รับข้อมูลนี้ ขั้น `prepare` ไม่ส่งข้อมูลออก

Summary ระบุ pages included/total และ full window coverage การผ่าน verification ต้องแยกจาก human-reviewed accuracy ไม่ให้สถานะ complete ทั้งไฟล์ถ้ามี skipped/unreviewed OCR pages หรือส่วนที่ไม่ได้ตรวจ

## 5. สถานะ implementation และขั้นทดสอบจริง

1. มี `prepare`/`review` แล้ว ทดสอบด้วย synthetic PDF หลายหน้า/page index/NFC และหน้า scan-only, mixed, blank, malformed/encrypted PDF โดยไม่ใช้ไฟล์ confidential
2. มี validation ของ conversion review/window plan/budgets ก่อน network แล้ว หน้าภาพที่มี text ร่วมด้วยยังต้องให้ผู้ใช้ตรวจเอง ไม่ใช้ข้อความที่ extract ได้เป็นหลักฐานว่า OCR ครบ
3. มี `run-core` กับ actual components/client และ MockTransport แล้ว ตรวจหลาย windows, duplicates, global counters, fresh redacted verification, document >1000characters และ fail-closed/no partial output Standalone tests **54 passed** เป็นhistorical snapshotก่อนprepare-md/pdfplumber/planner/diagnosticsใหม่ ไม่ใช่ real-document accuracy หรือ production capacity evidence รอบdiagnosticsใหม่ตรวจRuff check/format/Python syntax/core diagnostic importsผ่าน ไม่มีsynthetic rerun ผู้ใช้รันrealprogress/inspectแล้ว จึงมีruntimeevidenceของdiagnosticsในเส้นทางที่รัน แต่ไม่ครอบทุกfailurebranch
4. Recorded live checkpoints: PDF textคุณภาพไม่พอ/OCRทีมยังใช้ไม่ได้ จึงนำ reviewed Markdownผ่านprepare-md/reviewมาrun-core รอบv8หยุดwindow5; v9fullแรกaccepted1–7ก่อนwindow8transportfailure แล้วinspect8ผ่าน210.105s Fullrerunถัดมาaccepted1–9ก่อนwindow10value_not_found145.920s (candidate6ORGANIZATION/value35chars/structureถูกต้องแต่valueabsent) ยังไม่ถึงwhole-documentredaction/verification/accuracy acceptance สถานะและnextstepที่เปลี่ยนได้อ้างlearninghandoff
5. หลัง bridge ทำงานแล้ว จึงเพิ่ม human-reviewed expected PII สำหรับวัด recall/false positives ตามที่ต้องการ ไม่บังคับ private annotation workflow เป็น prerequisite ของการ implement converter

ใช้ design นี้สำหรับ script PDF หลายหน้า → Markdown → processing core ส่วน detailed oracle เป็นงานประเมินเพิ่มเติมภายหลัง
