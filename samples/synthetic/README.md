# Synthetic test pages

Invented pages for trying the service right after cloning. Every person, company,
place, case and number here is fictional: numbers use obvious patterns (`0000`,
`1 2345 67890 12 3`) and the e-mail uses the reserved `example.com` domain. Real
documents must never be added to the repository.

Each page is one request (under the service limit, 10000 code points by default). Send them with
[`tools/redact_client.py`](../../tools/redact_client.py).

## What should be redacted

The rule lane always catches the labelled numbers; names, addresses and
organizations come from the LLM lane and can vary between runs.

| Page | Rule lane (deterministic) | LLM lane (expected) |
| --- | --- | --- |
| [page-1](page-1.md) | CASE_NUMBER `123/2569`, `ก/2569`; ID_NUMBER; PHONE; OFFICIAL_LETTER_NUMBER ×2 (one written `หนังสือ ที่`) | NAME: นายสมมุติ ทดลองดี, นางสาวตัวอย่าง ใจงาม; ADDRESS: บ้านเลขที่ 99/9 … จังหวัดตัวอย่าง |
| [page-2](page-2.md) | TITLE_DEED_NUMBER (in prose); FAX; EMAIL; BANK_ACCOUNT_NUMBER; OFFICIAL_LETTER_NUMBER | TITLE_DEED_NUMBER and LAND_PARCEL_NUMBER inside the table; NAME ×2; ORGANIZATION: บริษัท ทดลองพัฒนาที่ดิน จำกัด; ADDRESS: the land location |
| [page-3](page-3.md) | CASE_NUMBER; BANK_ACCOUNT_NUMBER; PASSPORT_NUMBER; PHONE | NAME ×2; DATE_OF_BIRTH; ADDRESS split by an OCR page-break line (redacted as two parts, the `----|-- Page 2 --|` line stays); ORGANIZATION: นิติบุคคลอาคารชุด ตัวอย่างคอนโด |

## What should stay

- Single-letter pseudonyms: `บริษัท ก.`, `ห้างหุ้นส่วน ข.`
- Government agencies and courts: `สำนักงานที่ดินจังหวัดตัวอย่าง`, `กรมที่ดิน`, `ศาลปกครองกลาง`
- Survey page and map sheet (`หน้าสำรวจ`, `ระวาง`) and ordinary document dates
- Field labels such as `คดีหมายเลขดำที่`, `โฉนดเลขที่`, `หนังสือที่`
