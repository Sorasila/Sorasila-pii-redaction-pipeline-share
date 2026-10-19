from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PiiCandidate:
    pii_type: str
    value: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class PiiMatch:  # ผลจากการตรวจพบ PII หนึ่งตำแหน่งในเอกสารต้นฉบับ
    pii_type: str
    value: str = field(repr=False)
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class PiiEntry:  # mapping ชั่วคราวระหว่าง placeholder กับ PII จริง
    placeholder: str
    pii_type: str
    occurrence_index: int
    original_value: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RedactionResult:  # Markdown ที่ redact แล้วกับ mapping ชั่วคราวก่อน verification
    redacted_markdown: str = field(repr=False)
    entries: tuple[PiiEntry, ...]
