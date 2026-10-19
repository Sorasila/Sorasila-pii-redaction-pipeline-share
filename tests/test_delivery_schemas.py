"""The published manifest/metadata JSON Schemas must match real package output."""

import copy
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from test_delivery_package import fake_jwe

from pii_pipeline.core.models import PiiMatch, RedactionResult
from pii_pipeline.core.pii_types import CANONICAL_PII_TYPES
from pii_pipeline.core.redaction import redact
from pii_pipeline.llm.prompts import DETECTION_PROMPT_VERSION
from pii_pipeline.service.delivery import prepare_delivery

DOCS = Path(__file__).resolve().parents[1] / "docs"
MANIFEST_SCHEMA = json.loads(
    (DOCS / "pii-manifest.schema.json").read_text(encoding="utf-8")
)
METADATA_SCHEMA = json.loads(
    (DOCS / "metadata.schema.json").read_text(encoding="utf-8")
)
SUPPORTED_KEYWORDS = {
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "items",
    "enum",
    "pattern",
    "minLength",
    "minimum",
    "format",
}
JSON_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
}


def _format_ok(name: str, value: str) -> bool:
    if name == "uuid":
        try:
            return str(UUID(value)) == value
        except ValueError:
            return False
    if name == "date-time":
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        return parsed.tzinfo is not None
    raise AssertionError(f"Unsupported format {name}")


def schema_errors(schema: dict, value: object, path: str = "$") -> list[str]:
    """Minimal validator for exactly the keywords these two schemas use."""
    assert set(schema) <= SUPPORTED_KEYWORDS, set(schema) - SUPPORTED_KEYWORDS
    expected = JSON_TYPES[schema["type"]]
    if type(value) is bool or not isinstance(value, expected):
        return [f"{path}: type"]
    errors: list[str] = []
    if schema["type"] == "object":
        missing = set(schema.get("required", ())) - set(value)
        errors += [f"{path}.{key}: required" for key in sorted(missing)]
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(schema["properties"])
            errors += [f"{path}.{key}: additional" for key in sorted(extra)]
        for key, child in schema.get("properties", {}).items():
            if key in value:
                errors += schema_errors(child, value[key], f"{path}.{key}")
    if schema["type"] == "array":
        for index, item in enumerate(value):
            errors += schema_errors(schema["items"], item, f"{path}[{index}]")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: enum")
    if "pattern" in schema and re.search(schema["pattern"], value) is None:
        errors.append(f"{path}: pattern")
    if "minLength" in schema and len(value) < schema["minLength"]:
        errors.append(f"{path}: minLength")
    if "minimum" in schema and value < schema["minimum"]:
        errors.append(f"{path}: minimum")
    if "format" in schema and not _format_ok(schema["format"], value):
        errors.append(f"{path}: format")
    return errors


SOURCE = (
    "ชื่อ นายสมมติ ทดสอบ คดีหมายเลขดำที่ 123/2569 ชื่อ นางตัวอย่าง ใจดี และ นายสมมติ ทดสอบ อีกครั้ง"
)


def _match(pii_type: str, value: str, occurrence: int = 0) -> PiiMatch:
    start = -1
    for _ in range(occurrence + 1):
        start = SOURCE.index(value, start + 1)
    return PiiMatch(pii_type, value, start, start + len(value))


def _package(result: RedactionResult, redacted_at: datetime) -> tuple[dict, dict]:
    captured: dict[str, bytes] = {}

    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        captured["manifest"] = plaintext
        captured["metadata"] = additional_authenticated_data
        return fake_jwe(additional_authenticated_data)

    prepare_delivery(
        result,
        document_id=uuid4(),
        delivery_id=uuid4(),
        redacted_at=redacted_at,
        encrypt_manifest=encryptor,
    )
    return json.loads(captured["manifest"]), json.loads(captured["metadata"])


CASES = {
    "multiple_types_and_repeated_value": (
        lambda: redact(
            SOURCE,
            [
                _match("NAME", "นายสมมติ ทดสอบ"),
                _match("CASE_NUMBER", "123/2569"),
                _match("NAME", "นางตัวอย่าง ใจดี"),
                _match("NAME", "นายสมมติ ทดสอบ", 1),
            ],
        ),
        datetime(2026, 10, 5, 2, 41, 7, 512334, tzinfo=UTC),
    ),
    "clean_document": (
        lambda: redact("ไม่มีข้อมูลบุคคล\n", []),
        datetime(2026, 10, 5, 2, 41, 7, tzinfo=UTC),
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_real_package_output_matches_published_schemas(case: str) -> None:
    build, redacted_at = CASES[case]
    result = build()
    manifest, metadata = _package(result, redacted_at)

    assert schema_errors(MANIFEST_SCHEMA, manifest) == []
    assert schema_errors(METADATA_SCHEMA, metadata) == []
    # Cross-field rules documented in the schema descriptions.
    assert manifest["document_id"] == metadata["document_id"]
    assert metadata["detector_version"] == DETECTION_PROMPT_VERSION
    assert (
        metadata["redacted_md_sha256"]
        == hashlib.sha256(result.redacted_markdown.encode("utf-8")).hexdigest()
    )
    for entry in manifest["entries"]:
        assert entry["placeholder"] == (
            f"[PII_{entry['pii_type']}_{entry['occurrence_index']}]"
        )
        assert entry["redacted_at"] == metadata["created_at"]
    assert [entry["placeholder"] for entry in manifest["entries"]] == re.findall(
        r"\[PII_[A-Z][A-Z0-9_]*_[0-9]+\]", result.redacted_markdown
    )


def test_package_with_current_time_matches_schemas() -> None:
    manifest, metadata = _package(
        redact(SOURCE, [_match("NAME", "นางตัวอย่าง ใจดี")]), datetime.now(UTC)
    )
    assert schema_errors(MANIFEST_SCHEMA, manifest) == []
    assert schema_errors(METADATA_SCHEMA, metadata) == []


def test_schema_type_enum_stays_in_sync_with_canonical_vocabulary() -> None:
    enum = MANIFEST_SCHEMA["properties"]["entries"]["items"]["properties"]["pii_type"][
        "enum"
    ]
    assert enum == list(CANONICAL_PII_TYPES)


@pytest.mark.parametrize(
    "mutation,expected",
    [
        (lambda m: m["entries"][0].update(extra="x"), "$.entries[0].extra: additional"),
        (
            lambda m: m["entries"][0].pop("redacted_at"),
            "$.entries[0].redacted_at: required",
        ),
        (
            lambda m: m["entries"][0].update(placeholder="[PII_NAME_0]"),
            "$.entries[0].placeholder: pattern",
        ),
        (
            lambda m: m["entries"][0].update(pii_type="PERSON"),
            "$.entries[0].pii_type: enum",
        ),
        (
            lambda m: m["entries"][0].update(occurrence_index=True),
            "$.entries[0].occurrence_index: type",
        ),
        (
            lambda m: m["entries"][0].update(redacted_at="2026-10-05T02:41:07"),
            "$.entries[0].redacted_at: pattern",
        ),
        (lambda m: m.update(document_id="not-a-uuid"), "$.document_id: format"),
    ],
)
def test_validator_rejects_contract_violations(mutation, expected) -> None:
    build, redacted_at = CASES["multiple_types_and_repeated_value"]
    manifest, _ = _package(build(), redacted_at)
    broken = copy.deepcopy(manifest)
    mutation(broken)
    assert expected in schema_errors(MANIFEST_SCHEMA, broken)
