from ..core.pii_types import CANONICAL_PII_TYPES, PII_TYPE_SCOPE_NOTES

_JSON_SCHEMA_DRAFT = "http://json-schema.org/draft-07/schema#"


def _pii_type_schema() -> dict[str, object]:
    scope_notes = " ".join(
        f"{pii_type}: {description}"
        for pii_type, description in PII_TYPE_SCOPE_NOTES.items()
    )

    return {
        "type": "string",
        "enum": list(CANONICAL_PII_TYPES),
        "description": f"Canonical PII type. {scope_notes}",
    }


def build_detection_response_schema() -> dict[str, object]:
    """Return a closed schema for distinct exact PII type/value proposals."""

    return {
        "$schema": _JSON_SCHEMA_DRAFT,
        "type": "object",
        "description": (
            "Propose exact PII values from the NFC-normalized input text or chunk. "
            "Return each distinct type/value pair once when at least one occurrence is PII. Repeated values are selected separately by service occurrence IDs. "
            "Do not return offsets; the service resolves positions locally."
        ),
        "additionalProperties": False,
        "properties": {
            "candidates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "pii_type": _pii_type_schema(),
                        "value": {
                            "type": "string",
                            "minLength": 1,
                            "description": (
                                "Copy the exact source substring; "
                                "do not trim or rewrite it. "
                                "The service canonicalizes it to NFC before validation."
                            ),
                        },
                    },
                    "required": ["pii_type", "value"],
                },
            }
        },
        "required": ["candidates"],
    }


def build_occurrence_selection_schema(
    occurrence_ids: tuple[int, ...],
) -> dict[str, object]:
    """Require a closed decision set; exact ID completeness is checked locally."""
    if not occurrence_ids or any(
        type(item) is not int or item < 1 for item in occurrence_ids
    ):
        raise ValueError("Invalid occurrence selection configuration")
    return {
        "$schema": _JSON_SCHEMA_DRAFT,
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "decisions": {
                "type": "array",
                "minItems": len(occurrence_ids),
                "maxItems": len(occurrence_ids),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "occurrence_id": {
                            "type": "integer",
                            "enum": list(occurrence_ids),
                        },
                        "pii_type": {
                            "type": "string",
                            "enum": [*CANONICAL_PII_TYPES, "NOT_PII"],
                        },
                    },
                    "required": ["occurrence_id", "pii_type"],
                },
            },
        },
        "required": ["decisions"],
    }


def build_verification_response_schema() -> dict[str, object]:
    """Report residual types only; offsets and boolean consistency are local."""

    return {
        "$schema": _JSON_SCHEMA_DRAFT,
        "type": "object",
        "description": (
            "Independently report whether residual PII is present and its canonical "
            "types. Return each type once, without values, anchors or offsets. "
            "The service attaches the inspected window as a coarse location."
        ),
        "additionalProperties": False,
        "properties": {
            "has_pii": {"type": "boolean"},
            "findings": {
                "type": "array",
                "maxItems": len(CANONICAL_PII_TYPES),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "pii_type": _pii_type_schema(),
                    },
                    "required": ["pii_type"],
                },
            },
        },
        "required": ["has_pii", "findings"],
    }
