import json

import pytest

from pii_pipeline.core.pii_types import (
    CANONICAL_PII_TYPES,
    PII_TYPE_SCOPE_NOTES,
    PiiType,
    canonicalize_pii_type,
)
from pii_pipeline.llm.schema import (
    build_detection_response_schema,
    build_verification_response_schema,
)


def test_canonical_pii_types_cover_required_entities() -> None:
    assert set(CANONICAL_PII_TYPES) == {
        "NAME",
        "ORGANIZATION",
        "ID_NUMBER",
        "PASSPORT_NUMBER",
        "EMAIL",
        "PHONE",
        "FAX",
        "ADDRESS",
        "BANK_ACCOUNT_NUMBER",
        "PAYMENT_CARD_NUMBER",
        "VEHICLE_REGISTRATION",
        "DATE_OF_BIRTH",
        "SOCIAL_MEDIA_IDENTIFIER",
        "LAND_PARCEL_NUMBER",
        "CASE_NUMBER",
        "TITLE_DEED_NUMBER",
        "OFFICIAL_LETTER_NUMBER",
    }
    assert PiiType.PERSON_NAME == "NAME"
    assert PiiType.JURISTIC_PERSON_NAME == "ORGANIZATION"
    assert PiiType.NATIONAL_ID == "ID_NUMBER"
    assert PiiType.LAND_PARCEL_NUMBER == "LAND_PARCEL_NUMBER"
    assert PiiType.CASE_NUMBER == "CASE_NUMBER"
    assert PiiType.TITLE_DEED_NUMBER == "TITLE_DEED_NUMBER"


def test_scope_notes_lock_organization_and_land_number_meanings() -> None:
    organization_scope = PII_TYPE_SCOPE_NOTES["ORGANIZATION"]
    land_scope = PII_TYPE_SCOPE_NOTES["LAND_PARCEL_NUMBER"]

    assert "Private juristic persons only" in organization_scope
    assert "Government agencies, courts and their units are not ORGANIZATION" in (
        organization_scope
    )
    assert "Land parcel number only" in land_scope
    assert "title-deed number" in land_scope
    assert "survey-page number" in land_scope
    assert "cadastral-map" in land_scope


@pytest.mark.parametrize(
    ("raw_type", "expected"),
    [
        (" name ", "NAME"),
        ("organization", "ORGANIZATION"),
        ("land_parcel_number", "LAND_PARCEL_NUMBER"),
        ("case_number", "CASE_NUMBER"),
        ("title_deed_number", "TITLE_DEED_NUMBER"),
    ],
)
def test_canonicalize_pii_type_normalizes_approved_values(
    raw_type: str,
    expected: str,
) -> None:
    assert canonicalize_pii_type(raw_type) == expected


def test_canonicalize_pii_type_rejects_non_string_value() -> None:
    with pytest.raises(TypeError, match="Invalid canonical PII type"):
        canonicalize_pii_type(None)


@pytest.mark.parametrize("invalid_type", ["", "CUSTOM_IDENTIFIER"])
def test_canonicalize_pii_type_rejects_unapproved_string(
    invalid_type: str,
) -> None:
    with pytest.raises(ValueError, match="Invalid canonical PII type"):
        canonicalize_pii_type(invalid_type)


def test_detection_schema_is_closed_and_uses_canonical_types() -> None:
    schema = build_detection_response_schema()
    candidate_schema = schema["properties"]["candidates"]["items"]

    assert schema["additionalProperties"] is False
    assert candidate_schema["additionalProperties"] is False

    assert candidate_schema["required"] == ["pii_type", "value"]
    assert set(candidate_schema["properties"]) == {"pii_type", "value"}

    assert candidate_schema["properties"]["pii_type"]["enum"] == list(
        CANONICAL_PII_TYPES
    )

    type_description = candidate_schema["properties"]["pii_type"]["description"]
    assert PII_TYPE_SCOPE_NOTES["ORGANIZATION"] in type_description
    assert PII_TYPE_SCOPE_NOTES["LAND_PARCEL_NUMBER"] in type_description

    assert "each distinct type/value pair once" in schema["description"]
    assert "uniqueItems" not in schema["properties"]["candidates"]


def test_detection_schema_builder_returns_independent_objects() -> None:
    first_schema = build_detection_response_schema()
    second_schema = build_detection_response_schema()

    first_schema["properties"]["candidates"]["items"]["properties"]["pii_type"][
        "enum"
    ].append("INVALID")

    assert (
        "INVALID"
        not in second_schema["properties"]["candidates"]["items"]["properties"][
            "pii_type"
        ]["enum"]
    )


def test_verification_schema_is_closed_type_only_and_bounded() -> None:
    schema = build_verification_response_schema()
    finding_schema = schema["properties"]["findings"]["items"]

    assert schema["additionalProperties"] is False
    assert schema["required"] == ["has_pii", "findings"]
    assert set(schema["properties"]) == {"has_pii", "findings"}
    assert finding_schema["additionalProperties"] is False
    assert finding_schema["required"] == ["pii_type"]
    assert set(finding_schema["properties"]) == {"pii_type"}
    assert schema["properties"]["findings"]["maxItems"] == len(CANONICAL_PII_TYPES)
    assert finding_schema["properties"]["pii_type"]["enum"] == list(CANONICAL_PII_TYPES)


def test_verification_schema_avoids_conditional_decoding_constraints() -> None:
    serialized = json.dumps(build_verification_response_schema())

    for keyword in ("allOf", "if", "then", "else"):
        assert f'"{keyword}"' not in serialized


def test_verification_schema_builder_returns_independent_objects() -> None:
    first_schema = build_verification_response_schema()
    second_schema = build_verification_response_schema()
    first_schema["properties"]["findings"]["items"]["properties"]["pii_type"][
        "enum"
    ].append("INVALID")

    assert (
        "INVALID"
        not in second_schema["properties"]["findings"]["items"]["properties"][
            "pii_type"
        ]["enum"]
    )


def test_llm_schemas_are_json_serializable() -> None:
    json.dumps(build_detection_response_schema())
    json.dumps(build_verification_response_schema())
