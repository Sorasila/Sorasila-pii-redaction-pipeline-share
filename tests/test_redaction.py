import pytest

from pii_pipeline.models import PiiMatch
from pii_pipeline.redaction import (
    build_replacements_and_entries,
    is_exact_match,
    normalize_pii_type,
    redact,
    redact_many,
)


def test_exact_match_returns_true_for_matching_source() -> None:
    text = "NAME: Alice"
    value = "Alice"
    start = text.index(value)
    end = start + len(value)
    match = PiiMatch("NAME", value, start, end)

    result = is_exact_match(text, match)
    assert result is True


def test_exact_match_returns_false_for_different_value() -> None:
    text = "NAME: Bobby"
    source_value = "Bobby"
    detected_value = "Alice"
    start = text.index(source_value)
    end = start + len(source_value)
    match = PiiMatch("NAME", detected_value, start, end)

    result = is_exact_match(text, match)
    assert result is False


def test_exact_match_allows_value_in_middle_of_document() -> None:
    text = "NAME: Alice, Age: 30"
    value = "Alice"
    start = text.index(value)
    end = start + len(value)
    match = PiiMatch("NAME", value, start, end)
    result = is_exact_match(text, match)
    assert result is True


def test_exact_match_rejects_end_outside_document() -> None:
    text = "NAME: Alice"
    value = "Alice"
    start = text.index(value)
    invalid_end = len(text) + 1
    match = PiiMatch("NAME", value, start, invalid_end)
    result = is_exact_match(text, match)
    assert result is False


def test_redact_many_replaces_multiple_matches_in_order() -> None:
    text = "People: Alice met Bob today."

    alice_value = "Alice"
    alice_start = text.index(alice_value)
    alice_end = alice_start + len(alice_value)

    bob_value = "Bob"
    bob_start = text.index(bob_value)
    bob_end = bob_start + len(bob_value)

    alice = PiiMatch(
        pii_type="NAME",
        value=alice_value,
        start=alice_start,
        end=alice_end,
    )

    bob = PiiMatch(
        pii_type="NAME",
        value=bob_value,
        start=bob_start,
        end=bob_end,
    )

    replacements = [
        (alice, "[PII_NAME_1]"),
        (bob, "[PII_NAME_2]"),
    ]

    result = redact_many(text, replacements)

    expected = "People: [PII_NAME_1] met [PII_NAME_2] today."
    assert result == expected


def test_redact_many_handles_replacements_out_of_order() -> None:
    text = "People: Alice met Bob today."

    alice_value = "Alice"
    alice_start = text.index(alice_value)
    alice_end = alice_start + len(alice_value)

    bob_value = "Bob"
    bob_start = text.index(bob_value)
    bob_end = bob_start + len(bob_value)

    alice = PiiMatch(
        pii_type="NAME",
        value=alice_value,
        start=alice_start,
        end=alice_end,
    )

    bob = PiiMatch(
        pii_type="NAME",
        value=bob_value,
        start=bob_start,
        end=bob_end,
    )

    replacements = [
        (bob, "[PII_NAME_2]"),
        (alice, "[PII_NAME_1]"),
    ]

    result = redact_many(text, replacements)

    expected = "People: [PII_NAME_1] met [PII_NAME_2] today."
    assert result == expected


def test_redact_many_rejects_overlapping_matches() -> None:
    text = "Alice"

    full_match = PiiMatch("NAME", "Alice", 0, 5)
    partial_match = PiiMatch("NAME", "lice", 1, 5)

    replacements = [(full_match, "[PII_NAME_1]"), (partial_match, "[PII_NAME_2]")]
    with pytest.raises(ValueError):
        redact_many(text, replacements)


def test_redact_many_allows_adjacent_matches() -> None:
    text = "AliceBob"

    full_match = PiiMatch("NAME", "Alice", 0, 5)
    partial_match = PiiMatch("NAME", "Bob", 5, 8)

    replacements = [(full_match, "[PII_NAME_1]"), (partial_match, "[PII_NAME_2]")]

    result = redact_many(text, replacements)
    expected = "[PII_NAME_1][PII_NAME_2]"
    assert result == expected


def test_normalize_pii_type_accepts_valid_and_rejects_invalid() -> None:
    with pytest.raises(ValueError):
        normalize_pii_type(" Name! ")

    raw_type_1 = " name "
    expected_1 = "NAME"

    raw_type_2 = "id_number"
    expected_2 = "ID_NUMBER"

    normalize_1 = normalize_pii_type(raw_type_1)
    normalize_2 = normalize_pii_type(raw_type_2)

    assert normalize_1 == expected_1
    assert normalize_2 == expected_2


def test_build_replacements_numbers_each_type_in_source_order() -> None:
    alice = PiiMatch("Name", "Alice", 0, 5)
    phone = PiiMatch("PHONE", "0812345678", 6, 16)
    bob = PiiMatch("name", "Bob", 17, 20)

    replacements, entries = build_replacements_and_entries([bob, phone, alice])

    expected = [
        (alice, "[PII_NAME_1]"),
        (phone, "[PII_PHONE_1]"),
        (bob, "[PII_NAME_2]"),
    ]
    assert replacements == expected
    assert len(entries) == 3

    assert entries[0].placeholder == "[PII_NAME_1]"
    assert entries[0].pii_type == "NAME"
    assert entries[0].occurrence_index == 1
    assert entries[0].original_value == "Alice"

    assert entries[1].placeholder == "[PII_PHONE_1]"
    assert entries[1].pii_type == "PHONE"
    assert entries[1].occurrence_index == 1
    assert entries[1].original_value == "0812345678"

    assert entries[2].placeholder == "[PII_NAME_2]"
    assert entries[2].pii_type == "NAME"
    assert entries[2].occurrence_index == 2
    assert entries[2].original_value == "Bob"


def test_redact_returns_markdown_and_entries() -> None:
    text = "Alice met Bob"
    alice = PiiMatch("NAME", "Alice", 0, 5)
    bob = PiiMatch("NAME", "Bob", 10, 13)

    result = redact(text, [bob, alice])

    assert result.redacted_markdown == "[PII_NAME_1] met [PII_NAME_2]"
    assert len(result.entries) == 2


def test_redact_rejects_match_that_does_not_match_source() -> None:
    text = "Name: Alice"
    wrong_match = PiiMatch("NAME", "Bobby", 6, 11)

    with pytest.raises(ValueError):
        redact(text, [wrong_match])


def test_redact_rejects_placeholder_already_present_in_source() -> None:
    text = "[PII_NAME_1] Alice"

    value = "Alice"
    start = text.index(value)
    match = PiiMatch(
        pii_type="NAME",
        value=value,
        start=start,
        end=start + len(value),
    )

    with pytest.raises(ValueError):
        redact(text, [match])


def test_redact_deduplicates_exact_duplicate_matches() -> None:
    text = "Alice"

    first_match = PiiMatch(
        pii_type="NAME",
        value="Alice",
        start=0,
        end=5,
    )

    duplicate_match = PiiMatch(
        pii_type="name",
        value="Alice",
        start=0,
        end=5,
    )

    result = redact(text, [first_match, duplicate_match])

    assert result.redacted_markdown == "[PII_NAME_1]"
    assert len(result.entries) == 1
    assert result.entries[0].placeholder == "[PII_NAME_1]"


def test_redact_rejects_conflicting_types_for_same_span() -> None:
    text = "Alice"

    name_match = PiiMatch(
        pii_type="NAME",
        value="Alice",
        start=0,
        end=5,
    )

    address_match = PiiMatch(
        pii_type="ADDRESS",
        value="Alice",
        start=0,
        end=5,
    )

    with pytest.raises(ValueError):
        redact(text, [name_match, address_match])


@pytest.mark.parametrize(
    "invalid_match",
    [
        PiiMatch(None, "Alice", 0, 5),
        PiiMatch("NAME", None, 0, 5),
        PiiMatch("NAME", "Alice", "0", 5),
        PiiMatch("NAME", "Alice", 0, None),
        PiiMatch("NAME", "Alice", True, 5),
    ],
)
def test_exact_match_returns_false_for_runtime_invalid_fields(
    invalid_match: PiiMatch,
) -> None:
    assert is_exact_match("Alice", invalid_match) is False


def test_normalize_pii_type_rejects_non_string_with_safe_error() -> None:
    with pytest.raises(ValueError) as captured_error:
        normalize_pii_type(None)

    assert str(captured_error.value) == "Invalid PII type"


def test_redact_rejects_any_reserved_placeholder_in_source() -> None:
    text = "Existing: [PII_PHONE_99]; Name: Alice"
    value = "Alice"
    start = text.index(value)
    match = PiiMatch("NAME", value, start, start + len(value))

    with pytest.raises(
        ValueError,
        match="PII placeholder already exists in source document",
    ):
        redact(text, [match])


def test_redact_rejects_reserved_placeholder_when_matches_are_empty() -> None:
    with pytest.raises(
        ValueError,
        match="PII placeholder already exists in source document",
    ):
        redact("Already redacted: [PII_NAME_7]", [])


def test_redact_many_rejects_duplicate_placeholders() -> None:
    text = "Alice Bob"
    alice = PiiMatch("NAME", "Alice", 0, 5)
    bob = PiiMatch("NAME", "Bob", 6, 9)

    with pytest.raises(ValueError, match="Duplicate PII placeholder"):
        redact_many(
            text,
            [
                (alice, "[PII_NAME_1]"),
                (bob, "[PII_NAME_1]"),
            ],
        )


def test_build_replacements_rejects_runtime_invalid_match_safely() -> None:
    invalid_match = PiiMatch("NAME", "Alice", "0", 5)

    with pytest.raises(ValueError) as captured_error:
        build_replacements_and_entries([invalid_match])

    assert str(captured_error.value) == "Invalid PII match"
    assert "Alice" not in str(captured_error.value)


def test_build_replacements_rejects_overlapping_matches() -> None:
    full_match = PiiMatch("NAME", "Alice", 0, 5)
    partial_match = PiiMatch("NAME", "lice", 1, 5)

    with pytest.raises(ValueError, match="PII match overlapped"):
        build_replacements_and_entries([partial_match, full_match])


def test_exact_duplicate_representative_is_deterministic() -> None:
    canonical_match = PiiMatch("NAME", "Alice", 0, 5)
    equivalent_match = PiiMatch("name", "Alice", 0, 5)

    first_result = build_replacements_and_entries([equivalent_match, canonical_match])
    second_result = build_replacements_and_entries([canonical_match, equivalent_match])

    assert first_result == second_result
    assert first_result[0] == [(canonical_match, "[PII_NAME_1]")]
