import pytest

from pii_pipeline.core.detection import (
    DetectionError,
    normalize_unicode,
    run_detectors,
)
from pii_pipeline.core.models import PiiMatch


def test_normalize_unicode_converts_decomposed_text_to_nfc() -> None:
    decomposed = "Cafe\u0301"
    composed = "Café"

    result = normalize_unicode(decomposed)

    assert result == composed


def test_run_detectors_passes_nfc_markdown_to_detector() -> None:
    received_markdown: list[str] = []

    def fake_detector(markdown: str) -> list[PiiMatch]:
        received_markdown.append(markdown)
        return []

    normalize_markdown, matches = run_detectors(
        "Cafe\u0301",
        [fake_detector],
    )

    assert normalize_markdown == "Café"
    assert received_markdown == ["Café"]
    assert matches == []


def test_run_detectors_combines_matches_from_all_detectors() -> None:
    markdown = "Alice 0812345678"

    name_match = PiiMatch(
        pii_type="NAME",
        value="Alice",
        start=0,
        end=5,
    )
    phone_match = PiiMatch(
        pii_type="PHONE",
        value="0812345678",
        start=6,
        end=16,
    )

    def first_detector(_: str) -> list[PiiMatch]:
        return [name_match]

    def second_detector(_: str) -> list[PiiMatch]:
        return [phone_match]

    normalized_markdown, matches = run_detectors(
        markdown,
        [first_detector, second_detector],
    )

    assert normalized_markdown == markdown
    assert matches == [name_match, phone_match]


def test_run_detectors_fails_closed_when_detector_errors() -> None:
    markdown = "Customer: Alice"

    def broken_detector(_: str) -> list[PiiMatch]:
        raise RuntimeError("Detector failed while processing Alice")

    with pytest.raises(DetectionError) as error_info:
        run_detectors(
            markdown,
            [broken_detector],
        )

    assert str(error_info.value) == "PII detection failed"
    assert "Alice" not in str(error_info.value)


def test_run_detectors_fails_closed_for_non_list_result() -> None:
    markdown = "Customer: Alice"

    def invalid_detector(_: str) -> list[PiiMatch]:
        return None  # type: ignore[return-value]

    with pytest.raises(DetectionError) as error_info:
        run_detectors(
            markdown,
            [invalid_detector],
        )

    assert str(error_info.value) == "PII detection returned invalid result"


def test_run_detectors_fails_closed_for_non_match_list_item() -> None:
    markdown = "Customer: Alice"

    def invalid_detector(_: str) -> list[PiiMatch]:
        return ["invalid item"]  # type: ignore[list-item]

    with pytest.raises(DetectionError) as error_info:
        run_detectors(
            markdown,
            [invalid_detector],
        )

    assert str(error_info.value) == "PII detection returned invalid result"


def test_run_detectors_rejects_match_that_does_not_match_source() -> None:
    markdown = "Customer: Alice"

    invalid_match = PiiMatch(
        pii_type="NAME",
        value="Bobby",
        start=10,
        end=15,
    )

    def invalid_detector(_: str) -> list[PiiMatch]:
        return [invalid_match]

    with pytest.raises(DetectionError) as error_info:
        run_detectors(
            markdown,
            [invalid_detector],
        )

    assert str(error_info.value) == "PII detection returned invalid match"
    assert "Bobby" not in str(error_info.value)


def test_run_detectors_rejects_match_with_invalid_pii_type() -> None:
    markdown = "Customer: Alice"

    invalid_match = PiiMatch(
        pii_type="NAME!",
        value="Alice",
        start=10,
        end=15,
    )

    def invalid_detector(_: str) -> list[PiiMatch]:
        return [invalid_match]

    with pytest.raises(DetectionError) as error_info:
        run_detectors(
            markdown,
            [invalid_detector],
        )

    assert str(error_info.value) == "PII detection returned invalid match"


def test_run_detectors_fails_closed_when_no_detectors_are_configured() -> None:
    markdown = "Customer: Alice"

    with pytest.raises(DetectionError) as error_info:
        run_detectors(
            markdown,
            [],
        )

    assert str(error_info.value) == "No PII detectors configured"


def test_run_detectors_rejects_non_string_pii_type() -> None:
    markdown = "Customer: Alice"
    value = "Alice"
    start = markdown.index(value)

    invalid_match = PiiMatch(
        pii_type=None,  # type: ignore[arg-type]
        value=value,
        start=start,
        end=start + len(value),
    )

    def invalid_detector(_: str) -> list[PiiMatch]:
        return [invalid_match]

    with pytest.raises(DetectionError) as error_info:
        run_detectors(markdown, [invalid_detector])

    assert str(error_info.value) == "PII detection returned invalid match"


def test_run_detectors_canonicalizes_types_and_sorts_matches_by_source() -> None:
    markdown = "Bob met Alice"
    bob = PiiMatch("name", "Bob", 0, 3)
    alice = PiiMatch(" Name ", "Alice", 8, 13)

    def later_match(_: str) -> list[PiiMatch]:
        return [alice]

    def earlier_match(_: str) -> list[PiiMatch]:
        return [bob]

    _, matches = run_detectors(markdown, [later_match, earlier_match])

    assert matches == [
        PiiMatch("NAME", "Bob", 0, 3),
        PiiMatch("NAME", "Alice", 8, 13),
    ]


@pytest.mark.parametrize(
    ("value", "start", "end"),
    [
        (None, 10, 15),
        ("Alice", "10", 15),
        ("Alice", 10, None),
    ],
)
def test_run_detectors_rejects_invalid_match_field_types(
    value: object,
    start: object,
    end: object,
) -> None:
    markdown = "Customer: Alice"
    invalid_match = PiiMatch(
        pii_type="NAME",
        value=value,  # type: ignore[arg-type]
        start=start,  # type: ignore[arg-type]
        end=end,  # type: ignore[arg-type]
    )

    def invalid_detector(_: str) -> list[PiiMatch]:
        return [invalid_match]

    with pytest.raises(DetectionError) as error_info:
        run_detectors(markdown, [invalid_detector])

    assert str(error_info.value) == "PII detection returned invalid match"
    assert "Alice" not in str(error_info.value)


def test_run_detectors_rejects_non_callable_detector() -> None:
    with pytest.raises(DetectionError) as error_info:
        run_detectors(
            "Customer: Alice",
            [None],  # type: ignore[list-item]
        )

    assert str(error_info.value) == "PII detector configuration is invalid"


def test_run_detectors_rejects_non_string_source() -> None:
    def detector(_: str) -> list[PiiMatch]:
        return []

    with pytest.raises(DetectionError) as error_info:
        run_detectors(
            None,  # type: ignore[arg-type]
            [detector],
        )

    assert str(error_info.value) == "PII source document is invalid"
