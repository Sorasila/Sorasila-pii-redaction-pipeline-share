import re

import pytest

from pii_pipeline.models import PiiMatch
from pii_pipeline.verification import (
    VerificationError,
    make_detection_checker,
)


def regex_detector(pii_type, pattern):
    """A minimal rule-lane detector: every regex match is a PiiMatch."""

    def detector(markdown):
        return [
            PiiMatch(pii_type, match.group(0), match.start(), match.end())
            for match in pattern.finditer(markdown)
        ]

    return detector


def finds_no_pii(markdown: str) -> bool:
    return False


def finds_pii(markdown: str) -> bool:
    return True


def checker_fails(markdown: str) -> bool:
    raise RuntimeError("simulated checker failure")


def returns_invalid_result(markdown: str) -> bool:
    return None


def checker_times_out(markdown: str) -> bool:
    raise TimeoutError("simulated timeout")


def test_detection_checker_adapts_rule_matches_to_boolean_result() -> None:
    rule_detector = regex_detector("PHONE", re.compile(r"(?<![0-9])0[0-9]{9}(?![0-9])"))
    checker = make_detection_checker([rule_detector])

    assert checker("Contact: 0812345678") is True
    assert checker("No contact number") is False


@pytest.mark.parametrize(
    "detectors",
    [
        [],
        None,
        "invalid",
        b"invalid",
        [None],
    ],
)
def test_detection_checker_rejects_invalid_configuration(
    detectors: object,
) -> None:
    with pytest.raises(VerificationError) as captured_error:
        make_detection_checker(detectors)  # type: ignore[arg-type]

    assert str(captured_error.value) == "Verification detector configuration is invalid"


def test_detection_checker_sanitizes_detector_failure() -> None:
    def broken_detector(_: str) -> list[object]:
        raise RuntimeError("failed while processing Alice")

    checker = make_detection_checker([broken_detector])  # type: ignore[list-item]

    with pytest.raises(VerificationError) as captured_error:
        checker("Alice")

    assert str(captured_error.value) == "Verification detection failed"
    assert "Alice" not in str(captured_error.value)
