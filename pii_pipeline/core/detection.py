import unicodedata
from collections.abc import Callable
from inspect import iscoroutine

from .models import PiiCandidate, PiiMatch
from .redaction import is_exact_match, normalize_pii_type

Detector = Callable[[str], list[PiiMatch]]
CandidateExtractor = Callable[[str], list[PiiCandidate]]
RuleValidator = Callable[[str], bool]


class DetectionError(Exception):
    pass


def normalize_unicode(text: str) -> str:
    if not isinstance(text, str):
        raise DetectionError("PII text is invalid")

    return unicodedata.normalize("NFC", text)


def _normalize_pii_type_or_error(pii_type: object, error_message: str) -> str:
    if not isinstance(pii_type, str):
        raise DetectionError(error_message)

    try:
        return normalize_pii_type(pii_type)
    except ValueError:
        raise DetectionError(error_message) from None


def _validate_match(normalized_markdown: str, match: PiiMatch) -> PiiMatch:
    error_message = "PII detection returned invalid match"

    pii_type = _normalize_pii_type_or_error(match.pii_type, error_message)

    if not isinstance(match.value, str):
        raise DetectionError(error_message)

    if type(match.start) is not int or type(match.end) is not int:
        raise DetectionError(error_message)

    if not is_exact_match(normalized_markdown, match):
        raise DetectionError(error_message)

    return PiiMatch(
        pii_type=pii_type,
        value=match.value,
        start=match.start,
        end=match.end,
    )


def validate_detection_matches(
    normalized_markdown: str,
    detector_matches: object,
) -> list[PiiMatch]:
    """Validate detector output without invoking a detector a second time."""

    if (
        not isinstance(normalized_markdown, str)
        or normalize_unicode(normalized_markdown) != normalized_markdown
    ):
        raise DetectionError("PII source document is invalid")

    if iscoroutine(detector_matches):
        detector_matches.close()

    if not isinstance(detector_matches, list) or not all(
        isinstance(match, PiiMatch) for match in detector_matches
    ):
        raise DetectionError("PII detection returned invalid result")

    return [_validate_match(normalized_markdown, match) for match in detector_matches]


def run_detectors(
    markdown: str,
    detectors: list[Detector],
) -> tuple[str, list[PiiMatch]]:
    if not isinstance(markdown, str):
        raise DetectionError("PII source document is invalid")

    if not isinstance(detectors, list) or not detectors:
        raise DetectionError("No PII detectors configured")

    normalized_markdown = normalize_unicode(markdown)
    matches: list[PiiMatch] = []

    for detector in detectors:
        if not callable(detector):
            raise DetectionError("PII detector configuration is invalid")

        try:
            detector_matches = detector(normalized_markdown)
        # Detector implementations are external boundaries; any failure must fail closed.
        except Exception:  # noqa: BLE001
            raise DetectionError("PII detection failed") from None

        matches.extend(
            validate_detection_matches(normalized_markdown, detector_matches)
        )

    ordered_matches = sorted(
        matches,
        key=lambda match: (match.start, match.end, match.pii_type),
    )

    return normalized_markdown, ordered_matches
