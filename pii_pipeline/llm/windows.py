import unicodedata
from dataclasses import dataclass, field

from ..core.pii_types import canonicalize_pii_type
from .response import VerificationFinding, VerificationResponse


class WindowContractError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TextWindow:
    """An NFC document slice whose offsets are relative to the full document."""

    document_start: int
    document_end: int
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class VerificationWindowResult:
    """Validated local verification response for one text window."""

    window: TextWindow
    response: VerificationResponse


def _is_nfc_text(value: object) -> bool:
    return isinstance(value, str) and unicodedata.normalize("NFC", value) == value


def _require_nfc_document(normalized_document: object) -> str:
    if not _is_nfc_text(normalized_document):
        raise WindowContractError("LLM window source is invalid")

    return normalized_document


def _validate_window(normalized_document: str, window: object) -> TextWindow:
    if not isinstance(window, TextWindow):
        raise WindowContractError("LLM text window is invalid")

    start = window.document_start
    end = window.document_end

    if (
        type(start) is not int
        or type(end) is not int
        or not 0 <= start < end <= len(normalized_document)
        or not isinstance(window.text, str)
        or normalized_document[start:end] != window.text
    ):
        raise WindowContractError("LLM text window is invalid")

    return window


def make_text_window(
    normalized_document: str,
    document_start: int,
    document_end: int,
) -> TextWindow:
    """Create a window by slicing an exact NFC-normalized source document."""

    source = _require_nfc_document(normalized_document)

    if (
        type(document_start) is not int
        or type(document_end) is not int
        or not 0 <= document_start < document_end <= len(source)
    ):
        raise WindowContractError("LLM text window is invalid")

    return TextWindow(
        document_start=document_start,
        document_end=document_end,
        text=source[document_start:document_end],
    )


def validate_text_windows(
    normalized_document: str,
    windows: object,
) -> tuple[TextWindow, ...]:
    """Validate full coverage before any external call and freeze source order."""

    source = _require_nfc_document(normalized_document)
    if not isinstance(windows, list):
        raise WindowContractError("LLM text windows are invalid")

    if not source:
        if windows:
            raise WindowContractError("LLM text windows are invalid")
        return ()

    if not windows:
        raise WindowContractError("LLM windows do not cover source document")

    for window in windows:
        _validate_window(source, window)

    ordered_windows = sorted(
        windows, key=lambda window: (window.document_start, window.document_end)
    )
    covered_until = 0
    for window in ordered_windows:
        if window.document_start > covered_until:
            raise WindowContractError("LLM windows do not cover source document")
        covered_until = max(covered_until, window.document_end)

    if covered_until != len(source):
        raise WindowContractError("LLM windows do not cover source document")

    return tuple(ordered_windows)


def _validate_complete_window_results(
    normalized_document: str,
    results: object,
    result_type: type[VerificationWindowResult],
) -> list[VerificationWindowResult]:
    if not isinstance(results, list) or not all(
        isinstance(result, result_type) for result in results
    ):
        raise WindowContractError("LLM window results are invalid")

    validate_text_windows(normalized_document, [result.window for result in results])
    return sorted(
        results,
        key=lambda result: (
            result.window.document_start,
            result.window.document_end,
        ),
    )


def _validate_local_verification_finding(
    window: TextWindow,
    finding: object,
) -> VerificationFinding:
    if not isinstance(finding, VerificationFinding):
        raise WindowContractError("LLM window verification result is invalid")

    try:
        pii_type = canonicalize_pii_type(finding.pii_type)
    except (TypeError, ValueError):
        raise WindowContractError("LLM window verification result is invalid") from None

    if (
        pii_type != finding.pii_type
        or type(finding.start) is not int
        or type(finding.end) is not int
        or not 0 <= finding.start < finding.end <= len(window.text)
        or type(finding.location_scope) is not str
        or finding.location_scope not in {"reported", "window"}
        or (
            finding.location_scope == "window"
            and (finding.start != 0 or finding.end != len(window.text))
        )
    ):
        raise WindowContractError("LLM window verification result is invalid")

    return finding


def aggregate_verification_window_results(
    normalized_redacted_document: str,
    results: list[VerificationWindowResult],
) -> VerificationResponse:
    """Translate and deduplicate local residual-PII findings."""

    source = _require_nfc_document(normalized_redacted_document)
    ordered_results = _validate_complete_window_results(
        source,
        results,
        VerificationWindowResult,
    )
    unique_findings: dict[tuple[str, int, int, str], VerificationFinding] = {}

    for result in ordered_results:
        response = result.response

        if (
            not isinstance(response, VerificationResponse)
            or type(response.has_pii) is not bool
            or not isinstance(response.findings, tuple)
            or response.has_pii != bool(response.findings)
        ):
            raise WindowContractError("LLM window verification result is invalid")

        for local_finding in response.findings:
            finding = _validate_local_verification_finding(
                result.window,
                local_finding,
            )
            document_finding = VerificationFinding(
                pii_type=finding.pii_type,
                start=result.window.document_start + finding.start,
                end=result.window.document_start + finding.end,
                location_scope=finding.location_scope,
            )
            key = (
                document_finding.pii_type,
                document_finding.start,
                document_finding.end,
                document_finding.location_scope,
            )
            unique_findings[key] = document_finding

    findings = tuple(
        sorted(
            unique_findings.values(),
            key=lambda finding: (
                finding.start,
                finding.end,
                finding.pii_type,
                finding.location_scope,
            ),
        )
    )

    return VerificationResponse(
        has_pii=bool(findings),
        findings=findings,
    )
