"""Which failed LLM replies are blank (cheap to re-send) or recoverable."""

from ..llm.proxy import LlmProxyResponseError, is_recoverable_proxy_error
from ..llm.response import DetectionResponseError, VerificationResponseError

# Fast replies that carry nothing usable: an empty or non-schema structured
# output, or a failed generation. Timeouts and HTTP/transport failures are
# slow and stay on the counted recovery path.
BLANK_PROXY_CODES = frozenset(
    {"invalid_json", "invalid_structured_output", "unsuccessful_envelope"}
)
BLANK_DETECTION_CODES = frozenset({"invalid_response_shape", "candidates_not_list"})


def is_blank_proxy_error(error):
    return (
        isinstance(error, LlmProxyResponseError)
        and error.reason_code in BLANK_PROXY_CODES
    )


def is_blank_detection_outcome(outcome):
    """Nothing located and every issue says the reply was not the schema."""
    return (
        not outcome.matches
        and bool(outcome.issues)
        and all(issue.reason_code in BLANK_DETECTION_CODES for issue in outcome.issues)
    )


def is_blank_verification_error(error):
    return (
        isinstance(error, VerificationResponseError)
        and error.reason_code == "invalid_response_shape"
    ) or is_blank_proxy_error(error)


def is_blank_selection_error(error):
    return (
        isinstance(error, DetectionResponseError)
        and error.reason_code == "invalid_selection_shape"
    ) or is_blank_proxy_error(error)


def is_recoverable_detection_error(error):
    return (
        isinstance(error, DetectionResponseError)
        and error.reason_code not in {"invalid_source", "invalid_resolved_span"}
    ) or is_recoverable_proxy_error(error)


def is_recoverable_verification_error(error):
    return isinstance(error, VerificationResponseError) or is_recoverable_proxy_error(
        error
    )
