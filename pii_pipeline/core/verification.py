from collections.abc import Callable, Sequence
from inspect import iscoroutine

from .detection import Detector, run_detectors

VerificationChecker = Callable[[str], bool]


class VerificationError(Exception):
    pass


def make_detection_checker(
    detectors: Sequence[Detector],
) -> VerificationChecker:
    if isinstance(detectors, (str, bytes)) or not isinstance(detectors, Sequence):
        raise VerificationError("Verification detector configuration is invalid")

    if not detectors or not all(callable(detector) for detector in detectors):
        raise VerificationError("Verification detector configuration is invalid")

    configured_detectors = list(detectors)

    def checker(markdown: str) -> bool:
        try:
            _, matches = run_detectors(markdown, configured_detectors)
        except Exception:  # noqa: BLE001
            raise VerificationError("Verification detection failed") from None

        return bool(matches)

    return checker


def run_verification_checker(
    markdown: str,
    checker: VerificationChecker,
    *,
    checker_name: str,
) -> bool:
    # Checker implementations are external boundaries; any failure must fail closed.
    try:
        found_pii = checker(markdown)
    except Exception:  # noqa: BLE001
        raise VerificationError(f"{checker_name} verification failed") from None

    if iscoroutine(found_pii):
        found_pii.close()

    if not isinstance(found_pii, bool):
        raise VerificationError(f"{checker_name} verification returned invalid result")

    return found_pii
