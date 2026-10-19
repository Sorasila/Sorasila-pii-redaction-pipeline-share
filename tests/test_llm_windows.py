import pytest

from pii_pipeline.llm_response import (
    VerificationFinding,
    VerificationResponse,
    parse_verification_response,
)
from pii_pipeline.llm_windows import (
    TextWindow,
    VerificationWindowResult,
    WindowContractError,
    aggregate_verification_window_results,
    make_text_window,
)


def test_make_text_window_uses_exact_document_slice_and_hides_text_from_repr() -> None:
    window = make_text_window("Alice met Bob", 6, 13)

    assert window == TextWindow(6, 13, "met Bob")
    assert "met Bob" not in repr(window)


@pytest.mark.parametrize(
    ("source", "start", "end"),
    [
        ("Alice", True, 5),
        ("Alice", 0, False),
        ("Alice", -1, 5),
        ("Alice", 5, 5),
        ("Alice", 0, 6),
    ],
)
def test_make_text_window_rejects_invalid_bounds(
    source: str,
    start: object,
    end: object,
) -> None:
    with pytest.raises(WindowContractError, match="text window is invalid"):
        make_text_window(source, start, end)  # type: ignore[arg-type]


def test_make_text_window_requires_nfc_document() -> None:
    with pytest.raises(WindowContractError, match="source is invalid"):
        make_text_window("Cafe\u0301", 0, 5)


def test_aggregate_verification_translates_and_deduplicates_findings() -> None:
    document = "xxAlice yy"
    first_window = make_text_window(document, 0, 7)
    second_window = make_text_window(document, 2, 10)
    results = [
        VerificationWindowResult(
            first_window,
            VerificationResponse(
                has_pii=True,
                findings=(VerificationFinding("NAME", 2, 7),),
            ),
        ),
        VerificationWindowResult(
            second_window,
            VerificationResponse(
                has_pii=True,
                findings=(VerificationFinding("NAME", 0, 5),),
            ),
        ),
    ]

    assert aggregate_verification_window_results(document, results) == (
        VerificationResponse(
            has_pii=True,
            findings=(VerificationFinding("NAME", 2, 7),),
        )
    )


def test_verification_parser_composes_with_window_aggregation() -> None:
    document = "xxAlice yy"
    first_window = make_text_window(document, 0, 7)
    second_window = make_text_window(document, 2, 10)
    first_response = parse_verification_response(
        first_window.text,
        {
            "has_pii": True,
            "findings": [{"pii_type": "NAME"}],
        },
    )
    second_response = parse_verification_response(
        second_window.text,
        {
            "has_pii": True,
            "findings": [{"pii_type": "NAME"}],
        },
    )

    assert aggregate_verification_window_results(
        document,
        [
            VerificationWindowResult(first_window, first_response),
            VerificationWindowResult(second_window, second_response),
        ],
    ) == VerificationResponse(
        has_pii=True,
        findings=(
            VerificationFinding("NAME", 0, 7, location_scope="window"),
            VerificationFinding("NAME", 2, 10, location_scope="window"),
        ),
    )


def test_aggregate_verification_preserves_scopes_for_same_interval() -> None:
    document = "Alice"
    window = make_text_window(document, 0, len(document))
    reported = VerificationResponse(True, (VerificationFinding("NAME", 0, 5),))
    inspected = parse_verification_response(
        window.text, {"has_pii": True, "findings": [{"pii_type": "NAME"}]}
    )

    result = aggregate_verification_window_results(
        document,
        [
            VerificationWindowResult(window, reported),
            VerificationWindowResult(window, inspected),
        ],
    )

    assert result.has_pii is True
    assert len(result.findings) == 2
    assert {finding.location_scope for finding in result.findings} == {
        "reported",
        "window",
    }
    assert all((finding.start, finding.end) == (0, 5) for finding in result.findings)


def test_aggregate_verification_deduplicates_same_inspected_window_type() -> None:
    document = "Alice"
    window = make_text_window(document, 0, len(document))
    response = parse_verification_response(
        window.text, {"has_pii": True, "findings": [{"pii_type": "NAME"}]}
    )

    assert (
        aggregate_verification_window_results(
            document,
            [
                VerificationWindowResult(window, response),
                VerificationWindowResult(window, response),
            ],
        )
        == response
    )


@pytest.mark.parametrize("start,end", [(1, 5), (0, 4), (1, 4)])
def test_aggregate_verification_requires_window_scope_to_cover_whole_local_text(
    start: int,
    end: int,
) -> None:
    document = "Alice"
    window = make_text_window(document, 0, len(document))
    response = VerificationResponse(
        True, (VerificationFinding("NAME", start, end, location_scope="window"),)
    )

    with pytest.raises(WindowContractError, match="verification result is invalid"):
        aggregate_verification_window_results(
            document, [VerificationWindowResult(window, response)]
        )


@pytest.mark.parametrize("invalid_scope", ["exact", "NAME", None, True])
def test_aggregate_verification_rejects_unknown_location_scope(
    invalid_scope: object,
) -> None:
    document = "Alice"
    window = make_text_window(document, 0, len(document))
    finding = VerificationFinding("NAME", 0, len(document))
    object.__setattr__(finding, "location_scope", invalid_scope)
    response = VerificationResponse(True, (finding,))

    with pytest.raises(WindowContractError, match="verification result is invalid"):
        aggregate_verification_window_results(
            document, [VerificationWindowResult(window, response)]
        )


def test_aggregate_verification_returns_clean_for_clean_covering_windows() -> None:
    document = "No protected data"
    first_window = make_text_window(document, 0, 10)
    second_window = make_text_window(document, 8, len(document))
    clean = VerificationResponse(has_pii=False, findings=())

    assert aggregate_verification_window_results(
        document,
        [
            VerificationWindowResult(second_window, clean),
            VerificationWindowResult(first_window, clean),
        ],
    ) == VerificationResponse(has_pii=False, findings=())


def test_aggregate_verification_rejects_inconsistent_local_response() -> None:
    document = "Alice"
    window = make_text_window(document, 0, 5)
    inconsistent = VerificationResponse(has_pii=False, findings=())
    object.__setattr__(inconsistent, "has_pii", True)

    with pytest.raises(WindowContractError, match="verification result is invalid"):
        aggregate_verification_window_results(
            document,
            [VerificationWindowResult(window, inconsistent)],
        )


@pytest.mark.parametrize(
    "finding",
    [
        VerificationFinding("name", 0, 5),
        VerificationFinding("NAME", True, 5),
        VerificationFinding("NAME", 0, 6),
    ],
)
def test_aggregate_verification_rejects_invalid_local_finding(
    finding: VerificationFinding,
) -> None:
    document = "Alice"
    window = make_text_window(document, 0, 5)
    response = VerificationResponse(has_pii=True, findings=(finding,))

    with pytest.raises(WindowContractError, match="verification result is invalid"):
        aggregate_verification_window_results(
            document,
            [VerificationWindowResult(window, response)],
        )
