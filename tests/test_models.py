from pii_pipeline.models import PiiCandidate, PiiEntry, PiiMatch, RedactionResult


def test_sensitive_values_are_hidden_from_model_repr() -> None:
    synthetic_pii = "Alice"

    match = PiiMatch(
        pii_type="NAME",
        value=synthetic_pii,
        start=0,
        end=len(synthetic_pii),
    )

    entry = PiiEntry(
        placeholder="[PII_NAME_1]",
        pii_type="NAME",
        occurrence_index=1,
        original_value=synthetic_pii,
    )

    result = RedactionResult(
        redacted_markdown=f"Unverified: {synthetic_pii}",
        entries=(entry,),
    )

    assert synthetic_pii not in repr(match)
    assert synthetic_pii not in repr(entry)
    assert synthetic_pii not in repr(result)


def test_pii_candidate_hides_sensitive_value_from_repr() -> None:
    candidate = PiiCandidate(
        pii_type="NAME",
        value="Alice",
    )

    assert candidate.pii_type == "NAME"
    assert candidate.value == "Alice"
    assert "Alice" not in repr(candidate)
