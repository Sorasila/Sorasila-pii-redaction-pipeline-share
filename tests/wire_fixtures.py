"""Offline golden occurrence decisions for historical synthetic smoke cases.

The old stage handlers still model extraction/verification responses. This
adapter supplies the new intervening selection response from the frozen span
oracle, independently of the production resolver. Physical-request budgets are
tested separately; old handler counters describe primary stages only.
"""

import inspect
import json
import re
from urllib.parse import parse_qs

import httpx
import pytest

from pii_pipeline.llm_config import LLM_PROXY_MODEL
from smoke_llm import SMOKE_CASES


def decisions_for_plan(plan, expected_matches):
    expected = {(match.start, match.end): match.pii_type for match in expected_matches}
    return {
        "decisions": [
            {
                "occurrence_id": item.occurrence_id,
                "pii_type": expected.get((item.start, item.end), "NOT_PII"),
            }
            for item in plan.occurrences
        ]
    }


@pytest.fixture
def golden_selection_transport(monkeypatch, request):
    # These tests deliberately return WRONG occurrence decisions to exercise the oracle.
    if request.function.__name__ in {
        "test_equal_administrative_value_is_rejected_before_redaction_even_with_same_type_and_count",
        "test_birthday_smoke_rejects_document_date_false_positive_before_verification",
        "test_failed_birthday_smoke_reports_safe_match_diagnostics_and_stops",
        "test_smoke_rejects_incomplete_detection_before_verification",
    }:
        return
    original_init = httpx.MockTransport.__init__

    def init(transport, handler):
        async def wrapped(request):
            form = parse_qs(request.content.decode("utf-8"))
            schema = json.loads(form["json_schema"][0])
            if set(schema.get("properties", {})) != {"decisions"}:
                response = handler(request)
                return await response if inspect.isawaitable(response) else response
            annotated = json.loads(form["context"][0])["annotated_source"]
            spans = {}
            pieces = []
            cursor = 0
            source_position = 0
            for marker in re.finditer(r"<(\/?)PII_OCCURRENCE_\d+_(\d+)>", annotated):
                text = annotated[cursor : marker.start()]
                pieces.append(text)
                source_position += len(text)
                occurrence_id = int(marker[2])
                if marker[1]:
                    spans[occurrence_id].append(source_position)
                else:
                    spans[occurrence_id] = [source_position]
                cursor = marker.end()
            pieces.append(annotated[cursor:])
            source = "".join(pieces)
            case = next(case for case in SMOKE_CASES.values() if case.text == source)
            expected = {
                (match.start, match.end): match.pii_type
                for match in case.expected_matches
            }
            output = {
                "decisions": [
                    {
                        "occurrence_id": occurrence_id,
                        "pii_type": expected.get(tuple(span), "NOT_PII"),
                    }
                    for occurrence_id, span in spans.items()
                ]
            }
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "model": LLM_PROXY_MODEL,
                    "structured_output": output,
                },
            )

        original_init(transport, wrapped)

    monkeypatch.setattr(httpx.MockTransport, "__init__", init)
