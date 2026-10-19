from collections import Counter

"""Per-request LLM call counts: by role, HTTP attempts and recovery kinds."""

import asyncio
import json
import os
import re
from urllib.parse import parse_qs

import httpx
import pytest

from pii_pipeline.llm.call_stats import collect_call_stats, record, role_of
from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm.schema import (
    build_detection_response_schema,
    build_occurrence_selection_schema,
    build_verification_response_schema,
)
from pii_pipeline.service import ServiceSettings, create_service_app

TOKEN = "t" * 40
# No title: a repeated name with a title is settled without the LLM (3.1).
NAME = "สมมุติ ทดลองดี"


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_")):
            monkeypatch.delenv(name)


def test_recording_outside_a_collection_is_a_no_op():
    record("llm_detection")
    with collect_call_stats() as outer:
        record("llm_detection")
        with collect_call_stats() as inner:
            record("llm_verification")
        record("http_attempts")
    assert outer == {"llm_detection": 1, "http_attempts": 1}
    assert inner == {"llm_verification": 1}


def test_roles_follow_the_response_schema():
    assert role_of(build_detection_response_schema()) == "detection"
    assert role_of(build_verification_response_schema()) == "verification"
    assert role_of(build_occurrence_selection_schema([1, 2])) == "selection"
    assert role_of({"properties": {"other": {}}}) == "other"
    assert role_of(None) == "other"


def success(output):
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": LLM_PROXY_MODEL,
            "structured_output": output,
        },
    )


def make_wire(*, blank_first=False, unavailable_first=False):
    """Mock proxy: optional blank reply, then the repeated NAME needing selection."""
    seen = {"detection": 0, "http": 0}

    def wire(request):
        seen["http"] += 1
        if unavailable_first and seen["http"] == 1:
            return httpx.Response(503)
        form = {key: v[0] for key, v in parse_qs(request.content.decode()).items()}
        role = role_of(json.loads(form["json_schema"]))
        if role == "detection":
            seen["detection"] += 1
            if blank_first and seen["detection"] == 1:
                return success({"extracted_text": ""})
            return success({"candidates": [{"pii_type": "NAME", "value": NAME}]})
        if role == "selection":
            occurrences = json.loads(form["context"])["occurrences"]
            return success(
                {
                    "decisions": [
                        {"occurrence_id": item["occurrence_id"], "pii_type": "NAME"}
                        for item in occurrences
                    ]
                }
            )
        return success({"has_pii": False, "findings": []})

    return wire


def app_for(wire, max_retries=0):
    return create_service_app(
        ServiceSettings(
            api_token=TOKEN, allow_unencrypted_test_manifest=True, _env_file=None
        ),
        LlmProxySettings(
            base_url="https://proxy.example",
            api_key="k",
            max_retries=max_retries,
            retry_backoff_seconds=0.01,
            _env_file=None,
        ),
        llm_transport=httpx.MockTransport(wire),
    )


async def post_pages(app, count=1):
    # The same value twice makes detection ask the model to select occurrences.
    body = f"ผู้ฟ้องคดี {NAME}\nพยาน {NAME}".encode()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://service.local"
        ) as caller,
    ):
        return await asyncio.gather(
            *(
                caller.post(
                    "/redact",
                    content=body,
                    headers={
                        "content-type": "text/markdown; charset=utf-8",
                        "authorization": f"Bearer {TOKEN}",
                    },
                )
                for _ in range(count)
            )
        )


def log_fields(caplog):
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.name == "pii_pipeline.http_api"
    ]
    return [dict(re.findall(r"(\w+)=(\S+)", line)) for line in lines]


@pytest.mark.asyncio
async def test_log_counts_calls_inside_detection_and_blank_resends(caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    (response,) = await post_pages(app_for(make_wire(blank_first=True)))
    assert response.status_code == 200
    (fields,) = log_fields(caplog)
    # Blank detection, detection, occurrence selection, verification.
    assert fields["llm_calls"] == "4"
    assert fields["by_role"] == "detection:2,selection:1,verification:1"
    assert fields["http_attempts"] == "4"
    assert fields["blank_resends"] == "detection:1"
    assert fields["repairs"] == "0"
    assert fields["residual_rounds"] == "0"
    # The selection inside detection is not a budgeted role call.
    assert fields["role_calls"] == "3"


@pytest.mark.asyncio
async def test_transport_retries_show_as_extra_http_attempts(caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    (response,) = await post_pages(app_for(make_wire(unavailable_first=True), 1))
    assert response.status_code == 200
    (fields,) = log_fields(caplog)
    assert fields["llm_calls"] == "3"
    assert fields["http_attempts"] == "4"
    assert fields["attempt_seconds"] == (
        "detection:http_503@0,detection:0,selection:0,verification:0"
    )


@pytest.mark.asyncio
async def test_concurrent_requests_keep_separate_counts(caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    responses = await post_pages(app_for(make_wire()), count=3)
    assert [response.status_code for response in responses] == [200, 200, 200]
    fields = log_fields(caplog)
    assert len(fields) == 3
    assert {line["by_role"] for line in fields} == {
        "detection:1,selection:1,verification:1"
    }
    assert {line["http_attempts"] for line in fields} == {"3"}


def test_selection_calls_and_settled_copies_are_counted():
    from pii_pipeline.llm.call_stats import record_selection, record_settled
    from pii_pipeline.service.request_log import selection_summary

    with collect_call_stats() as calls:
        record_selection("occurrence", [(("NAME",), "สมชาย ใจดี")])
        record_selection("occurrence", [(("NAME", "ORGANIZATION"), "สมชาย")])
        record_selection("conflict", [(("NAME",), "a"), (("ADDRESS",), "b")])
        record_settled(3)
    assert selection_summary(calls) == (
        "occurrence:2;occurrence_types:NAME_2+ORGANIZATION_1;"
        "conflict:1;conflict_types:ADDRESS_1+NAME_1;settled_without_llm:3"
    )
    with collect_call_stats() as calls:
        record_settled(2)  # every copy settled: no selection call at all
    assert selection_summary(calls) == "settled_without_llm:2"
    assert selection_summary(Counter()) == "-"


def test_attempt_seconds_show_time_and_outcome_in_order():
    from pii_pipeline.llm.call_stats import record_attempt
    from pii_pipeline.service.request_log import attempt_summary

    with collect_call_stats() as calls:
        record_attempt("detection", 300.2, "timeout")
        record_attempt("detection", 199.6, "cut")
        record_attempt("detection", 141.7, "ok")
        record_attempt("verification", 300.1, "http_504")
        record_attempt("verification", 88.4, "ok")
    record_attempt("detection", 5, "ok")  # outside a collection: ignored
    assert attempt_summary(calls) == (
        "detection:timeout@300,detection:cut@200,detection:142,"
        "verification:http_504@300,verification:88"
    )
    assert attempt_summary(Counter()) == "-"


@pytest.mark.asyncio
async def test_an_attempt_cut_by_the_call_deadline_is_logged_as_cut(caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")

    async def silent_then_answer(request):
        if not silent_then_answer.done:
            silent_then_answer.done = True
            await asyncio.sleep(5)
        return make_wire()(request)

    silent_then_answer.done = False
    app = create_service_app(
        ServiceSettings(
            api_token=TOKEN, allow_unencrypted_test_manifest=True, _env_file=None
        ),
        LlmProxySettings(
            base_url="https://proxy.example",
            api_key="k",
            connect_timeout_seconds=0.2,
            read_timeout_seconds=0.2,
            write_timeout_seconds=0.2,
            pool_timeout_seconds=0.2,
            request_deadline_seconds=0.2,
            max_retries=0,
            _env_file=None,
        ),
        llm_transport=httpx.MockTransport(silent_then_answer),
    )
    (response,) = await post_pages(app)
    (fields,) = log_fields(caplog)
    first = fields["attempt_seconds"].split(",")[0]
    assert first == "detection:cut@0"
    assert response.status_code == 200


# Measurement for proposal C10 (approved 2026-10-19): why windows are repaired.


@pytest.mark.asyncio
async def test_repair_reasons_name_the_issue_that_caused_each_repair(caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    detections = []

    def wire(request):
        form = {key: v[0] for key, v in parse_qs(request.content.decode()).items()}
        if role_of(json.loads(form["json_schema"])) != "detection":
            return success({"has_pii": False, "findings": []})
        detections.append(1)
        if len(detections) == 1:
            # A value that is not in the page: value_not_found, so a repair.
            return success({"candidates": [{"pii_type": "NAME", "value": "ไม่มีในหน้านี้"}]})
        return success({"candidates": [{"pii_type": "NAME", "value": NAME}]})

    app = app_for(wire)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://service.local"
        ) as caller,
    ):
        response = await caller.post(
            "/redact",
            content=f"ผู้ฟ้องคดี {NAME}".encode(),
            headers={
                "content-type": "text/markdown; charset=utf-8",
                "authorization": f"Bearer {TOKEN}",
            },
        )
    assert response.status_code == 200
    (fields,) = log_fields(caplog)
    assert fields["repairs"] == "1"
    assert fields["repair_reasons"] == "value_not_found:1"


def test_repair_summary_counts_each_code_once_per_repair():
    from pii_pipeline.llm.call_stats import record_repair_reasons
    from pii_pipeline.service.request_log import repair_summary

    with collect_call_stats() as calls:
        record_repair_reasons(["value_not_found", "value_not_found", "invalid_value"])
        record_repair_reasons(["detection_unavailable"])
        record_repair_reasons(["value_not_found"])
    assert repair_summary(calls) == (
        "detection_unavailable:1,invalid_value:1,value_not_found:2"
    )
    assert repair_summary(Counter()) == "-"
