import os
import traceback

import httpx
import pytest

from pii_pipeline.llm.client import LlmProxyClient
from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm.processing import LlmDocumentProcessor
from pii_pipeline.llm.windows import TextWindow, WindowContractError, make_text_window


@pytest.fixture(autouse=True)
def isolate_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(name)


def settings() -> LlmProxySettings:
    return LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-secret",
        max_retries=0,
        _env_file=None,
    )


def success(output: dict[str, object]) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": LLM_PROXY_MODEL,
            "structured_output": output,
        },
    )


def whole_document(source: str) -> list[TextWindow]:
    return [make_text_window(source, 0, len(source))]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation", ["detection_window_planner", "verification_window_planner"]
)
@pytest.mark.parametrize(
    "windows",
    [
        [],
        [TextWindow(1, 13, "lice met Bob")],
        [TextWindow(0, 4, "Alic"), TextWindow(6, 13, "met Bob")],
        [TextWindow(0, 13, "wrong source")],
        [TextWindow(0, 14, "Alice met Bob")],
        [TextWindow(True, 13, "Alice met Bob")],
        (TextWindow(0, 13, "Alice met Bob"),),
    ],
)
async def test_document_processor_rejects_invalid_plan_before_any_llm_call(
    windows, operation: str
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success({"candidates": []})

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        processor = LlmDocumentProcessor(
            client, lambda source: windows, lambda source: windows
        )
        with pytest.raises(WindowContractError):
            processor._plan("Alice met Bob", getattr(processor, operation))

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation", ["detection_window_planner", "verification_window_planner"]
)
async def test_document_processor_sanitizes_planner_failure(operation: str) -> None:
    source = "Synthetic Person"

    def broken_plan(source: str) -> list[TextWindow]:
        raise RuntimeError(f"failed on {source} synthetic-secret")

    async with LlmProxyClient(
        settings(),
        transport=httpx.MockTransport(lambda request: success({"candidates": []})),
    ) as client:
        processor = LlmDocumentProcessor(client, broken_plan, broken_plan)
        with pytest.raises(WindowContractError) as captured:
            processor._plan(source, getattr(processor, operation))

    rendered = "".join(traceback.format_exception(captured.value))
    assert source not in rendered
    assert "synthetic-secret" not in rendered


@pytest.mark.parametrize("bad_planner", [None, [], "whole_document"])
def test_document_processor_requires_explicit_callable_window_planners(
    bad_planner,
) -> None:
    with pytest.raises(WindowContractError):
        LlmDocumentProcessor(object(), bad_planner, whole_document)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation", ["detection_window_planner", "verification_window_planner"]
)
@pytest.mark.parametrize("source", [None, "Cafe\u0301"])
async def test_document_processor_requires_nfc_source_before_planning(
    source, operation: str
) -> None:
    planned: list[str] = []

    def plan(source: str) -> list[TextWindow]:
        planned.append(source)
        return []

    async with LlmProxyClient(
        settings(),
        transport=httpx.MockTransport(lambda request: success({"candidates": []})),
    ) as client:
        processor = LlmDocumentProcessor(client, plan, plan)
        with pytest.raises(WindowContractError):
            processor._plan(source, getattr(processor, operation))

    assert planned == []


@pytest.mark.asyncio
async def test_document_processor_rejects_async_callable_planner_at_configuration() -> (
    None
):
    class AsyncPlanner:
        async def __call__(self, source: str) -> list[TextWindow]:
            return whole_document(source)

    async with LlmProxyClient(
        settings(),
        transport=httpx.MockTransport(lambda request: success({"candidates": []})),
    ) as client:
        with pytest.raises(WindowContractError):
            LlmDocumentProcessor(client, AsyncPlanner(), whole_document)
