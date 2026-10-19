"""Replay recorded proxy replies: requests and outputs must match the goldens.

The goldens in tests/replay/ were built from the code before the structural
refactor (see replay_scenarios.py). A failure here means behaviour changed:
fix the code, never the golden, unless the change was approved.
"""

import json
import os
from pathlib import Path

import pytest
from replay_support import ReplayTransport, run_pipeline, run_service

GOLDENS = sorted((Path(__file__).parent / "replay").glob("*.json"))


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_")):
            monkeypatch.delenv(name)


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_goldens_cover_every_scenario():
    from replay_scenarios import REJECTIONS, SCENARIOS

    assert {path.stem for path in GOLDENS} == {*SCENARIOS, *REJECTIONS}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", GOLDENS, ids=[path.stem for path in GOLDENS])
async def test_service_replays_the_golden(path):
    golden = load(path)
    transport = ReplayTransport(golden["calls"])
    request = golden.get("request", {})
    body = request.get("body_utf8")
    service = await run_service(
        golden["source"],
        transport,
        body=None if body is None else body.encode("utf-8"),
        headers=request.get("headers"),
    )
    assert transport.mismatches == []
    assert transport.finished, f"only {transport.used} of {len(golden['calls'])} calls"
    assert service == golden["service"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [path for path in GOLDENS if "pipeline" in load(path)],
    ids=lambda path: path.stem,
)
async def test_pipeline_replays_the_golden(path):
    golden = load(path)
    transport = ReplayTransport(golden["calls"])
    pipeline = await run_pipeline(golden["source"], transport)
    assert transport.mismatches == []
    assert transport.finished
    assert pipeline == golden["pipeline"]
