"""Page tools: split a document, plan harness windows, record and replay pages."""

import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import httpx
import pytest
from replay_scenarios import detect, scripted, verify
from replay_support import llm_settings

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "pdf-core-test"))
import pdf_to_pipeline as bridge

SOURCE = (
    "คำพิพากษา\n\nโจทก์ นายสมชาย ใจดี ยื่นฟ้อง\n\n"
    + "ข้อความทั่วไปของคดี " * 30
    + "\n\nโฉนดเลขที่ 1234 ตำบลบางพลี อำเภอบางพลี จังหวัดสมุทรปราการ\n\n"
    + "ข้อความทั่วไป " * 20
    + "\n"
)


def load_tool(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


split = load_tool("split_md_pages")
plan_windows = load_tool("plan_windows_from_pages")
record = load_tool("record_replay_pages")
replay = load_tool("replay_pages")
http_runner = load_tool("run_pages_via_http")


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_")):
            monkeypatch.delenv(name)


# --- split_md_pages.py ----------------------------------------------------


@pytest.mark.parametrize("max_chars", [100, 150, 400])
def test_pages_reproduce_the_input_within_the_limit(max_chars):
    pages = split.plan_pages(SOURCE, max_chars)
    assert "".join(SOURCE[start:end] for start, end, _ in pages) == SOURCE
    assert all(0 < end - start <= max_chars for start, end, _ in pages)
    assert [start for start, _, _ in pages[1:]] == [end for _, end, _ in pages[:-1]]


def test_pages_prefer_a_paragraph_break_then_a_line_then_whitespace():
    text = "ก" * 60 + "\n\n" + "ข" * 60 + "\n" + "ค" * 30 + " " + "ง" * 30
    kinds = [kind for *_, kind in split.plan_pages(text, 100)]
    assert kinds == ["paragraph", "line", "end"]
    assert [kind for *_, kind in split.plan_pages("ก" * 250, 100)] == [
        "hard",
        "hard",
        "end",
    ]


def test_a_blank_tail_joins_the_previous_page():
    text = "ก" * 90 + "\n\n" + "ข" * 50 + "\n\n   \n"
    pages = split.plan_pages(text, 100)
    assert all(text[start:end].strip() for start, end, _ in pages)
    assert pages[-1][1] == len(text)


def test_split_writes_new_files_and_counts_only(tmp_path, capsys):
    source = tmp_path / "doc.md"
    source.write_text(SOURCE, encoding="utf-8", newline="")
    out = tmp_path / "pages"
    assert (
        split.main([str(source), "--output-dir", str(out), "--max-chars", "150"]) == 0
    )
    index = json.loads((out / "index.json").read_text(encoding="utf-8"))
    files = [out / page["file"] for page in index["pages"]]
    assert "".join(f.read_bytes().decode("utf-8") for f in files) == SOURCE
    printed = capsys.readouterr().out
    assert "สมชาย" not in printed and "SPLIT_COMPLETE" in printed
    # An existing folder is never written into.
    assert split.main([str(source), "--output-dir", str(out)]) == 1


# --- plan_windows_from_pages.py + record/replay_pages.py ------------------


def prepared_work_dir(tmp_path, *, reviewed=False):
    """A harness work dir; one line is longer than a window, as in real OCR."""
    markdown = tmp_path / "doc.md"
    markdown.write_text(SOURCE, encoding="utf-8", newline="")
    work = tmp_path / "work"
    bridge.prepare_md(
        markdown,
        work,
        window_chars=400,
        overlap_blocks=0,
        max_windows=50,
        boundary="line",
    )
    if reviewed:
        assert plan_windows.main([str(work), "--max-chars", "400"]) == 0
        bridge.review(work, [])
    return work


def test_plan_windows_writes_an_unreviewed_plan_on_the_same_source(tmp_path, capsys):
    work = prepared_work_dir(tmp_path)
    assert plan_windows.main([str(work), "--max-chars", "150"]) == 0
    assert "สมชาย" not in capsys.readouterr().out
    plan = json.loads((work / "detection-windows.json").read_text(encoding="utf-8"))
    assert plan["reviewed"] is False and plan["window_chars"] == 150
    source = bridge.read_text(work / "source.md")
    windows = [(w["start"], w["end"]) for w in plan["windows"]]
    assert windows == [(s, e) for s, e, _ in split.plan_pages(source, 150)]
    # A reviewed plan is never replaced.
    bridge.review(work, [])
    assert plan_windows.main([str(work)]) == 1


class FakeProxyTransport(httpx.AsyncBaseTransport):
    """Stands in for the real proxy connection inside record_replay_pages."""

    replies: ClassVar[list] = []
    # Number of first calls that never answer (the client's deadline cuts them).
    silent_calls: ClassVar[int] = 0

    def __init__(self, **_options):
        self._send = scripted(list(self.replies))
        self._silent = self.silent_calls

    async def handle_async_request(self, request):
        if self._silent:
            self._silent -= 1
            await asyncio.sleep(60)
        return self._send(request)


def test_recorded_pages_replay_and_a_code_change_is_reported(
    tmp_path, monkeypatch, capsys
):
    work = prepared_work_dir(tmp_path, reviewed=True)
    monkeypatch.setattr(record.httpx, "AsyncHTTPTransport", FakeProxyTransport)
    FakeProxyTransport.replies = [detect(("NAME", "นายสมชาย ใจดี")), verify()]
    out = tmp_path / "recording"
    args = SimpleNamespace(
        work_dir=work, output_dir=out, windows=[1], parallel=1, env_file=None
    )
    monkeypatch.setattr(record, "LlmProxySettings", lambda **_: llm_settings())
    asyncio.run(record.main_async(args))
    printed = capsys.readouterr().out
    assert '"status": 200' in printed and "สมชาย" not in printed
    page = json.loads((out / "page-0001.json").read_text(encoding="utf-8"))
    assert page["pipeline_replay_consistent"] is True

    assert asyncio.run(replay.main_async(out)) == 0
    assert '"failed": 0' in capsys.readouterr().out

    # A reply that no longer matches the request the code sends now.
    page["calls"][0]["body_sha256"] = "0" * 64
    (out / "page-0001.json").write_text(json.dumps(page), encoding="utf-8")
    assert asyncio.run(replay.main_async(out)) == 1
    assert "request differs" in capsys.readouterr().out


def test_a_page_cut_by_a_deadline_is_recorded_as_not_replayable(
    tmp_path, monkeypatch, capsys
):
    work = prepared_work_dir(tmp_path, reviewed=True)
    monkeypatch.setattr(record.httpx, "AsyncHTTPTransport", FakeProxyTransport)
    monkeypatch.setattr(FakeProxyTransport, "silent_calls", 1)
    FakeProxyTransport.replies = [detect(), verify()]
    # The first detection attempt gets no answer before the call deadline.
    short = llm_settings().model_copy(update={"request_deadline_seconds": 0.2})
    monkeypatch.setattr(record, "LlmProxySettings", lambda **_: short)
    out = tmp_path / "recording"
    args = SimpleNamespace(
        work_dir=work, output_dir=out, windows=[1], parallel=1, env_file=None
    )
    asyncio.run(record.main_async(args))
    assert '"cut_by_deadline": 1' in capsys.readouterr().out
    page = json.loads((out / "page-0001.json").read_text(encoding="utf-8"))
    assert page["calls"][0]["error"] == "cancelled"
    assert page["pipeline_replay_consistent"] is False

    # Reported as not replayable, not as a code change; no page left to compare.
    assert asyncio.run(replay.main_async(out)) == 1
    printed = capsys.readouterr().out
    assert "cut by a deadline when recorded" in printed
    assert '"failed": 0, "not_replayable": 1' in printed


def test_recording_refuses_an_existing_folder(tmp_path):
    work = prepared_work_dir(tmp_path, reviewed=True)
    args = SimpleNamespace(
        work_dir=work, output_dir=tmp_path, windows=None, parallel=1, env_file=None
    )
    with pytest.raises(SystemExit, match="already exists"):
        asyncio.run(record.main_async(args))


# --- run_pages_via_http.py ------------------------------------------------


def test_http_runner_checks_its_arguments_before_sending(tmp_path, capsys):
    work = prepared_work_dir(tmp_path, reviewed=True)
    assert (
        http_runner.main(
            [str(work), "--output-dir", str(tmp_path / "o"), "--parallel", "5"]
        )
        == 1
    )
    assert "--parallel must be between 1 and 4" in capsys.readouterr().out
    assert (
        http_runner.main(
            [str(work), "--output-dir", str(tmp_path / "o"), "--windows", "99"]
        )
        == 1
    )
    assert "window numbers" in capsys.readouterr().out
    assert http_runner.main([str(work), "--output-dir", str(tmp_path)]) == 1
    assert "already exists" in capsys.readouterr().out


def test_a_recording_with_fewer_calls_than_counted_attempts_is_not_replayable():
    # Recorded before attempts cut by a deadline were kept (2026-10-16).
    page = {
        "calls": [{"role": "candidates"}, {"role": "has_pii"}],
        "service": {"log": ["status=200 llm_calls=2 http_attempts=3 role_calls=2"]},
    }
    assert replay.unrecorded_reason(page) == "1 attempt(s) not recorded"
    page["service"]["log"] = ["status=200 llm_calls=2 http_attempts=2 role_calls=2"]
    assert replay.unrecorded_reason(page) is None
    page["calls"].append({"role": "candidates", "error": "cancelled"})
    assert (
        replay.unrecorded_reason(page) == "1 attempt(s) cut by a deadline when recorded"
    )
