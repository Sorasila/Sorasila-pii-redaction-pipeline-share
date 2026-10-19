"""Replay recorded real pages against the current code.

Usage:
    python tools/replay_pages.py <recording folder>

For each page-NNNN.json from tools/record_replay_pages.py the service and the
pipeline are replayed with the recorded proxy replies; nothing is sent to the
proxy. A page passes when every request matches the recording and the
normalised outputs, log line and events are identical. A page whose recording
holds an attempt the client's deadline cut is reported as not replayable (its
timing cannot be reproduced) instead of being compared. Stdout carries page
numbers and pass/fail reasons only. Exit code 0 means no page failed.
"""

import asyncio
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO / "tests")]

from replay_support import ReplayTransport, cancelled_calls, run_pipeline, run_service


def unrecorded_reason(page):
    """Why a recording cannot be replayed, or None."""
    cut = cancelled_calls(page["calls"])
    if cut:
        return f"{cut} attempt(s) cut by a deadline when recorded"
    # Recordings made before cut attempts were kept: the service counted more
    # HTTP attempts than were recorded.
    counted = sum(
        int(found)
        for line in page["service"]["log"]
        for found in re.findall(r" http_attempts=(\d+)", line)
    )
    if counted > len(page["calls"]):
        return f"{counted - len(page['calls'])} attempt(s) not recorded"
    return None


async def replay_page(page):
    problems = []
    transport = ReplayTransport(page["calls"])
    service = await run_service(page["source"], transport)
    problems += [f"service {m}" for m in transport.mismatches]
    if not transport.finished:
        problems.append(f"service used {transport.used} of {len(page['calls'])} calls")
    if service["response"] != page["service"]["response"]:
        problems.append("service response differs")
    if service["log"] != page["service"]["log"]:
        problems.append("log line differs")
    transport = ReplayTransport(page["calls"])
    pipeline = await run_pipeline(page["source"], transport)
    problems += [f"pipeline {m}" for m in transport.mismatches]
    if pipeline.get("events") != page["pipeline"].get("events"):
        problems.append("pipeline events differ")
    if {k: v for k, v in pipeline.items() if k != "events"} != {
        k: v for k, v in page["pipeline"].items() if k != "events"
    }:
        problems.append("pipeline result differs")
    return problems


async def main_async(folder):
    paths = sorted(folder.glob("page-*.json"))
    failed = not_replayable = 0
    for path in paths:
        page = json.loads(path.read_text(encoding="utf-8"))
        reason = unrecorded_reason(page)
        if reason:
            not_replayable += 1
            result = {"page": page["page"], "ok": None, "not_replayable": reason}
        else:
            problems = await replay_page(page)
            failed += bool(problems)
            result = {"page": page["page"], "ok": not problems, "problems": problems}
        print(json.dumps(result), flush=True)
    print(
        json.dumps(
            {"pages": len(paths), "failed": failed, "not_replayable": not_replayable}
        )
    )
    return 1 if failed or len(paths) == not_replayable else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async(Path(sys.argv[1]).resolve())))
