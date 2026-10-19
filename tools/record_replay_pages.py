"""Record real proxy replies for reviewed pages, to replay them after code changes.

Usage:
    python tools/record_replay_pages.py <work-dir> --output-dir <new folder>
        [--windows 1 2 3] [--parallel 2] [--env-file .env]

<work-dir> is a reviewed tools/pdf-core-test work dir. Each page goes through
the real service app in-process (same code path as POST /redact) with a
recording transport in front of the real proxy. Per page
<output-dir>/page-NNNN.json keeps the request fingerprints, the proxy replies
(these contain document text and PII: keep the folder private, outside Git),
the normalised service response and log line, and the pipeline's events from
an immediate replay of the same calls. Stdout carries statuses and counts only.
Check the recording with tools/replay_pages.py. An attempt the client's own
deadline cut is kept as a "cancelled" call; such a page cannot be replayed.

To record with an older commit, run this file from a git worktree of that
commit and pass --env-file pointing at the main checkout's .env.
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO / "tests"), str(REPO / "tools" / "pdf-core-test")]

import httpx
import pdf_to_pipeline as bridge
from replay_support import (
    RecordingTransport,
    ReplayTransport,
    cancelled_calls,
    run_pipeline,
    run_service,
)

from pii_pipeline.llm.client import _build_tls_context
from pii_pipeline.llm.config import LlmProxySettings


def say(event, **fields):
    print(json.dumps({"event": event, **fields}, ensure_ascii=True), flush=True)


async def record_page(number, text, output, gate, llm):
    async with gate:
        verify = False if llm.tls_verify is False else _build_tls_context(llm)
        async with httpx.AsyncHTTPTransport(verify=verify, retries=0) as inner:
            transport = RecordingTransport(inner.handle_async_request)
            started = time.perf_counter()
            say("PAGE_STARTED", page=number, characters=len(text))
            service = await run_service(text, transport, llm=llm, deadline=3600)
        replay = ReplayTransport(transport.calls)
        pipeline = await run_pipeline(text, replay)
        consistent = not replay.mismatches and replay.finished
        page = {
            "page": number,
            "source": text,
            "calls": transport.calls,
            "service": service,
            "pipeline": pipeline,
            "pipeline_replay_consistent": consistent,
        }
        path = output / f"page-{number:04d}.json"
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(page, stream, ensure_ascii=False, indent=1)
        say(
            "PAGE_RECORDED",
            page=number,
            status=service["response"]["status"],
            calls=len(transport.calls),
            seconds=round(time.perf_counter() - started, 1),
            pipeline_replay_consistent=consistent,
            # Attempts cut by the client's deadline make a page not replayable.
            cut_by_deadline=cancelled_calls(transport.calls),
        )


async def main_async(args):
    source, _meta, plan = bridge.read_prepared(
        args.work_dir.resolve(), require_review=True
    )
    windows = plan["windows"]
    selected = args.windows or list(range(1, len(windows) + 1))
    if any(not 1 <= n <= len(windows) for n in selected):
        raise SystemExit(
            f"STOPPED: window numbers must be between 1 and {len(windows)}"
        )
    output = args.output_dir.resolve()
    if output.exists():
        raise SystemExit("STOPPED: output folder already exists; choose a new folder")
    if any((parent / ".git").exists() for parent in (output, *output.parents)):
        raise SystemExit("STOPPED: output folder is inside a Git repository")
    llm = LlmProxySettings(_env_file=args.env_file)
    output.mkdir(parents=True)
    gate = asyncio.Semaphore(args.parallel)
    started = time.perf_counter()
    say("RUN_STARTED", pages=len(selected), parallel=args.parallel)
    await asyncio.gather(
        *(
            record_page(
                n,
                source[windows[n - 1]["start"] : windows[n - 1]["end"]],
                output,
                gate,
                llm,
            )
            for n in selected
        )
    )
    say(
        "RUN_FINISHED",
        total_seconds=round(time.perf_counter() - started, 1),
        output_dir=str(output),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("work_dir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--windows", type=int, nargs="*")
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--env-file", type=Path, default=REPO / ".env")
    asyncio.run(main_async(parser.parse_args(argv)))


if __name__ == "__main__":
    main()
