"""Send reviewed windows to the running service (POST /redact) and keep results.

Usage (service already running, see setup_service_env.py):
    python tools/run_pages_via_http.py <work-dir> --output-dir <new folder>
        [--windows 4 5 6] [--parallel 2] [--url http://127.0.0.1:8080/redact]
        [--env-file .env]

<work-dir> is a reviewed tools/pdf-core-test work dir. Each window is one HTTP
request, exactly as the backend will send a page. --parallel N keeps up to N
requests open at once; pages may finish out of order. The caller token is read
from the repository .env (PII_SERVICE_API_TOKEN) and never printed. Per window:

    page-0001.redacted.md       redacted_md part
    page-0001.manifest.json     decoded from the UNENCRYPTED test envelope (PII),
                                only with PII_SERVICE_RETURN_MANIFEST=true
    page-0001.metadata.json     metadata part
    page-0001.error.json        HTTP status, fixed error code, seconds (on failure)

The terminal and summary.json carry statuses, codes, counts and timings only.
"""

import argparse
import asyncio
import base64
import json
import sys
import time
from collections import Counter
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools" / "pdf-core-test"))

import httpx
import pdf_to_pipeline as bridge

from pii_pipeline.service import UNENCRYPTED_TEST_KID, ServiceSettings


def say(event: str, **fields) -> None:
    print(json.dumps({"event": event, **fields}, ensure_ascii=True), flush=True)


def write_new(path: Path, data: str | bytes) -> None:
    if isinstance(data, bytes):
        with path.open("xb") as stream:
            stream.write(data)
    else:
        with path.open("x", encoding="utf-8", newline="") as stream:
            stream.write(data)


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def multipart(response: httpx.Response) -> dict[str, bytes]:
    if response.headers["content-type"].startswith("text/markdown"):
        # Default service mode: the body is the redacted Markdown alone.
        return {"redacted_md": response.content}
    message = BytesParser(policy=policy.HTTP).parsebytes(
        b"Content-Type: "
        + response.headers["content-type"].encode()
        + b"\r\n\r\n"
        + response.content
    )
    return {
        part.get_param("name", header="content-disposition"): part.get_payload(
            decode=True
        )
        for part in message.iter_parts()
    }


def test_manifest(envelope_bytes: bytes) -> dict:
    envelope = json.loads(envelope_bytes)
    protected = json.loads(_unb64(envelope["protected"]))
    if protected.get("kid") != UNENCRYPTED_TEST_KID:
        raise ValueError("manifest is not the unencrypted test envelope")
    return json.loads(_unb64(envelope["ciphertext"]))


def save_summary(output: Path, summary: list, state: str, current=(), **extra) -> None:
    """Rewritten after every page so an interrupted run keeps its record.

    state "running" with an old updated_at means the process was killed (for
    example the window was closed); "interrupted" means Ctrl+C during a page.
    """
    record = {
        "state": state,
        "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        **extra,
        "windows": sorted(summary, key=lambda item: item["window"]),
    }
    if current:
        record["interrupted_during_window"] = min(current)
        record["interrupted_during_windows"] = sorted(current)
    (output / "summary.json").write_text(
        json.dumps(record, ensure_ascii=True, indent=2), encoding="utf-8"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("work_dir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--windows", type=int, nargs="*")
    parser.add_argument("--url", default="http://127.0.0.1:8080/redact")
    parser.add_argument("--env-file", type=Path, default=REPO / ".env")
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="pages sent at the same time (1-4, default 1 = one after another)",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.parallel <= 4:
        print("STOPPED: --parallel must be between 1 and 4")
        return 1

    source, _meta, plan = bridge.read_prepared(
        args.work_dir.resolve(), require_review=True
    )
    windows = plan["windows"]
    selected = args.windows or list(range(1, len(windows) + 1))
    if any(not 1 <= n <= len(windows) for n in selected):
        print(f"STOPPED: window numbers must be between 1 and {len(windows)}")
        return 1
    output = args.output_dir.resolve()
    if output.exists():
        print("STOPPED: output folder already exists; choose a new folder")
        return 1
    if any((parent / ".git").exists() for parent in (output, *output.parents)):
        print("STOPPED: output folder is inside a Git repository; use a private folder")
        return 1

    service = ServiceSettings(_env_file=args.env_file)
    headers = {
        "content-type": "text/markdown; charset=utf-8",
        "authorization": f"Bearer {service.api_token.get_secret_value()}",
    }
    # The client must outlast the service's own whole-request deadline.
    timeout = httpx.Timeout(10, read=service.request_deadline_seconds + 120)
    output.mkdir(parents=True)
    say("RUN_STARTED", windows=len(selected), parallel=args.parallel, url=args.url)
    run = Run(output, args.parallel)
    run.save("running")
    try:
        asyncio.run(
            run_pages(
                run,
                [(n, windows[n - 1]) for n in selected],
                source,
                url=args.url,
                headers=headers,
                timeout=timeout,
            )
        )
    except KeyboardInterrupt:
        run.save("interrupted", current=run.in_flight)
        raise
    run.save("finished")
    passed = sum(record["status"] == "VERIFIED" for record in run.summary)
    say(
        "RUN_FINISHED",
        verified=passed,
        stopped=len(run.summary) - passed,
        total_seconds=run.elapsed(),
        output_dir=str(output),
    )
    return 0 if passed == len(run.summary) else 2


class Run:
    """Shared record of one run; pages finish in any order when parallel."""

    def __init__(self, output: Path, parallel: int) -> None:
        self.output = output
        self.parallel = parallel
        self.summary: list = []
        self.in_flight: set[int] = set()
        self.started = time.perf_counter()

    def elapsed(self) -> float:
        return round(time.perf_counter() - self.started, 1)

    def save(self, state: str, current=()) -> None:
        save_summary(
            self.output,
            self.summary,
            state,
            current,
            parallel=self.parallel,
            total_seconds=self.elapsed(),
        )


async def run_pages(run, pages, source, *, url, headers, timeout) -> None:
    """POST up to run.parallel pages at once; summary.json is rewritten after each."""
    gate = asyncio.Semaphore(run.parallel)
    limits = httpx.Limits(max_connections=run.parallel)
    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:

        async def one(number, window):
            async with gate:
                run.in_flight.add(number)
                record = await send_page(
                    client, number, window, source, run, url, headers
                )
                run.in_flight.discard(number)
                run.summary.append(record)
                run.save("running")
                say("WINDOW_FINISHED", **record)

        await asyncio.gather(*(one(number, window) for number, window in pages))


async def send_page(client, number, window, source, run, url, headers) -> dict:
    text = source[window["start"] : window["end"]]
    stem = f"page-{number:04d}"
    output = run.output
    say("WINDOW_STARTED", window=number, characters=len(text), at_seconds=run.elapsed())
    started = time.perf_counter()
    try:
        response = await client.post(url, content=text.encode("utf-8"), headers=headers)
    except httpx.HTTPError as error:
        record = {
            "window": number,
            "status": "STOPPED",
            "reason": f"client:{type(error).__name__}",
            "seconds": round(time.perf_counter() - started, 1),
        }
        write_new(output / f"{stem}.error.json", json.dumps(record, indent=2))
        return record
    seconds = round(time.perf_counter() - started, 1)
    if response.status_code == 200:
        received = multipart(response)
        write_new(output / f"{stem}.redacted.md", received["redacted_md"])
        if "metadata" in received:
            write_new(output / f"{stem}.metadata.json", received["metadata"])
        if "pii_manifest" not in received:
            # PII_SERVICE_RETURN_MANIFEST is off: no manifest, no type counts.
            return {
                "window": number,
                "status": "VERIFIED",
                "seconds": seconds,
                "document_id": response.headers.get("x-document-id"),
            }
        manifest = test_manifest(received["pii_manifest"])
        write_new(
            output / f"{stem}.manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2),
        )
        return {
            "window": number,
            "status": "VERIFIED",
            "seconds": seconds,
            "document_id": response.headers.get("x-document-id"),
            "entries_by_type": dict(
                Counter(entry["pii_type"] for entry in manifest["entries"])
            ),
        }
    try:
        body = response.json()
    except ValueError:
        body = {}
    code = body.get("error")
    record = {
        "window": number,
        "status": "STOPPED",
        "http_status": response.status_code,
        "reason": code if isinstance(code, str) else "unknown",
        "seconds": seconds,
        # Matches the service log line that names the cause.
        "document_id": body.get("document_id"),
    }
    write_new(output / f"{stem}.error.json", json.dumps(record, indent=2))
    return record


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('{"status": "CANCELLED"}')
        raise SystemExit(130) from None
