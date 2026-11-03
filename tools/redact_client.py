"""Send Markdown pages to POST /redact and save the three response parts.

Usage (service running, from the repository root):
    python tools/redact_client.py samples/synthetic/*.md --output-dir ../redact-out
        [--url http://127.0.0.1:8080/redact] [--env-file .env]

Each file is one request (at most PII_SERVICE_MAX_SOURCE_CHARACTERS Unicode
code points, default 10000, as the service requires). For every file the
output folder receives:

    <name>.redacted.md        redacted_md part, exact bytes
    <name>.metadata.json      metadata part (only with PII_SERVICE_RETURN_METADATA
                              or PII_SERVICE_RETURN_MANIFEST; by default the
                              response is the redacted Markdown alone)
    <name>.manifest.json      manifest decoded from the UNENCRYPTED test envelope
                              (contains the original PII values)
    <name>.manifest.jwe.json  the envelope as received, when it is really encrypted
                              (no manifest file when the service runs with the
                              default PII_SERVICE_RETURN_MANIFEST=false)
    <name>.error.json         HTTP status and fixed error code, on failure

The output folder must be outside any Git repository so that PII never gets
committed. The token comes from PII_SERVICE_API_TOKEN (environment or env file)
and is never printed. Only httpx and the standard library are needed.
"""

import argparse
import base64
import glob
import hashlib
import json
import os
import sys
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[1]
DEFAULT_MAX_CODE_POINTS = 10000
UNENCRYPTED_TEST_KID = "UNENCRYPTED-TEST-ONLY"


def read_env_file(path: Path) -> dict[str, str]:
    values = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key, value = stripped.split("=", 1)
                values[key.strip()] = value.strip()
    return values


def setting(name: str, env_file_values: dict[str, str], default: str = "") -> str:
    return os.environ.get(name) or env_file_values.get(name, default)


def inside_git_repository(path: Path) -> bool:
    return any((parent / ".git").exists() for parent in (path, *path.parents))


def page_problem(data: bytes, max_code_points: int) -> str | None:
    """Reasons the service would reject the page, checked before sending."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "not_utf8"
    if not text.strip():
        return "empty"
    if len(text) > max_code_points:
        return f"too_long_{len(text)}_code_points"
    return None


def multipart_parts(response: httpx.Response) -> dict[str, bytes]:
    if response.headers["content-type"].startswith("text/markdown"):
        # Default service mode: the body is the redacted Markdown alone.
        return {"redacted_md": response.content}
    message = BytesParser(policy=policy.HTTP).parsebytes(
        b"Content-Type: "
        + response.headers["content-type"].encode("ascii")
        + b"\r\n\r\n"
        + response.content
    )
    return {
        part.get_param("name", header="content-disposition"): part.get_payload(
            decode=True
        )
        for part in message.iter_parts()
    }


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_manifest(envelope_bytes: bytes) -> dict | None:
    """The plaintext manifest of an unencrypted test envelope, else None."""
    envelope = json.loads(envelope_bytes)
    protected = json.loads(_unb64(envelope["protected"]))
    if protected.get("kid") != UNENCRYPTED_TEST_KID:
        return None
    return json.loads(_unb64(envelope["ciphertext"]))


def save_success(output: Path, stem: str, parts: dict[str, bytes]) -> dict:
    redacted = parts["redacted_md"]
    metadata = parts.get("metadata")
    (output / f"{stem}.redacted.md").write_bytes(redacted)
    if metadata is not None:
        (output / f"{stem}.metadata.json").write_bytes(metadata)
    if "pii_manifest" not in parts:
        # The service returns no manifest unless PII_SERVICE_RETURN_MANIFEST=true.
        manifest, kind, types = None, "not_returned", {}
    elif (manifest := test_manifest(parts["pii_manifest"])) is None:
        (output / f"{stem}.manifest.jwe.json").write_bytes(parts["pii_manifest"])
        kind, types = "encrypted", {}
    else:
        (output / f"{stem}.manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        kind, types = "plaintext_test", {}
        for entry in manifest["entries"]:
            types[entry["pii_type"]] = types.get(entry["pii_type"], 0) + 1
    # Without metadata there is no hash to check against (None).
    expected_hash = json.loads(metadata)["redacted_md_sha256"] if metadata else None
    return {
        "status": "VERIFIED",
        "hash_ok": None
        if expected_hash is None
        else hashlib.sha256(redacted).hexdigest() == expected_hash,
        "manifest": kind,
        "entries_by_type": types,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="Markdown pages (wildcards allowed)")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8080/redact")
    parser.add_argument("--env-file", type=Path, default=REPO / ".env")
    args = parser.parse_args()

    files = [
        Path(name) for pattern in args.files for name in sorted(glob.glob(pattern))
    ]
    if not files:
        print("STOPPED: no input files matched")
        return 1
    output = args.output_dir.resolve()
    if inside_git_repository(output):
        print(
            "STOPPED: the output folder is inside a Git repository; choose one outside it"
        )
        return 1
    env_values = read_env_file(args.env_file)
    token = setting("PII_SERVICE_API_TOKEN", env_values)
    if not token:
        print(
            "STOPPED: PII_SERVICE_API_TOKEN is not set (run tools/setup_service_env.py)"
        )
        return 1
    deadline = float(
        setting("PII_SERVICE_REQUEST_DEADLINE_SECONDS", env_values, "7200")
    )
    max_code_points = int(
        setting(
            "PII_SERVICE_MAX_SOURCE_CHARACTERS",
            env_values,
            str(DEFAULT_MAX_CODE_POINTS),
        )
    )
    output.mkdir(parents=True, exist_ok=True)

    headers = {
        "content-type": "text/markdown; charset=utf-8",
        "authorization": f"Bearer {token}",
    }
    summary = []
    # The client waits a little longer than the service's own deadline.
    with httpx.Client(timeout=httpx.Timeout(10, read=deadline + 60)) as client:
        for path in files:
            stem = path.stem
            if (output / f"{stem}.redacted.md").exists():
                print(f"STOPPED: results for {stem} already exist in {output}")
                return 1
            data = path.read_bytes()
            record = {"file": path.name}
            problem = page_problem(data, max_code_points)
            started = time.perf_counter()
            if problem:
                record.update(status="SKIPPED", reason=problem)
            else:
                try:
                    response = client.post(args.url, content=data, headers=headers)
                except httpx.HTTPError as error:
                    record.update(
                        status="STOPPED", reason=f"client:{type(error).__name__}"
                    )
                else:
                    if response.status_code == 200:
                        record.update(
                            save_success(output, stem, multipart_parts(response)),
                            # Matches the service log line (no PII).
                            document_id=response.headers.get("x-document-id"),
                        )
                    else:
                        try:
                            body = response.json()
                        except ValueError:
                            body = {}
                        record.update(
                            status="STOPPED",
                            http_status=response.status_code,
                            reason=body.get("error", "unknown"),
                            document_id=body.get("document_id"),
                        )
            record["seconds"] = round(time.perf_counter() - started, 1)
            if record["status"] != "VERIFIED":
                (output / f"{stem}.error.json").write_text(
                    json.dumps(record, indent=2), encoding="utf-8"
                )
            summary.append(record)
            print(json.dumps(record, ensure_ascii=True), flush=True)
    (output / "summary.json").write_text(
        json.dumps({"files": summary}, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    passed = sum(record["status"] == "VERIFIED" for record in summary)
    print(f"Done: {passed}/{len(summary)} verified. Results in {output}")
    return 0 if passed == len(summary) else 2


if __name__ == "__main__":
    sys.exit(main())
