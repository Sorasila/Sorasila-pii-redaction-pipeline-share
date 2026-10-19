# PII Redaction Pipeline: design overview

How the service decides what is PII and how a request is processed. For
running and configuring the container, see the [README](../README.md).

Python service core that detects, redacts and verifies PII in OCR-generated Thai
Markdown before the text is returned to the calling system. Each request returns
the redacted Markdown together with an encrypted mapping of placeholders to the
original values, or a safe error. Nothing partial is ever returned.

This is a unit-tested prototype, not a production-ready service.

## How a request is processed

```text
raw Markdown (≤2000 code points)
  │  NFC normalization; reject text that already contains [PII_…] placeholders
  ▼
detection ──┬── rule lane: deterministic regex rules on the original text
            └── LLM lane: model proposes {pii_type, value}; the service locates
                it in the source itself (exactly, or as a bounded near copy) and
                asks the model to classify repeated or overlapping occurrences
                (or NOT_PII)
  ▼  merge exact source spans; conflicts resolved by legal non-overlapping options
redaction: deterministic [PII_<TYPE>_<n>] placeholders, numbered per type in document order
  ▼
verification of the final redacted text only: rules AND an independent LLM pass
  ├── residual PII → one bounded re-detection round, then verify again
  └── clean → encrypt manifest → multipart response
```

Design rules that hold throughout:

- **The model never edits text.** It only proposes values; the service finds
  each value in the source and always redacts the source text, never the model's
  copy. Beyond exact copies it accepts only the bounded near copies described
  under "Near copies" below; anything else is rejected.
- **Rule matches are mandatory.** A model proposal that overlaps a rule match
  cannot override it. When a rule leaves only one legal option, the service
  resolves the conflict locally without an LLM call.
- **Fail closed.** An issue left by detection is never treated as "no PII". A
  request succeeds only if the fresh verification of the final text finds
  nothing; otherwise it ends with a safe error.
- **Bounded recovery.** Repairs, retries and the residual round share a fixed
  budget inside one request:

| `RecoveryPolicy` field | Default | Meaning |
| --- | --- | --- |
| `max_role_calls` | 64 | All logical calls in the request |
| `max_recovery_calls` | 4 | Extra calls for repair, conflict selection, verification retry and residual recovery |
| `reserved_recovery_calls` | 0 | Part of the above that initial window repairs may not use |
| `window_repair_attempts` | 2 | Re-extractions per detection window with issues (an empty or failed generation counts as an issue) |
| `verification_retry_attempts` | 1 | Retries per verification window |
| `conflict_selection_attempts` | 1 | LLM selections per conflict batch |
| `max_residual_rounds` | 1 | Re-detection rounds after verification finds residual PII |
| `blank_response_retries` | 3 | Re-sends per detection or verification window, or per merge conflict selection, when the reply is blank or not the requested shape, or the generation failed; counts toward `max_role_calls` and the deadline, not `max_recovery_calls` |
| `deadline_seconds` | 600 | Whole-request processing deadline |

## PII scope

Seventeen canonical types (`pii_pipeline/core/pii_types.py`): `NAME`, `ORGANIZATION`,
`ID_NUMBER`, `PASSPORT_NUMBER`, `EMAIL`, `PHONE`, `FAX`, `ADDRESS`,
`BANK_ACCOUNT_NUMBER`, `PAYMENT_CARD_NUMBER`, `VEHICLE_REGISTRATION`,
`DATE_OF_BIRTH`, `SOCIAL_MEDIA_IDENTIFIER`, `LAND_PARCEL_NUMBER`, `CASE_NUMBER`,
`TITLE_DEED_NUMBER`, `OFFICIAL_LETTER_NUMBER`.

Agreed boundaries (both prompts state the same scope):

| Topic | Policy |
| --- | --- |
| Field labels | Labels such as `คดีหมายเลขดำที่`, `หนังสือที่`, `โฉนดเลขที่`, `เลขที่ดิน`, `ชื่อ` and the labels of the rule lane stay in the text; only the value is replaced. |
| NAME | Honorific and name are replaced together; a given name alone also counts; quotation marks around a quoted name stay outside. |
| ADDRESS | Starts at `บ้านเลขที่` or another first address label such as `ห้องชุดเลขที่`, and runs through the province, labels included, across line breaks. An organization name inside an address is a separate `ORGANIZATION`, splitting the address into two values. A locality alone (`แขวง…เขต…จังหวัด…`, `ตำบล…อำเภอ…จังหวัด…`) counts when it locates a person or property, not when it is part of an agency or court name. |
| ORGANIZATION | Private juristic persons only (companies, partnerships, foundations, associations, condominium juristic persons). Government bodies (ministries, departments, government or provincial offices, courts, local administrations) are never ORGANIZATION, even though they are juristic persons in law. The name is copied exactly, without adding or removing words such as `นิติบุคคล`, `บริษัท` or `จำกัด`. |
| CASE_NUMBER | After `คดีหมายเลขดำที่`/`คดีหมายเลขแดงที่`: a number part of digits or Thai letters, `/`, and a four-digit year (for example `123/2569` or `ก/2569`); the label stays. |
| Repeated values | When a proposed value occurs at several places, the model normally chooses which copies are PII. Approved 2026-10-15, no choice is asked for a copy that a rule matched exactly (rules always win), nor for a NAME with a title (`นาย`, `นาง`, `น.ส.`, `เด็กชาย`, `เด็กหญิง`, `ด.ช.`, `ด.ญ.`) or an ADDRESS of 20+ non-space characters proposed with that one type: those copies are PII. Other copies still go to the model; when none is left, the call is skipped. |
| Land number + location | A title-deed, `น.ส. 3 ก.` or land parcel number directly followed by the location of that land is one ADDRESS value (`น.ส. 3 ก. เลขที่ [PII_ADDRESS_1]`); the label stays. The rule lane produces it itself when a labelled number is followed by a location of at least two levels (`ตำบล`/`ต.`, `แขวง`, `อำเภอ`/`อ.`, `เขต`, `จังหวัด`/`จ.`, `หมู่ที่`/`ม.`; at most one line break between parts; approved 2026-10-15), so a location the model misses is still masked. The service also joins a number and an ADDRESS the model returns separately. A land number or an ADDRESS strictly inside a larger ADDRESS that overlaps nothing else is covered by it without asking the model again (rule matches included). In the residual pass, which reads redacted text, an ADDRESS that starts with a land-number placeholder (`[PII_TITLE_DEED_NUMBER_1] ตำบล…`) keeps only the location, which is then joined with the number. Approved 2026-10-19, any other residual value that contains placeholders keeps only its text between them: each part of at least 4 non-whitespace characters that is not only a label or title (`เลขที่`, `นางสาว`, …) becomes a value of the same type, and a value of placeholders and labels alone is dropped; final verification still runs afterwards. Other types never override a rule match. |
| TITLE_DEED_NUMBER | After `โฉนดเลขที่`, `ที่ดินโฉนดเลขที่`, `โฉนดที่ดินเลขที่`, and land-use certificates `น.ส. 3` / `น.ส. 3 ก.` followed by `เลขที่` (OCR periods, spaces or line breaks vary); the digits only. |
| OFFICIAL_LETTER_NUMBER | After `หนังสือที่`/`หนังสือ ที่` (also across line breaks): agency letters, digit groups with or without periods, `/`, and a running number (for example `กข 0000.00.0/0000`); OCR periods, dashes or single spaces inside the value are tolerated; the label stays. |
| Pseudonyms | Single-letter pseudonyms that already anonymize a party (`บริษัท ก.`, `นาย ข.`) are not PII. |
| DATE_OF_BIRTH | Only dates identified by birth context; document dates stay. |
| Near copies | When the model's value is not in the source, the service still locates it if it differs only in whitespace (dropped `\r`, line-break indentation), or by a few code-point edits: at most max(2, length ÷ 10) for values of 20+ non-whitespace characters, and max(1, length ÷ 7) for 10–19 characters (approved 2026-10-19: one fixed letter in 10–13 characters, two in 14–19) (OCR "repairs" such as a moved tone mark, an added letter or a corrected misspelling) with the first character exact; when the last character differs, the match runs to the end of that word (letters, vowel and tone marks, digits; at most one edit budget further), so a changed final letter cannot leave the rest of the word visible. Exactly one source text may be that close. A value joined across an OCR page break (2–4 exact parts of 4+ non-whitespace characters, separated only by text with no Thai letters and no placeholder, such as `---`, `|` or a page number) is redacted as separate parts of the same type, leaving the separator. The source text, never the model's copy, is redacted; anything else fails closed. |
| Equal values | Each occurrence is decided on its own context; equal values elsewhere are not replaced automatically. |

The rule lane (`pii_pipeline/rules/thai.py`, `detect_thai_rule_pii`) requires a
label before every number: for example `เลขประจำตัวประชาชน`, `โทร.`/`โทรศัพท์`,
`โทรสาร`, `เลขที่บัญชี` or `หนังสือเดินทางเลขที่`. Email addresses need no label.
Unlabelled numbers are left to the LLM lane and verification. The core keeps rule
detectors opt-in; `pii_pipeline.service` enables all of them for detection and
for rule verification.

## Output contract

See [docs/http-contract.md](http-contract.md). The manifest and metadata are
defined as JSON Schemas in [docs/pii-manifest.schema.json](pii-manifest.schema.json)
and [docs/metadata.schema.json](metadata.schema.json);
`tests/test_delivery_schemas.py` checks real package output against them.

| Status | Body |
| --- | --- |
| 200 | By default `text/markdown; charset=utf-8`: the redacted Markdown itself. With `PII_SERVICE_RETURN_METADATA=true`: `multipart/form-data` with `redacted_md` (`text/markdown`) and `metadata` (`application/json`); with `PII_SERVICE_RETURN_MANIFEST=true` also `pii_manifest` (encrypted JWE JSON; in the service's test mode a JWE-shaped envelope carrying the plaintext manifest). Every 200 has an `X-Document-Id` header |
| 400 / 401 / 404 / 405 / 413 / 415 | JSON `{"error": …}`: invalid input, authentication, route, method, size, media type (`Allow: POST` on `/redact`, `Allow: GET` on the probes) |
| 502 | `processing_failed`: detection, verification or packaging did not succeed |
| 504 | `request_timeout`: the configured request deadline was reached |

**Only the redacted text leaves by default (decided 2026-10-16).** The body
is the redacted Markdown; no manifest is built and no encryptor is needed. The
`X-Document-Id` header matches the request log line.
`PII_SERVICE_RETURN_METADATA=true` answers the multipart package with
`redacted_md` and `metadata`. `PII_SERVICE_RETURN_MANIFEST=true` adds the
`pii_manifest` part (and always the metadata it is bound to) for callers that
must map placeholders back to the original values; that needs the manifest
encryptor (today only the unencrypted test envelope, so test machines only).

Placeholders are unique only within one `document_id`; receivers key manifest
entries by `document_id` and `placeholder`. When the manifest is returned, a
document with no PII still gets one with empty `entries`.

## Configuration

`pii_pipeline.llm.config.LlmProxySettings` reads `LLM_PROXY_*` variables from the
environment or `.env` (ignored by Git). [.env.example](../.env.example) lists them:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLM_PROXY_BASE_URL`, `LLM_PROXY_API_KEY` | required | Proxy endpoint (`POST /structured-output`) and Bearer key |
| `LLM_PROXY_MODEL` | `qwen/qwen3.6-27b` | Only accepted model |
| `LLM_PROXY_CA_BUNDLE` | unset | Extra trusted CA for the proxy |
| `LLM_PROXY_VERIFY_TLS` | `true` | See the TLS exception below |
| `LLM_PROXY_CONNECT/READ/WRITE/POOL_TIMEOUT_SECONDS` | 10 / 300 / 30 / 10 | Per-attempt phase timeouts (read 300 → 400 on 2026-10-05; 300 again since 2026-10-16: replies that succeed have taken up to about 290 s, and two full attempts fit in the 600 s call deadline). The log's `attempt_seconds` shows each attempt's time for tuning it |
| `LLM_PROXY_REQUEST_DEADLINE_SECONDS` | 600 | Deadline per LLM call, including retries |
| `LLM_PROXY_MAX_RETRIES` | 2 (0–2) | Retries for transient 5xx/network errors only |
| `LLM_PROXY_DETECTION_USE_THINKING`, `LLM_PROXY_VERIFICATION_USE_THINKING` | `false` | Model thinking per role |

The client never follows redirects, reads error bodies or substitutes an empty
result for a failure. Fatal TLS errors, HTTP 4xx and invalid responses are not
retried. The FastAPI adapter (`service.http.create_app`) requires the caller to
supply the LLM processor and recovery policy, the rule detectors and rule check,
authentication, the manifest encryptor and a finite request deadline; it has no
defaults for any of them. Every request goes through automatic recovery.
`pii_pipeline.service` is the composition that supplies them.

### Running the service

`pii_pipeline.service.create_service_app` composes the adapter the same way the
test runner does: the Thai rule lane, the LLM lane with automatic recovery, one
window per request and a whole-request deadline.

```bash
uvicorn pii_pipeline.service:create_service_app --factory --host 127.0.0.1 --port 8080
```

Container probes need no token and touch no document, LLM proxy or store:
`GET /healthz` answers `200 {"status": "ok"}` while the process runs, and
`GET /readyz` answers `200 {"status": "ready"}` once the LLM client is open
(`503 {"status": "not_ready"}` before that and during shutdown). They write no
request log line.

**Container (reference).** [Dockerfile](../Dockerfile) is an example for the
platform team to adapt: Python 3.13 slim, `pip install -r requirements.txt`
(versions from `constraints.txt`), only `pii_pipeline/` copied, an unprivileged
user, port 8080, a `HEALTHCHECK` on `/readyz`, and uvicorn on `0.0.0.0`.
[.dockerignore](../.dockerignore) is an allow list, so `.env`, `.venv` and test
data never enter the build context. Settings and secrets come from the
environment at run time (the table below); the image needs no `.env`, no volume
and no database, and writes no files. Set the platform's stop grace period
longer than `PII_SERVICE_REQUEST_DEADLINE_SECONDS`, or deploys kill requests in
progress.

```bash
docker build -t pii-redaction-service .
docker run --rm -p 8080:8080 --env-file <env file kept outside the image> pii-redaction-service
```

It reads `PII_SERVICE_*` settings next to `LLM_PROXY_*` and refuses to start
when a required one is missing:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PII_SERVICE_API_TOKEN` | required (32+ characters) | Provisional caller authentication: `Authorization: Bearer <token>` until the integration scheme is agreed |
| `PII_SERVICE_REQUEST_DEADLINE_SECONDS` | 1200 | Whole-request deadline, also used as the recovery deadline (covers the slowest page measured on the test LLM, 1036 s) |
| `PII_SERVICE_RETURN_METADATA` | `false` | Answers multipart `redacted_md` + `metadata` instead of the redacted Markdown alone |
| `PII_SERVICE_RETURN_MANIFEST` | `false` | Adds the `pii_manifest` part (implies the metadata). Off: no manifest is built or sent, and the service starts without an encryptor (unless a store is configured) |
| `PII_SERVICE_ALLOW_UNENCRYPTED_TEST_MANIFEST` | `false` | The only way to run before the encryption design exists. The manifest part is then a JWE-shaped envelope with `kid` `UNENCRYPTED-TEST-ONLY` whose `ciphertext` is the **plaintext** manifest. Test machines only |
| `PII_STORE_URL` | unset | **Off by default; the intended production setup stores no PII** (the manifest leaves only in the response). Prepared for a future approved database: a PostgREST base URL with an insert-only `pii_manifests` table. When set, each delivery's manifest envelope, metadata, key id and `redacted_md_sha256` are stored before the response; a failed store fails the request (502, `reason=ManifestStoreError:<code>`). With the unencrypted test manifest the URL must be this machine (`127.0.0.1`, `localhost`, `::1`). Read only by the uvicorn factory, never when the app is built with explicit settings. [deploy/local-db/](../deploy/local-db/) runs one on this machine (below) |
| `PII_STORE_TOKEN` | required with `PII_STORE_URL` | Bearer JWT of the store's insert-only writer role |

**Local manifest store (test setup).** Turning a store on keeps PII after the
response, which the production design avoids; before using a real database it
needs a real manifest encryptor, retention and deletion (rows here never
expire), access control and a PDPA review. `deploy/local-db/` runs Postgres 16 and PostgREST
v12.2.3 with Docker; only PostgREST is published, on `127.0.0.1:3000`. The
schema (`init/001_schema.sql`) has one table, `api.pii_manifests`, and an
insert-only role `pii_writer`: the service cannot read, change or delete rows,
and nothing expires during the test phase. Set in `.env` `PII_DB_ADMIN_PASSWORD`,
`PII_DB_AUTHENTICATOR_PASSWORD`, `PII_DB_JWT_SECRET` (32+ characters),
`PII_STORE_TOKEN` (an HS256 JWT signed with that secret, payload
`{"role": "pii_writer"}`) and `PII_STORE_URL=http://127.0.0.1:3000`, then from
`deploy/local-db`:

```powershell
docker compose --env-file ..\..\.env up -d
docker compose --env-file ..\..\.env exec db psql -U pii_admin -d pii -c "select count(*) from api.pii_manifests;"
```

The init scripts run only on an empty volume (`down -v` deletes all stored
rows). `init/002_roles.sh` must keep LF line endings.

The service also uses `LLM_PROXY_MAX_RETRIES` (default 2), so a proxy 504 can be
retried at the transport level; the private test runner used 0.

Each request logs one line with `document_id`, HTTP status and seconds, then
where the LLM calls went, and on failure the exception chain with this
package's fixed messages, for example
`reason=VerificationError("Residual PII remains after bounded recovery")`.
When the caller closes the connection while the page is processed, the work
stops at once (in-flight LLM requests are closed, nothing is retried or
stored) and the line shows `status=499` with
`reason=ClientDisconnected("Caller closed the connection")`; nobody receives
that response:

| Field | Counts |
| --- | --- |
| `llm_calls`, `by_role` | Every structured-output call that reached the client, by role (`detection`, `selection`, `verification`), including occurrence and conflict selections made inside detection |
| `http_attempts` | HTTP requests actually sent to the proxy; higher than `llm_calls` when the client retried a 502/503/504 or a dropped connection |
| `attempt_seconds` | Each HTTP attempt in order as `role:seconds` when the proxy answered HTTP 200, otherwise `role:<outcome>@seconds` with outcome `timeout` (read timeout), `http_<status>`, `error` or `cut` (the call's 600 s deadline cancelled it); for tuning `LLM_PROXY_READ_TIMEOUT_SECONDS` |
| `repair_reasons` | Why initial detection windows were detected again: each repair counts the issue codes of the attempt it repairs once, for example `value_not_found:2,detection_unavailable:1` (a value the source does not contain; the LLM call failed); `-` without repairs. Residual-round windows are explained by `residual` |
| `repairs`, `blank_resends`, `verification_retries`, `residual_rounds`, `merge_selections` | Why calls beyond the basic detection + verification pair were made |
| `role_calls`, `recovery_calls` | The recovery budget as counted by `RecoveryPolicy` |
| `residual` | `-` without a residual round; otherwise the last round's verifier finding types, whether the rule check found a residual, and the recovery candidates' shapes: count, types, how many still contain a placeholder (`placeholder`), how many parts were kept from them (`placeholder_parts`), how many had a land-number placeholder cut, how many cannot map back to the source, and the fixed detection issue codes |
| `selections` | `-` without selection calls; otherwise per kind (`occurrence`: which copies of a repeated value are PII; `conflict`: which of overlapping values) the number of calls and the PII types they asked about, and `settled_without_llm`: copies of repeated values decided without asking (see Repeated values) |

The line never contains document text, values or external error messages.

**TLS exception (approved 2026-09-30).** Certificate and hostname verification
may be disabled for the configured LLM proxy only, by an explicit
`LLM_PROXY_VERIFY_TLS=false`; it is never an automatic fallback. Traffic is still
HTTPS with Bearer authentication, but the server is not authenticated, so API
keys and PII are exposed to impersonation risk. The exception does not apply to
the caller connection and does not relax PII verification. A production risk
owner and review date still need to be recorded.

## How a request flows

```text
POST /redact ─ service/http: authorize → read page (service/document_input)
  └ recovery/process
      1. detect each window (recovery/detect): LLM reply → parse and locate
         values in the source (llm/response, llm/locate) → repeated values and
         overlapping spans chosen (selection/) → repair or re-send if needed
      2. add rule matches (rules/thai) and merge; rules win (recovery/merge)
      3. join land numbers with their location (selection/land), redact
         (core/redaction), rule check + independent LLM verification
         (recovery/verify)
      4. anything left → one residual round (recovery/residual), back to 3;
         no progress → fail closed
  → package (service/delivery) → 200 multipart, or 4xx/5xx JSON
  → one log line per request (service/request_log)
```

## Module map

| Package | Modules | Responsibility |
| --- | --- | --- |
| `core/` | `models`, `pii_types` | Match/entry models and the closed type vocabulary |
| | `detection`, `redaction`, `verification` | Exact-span validation, deterministic placeholder redaction, verification checkers |
| `rules/` | `thai` | Labelled Thai field and identifier rules (`detect_thai_rule_pii`) |
| `llm/` | `config`, `proxy`, `client` | Proxy settings, response envelope checks and the async structured-output client |
| | `prompts`, `schema` | Versioned prompts and closed JSON Schemas |
| | `response`, `errors`, `locate` | Reply parsing, reply errors with fixed codes, locating values in the source (exact, whitespace, near copy, page-break pieces) |
| | `windows`, `processing`, `call_stats` | Window planning and checks, the LLM client + planners + prompts bundle the recovery pipeline uses, per-request LLM call counts |
| `selection/` | `occurrences`, `spans`, `conflicts`, `land` | Which copies of a repeated value are PII; the shared span-choice engine; legal options for overlapping spans; the land-number + location policy |
| `recovery/` | `process` | Request flow and `process_markdown_with_recovery_async` |
| | `policy`, `replies` | Limits, call budget, failure classes; which failed replies are blank or recoverable |
| | `detect`, `merge`, `verify`, `residual` | Window detection with repairs, merging and conflict choice, independent verification, the residual round |
| `service/` | `app` | Deployable composition: settings, caller token, LLM client lifespan (`pii_pipeline.service:create_service_app`) |
| | `http`, `document_input`, `request_log`, `delivery` | The FastAPI adapter, page input limits, the request log line, the three-part multipart package |

Import from these package modules (for example `pii_pipeline.recovery.process`,
`pii_pipeline.service.http`, `pii_pipeline.rules.thai`); the former flat module
names were removed on 2026-10-19. The request log keeps its logger name
`pii_pipeline.http_api`.

## Development

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Quality gates from the repository root (Python 3.12 or 3.13):

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check pii_pipeline tests smoke_llm.py tools
git diff --check
```

`pytest.ini` limits the root run to `tests/`. Unit tests never read the real
`.env` or call the proxy. Every package version, direct and transitive, is
fixed in [constraints.txt](../constraints.txt), which all requirements files load
with `-c`; it is the set the suites last passed with. To upgrade, install the
new versions, run both suites and the replays, then update that file. The
`tools/pdf-core-test` harness needs extra packages:
`python -m pip install -r tools/pdf-core-test/requirements.txt`.

**Replay goldens.** `tests/replay/*.json` record, for synthetic pages, the
proxy replies and the service's exact requests, responses, log lines and
progress events. A refactor must keep them passing unchanged. Rebuild them
(`python tests/replay_scenarios.py --write`) only together with an approved
change of behaviour, prompts or schemas, and review the diff.

## Try it after cloning

Step-by-step guide in Thai, including troubleshooting:
[docs/SETUP_AND_USAGE.md](SETUP_AND_USAGE.md).

Needs Python 3.12+, network access to the LLM proxy and its API key (shared
privately, never through Git). From the repository root:

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe tools\setup_service_env.py
```

The setup script creates `.env` from `.env.example` when needed, generates the
caller token and enables the unencrypted test manifest, printing key names only.
Then set the real `LLM_PROXY_BASE_URL` and `LLM_PROXY_API_KEY` in `.env` (and
`LLM_PROXY_VERIFY_TLS=false` only under the approved proxy exception below).

Start the service in one terminal:

```powershell
.venv\Scripts\python.exe -m uvicorn pii_pipeline.service:create_service_app --factory --host 127.0.0.1 --port 8080
```

Send the [synthetic pages](../samples/synthetic/) from another terminal; results go
to a folder outside the repository:

```powershell
.venv\Scripts\python.exe tools\redact_client.py samples\synthetic\page-*.md --output-dir ..\redact-out
```

Each page takes one to several minutes on the test LLM machine. For every page
the client writes `<name>.redacted.md`, `<name>.metadata.json` and the decoded
test manifest `<name>.manifest.json` (original values, so keep that folder
private), or `<name>.error.json`; the service window logs one line per request
with the cause of any failure. Compare the output with the expected values in
[samples/synthetic/README.md](../samples/synthetic/README.md).

## Testing against the real LLM

- **Synthetic smoke tests** (no real documents): `python smoke_llm.py --case <name>`
  runs one frozen fixture against the configured proxy, for example
  `basic-thai`, `mixed-types`, `thai-address-forms`, `negative-document-dates`,
  `injection-thai-name` or `residual-only`; `--help` lists all cases. The
  fixtures and their expected matches live in `smoke_llm.py` and also serve as
  oracles for offline tests.
- **Real documents:** the harness in [tools/pdf-core-test/](../tools/pdf-core-test/)
  prepares a private document into reviewed windows and runs the full core with
  call/time caps and safe traces. Real documents and work directories stay
  outside the repository.
- **Page tools** (stdout carries counts and statuses only; every output folder
  must be new and outside Git):
  - `tools/split_md_pages.py <doc.md> --output-dir <dir>` splits a long document
    into files of at most 2000 code points, cutting at a blank line, then a line
    end, then whitespace, and only then inside a word; the files concatenate back
    to the input exactly. Send them with `tools/redact_client.py`.
  - `tools/plan_windows_from_pages.py <work-dir>` writes a window plan with the
    same cut rules when `prepare-md --boundary line` stops with
    `BLOCK_EXCEEDS_WINDOW` (an OCR line longer than a window). A person must
    still run `review` afterwards.
  - `tools/run_pages_via_http.py <work-dir> --output-dir <dir> [--windows ...]
    [--parallel 2]` sends each reviewed window to the running service as one
    `POST /redact` and keeps the parts and a `summary.json`.
  - `tools/record_replay_pages.py <work-dir> --output-dir <dir>` records the
    real proxy replies for each window (the recording holds document text and
    PII); `tools/replay_pages.py <dir>` later replays them against the current
    code without calling the proxy and fails if any request, response, log line
    or event changed. Use it before and after a refactor.

## Data handling

- Never log raw Markdown, detected values, manifests or LLM prompts/responses.
  Errors and diagnostics carry fixed reason codes, fixed messages, counts and
  types only.
- The client and test-mode manifests contain original values: keep their output
  folders outside the repository.
- In-memory models can hold plaintext PII even though their `repr()` hides it.
- Real documents, credentials and live results stay outside the repository.
  The full design handoff and the progress log with live results are private
  working notes kept outside this repository.
