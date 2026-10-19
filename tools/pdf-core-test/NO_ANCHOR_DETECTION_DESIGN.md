# Detection without anchors — v9

Current decision, 2026-10-03: remove model-copied anchors; preserve non-PII occurrences of equal values. This supersedes EXACT_VALUE_LOCATION_PROPOSAL.md. Frontend input/output and deferred encryption are unchanged.

## Flow

1. Trusted planner supplies complete NFC source windows. Extraction returns closed `candidates` containing only canonical `pii_type` and exact `value`; repeated pairs are deduplicated.
2. Python enumerates all exact occurrences. Unique value with one proposed type resolves directly. Repeated values or multiple proposed types require selection; equality does not classify every copy as PII.
3. Service inserts collision-free temporary ID markers into a copy of the whole inspected window. It sends that annotated source and the IDs/candidate types in an internal JSON context. Markers can nest/cross for overlapping proposals. They do not change the original source used for redaction.
4. A second structured-output request selects one allowed type or `NOT_PII` for EVERY supplied ID. Missing/duplicate/unknown IDs, extra fields, invalid types or selected overlapping spans reject the whole detection result. All-NOT_PII decisions retain the source and still require independent verification.
5. Selected local spans translate to global document spans; exact overlap duplicates merge. The existing deterministic redactor assigns a fresh placeholder per selected occurrence in source order. Each memory manifest entry stores its placeholder, canonical type, occurrence index and exact original value. Equal PII values at separate positions have separate placeholders/entries.
6. Fresh rule and LLM verification inspect the actual final redacted text. Errors/residual PII never publish partial outputs.

## Implementation boundaries

- `llm_schema.py`: two-field proposals and closed ID/type decisions.
- `llm_response.py`: strict source-copy validation and safe errors; old anchor fields are rejected.
- `llm_occurrences.py`: service-computed spans, temporary annotation plan and complete selection validation.
- `llm_client.py`: one extraction call plus at most one selection call per window, sharing the overall detection deadline and effective thinking flag (default false).
- Existing models, rule/NER lane, window aggregation, placeholder/mapping, verification and multipart packaging remain the composition contracts. Generic non-LLM candidate resolver retains its separate fail-closed policy.
- Standalone diagnostic transport counts every actual proxy attempt, including selection, before send. `CALL_*` describes the logical detect/verify operation; `PROXY_REQUEST_STARTED` reports each physical request and fixed role. `proxy_request_count` is the call-cap total. A detection-only inspection can now use up to two requests.

## Limits and evidence

Exact IDs prove source location, not semantic correctness. A model can still misclassify a non-PII occurrence, omit an entire value, truncate a PII boundary or return invalid JSON. Independent residual verification helps detect omissions but does not prove absence of over-redaction. Annotated selection context/schema can be larger than extraction context; backend token limits and production latency remain deployment requirements, not guessed assurances.

Historical frozen v8 Swagger inputs/oracles remain historical files; generate a new export for v9. Do not rewrite frozen oracles to fit a real model response. No live proxy call, confidential text display or plaintext manifest export is part of implementing this change.

## Offline validation (2026-10-03)

Core: 1163 tests passed in18.74s. Standalone:62 tests passed in5.91s. Ruff check/format:52files passed; git diff --check passed. Reviewed real-document preflight:118327characters/28windows passed without displaying confidential source. Unit/mock fixtures verify mechanical selection/redaction/trace, fail-closed responses and request budgets; they do not establish live model accuracy, completeness or latency. The initial collection used an incompatible site-packages precedence, then was corrected to append the core environment to the bundled Python runtime. Subsequent contract-fixture migration failures were resolved; these are not proxy/real-document results.

After the transport-diagnostics addition: 72 standalone tests passed in5.91s; scoped Ruff check/format passed for the two changed files. Known/unknown exception kinds, numeric-only timeout logging, privacy, single attempts and no partial publication were tested with MockTransport. Production core/settings/limits/prompt/schema were unchanged, so the core suite was not rerun. No assistant live invocation or confidential source access occurred.

## Live detection evidence (2026-10-03)

The user ran the baseline/thinking-false window-5 inspection against the real proxy. It returned `DETECTION_WINDOW_ACCEPTED` after 239.216 seconds with two actual requests: extraction (4923 context characters) and selection (5502 context characters). Both responses passed local validation. This was a user-run invocation; the assistant did not upload or display confidential text.

The final shape describes the selection response: five decisions, required keys present, no unexpected keys, and a matching schema echo. `candidates_present=false` and `request_has_detection_schema=false` are expected for that role. Five decisions count ambiguous occurrences, including possible NOT_PII decisions; they do not count all detected PII. Schema echo diagnostics do not establish universal backend schema enforcement. The log does not provide separate extraction/selection timings or semantic accuracy evidence.

`verification_performed=false` and `outputs_published=false`: this accepted inspection performed no redaction, independent verification or output publication. No whole-document CORE_VERIFIED or human accuracy acceptance has been recorded. The earlier command is retained as the completed checkpoint:

```powershell
& $pdfTestPython .\pdf_to_pipeline.py inspect-detection --work-dir $mdWorkDir --allow-proxy-upload --window-number 5 --prompt-profile baseline --use-thinking false
```

## Full-core attempt (2026-10-03)

The user ran the full 28-window core command below. Windows1–7 passed local detection validation (elapsed54.010/165.681/72.194/188.721/235.723/47.309/61.207 seconds). Windows2/5/6/7 required selection. Window8 (4992 characters) stopped during extraction with PROXY_TRANSPORT_ERROR at300.013 seconds, before any selection. Total elapsed1124.890 seconds, actual proxy requests12/retry0/verification0. No full-document CORE_VERIFIED, redacted output publication or human accuracy acceptance resulted.

Recorded full-run command, not the next retry instruction:

```powershell
& $pdfTestPython .\pdf_to_pipeline.py run-core --work-dir $mdWorkDir --allow-proxy-upload --use-thinking false --max-calls 96 --max-verification-windows 40 --run-deadline-seconds 7200
```

This stop occurred below the96-request cap and7200-second whole-run deadline. Defaults are read300 seconds and request deadline600 seconds. The300.013-second failure is consistent with a read timeout, but the original generic error log does not identify the HTTPX exception or effective settings; it does not establish HTTP504 or a backend/model fault. A longer whole-run deadline does not by itself change HTTPX phase timeouts. Accepted detection validates source/IDs, not accuracy.

## Subsequent window-8 inspection (2026-10-03)

The user completed the window8 inspection below with unchanged baseline/thinking/settings. It returned DETECTION_WINDOW_ACCEPTED in210.105 seconds:4992 context characters/one extraction request/candidate_count1. Local schema/source resolution passed; this response required no selection. Observed effective phase limits were connect10/read300/write30/pool10 seconds and request deadline600 seconds. The inspected operation finished inside both limits.

```powershell
& $pdfTestPython .\pdf_to_pipeline.py inspect-detection --work-dir $mdWorkDir --allow-proxy-upload --window-number 8 --prompt-profile baseline --use-thinking false
```

No transport failure occurred, so this result does not identify the original failed request's exception or establish HTTP504/backend queue/model health. One candidate is the proposal count, not proof of complete PII detection. Schema echo matched, but local validation, not an echo, is the acceptance guard. verification_performed=false/outputs_published=false; this inspection did not redact, verify or publish outputs. At that checkpoint windows9–28 had no full-core result; the later rerun is recorded below. Successful isolated probes do not combine into a whole-document pass.

## Historical full-core rerun: window10 source-copy rejection (2026-10-03)

The user's latest attachment includes prior invocations plus a new full run. Count only its final RUN_SETTINGS/STOPPED pair as the new evidence. With unchanged28-window plan/thinking false/read300/request deadline600/max-calls96/verification-cap40/whole deadline7200/retry0, windows1–9 passed local detection validation. Elapsed per window:30.134/82.811/196.286/74.455/124.621/93.550/272.420/111.611/32.679 seconds. Windows5/6/7 required selection; window8 passed during this full run.

Window10 (4943 characters) rejected after145.920 seconds/one extraction request with DETECTION_RESPONSE_REJECTED/value_not_found. Response structure had six candidates/required keys/no unexpected keys/a matching schema echo. Candidate6 (one-based) ORGANIZATION/value35 characters was absent from the inspected NFC source; whitespace-stripped/format-stripped/NFKC comparisons were all false. No selection occurred for window10. Total13physicalrequests/1164.523seconds/verification0/STOPPED at semantic_detection. No redacted outputs, manifest publication, whole-document CORE_VERIFIED or human accuracy acceptance.

Schema controls structure, not membership of a free-text value in this source. The existing v9 prompt already requires verbatim substrings/no repair/no disconnected-span joining. The local source guard therefore rejected an unlocatable value as designed. Possible rewriting, invention, abbreviation expansion, disconnected-span assembly, boundary issues or upstream text changes cannot be distinguished from lengths/flags; the failed raw value was not persisted. Do not drop the candidate, substitute a fuzzy source match or return an empty clean result to continue. This invocation failed on source copying, before selection/redaction, without a transport timeout or HTTP504 result.

## Window10 isolated inspection repeated the rejection (2026-10-04)

The user ran the isolated baseline/thinking-false window10 check and got DETECTION_RESPONSE_REJECTED/value_not_found again at121.876 seconds with one extraction request/retry0/no selection. Context4943characters, effective connect10/read300/write30/pool10 and request deadline600 seconds. Structure had six candidates/no extra keys/required keys/a matching schema echo; candidate6 ORGANIZATION/value35characters remained absent even under whitespace/format/NFKC diagnostic comparisons. These metadata match the full-run failure, but do not establish identical candidate strings or deterministic complete responses. No raw failed value was retained. This was not a timeout and performed no redaction, verification or publication.

## Completed window10 inspection

Recorded completed checkpoint, not an instruction to repeat it for a pass:

```powershell
& $pdfTestPython .\pdf_to_pipeline.py inspect-detection --work-dir $mdWorkDir --allow-proxy-upload --window-number 10 --prompt-profile baseline --use-thinking false
```

## Private value/source comparison checkpoint

Use the existing offline export to prepare the exact window10 context/prompt/schema/public parameters. This writes input files only inside the reviewed private work directory, uses the actual serializer and checks the form roundtrip. It reads no credentials/settings and sends no request; the assistant does not inspect the exported confidential files.

```powershell
& $pdfTestPython .\pdf_to_pipeline.py export-swagger --work-dir $mdWorkDir --window-number 10 --prompt-profile baseline --use-thinking false
```

On SWAGGER_INPUT_READY, files are under `$mdWorkDir/swagger-inputs/<export_id>`: context.txt to context, prompt.txt to prompt, json_schema.json to json_schema, model/use_thinking from parameters.json. The user authorizes Swagger and sends the request themselves. Use all fields unchanged and compare ORGANIZATION values from the new response to the exact context privately. Report only the difference category (expanded abbreviation, changed spelling, disconnected pieces, literal escaping, absent value, or acceptance). Do not share values/source/raw responses/Curl/credentials in chat or commit them.

Swagger is a new model invocation and cannot recover the old discarded response. A new pass does not explain prior invalid values or establish whole-document accuracy. Repeated failure now warrants this concrete comparison before a prompt/schema/strategy change, rather than another blind inspect/full retry or a larger timeout. Keep source guards, independent verification and mapping traceability. No fuzzy acceptance, candidate dropping, empty clean fallback, plaintext manifest export or raw-response persistence was introduced. Window-plan changes require preparation/review again; a future full rerun has no resume/cache.

### User comparison result (2026-10-04)

The offline window10 export completed with SWAGGER_INPUT_READY, export_id input-3d256c36da2a41258f7333555310ab9c, 4943 characters, baseline/v9/thinking false, form roundtrip PASSED, network0. The user compared a new Swagger ORGANIZATION value with its context and identified an extra character inside the name. Do not copy the real name into documentation or fixtures. This response has a spelling/source-copy error and would correctly fail exact membership; it is not merely a schema or timeout issue. It does not recover or establish the identity of the earlier rejected strings.

Automatic recovery v3 is implemented (2026-10-04). Conflict selection now uses service-generated legal nonoverlapping option sets; the model returns one enumerated option ID per required group key. Every option preserves configured mandatory rules and finalized replacements. Original source spans, contextual NOT_PII, shared budgets and fresh final rules AND LLM verification remain. Generation has fixed group/span/option/work bounds; invalid or unavailable choices stop safely. **1359 combined tests passed / 19.77s**; Ruff check/format core56/standalone4 files and tracked diff check passed. Historical full v2 stopped at prepared20: conflict_selection_rejected / 2680.564s / 33 requests / verification0, because independent ID/type votes selected overlapping spans. Current scoped/full live status and resume point are recorded only in the learning handoff (`LEARNING_HANDOFF.md`, เอกสารส่วนตัว ไม่อยู่ใน repo). See [conflict design](CONFLICT_RECONCILIATION_DESIGN.md).

Only `CORE_VERIFIED` publishes `results/run-<id>/redacted.md` and a safe `summary.json`; the test harness continues to omit plaintext PII manifest export while encryption is deferred. Review the redacted document locally against expected PII/non-PII occurrences before reporting accuracy.

Historical1317 safe-merge-diagnostics checkpoint preceded v2/1338 and the current v3/1359 gate above. The discarded old response cannot be replayed; the diagnostic only confirms that new invocation's LLM/rule collision. Current scoped/full test status is recorded in the learning handoff (`LEARNING_HANDOFF.md`, เอกสารส่วนตัว ไม่อยู่ใน repo).

`run-core --window-number N` returns `CORE_WINDOW_VERIFIED` only after verifying that isolated window's final text, and publishes no files. This scope is not whole-document acceptance. Human expected-PII comparison is offline evaluation, not a production approval step.
