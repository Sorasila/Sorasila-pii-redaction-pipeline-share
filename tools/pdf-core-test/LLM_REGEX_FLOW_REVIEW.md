# LLM-first and regex safety-net flow: implementation review

2026-10-04. The user approved implementation and fully automatic request handling. Automatic recovery v1 is implemented in the core, supported by trusted HTTP adapter configuration and enabled by default in standalone `run-core`. Offline regression gates: **1317 passed / 12.06s** (core and standalone, after merge diagnostics); Ruff checks/format and tracked Git diff checks passed. User-authorized isolated window 10 passed **CORE_WINDOW_VERIFIED / 205.614s / 4 proxy requests**, with 8 entries and 2 final verification windows. The subsequent full run completed detection windows 1–20, including successful targeted repairs at windows 7 and 20, then stopped after the window 21 repair response: **SEMANTIC_DETECTION_REJECTED / 3054.748s / 32 proxy requests / 3 recovery role calls / verification 0**. No full-document output or manifest was published. No notebook execution or manual inspection/display of confidential source, raw responses or credentials was performed; the script internally loaded its required source/config.

Confirmed production constraint: the service must handle each request automatically. No person or frontend approval step reviews individual proposals, chooses replacements, or releases a failed result. Production deployment/client lifecycle and real encryption remain unbound; offline tests do not establish LLM accuracy or latency.

## Baseline comparison that led to the change

Current `pii_pipeline/async_pipeline.py:process_markdown_async`:

1. Normalize and validate the original source.
2. Run rule detectors on that source and collect matches. This does **not** redact the source.
3. Run semantic detectors on the same original source. In the real-document bridge this calls the windowed v9 LLM extraction/occurrence-selection lane.
4. Validate/merge all source spans, then call deterministic `redact` once to create placeholders and in-memory entries.
5. Check the final redacted text using independent rules and a fresh LLM verification; return only after both pass.

These strict reference entry points remain available. The new recovery entry point is `pii_pipeline.llm_recovery.process_markdown_with_recovery_async`; its behavior is described below. The LLM does not receive a regex-redacted document for initial extraction in either path. Rules executing first is distinct from redacting first. The actual standalone numeric rule checker covers CASE_NUMBER, TITLE_DEED_NUMBER and LAND_PARCEL_NUMBER; it is not proof that regex covers NAME, ORGANIZATION and ADDRESS or every other canonical type.

Notebook `demo_structured_output_to_db.ipynb`, section2.3 (code cells25/27/28), `redact_pdpa`:

1. `extract_pii_llm(text)` returns a list of strings from chat completion.
2. `extract_pii_regex(text)` inspects the same original text.
3. Deduplicate the combined strings, sort longer strings first, `re.escape` them into a literal alternation pattern.
4. One `re.sub` replaces matching text globally with the supplied replacement and returns the text plus value lists.

This notebook is not a sequential LLM-redaction then regex-redaction pipeline either. Both detectors inspect the original and one replacement follows. Its label “same as real pipeline” is not evidence that it calls the current processing core: this function implements its own extraction/substitution path.

## The differences that affect failures

| Concern | Current core | Notebook section2.3 |
|---|---|---|
| A proposed string is absent from source | Rejects that detection window; exception aborts the current document call | Literal replacement matches nothing for that string; function can still return text |
| LLM timeout / parse / other error | Explicit failure, no clean fallback; harness transport retries0 | Broad Exception handler prints an error category and returns[] |
| Failed detection versus no PII | Distinguished | Both can become an empty list |
| Same value in PII and NOT_PII positions | Service occurrence IDs and contextual decisions preserve NOT_PII | Global literal replacement can change every occurrence |
| Replacement traceability | Per-occurrence type/index/placeholder and original-source entry | One replacement argument plus lists/source table; no equivalent per-occurrence manifest construction in this function |
| Final independent verification | Rules AND fresh LLM required before delivery | No independent final verification call in `redact_pdpa` |

Changing only detector order does not fix the current source-copy failure. If LLM adds a character, the resulting value still cannot be located exactly. Regex may independently find the real value only when a suitable rule actually covers it. A regex-clean result does not establish that semantic names, juristic-person names, addresses and other unsupported cases are absent.

## Implemented recovery flow

The useful change is recoverable processing with a strict final output gate, rather than copying the notebook's error-to-empty-list behavior:

```text
Original source
  -> LLM proposals + explicit inspection outcome/issues
  -> exact-source resolution / occurrence decisions
  -> regex/rule candidates on the original source
  -> reconcile original-source spans
  -> deterministic redaction + in-memory manifest (intermediate only)
  -> independent rules AND fresh LLM verification
      -> passed: complete output package
      -> residual or recoverable issue: bounded targeted recovery, then verify again
      -> total call/time budget exhausted / final verification incomplete: safe error, no success package
```

Rules can run after LLM detection while still operating on the original text. Retaining one replacement pass avoids having to map second-pass offsets back through inserted placeholders and reconstruct entries across two different text versions. Regex inspection of the final redacted text remains a separate last check. If actual two-pass replacement is chosen instead, offset provenance, placeholder exclusion and a unified manifest require additional design.

An explicit detection outcome should distinguish valid proposals, unlocatable/invalid proposals, inspected versus uninspected windows, transport status and unresolved semantic coverage. An unlocatable proposal cannot be used as a replacement value or a manifest entry; failure must not be represented as a successful empty extraction. Valid proposals and results for unaffected windows may be retained **inside the same request** while recovery proceeds. No cross-request session, disk checkpoint, plaintext manifest or retry storage is implied.

Implemented policy:

- For a copy error, preserve valid source proposals, let rules supply independently validated source spans, and attempt bounded targeted re-extraction/resolution when needed. A similarity score alone cannot select a span or establish its PII context.
- For a timeout, record the region as uninspected; rules can still produce an intermediate result. A fresh independent verifier that successfully covers the entire actual redacted result can inform recovery. Regex alone cannot clear semantic coverage. If the verifier reports residual types, targeted detection can repair that region within budget; if verification remains unavailable, do not claim the document is clean.
- For a residual match, add only validated original-source replacements, rebuild/reconcile the manifest and rerun independent verification on the new result.
- Bound all extra calls, window coverage, attempts and total request time. Do not reset budgets during recovery or silently add unlimited retries. Recovery does not promise faster inference and may increase total latency.

Automatic acceptance policy v3: a successful fresh rules AND LLM verification covering the entire final redacted text can clear preliminary unmatched extraction proposals or detection outages. Initial failures remain explicit issues, never clean `[]`; this rule does not clear failed/incomplete final verification. Defaults are one targeted extraction repair per affected window, one verification retry per window, one residual repair round, and at most four extra recovery role calls across the request. Global role-call and time budgets never reset. Role calls may contain extraction plus selection and bounded transport attempts; the standalone bridge also caps every actual proxy attempt. Fatal auth/configuration/model/TLS failures stop safely. Exact-span conflicts use bounded contextual selection from service-generated nonoverlapping options within an existing complete trusted detection window, preserving mandatory configured rules and finalized replacements. Default one selection attempt per batch (trusted policy at most two) consumes the same recovery/actual-call/time budget. Invalid/incomplete/overlapping/required-omitted or unavailable decisions stop safely; no latest/longest/fuzzy guess. Final unverifiable output returns a safe error, never an ordinary200 multipart success. Quarantine persistence/encryption/retention remain deferred.

Residual extraction runs on the reported redacted windows. Each new match must lie entirely in an unchanged text segment, then map exactly to the original source; a span touching a placeholder is rejected. Rebuild the text and manifest from all original-source spans and run full independent verification again. Intermediate placeholder numbers may shift as new source-order matches are inserted; only the final consistent package is exposed.

## Fully automatic request handling

Candidate validation, source resolution, occurrence selection, rule coverage, recovery and final verification must all run inside the same synchronous request. Valid/invalid/uninspected classifications are internal processing states, not lists for a human or frontend to approve. Conflicting or ambiguous decisions must follow a defined automatic policy; they cannot fall through to manual release.

The caller receives either the complete verified multipart package or a safe terminal error within the effective request deadline. It does not wait for a reviewer, poll a review queue, or receive intermediate unverified Markdown/PII mapping. Ordinary HTTP error handling is still required at the caller; the exact error contract and time budget remain part of dev integration. No design can guarantee a successful verified response on every request when required LLM inspection remains unavailable.

Human comparison against expected PII belongs to offline system evaluation and development testing. It is not a runtime gate. Automated verification checks the configured acceptance criteria; passing it does not establish perfect semantic accuracy on arbitrary documents.

## Implementation impact

| Area | Implemented behavior |
|---|---|
| `llm_response.py` / `llm_client.py` | New internal outcomes retain valid proposals and safe issues; preserve strict legacy parsers; invalid/repeated unselected values never enter replacement |
| `llm_processing.py` | Reuse trusted full-coverage planners and original span contracts; strict reference methods remain unchanged |
| `llm_recovery.py` | New LLM-first/rule safety-net orchestration, bounded window/residual recovery, source mapping and final AND verification |
| `redaction.py` / `llm_occurrences.py` | Reuse source-span redaction, per-occurrence counters and NOT_PII selection; reconcile overlap conflicts without global equality replacement |
| Verification / budgets | Distinguish residual, unavailable and verified-clean; bound recovery and require full inspected output coverage |
| HTTP adapter / harness | Explicit processor+policy composition in `create_app`; `run-core` uses recovery by default; safe events/call caps and isolated-window test scope, no output publication for that scope |

HTTP raw1000-character ingress, synchronous response, final multipart parts and deferred encryption do not need to change merely to reorder detection/recover within the request. Operational time limits may still make a safe error unavoidable; removing the early exception does not eliminate the caller/gateway deadline.

## Activation and remaining validation

Handoff.revised §4.4/4.7 now distinguish intermediate recoverable issues from final delivery failure. Detection schema/base prompt v9, contextual NOT_PII selection, verification schema/prompt v4, raw1000-character input and multipart encryption contract remain unchanged. Targeted repair appends a trusted instruction without interpolating rejected values. Transport retry defaults are unchanged; the standalone live bridge still uses transport retry0 and thinking false by default.

For HTTP composition, supply the same `LlmDocumentProcessor` bound in `AsyncPipelineComponents` as `recovery_processor`, plus a trusted `RecoveryPolicy`, to `create_app`. Without those arguments the old strict path remains available; deployment is not automatically configured. The HTTP outer request deadline still includes authentication, processing and encryption.

The isolated prepared-window 10 core test including final verification passed without recovery and published no files/manifest. Initial restricted-sandbox attempts failed immediately with CONNECT_ERROR; the same authorized command passed after tool-approved network escalation. Those connection failures are not evidence of LLM inference failure.

Historical v1 full reviewed-document test ran under explicit budgets: 144 actual proxy requests, 40 verification windows, 4 extra recovery role calls, 1 residual round, 7200 seconds, thinking false and transport retry 0. Window 7 repaired value_not_found 1 to merged matches 7/issues 0; window 20 repaired value_not_found 2 to merged matches 6/issues 0. At window 21 the first outcome retained 5 valid matches with 2 issues; the repair call returned 1 value_not_found issue at 132.049 seconds, but no DETECTION_WINDOW_OUTCOME followed before terminal failure. No timeout or budget exhaustion was reported. Windows 22–28 and final verification were not reached.

Historical v1 code/event review pointed to merging retained and repair spans, where overlapping spans or conflicting types remain fatal. Offline reproduction now confirms that both changed boundaries and changed types can produce the same old terminal/event signature, including issue counts 2→1 and no verification. A control with exact duplicate matches plus one remaining value_not_found issue reaches final verification. This confirms the failure mechanism, not the exact confidential pair: the old run retained no raw outcomes/spans or typed merge reason for replay.

Automatic recovery v3 is implemented (2026-10-04). Conflict selection now uses service-generated legal nonoverlapping option sets; the model returns one enumerated option ID per required group key. Every option preserves configured mandatory rules and finalized replacements. Original source spans, contextual NOT_PII, shared budgets and fresh final rules AND LLM verification remain. Generation has fixed group/span/option/work bounds; invalid or unavailable choices stop safely. **1359 combined tests passed / 19.77s**; Ruff check/format core56/standalone4 files and tracked diff check passed. Historical full v2 stopped at prepared20: conflict_selection_rejected / 2680.564s / 33 requests / verification0, because independent ID/type votes selected overlapping spans. Current scoped/full live status and resume point are recorded only in the learning handoff (`LEARNING_HANDOFF.md`, เอกสารส่วนตัว ไม่อยู่ใน repo). See [conflict design](CONFLICT_RECONCILIATION_DESIGN.md).