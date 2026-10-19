"""Which located spans are PII when the LLM reply alone cannot say.

- occurrences: a value found at several places; which copies are PII.
- spans: the shared choice engine (service IDs for spans, required rule spans)
  and ``match_key``.
- conflicts: overlapping spans; precomputed legal non-overlapping options.
- land: the land-number + location policy (approved 2026-10-12).
"""
