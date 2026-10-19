"""Former location of ``pii_pipeline.rules.thai`` (kept for existing imports)."""

import sys

from .rules import thai as _module

sys.modules[__name__] = _module
