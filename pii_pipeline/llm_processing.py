"""Former location of ``pii_pipeline.llm.processing`` (kept for existing imports)."""

import sys

from .llm import processing as _module

sys.modules[__name__] = _module
