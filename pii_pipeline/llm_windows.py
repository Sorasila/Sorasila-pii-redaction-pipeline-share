"""Former location of ``pii_pipeline.llm.windows`` (kept for existing imports)."""

import sys

from .llm import windows as _module

sys.modules[__name__] = _module
