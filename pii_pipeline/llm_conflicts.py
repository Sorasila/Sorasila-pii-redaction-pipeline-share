"""Former location of ``pii_pipeline.selection.spans`` (kept for existing imports)."""

import sys

from .selection import spans as _module

sys.modules[__name__] = _module
