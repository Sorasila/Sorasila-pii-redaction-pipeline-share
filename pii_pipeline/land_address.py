"""Former location of ``pii_pipeline.selection.land`` (kept for existing imports)."""

import sys

from .selection import land as _module

sys.modules[__name__] = _module
