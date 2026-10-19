"""Former location of ``pii_pipeline.selection.occurrences`` (kept for existing imports)."""

import sys

from .selection import occurrences as _module

sys.modules[__name__] = _module
