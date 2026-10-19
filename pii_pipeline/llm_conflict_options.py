"""Former location of ``pii_pipeline.selection.conflicts`` (kept for existing imports)."""

import sys

from .selection import conflicts as _module

sys.modules[__name__] = _module
