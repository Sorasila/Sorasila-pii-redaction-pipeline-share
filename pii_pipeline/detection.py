"""Former location of ``pii_pipeline.core.detection`` (kept for existing imports)."""

import sys

from .core import detection as _module

sys.modules[__name__] = _module
