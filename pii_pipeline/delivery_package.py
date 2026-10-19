"""Former location of ``pii_pipeline.service.delivery`` (kept for existing imports)."""

import sys

from .service import delivery as _module

sys.modules[__name__] = _module
