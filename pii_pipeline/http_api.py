"""Former location of ``pii_pipeline.service.http`` (kept for existing imports)."""

import sys

from .service import http as _module

sys.modules[__name__] = _module
