"""HTTP service: app factory, /redact adapter and delivery package.

`uvicorn pii_pipeline.service:create_service_app --factory` is the documented
entry point, so the app module's public names are re-exported here.
"""

from .app import (
    UNENCRYPTED_TEST_KID,
    ServiceConfigurationError,
    ServiceSettings,
    bearer_authenticator,
    create_service_app,
    unencrypted_test_manifest_envelope,
)

__all__ = [
    "UNENCRYPTED_TEST_KID",
    "ServiceConfigurationError",
    "ServiceSettings",
    "bearer_authenticator",
    "create_service_app",
    "unencrypted_test_manifest_envelope",
]
