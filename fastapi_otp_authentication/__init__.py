"""FastAPI OTP Authentication - A flexible, type-safe library for OTP-based authentication."""

from fastapi_otp_authentication.config import OTPAuthConfig
from fastapi_otp_authentication.db import (
    BaseOTPUserTable,
    DatabaseAdapter,
    SQLAlchemyAdapter,
    TokenBlacklist,
)
from fastapi_otp_authentication.dependencies import (
    get_current_user_dependency,
    get_custom_claims_dependency,
    get_verified_user_dependency,
)
from fastapi_otp_authentication.router import get_auth_router
from fastapi_otp_authentication.schemas import (
    MessageResponse,
    OTPRequest,
    OTPVerify,
    TokenResponse,
)

__version__ = "0.1.0"

__all__ = [
    "BaseOTPUserTable",
    "DatabaseAdapter",
    "MessageResponse",
    "OTPAuthConfig",
    "OTPRequest",
    "OTPVerify",
    "SQLAlchemyAdapter",
    "TokenBlacklist",
    "TokenResponse",
    "get_auth_router",
    "get_current_user_dependency",
    "get_custom_claims_dependency",
    "get_verified_user_dependency",
]

# Conditionally export MongoDB classes if motor is installed
try:
    from fastapi_otp_authentication.db import (
        BaseOTPUserDocument,
        MongoDBAdapter,
        TokenBlacklistDocument,
    )

    __all__ += ["BaseOTPUserDocument", "MongoDBAdapter", "TokenBlacklistDocument"]
except ImportError:
    # MongoDB support not installed
    pass
