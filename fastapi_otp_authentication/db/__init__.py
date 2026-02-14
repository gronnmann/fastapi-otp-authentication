"""Database models and adapters for fastapi-otp-authentication."""

from fastapi_otp_authentication.db.adapter import DatabaseAdapter
from fastapi_otp_authentication.db.sqlalchemy.adapter import SQLAlchemyAdapter
from fastapi_otp_authentication.db.sqlalchemy.models import (
    BaseOTPUserTable,
    TokenBlacklist,
)
from fastapi_otp_authentication.db.sqlalchemy.types import UTCDateTime

__all__ = [
    "BaseOTPUserTable",
    "DatabaseAdapter",
    "SQLAlchemyAdapter",
    "TokenBlacklist",
    "UTCDateTime",
]

# Conditionally export MongoDB classes if motor is installed
try:
    from fastapi_otp_authentication.db.mongodb.adapter import MongoDBAdapter
    from fastapi_otp_authentication.db.mongodb.models import (
        BaseOTPUserDocument,
        TokenBlacklistDocument,
    )

    __all__ += ["BaseOTPUserDocument", "MongoDBAdapter", "TokenBlacklistDocument"]
except ImportError:
    # MongoDB support not installed
    pass
