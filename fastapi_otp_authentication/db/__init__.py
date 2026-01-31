"""Database models and adapters for fastapi-otp-authentication."""

from fastapi_otp_authentication.db.adapter import OTPDatabase
from fastapi_otp_authentication.db.models import BaseOTPUserTable, TokenBlacklist

__all__ = ["BaseOTPUserTable", "OTPDatabase", "TokenBlacklist"]
