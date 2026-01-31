"""Type definitions for fastapi-otp-authentication."""

from typing import Any, Protocol, TypeVar

# Generic type variable for user ID (int, UUID, str, etc.)
ID = TypeVar("ID")

# Generic type variable for user models
UserType = TypeVar("UserType", bound="OTPUserProtocol")


class OTPUserProtocol(Protocol):
    """Protocol defining required attributes for OTP user models."""

    id: Any
    email: str
    otp_code: str | None
    otp_created_at: Any  # datetime
    otp_attempts: int
    is_verified: bool
