"""Protocols defining user and model interfaces for OTP authentication."""

from datetime import datetime
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class OTPUserProtocol(Protocol):
    """
    Protocol defining the required interface for OTP user objects.

    Any user model (SQLAlchemy, Pydantic, etc.) used with adapters
    must provide these attributes.
    """

    id: int | str
    email: str
    is_verified: bool
    otp_code: str | None
    otp_created_at: datetime | None
    otp_attempts: int
    last_otp_request_at: datetime | None


@runtime_checkable
class PydanticOTPUserProtocol(OTPUserProtocol, Protocol):
    """
    Protocol for Pydantic-based OTP user models.

    Extends OTPUserProtocol with Pydantic-specific methods.
    """

    def model_dump(
        self, *, by_alias: bool = False, exclude_none: bool = True
    ) -> dict[str, Any]:
        """Serialize model to dictionary."""
        ...

    @classmethod
    def model_validate(cls, obj: Any) -> "PydanticOTPUserProtocol":  # noqa: ANN401
        """Validate and create model from dictionary."""
        ...


@runtime_checkable
class SQLAlchemyUserModelProtocol(Protocol):
    """
    Protocol for SQLAlchemy user model classes (not instances).

    This protocol is for the class/table itself, used in queries.
    """

    email: Any  # Column attribute for WHERE clauses
