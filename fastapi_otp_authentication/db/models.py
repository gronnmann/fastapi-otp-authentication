"""Database models for OTP authentication."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column  # type: ignore[import-untyped]


class BaseOTPUserTable[ID]:
    """
    Base class for user models with OTP authentication support.

    Generic type parameter ID allows for different primary key types (int, UUID, etc.).

    Required fields:
        - email: User's email address (unique, indexed)
        - otp_code: Current OTP code (nullable)
        - otp_created_at: Timestamp when OTP was created (nullable)
        - otp_attempts: Number of failed OTP verification attempts
        - last_otp_request_at: Timestamp of last OTP request for rate limiting
        - is_verified: Whether user has completed OTP verification

    Example:
        ```python
        from sqlalchemy.orm import DeclarativeBase

        class Base(DeclarativeBase):
            pass

        class User(BaseOTPUserTable[int], Base):
            __tablename__ = "users"

            id: Mapped[int] = mapped_column(Integer, primary_key=True)
            username: Mapped[str] = mapped_column(String(50), unique=True)
        ```
    """

    # Email field - unique and indexed for fast lookups
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )

    # OTP-related fields
    otp_code: Mapped[str | None] = mapped_column(String(20), nullable=True)
    otp_created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    otp_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_otp_request_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Verification status
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class TokenBlacklist:
    """
    Model for storing blacklisted JWT tokens.

    Tokens are added to blacklist on logout or when they need to be revoked.
    Expired tokens should be periodically cleaned up using the cleanup method.

    Example:
        ```python
        from sqlalchemy.orm import DeclarativeBase

        class Base(DeclarativeBase):
            pass

        class Blacklist(TokenBlacklist, Base):
            __tablename__ = "token_blacklist"

            id: Mapped[int] = mapped_column(Integer, primary_key=True)
        ```
    """

    __tablename__ = "token_blacklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # JWT ID (jti claim) - unique identifier for the token
    jti: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )

    # Token type (access or refresh)
    token_type: Mapped[str] = mapped_column(String(10), nullable=False)

    # Timestamps
    blacklisted_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
