"""Configuration class for OTP authentication."""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any

from fastapi import HTTPException, status  # type: ignore[import-untyped]


class OTPAuthConfig(ABC):
    """
    Abstract configuration class for OTP authentication.

    Users must extend this class and implement the send_otp method.
    Configuration can be set via class attributes or constructor.

    Example:
        ```python
        class MyOTPConfig(OTPAuthConfig):
            secret_key = "your-secret-key-here"
            access_token_lifetime = timedelta(hours=1)
            refresh_token_lifetime = timedelta(days=7)
            otp_expiry = timedelta(minutes=10)

            async def send_otp(self, email: str, code: str) -> None:
                # Send email with OTP code
                print(f"Sending OTP {code} to {email}")
        ```
    """

    # Required configuration - these must be set
    secret_key: str

    cookie_secure: bool = True
    """Whether to set the 'Secure' flag on cookies (require https)."""

    # Token lifetimes
    access_token_lifetime: timedelta = timedelta(hours=1)
    refresh_token_lifetime: timedelta = timedelta(days=7)

    # OTP configuration
    otp_length: int = 6
    otp_expiry: timedelta = timedelta(minutes=10)
    max_otp_attempts: int = 5

    # Rate limiting
    otp_rate_limit_seconds: int = 60  # Minimum seconds between OTP requests

    # User management
    auto_create_user: bool = True

    # Security settings
    developer_mode: bool = False
    algorithm: str = "HS256"

    def __init__(self) -> None:
        """Initialize and validate configuration."""
        self.validate_secret()

    def validate_secret(self) -> None:
        """
        Validate that the secret key is secure.

        In production mode, requires secret to be at least 32 characters.
        In developer mode, any secret is allowed.

        Raises:
            HTTPException: 500 if secret is not secure enough
        """
        if self.developer_mode:
            # Allow any secret in developer mode
            return

        if not hasattr(self, "secret_key") or not self.secret_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="secret_key must be set. Generate with: openssl rand -hex 32",
            )

        if len(self.secret_key) < 32:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="secret_key must be at least 32 characters long. "
                "Generate with: openssl rand -hex 32",
            )

    @abstractmethod
    async def send_otp(self, email: str, code: str) -> None:
        """
        Send OTP code to user's email.

        This method must be implemented by the user to handle OTP delivery.
        Implementation can send email, SMS, push notification, etc.

        Args:
            email: User's email address
            code: OTP code to send

        Example:
            ```python
            async def send_otp(self, email: str, code: str) -> None:
                # Example: send email
                await send_email(
                    to=email,
                    subject="Your OTP Code",
                    body=f"Your verification code is: {code}"
                )
            ```
        """
        raise NotImplementedError("send_otp method must be implemented")

    def get_additional_claims(self, _user: Any) -> dict[str, Any]:  # noqa: ANN401
        """
        Get additional claims to include in JWT tokens.

        Override this method to add custom claims based on the user.

        Args:
            user: User object

        Returns:
            Dictionary of additional claims

        Example:
            ```python
            def get_additional_claims(self, user: User) -> dict[str, Any]:
                return {
                    "role": user.role,
                    "permissions": user.permissions,
                }
            ```
        """
        return {}
