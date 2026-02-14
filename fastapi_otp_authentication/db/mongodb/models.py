"""MongoDB document models for OTP authentication."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class BaseOTPUserDocument(BaseModel):
    """
    Base Pydantic model for user documents with OTP authentication support in MongoDB.

    This model defines the required fields for OTP authentication.
    Users should inherit from this class and add their custom fields.

    Required fields:
        - id: Unique identifier (MongoDB ObjectId as string, optional for auto-generation)
        - email: User's email address (unique, indexed)
        - is_verified: Whether user has completed OTP verification
        - otp_code: Current OTP code (nullable)
        - otp_created_at: Timestamp when OTP was created (nullable)
        - otp_expires_at: Timestamp when OTP expires (nullable)
        - otp_attempts: Number of failed OTP verification attempts
        - last_otp_request_at: Timestamp of last OTP request for rate limiting

    Example:
        ```python
        from pydantic import Field

        class User(BaseOTPUserDocument):
            username: str
            full_name: str | None = None

            model_config = ConfigDict(
                collection="users",
                json_schema_extra={
                    "example": {
                        "email": "user@example.com",
                        "username": "johndoe",
                        "full_name": "John Doe"
                    }
                }
            )
        ```
    """

    # MongoDB _id field (ObjectId as string)
    id: str | None = Field(default=None, alias="_id")

    # Email field - must be unique and indexed in the collection
    email: EmailStr = Field(..., description="User's email address")

    # Verification status
    is_verified: bool = Field(
        default=False, description="Whether user has verified their email"
    )

    # OTP-related fields
    otp_code: str | None = Field(
        default=None, description="Current OTP code", max_length=20
    )
    otp_created_at: datetime | None = Field(
        default=None, description="When OTP was created"
    )
    otp_expires_at: datetime | None = Field(
        default=None, description="When OTP expires"
    )
    otp_attempts: int = Field(
        default=0, description="Number of failed OTP verification attempts"
    )
    last_otp_request_at: datetime | None = Field(
        default=None, description="Last time user requested an OTP"
    )

    model_config = ConfigDict(
        populate_by_name=True,  # Allow both 'id' and '_id'
        from_attributes=True,  # Enable ORM mode for compatibility
        arbitrary_types_allowed=True,
    )


class TokenBlacklistDocument(BaseModel):
    """
    Pydantic model for blacklisted JWT tokens in MongoDB.

    Tokens are added to blacklist on logout or when they need to be revoked.
    Expired tokens should be periodically cleaned up using the cleanup method.

    Fields:
        - id: MongoDB ObjectId as string (auto-generated)
        - jti: JWT ID (jti claim) - unique identifier for the token
        - token_type: Type of token ("access" or "refresh")
        - blacklisted_at: When the token was blacklisted
        - expires_at: When the token expires

    Example:
        ```python
        # Used internally by the adapter, typically not instantiated directly
        blacklist_entry = TokenBlacklistDocument(
            jti="unique-jwt-id",
            token_type="access",
            blacklisted_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=1)
        )
        ```
    """

    # MongoDB _id field (ObjectId as string)
    id: str | None = Field(default=None, alias="_id")

    # JWT ID (jti claim) - unique identifier for the token
    jti: str = Field(..., description="JWT ID from token claims", max_length=255)

    # Token type (access or refresh)
    token_type: str = Field(..., description="Type of token", max_length=10)

    # Timestamps
    blacklisted_at: datetime = Field(..., description="When token was blacklisted")
    expires_at: datetime = Field(..., description="When token expires")

    model_config = ConfigDict(
        populate_by_name=True,  # Allow both 'id' and '_id'
        from_attributes=True,
        arbitrary_types_allowed=True,
    )
