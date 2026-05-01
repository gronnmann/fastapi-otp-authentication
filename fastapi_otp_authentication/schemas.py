"""Pydantic schemas for request/response models."""

from pydantic import BaseModel, EmailStr, Field


class OTPRequest(BaseModel):
    """Request schema for OTP generation."""

    email: EmailStr = Field(..., description="Email address to send OTP code to")


class OTPVerify(BaseModel):
    """Request schema for OTP verification."""

    email: EmailStr = Field(..., description="Email address of the user")
    code: str = Field(
        ..., min_length=4, max_length=10, description="OTP code to verify"
    )


class TokenResponse(BaseModel):
    """Response schema for token generation."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    refresh_token: str | None = Field(
        None,
        description="Refresh token (only present when refresh_token_delivery is 'body' or 'both')",
    )


class RefreshRequest(BaseModel):
    """Request schema for token refresh (body delivery mode)."""

    refresh_token: str | None = Field(
        None,
        description="Refresh token (required when not using cookie delivery)",
    )


class LogoutRequest(BaseModel):
    """Request schema for logout (body delivery mode)."""

    refresh_token: str | None = Field(
        None,
        description="Refresh token (required when not using cookie delivery)",
    )


class MessageResponse(BaseModel):
    """Generic message response schema."""

    message: str = Field(..., description="Response message")
