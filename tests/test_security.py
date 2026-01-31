"""Tests for OTP security functions."""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from fastapi_otp_authentication.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    verify_otp_code,
)


def test_generate_otp_production() -> None:
    """Test OTP generation in production mode."""
    code = generate_otp(6, developer_mode=False)
    assert len(code) == 6
    assert code.isdigit()


def test_generate_otp_developer_mode() -> None:
    """Test OTP generation in developer mode."""
    code = generate_otp(6, developer_mode=True)
    assert code == "000000"


def test_generate_otp_custom_length() -> None:
    """Test OTP generation with custom length."""
    code = generate_otp(8, developer_mode=False)
    assert len(code) == 8
    assert code.isdigit()


def test_create_and_decode_access_token() -> None:
    """Test access token creation and decoding."""
    secret = "test-secret-key-minimum-32-chars-long"
    user_id = 123
    additional_claims = {"role": "admin"}

    token = create_access_token(
        user_id=user_id,
        additional_claims=additional_claims,
        secret_key=secret,
        algorithm="HS256",
        lifetime=timedelta(hours=1),
    )

    claims = decode_token(token, secret, "HS256")

    assert claims["sub"] == str(user_id)
    assert claims["type"] == "access"
    assert claims["role"] == "admin"
    assert "jti" in claims
    assert "exp" in claims


def test_create_and_decode_refresh_token() -> None:
    """Test refresh token creation and decoding."""
    secret = "test-secret-key-minimum-32-chars-long"
    user_id = 456

    token = create_refresh_token(
        user_id=user_id,
        secret_key=secret,
        algorithm="HS256",
        lifetime=timedelta(days=7),
    )

    claims = decode_token(token, secret, "HS256")

    assert claims["sub"] == str(user_id)
    assert claims["type"] == "refresh"
    assert "jti" in claims


def test_verify_otp_code_success() -> None:
    """Test successful OTP verification."""
    stored_code = "123456"
    input_code = "123456"
    created_at = datetime.now()
    expiry = timedelta(minutes=10)

    is_valid = verify_otp_code(
        stored_code=stored_code,
        input_code=input_code,
        created_at=created_at,
        expiry=expiry,
        max_attempts=5,
        current_attempts=0,
    )

    assert is_valid is True


def test_verify_otp_code_invalid() -> None:
    """Test OTP verification with wrong code."""

    stored_code = "123456"
    input_code = "999999"
    created_at = datetime.now()
    expiry = timedelta(minutes=10)

    # Incrementing attempts should not raise
    is_valid = verify_otp_code(
        stored_code=stored_code,
        input_code=input_code,
        created_at=created_at,
        expiry=expiry,
        max_attempts=5,
        current_attempts=0,
    )

    assert is_valid is False


def test_verify_otp_code_expired() -> None:
    """Test OTP verification with expired code."""
    stored_code = "123456"
    input_code = "123456"
    created_at = datetime.now() - timedelta(minutes=15)
    expiry = timedelta(minutes=10)

    with pytest.raises(HTTPException) as exc_info:
        verify_otp_code(
            stored_code=stored_code,
            input_code=input_code,
            created_at=created_at,
            expiry=expiry,
            max_attempts=5,
            current_attempts=0,
        )
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


def test_verify_otp_code_too_many_attempts() -> None:
    """Test OTP verification with too many attempts."""
    stored_code = "123456"
    input_code = "123456"
    created_at = datetime.now()
    expiry = timedelta(minutes=10)

    with pytest.raises(HTTPException) as exc_info:
        verify_otp_code(
            stored_code=stored_code,
            input_code=input_code,
            created_at=created_at,
            expiry=expiry,
            max_attempts=5,
            current_attempts=5,
        )
    assert exc_info.value.status_code == 429
    assert "too many" in exc_info.value.detail.lower()
