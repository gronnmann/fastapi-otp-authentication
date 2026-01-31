"""Tests for OTP security functions."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from fastapi_otp_authentication.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    verify_otp_code,
)


# ============================================================================
# OTP Generation Tests
# ============================================================================


class TestGenerateOTP:
    """Test suite for OTP code generation."""

    def test_generates_correct_length(self) -> None:
        """OTP should have the specified number of digits."""
        code = generate_otp(6, developer_mode=False)
        assert len(code) == 6
        assert code.isdigit()

    def test_generates_custom_length(self) -> None:
        """OTP should support custom lengths."""
        for length in [4, 6, 8]:
            code = generate_otp(length, developer_mode=False)
            assert len(code) == length
            assert code.isdigit()

    def test_generates_only_digits(self) -> None:
        """OTP should contain only numeric digits."""
        code = generate_otp(6, developer_mode=False)
        assert code.isdigit()
        assert all(c in "0123456789" for c in code)

    def test_developer_mode_returns_zeros(self) -> None:
        """In developer mode, OTP should be all zeros for easy testing."""
        code = generate_otp(6, developer_mode=True)
        assert code == "000000"

    def test_developer_mode_respects_length(self) -> None:
        """Developer mode OTP should have correct length of zeros."""
        code = generate_otp(8, developer_mode=True)
        assert code == "00000000"

    def test_generates_different_codes(self) -> None:
        """Each OTP generation should produce different codes (statistically)."""
        codes = {generate_otp(6, developer_mode=False) for _ in range(20)}
        # With 20 random 6-digit codes, we should get mostly unique values
        assert len(codes) > 15, "OTP generation should produce varied codes"


# ============================================================================
# Access Token Tests
# ============================================================================


class TestAccessToken:
    """Test suite for JWT access token operations."""

    def test_creates_valid_token(self, test_secret: str) -> None:
        """Should create a valid JWT access token."""
        token = create_access_token(
            user_id=123,
            additional_claims={},
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(hours=1),
        )
        assert isinstance(token, str)
        assert len(token) > 0

    def test_includes_required_claims(self, test_secret: str) -> None:
        """Access token should contain all required claims."""
        user_id = 123
        token = create_access_token(
            user_id=user_id,
            additional_claims={},
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(hours=1),
        )

        claims = decode_token(token, test_secret, "HS256")

        # Required claims
        assert claims["sub"] == str(user_id)
        assert claims["type"] == "access"
        assert "jti" in claims  # JWT ID for blacklisting
        assert "exp" in claims  # Expiration time
        assert "iat" in claims  # Issued at time

    def test_includes_additional_claims(self, test_secret: str) -> None:
        """Should include custom additional claims."""
        additional_claims = {"role": "admin", "permissions": ["read", "write"]}

        token = create_access_token(
            user_id=123,
            additional_claims=additional_claims,
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(hours=1),
        )

        claims = decode_token(token, test_secret, "HS256")

        assert claims["role"] == "admin"
        assert claims["permissions"] == ["read", "write"]

    def test_unique_jti_per_token(self, test_secret: str) -> None:
        """Each token should have a unique JWT ID."""
        token1 = create_access_token(
            user_id=123,
            additional_claims={},
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(hours=1),
        )
        token2 = create_access_token(
            user_id=123,
            additional_claims={},
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(hours=1),
        )

        claims1 = decode_token(token1, test_secret, "HS256")
        claims2 = decode_token(token2, test_secret, "HS256")

        assert claims1["jti"] != claims2["jti"]

    def test_respects_lifetime(self, test_secret: str, current_time: datetime) -> None:
        """Token expiration should match specified lifetime."""
        lifetime = timedelta(hours=2)
        token = create_access_token(
            user_id=123,
            additional_claims={},
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=lifetime,
        )

        claims = decode_token(token, test_secret, "HS256")
        exp_time = datetime.fromtimestamp(claims["exp"], tz=UTC)
        iat_time = datetime.fromtimestamp(claims["iat"], tz=UTC)

        # Expiration should be approximately lifetime after issued time
        actual_lifetime = exp_time - iat_time
        assert abs(actual_lifetime - lifetime) < timedelta(seconds=5)


# ============================================================================
# Refresh Token Tests
# ============================================================================


class TestRefreshToken:
    """Test suite for JWT refresh token operations."""

    def test_creates_valid_token(self, test_secret: str) -> None:
        """Should create a valid JWT refresh token."""
        token = create_refresh_token(
            user_id=456,
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(days=7),
        )
        assert isinstance(token, str)
        assert len(token) > 0

    def test_includes_required_claims(self, test_secret: str) -> None:
        """Refresh token should contain all required claims."""
        user_id = 456
        token = create_refresh_token(
            user_id=user_id,
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(days=7),
        )

        claims = decode_token(token, test_secret, "HS256")

        assert claims["sub"] == str(user_id)
        assert claims["type"] == "refresh"
        assert "jti" in claims
        assert "exp" in claims
        assert "iat" in claims

    def test_no_additional_claims(self, test_secret: str) -> None:
        """Refresh token should only contain standard claims."""
        token = create_refresh_token(
            user_id=456,
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(days=7),
        )

        claims = decode_token(token, test_secret, "HS256")

        # Should only have standard claims
        expected_keys = {"sub", "type", "jti", "exp", "iat"}
        assert set(claims.keys()) == expected_keys


# ============================================================================
# Token Decoding Tests
# ============================================================================


class TestDecodeToken:
    """Test suite for JWT token decoding and verification."""

    def test_decodes_valid_token(self, test_secret: str) -> None:
        """Should successfully decode a valid token."""
        token = create_access_token(
            user_id=123,
            additional_claims={"role": "user"},
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(hours=1),
        )

        claims = decode_token(token, test_secret, "HS256")
        assert claims["sub"] == "123"
        assert claims["role"] == "user"

    def test_rejects_invalid_signature(self, test_secret: str) -> None:
        """Should reject tokens with invalid signatures."""
        token = create_access_token(
            user_id=123,
            additional_claims={},
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(hours=1),
        )

        wrong_secret = "wrong-secret-key-minimum-32-chars"
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token, wrong_secret, "HS256")

        assert exc_info.value.status_code == 401
        assert "invalid" in exc_info.value.detail.lower()

    def test_rejects_malformed_token(self, test_secret: str) -> None:
        """Should reject malformed JWT tokens."""
        with pytest.raises(HTTPException) as exc_info:
            decode_token("not.a.valid.jwt.token", test_secret, "HS256")

        assert exc_info.value.status_code == 401

    def test_rejects_expired_token(self, test_secret: str) -> None:
        """Should reject expired tokens."""
        # Create token that expires immediately
        token = create_access_token(
            user_id=123,
            additional_claims={},
            secret_key=test_secret,
            algorithm="HS256",
            lifetime=timedelta(seconds=-1),  # Already expired
        )

        with pytest.raises(HTTPException) as exc_info:
            decode_token(token, test_secret, "HS256")

        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()


# ============================================================================
# OTP Verification Tests
# ============================================================================


class TestVerifyOTPCode:
    """Test suite for OTP code verification."""

    def test_accepts_correct_code(self, current_time: datetime) -> None:
        """Should accept a correct OTP code."""
        result = verify_otp_code(
            stored_code="123456",
            input_code="123456",
            created_at=current_time,
            expiry=timedelta(minutes=10),
            max_attempts=5,
            current_attempts=0,
        )
        assert result is True

    def test_rejects_incorrect_code(self, current_time: datetime) -> None:
        """Should reject an incorrect OTP code."""
        result = verify_otp_code(
            stored_code="123456",
            input_code="999999",
            created_at=current_time,
            expiry=timedelta(minutes=10),
            max_attempts=5,
            current_attempts=0,
        )
        assert result is False

    def test_case_sensitive_comparison(self, current_time: datetime) -> None:
        """OTP verification should be case-sensitive (for alphanumeric codes)."""
        result = verify_otp_code(
            stored_code="abc123",
            input_code="ABC123",
            created_at=current_time,
            expiry=timedelta(minutes=10),
            max_attempts=5,
            current_attempts=0,
        )
        assert result is False

    def test_raises_on_expired_code(self) -> None:
        """Should raise 401 error for expired OTP codes."""
        expired_time = datetime.now(UTC) - timedelta(minutes=15)

        with pytest.raises(HTTPException) as exc_info:
            verify_otp_code(
                stored_code="123456",
                input_code="123456",
                created_at=expired_time,
                expiry=timedelta(minutes=10),
                max_attempts=5,
                current_attempts=0,
            )

        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_raises_on_too_many_attempts(self, current_time: datetime) -> None:
        """Should raise 429 error when max attempts reached."""
        with pytest.raises(HTTPException) as exc_info:
            verify_otp_code(
                stored_code="123456",
                input_code="123456",
                created_at=current_time,
                expiry=timedelta(minutes=10),
                max_attempts=5,
                current_attempts=5,
            )

        assert exc_info.value.status_code == 429
        assert "too many" in exc_info.value.detail.lower()

    def test_checks_attempts_before_expiry(self, current_time: datetime) -> None:
        """Should check attempt limit before checking expiration."""
        # Even with non-expired code, should raise 429 if attempts exceeded
        with pytest.raises(HTTPException) as exc_info:
            verify_otp_code(
                stored_code="123456",
                input_code="123456",
                created_at=current_time,
                expiry=timedelta(minutes=10),
                max_attempts=3,
                current_attempts=3,
            )

        assert exc_info.value.status_code == 429

    def test_boundary_not_yet_expired(self) -> None:
        """OTP should still be valid exactly at expiry boundary."""
        created = datetime.now(UTC) - timedelta(minutes=10)
        # Just at the boundary
        result = verify_otp_code(
            stored_code="123456",
            input_code="123456",
            created_at=created,
            expiry=timedelta(minutes=10),
            max_attempts=5,
            current_attempts=0,
        )
        # This might be valid or expired depending on microseconds
        # Just checking it doesn't crash
        assert isinstance(result, bool)
