"""Tests for OTP authentication configuration."""

from datetime import timedelta
from typing import Any

import pytest
from fastapi import HTTPException

from fastapi_otp_authentication.config import OTPAuthConfig

# ============================================================================
# Test Configuration Classes
# ============================================================================


class MinimalConfig(OTPAuthConfig):
    """Minimal configuration with all required fields."""

    secret_key = "test-secret-key-minimum-32-chars-long"

    async def send_otp(self, email: str, code: str) -> None:
        """Minimal send_otp implementation."""


class ProductionConfig(OTPAuthConfig):
    """Production-like configuration."""

    secret_key = "production-secret-key-very-long-and-secure-string-here"
    developer_mode = False
    access_token_lifetime = timedelta(hours=2)
    refresh_token_lifetime = timedelta(days=30)
    otp_expiry = timedelta(minutes=5)
    max_otp_attempts = 3

    async def send_otp(self, email: str, code: str) -> None:
        """Production send_otp implementation."""


class CustomClaimsConfig(OTPAuthConfig):
    """Configuration with custom JWT claims."""

    secret_key = "test-secret-key-minimum-32-chars-long"
    developer_mode = True

    def get_additional_claims(self, user: Any) -> dict[str, Any]:  # noqa: ANN401
        """Add custom claims based on user."""
        return {
            "email": user.email,
            "role": getattr(user, "role", "user"),
        }

    async def send_otp(self, email: str, code: str) -> None:
        """Test send_otp implementation."""


# ============================================================================
# Configuration Validation Tests
# ============================================================================


class TestConfigValidation:
    """Test suite for configuration validation."""

    def test_minimal_valid_config(self) -> None:
        """Should accept minimal valid configuration."""
        config = MinimalConfig()
        assert config.secret_key == "test-secret-key-minimum-32-chars-long"

    def test_rejects_short_secret_in_production(self) -> None:
        """Should reject secret keys shorter than 32 characters in production."""

        class ShortSecretConfig(OTPAuthConfig):
            secret_key = "short"
            developer_mode = False

            async def send_otp(self, email: str, code: str) -> None:
                pass

        with pytest.raises(HTTPException) as exc_info:
            ShortSecretConfig()

        assert exc_info.value.status_code == 500
        assert "32 characters" in exc_info.value.detail

    def test_accepts_short_secret_in_dev_mode(self) -> None:
        """Should accept short secret keys in developer mode."""

        class DevConfig(OTPAuthConfig):
            secret_key = "short"
            developer_mode = True

            async def send_otp(self, email: str, code: str) -> None:
                pass

        config = DevConfig()
        assert config.secret_key == "short"

    def test_rejects_missing_secret(self) -> None:
        """Should reject configuration without secret_key."""

        class NoSecretConfig(OTPAuthConfig):
            developer_mode = False

            async def send_otp(self, email: str, code: str) -> None:
                pass

        with pytest.raises(HTTPException) as exc_info:
            NoSecretConfig()

        assert exc_info.value.status_code == 500
        assert "secret_key must be set" in exc_info.value.detail


# ============================================================================
# Default Configuration Tests
# ============================================================================


class TestDefaultConfiguration:
    """Test suite for default configuration values."""

    def test_default_token_lifetimes(self) -> None:
        """Should have sensible default token lifetimes."""
        config = MinimalConfig()

        assert config.access_token_lifetime == timedelta(hours=1)
        assert config.refresh_token_lifetime == timedelta(days=7)

    def test_default_otp_settings(self) -> None:
        """Should have sensible default OTP settings."""
        config = MinimalConfig()

        assert config.otp_length == 6
        assert config.otp_expiry == timedelta(minutes=10)
        assert config.max_otp_attempts == 5

    def test_default_rate_limiting(self) -> None:
        """Should have default rate limiting."""
        config = MinimalConfig()

        assert config.otp_rate_limit_seconds == 60

    def test_default_auto_create_user(self) -> None:
        """Should auto-create users by default."""
        config = MinimalConfig()

        assert config.auto_create_user is True

    def test_default_developer_mode(self) -> None:
        """Should be in production mode by default."""
        config = MinimalConfig()

        assert config.developer_mode is False

    def test_default_algorithm(self) -> None:
        """Should use HS256 algorithm by default."""
        config = MinimalConfig()

        assert config.algorithm == "HS256"


# ============================================================================
# Custom Configuration Tests
# ============================================================================


class TestCustomConfiguration:
    """Test suite for customized configuration."""

    def test_custom_token_lifetimes(self) -> None:
        """Should allow custom token lifetimes."""
        config = ProductionConfig()

        assert config.access_token_lifetime == timedelta(hours=2)
        assert config.refresh_token_lifetime == timedelta(days=30)

    def test_custom_otp_settings(self) -> None:
        """Should allow custom OTP settings."""
        config = ProductionConfig()

        assert config.otp_expiry == timedelta(minutes=5)
        assert config.max_otp_attempts == 3

    def test_custom_additional_claims(self) -> None:
        """Should support custom get_additional_claims method."""

        class MockUser:
            email = "test@example.com"
            role = "admin"

        config = CustomClaimsConfig()
        user = MockUser()

        claims = config.get_additional_claims(user)

        assert claims["email"] == "test@example.com"
        assert claims["role"] == "admin"

    def test_default_additional_claims_returns_empty(self) -> None:
        """Default get_additional_claims should return empty dict."""
        config = MinimalConfig()

        class MockUser:
            pass

        claims = config.get_additional_claims(MockUser())

        assert claims == {}


# ============================================================================
# Abstract Method Tests
# ============================================================================


class TestAbstractMethods:
    """Test suite for abstract method requirements."""

    def test_send_otp_must_be_implemented(self) -> None:
        """Should require send_otp implementation."""

        # This should work - abstract class can't be instantiated without implementation
        class IncompleteConfig(OTPAuthConfig):
            secret_key = "test-secret-key-minimum-32-chars-long"
            developer_mode = True

        # But we can't actually test instantiation without implementation
        # because Python's ABC enforcement happens at instantiation
        with pytest.raises(TypeError):
            IncompleteConfig()  # type: ignore[abstract]

    @pytest.mark.asyncio
    async def test_send_otp_is_async(self) -> None:
        """send_otp should be an async method."""
        config = MinimalConfig()

        # Should be callable as async
        result = config.send_otp("test@example.com", "123456")
        assert hasattr(result, "__await__")
        await result


# ============================================================================
# Configuration Modification Tests
# ============================================================================


class TestConfigurationModification:
    """Test suite for configuration instance modification."""

    def test_can_modify_settings_at_runtime(self) -> None:
        """Should allow runtime modification of settings."""
        config = MinimalConfig()

        # Modify settings
        config.otp_length = 8
        config.max_otp_attempts = 10

        assert config.otp_length == 8
        assert config.max_otp_attempts == 10

    def test_instances_are_independent(self) -> None:
        """Multiple config instances should be independent."""
        config1 = MinimalConfig()
        config2 = MinimalConfig()

        config1.otp_length = 8
        config2.otp_length = 4

        assert config1.otp_length == 8
        assert config2.otp_length == 4
