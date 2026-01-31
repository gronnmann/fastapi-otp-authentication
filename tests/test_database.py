"""Tests for database adapter operations."""

from datetime import UTC, datetime, timedelta

import pytest

from fastapi_otp_authentication.db.adapter import OTPDatabase
from tests.conftest import User


# ============================================================================
# User Retrieval Tests
# ============================================================================


class TestUserRetrieval:
    """Test suite for user retrieval operations."""

    @pytest.mark.asyncio
    async def test_get_by_email_existing_user(
        self, otp_db: OTPDatabase[User], test_user: User
    ) -> None:
        """Should retrieve existing user by email."""
        user = await otp_db.get_by_email("test@example.com")
        assert user is not None
        assert user.email == "test@example.com"
        assert user.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_by_email_nonexistent_user(
        self, otp_db: OTPDatabase[User]
    ) -> None:
        """Should return None for non-existent email."""
        user = await otp_db.get_by_email("nonexistent@example.com")
        assert user is None

    @pytest.mark.asyncio
    async def test_get_by_id_existing_user(
        self, otp_db: OTPDatabase[User], test_user: User
    ) -> None:
        """Should retrieve existing user by ID."""
        user = await otp_db.get_by_id(test_user.id)
        assert user is not None
        assert user.id == test_user.id
        assert user.email == test_user.email

    @pytest.mark.asyncio
    async def test_get_by_id_nonexistent_user(
        self, otp_db: OTPDatabase[User]
    ) -> None:
        """Should return None for non-existent ID."""
        user = await otp_db.get_by_id(99999)
        assert user is None


# ============================================================================
# User Creation Tests
# ============================================================================


class TestUserCreation:
    """Test suite for user creation operations."""

    @pytest.mark.asyncio
    async def test_create_user_basic(self, otp_db: OTPDatabase[User]) -> None:
        """Should create a new user with basic fields."""
        user = await otp_db.create_user(
            email="new@example.com",
            username="newuser",
        )

        assert user.email == "new@example.com"
        assert user.username == "newuser"
        assert user.is_verified is False
        assert user.otp_code is None
        assert user.otp_attempts == 0

    @pytest.mark.asyncio
    async def test_create_user_persists(self, otp_db: OTPDatabase[User]) -> None:
        """Created user should be retrievable from database."""
        user = await otp_db.create_user(
            email="persistent@example.com",
            username="persistent",
        )

        # Retrieve by email
        retrieved = await otp_db.get_by_email("persistent@example.com")
        assert retrieved is not None
        assert retrieved.id == user.id

    @pytest.mark.asyncio
    async def test_create_user_with_extra_fields(
        self, otp_db: OTPDatabase[User]
    ) -> None:
        """Should support additional fields via kwargs."""
        user = await otp_db.create_user(
            email="extra@example.com",
            username="extrauser",
        )

        assert user.username == "extrauser"


# ============================================================================
# OTP Management Tests
# ============================================================================


class TestOTPManagement:
    """Test suite for OTP code management."""

    @pytest.mark.asyncio
    async def test_update_otp_sets_code(
        self, otp_db: OTPDatabase[User], test_user: User
    ) -> None:
        """Should set OTP code on user."""
        await otp_db.update_otp(test_user, "123456")

        user = await otp_db.get_by_id(test_user.id)
        assert user is not None
        assert user.otp_code == "123456"

    @pytest.mark.asyncio
    async def test_update_otp_sets_created_at(
        self, otp_db: OTPDatabase[User], test_user: User
    ) -> None:
        """Should set OTP creation timestamp."""
        before = datetime.now(UTC)
        await otp_db.update_otp(test_user, "123456")
        after = datetime.now(UTC)

        user = await otp_db.get_by_id(test_user.id)
        assert user is not None
        assert user.otp_created_at is not None
        assert before <= user.otp_created_at <= after

    @pytest.mark.asyncio
    async def test_update_otp_resets_attempts(
        self, otp_db: OTPDatabase[User], test_user: User
    ) -> None:
        """Should reset attempt counter to 0."""
        # First set some attempts
        test_user.otp_attempts = 3
        await otp_db.session.commit()

        # Update OTP should reset
        await otp_db.update_otp(test_user, "123456")

        user = await otp_db.get_by_id(test_user.id)
        assert user is not None
        assert user.otp_attempts == 0

    @pytest.mark.asyncio
    async def test_update_otp_sets_request_time(
        self, otp_db: OTPDatabase[User], test_user: User
    ) -> None:
        """Should set last request timestamp for rate limiting."""
        before = datetime.now(UTC)
        await otp_db.update_otp(test_user, "123456")
        after = datetime.now(UTC)

        user = await otp_db.get_by_id(test_user.id)
        assert user is not None
        assert user.last_otp_request_at is not None
        assert before <= user.last_otp_request_at <= after

    @pytest.mark.asyncio
    async def test_clear_otp_removes_code(
        self, otp_db: OTPDatabase[User], user_with_otp: User
    ) -> None:
        """Should clear OTP code from user."""
        await otp_db.clear_otp(user_with_otp)

        user = await otp_db.get_by_id(user_with_otp.id)
        assert user is not None
        assert user.otp_code is None
        assert user.otp_created_at is None
        assert user.otp_attempts == 0

    @pytest.mark.asyncio
    async def test_clear_otp_keeps_verification_status(
        self, otp_db: OTPDatabase[User], verified_user: User
    ) -> None:
        """Should not change verification status when clearing OTP."""
        # Set OTP on verified user
        await otp_db.update_otp(verified_user, "123456")
        assert verified_user.is_verified is True

        # Clear should not affect verification
        await otp_db.clear_otp(verified_user)

        user = await otp_db.get_by_id(verified_user.id)
        assert user is not None
        assert user.is_verified is True


# ============================================================================
# OTP Attempt Tracking Tests
# ============================================================================


class TestOTPAttempts:
    """Test suite for OTP verification attempt tracking."""

    @pytest.mark.asyncio
    async def test_increment_attempts_increases_counter(
        self, otp_db: OTPDatabase[User], user_with_otp: User
    ) -> None:
        """Should increment attempt counter by 1."""
        initial_attempts = user_with_otp.otp_attempts
        await otp_db.increment_otp_attempts(user_with_otp)

        user = await otp_db.get_by_id(user_with_otp.id)
        assert user is not None
        assert user.otp_attempts == initial_attempts + 1

    @pytest.mark.asyncio
    async def test_increment_attempts_multiple_times(
        self, otp_db: OTPDatabase[User], user_with_otp: User
    ) -> None:
        """Should track multiple failed attempts."""
        for i in range(1, 5):
            await otp_db.increment_otp_attempts(user_with_otp)
            user = await otp_db.get_by_id(user_with_otp.id)
            assert user is not None
            assert user.otp_attempts == i


# ============================================================================
# User Verification Tests
# ============================================================================


class TestUserVerification:
    """Test suite for user verification operations."""

    @pytest.mark.asyncio
    async def test_verify_user_sets_verified_flag(
        self, otp_db: OTPDatabase[User], user_with_otp: User
    ) -> None:
        """Should mark user as verified."""
        await otp_db.verify_user(user_with_otp)

        user = await otp_db.get_by_id(user_with_otp.id)
        assert user is not None
        assert user.is_verified is True

    @pytest.mark.asyncio
    async def test_verify_user_clears_otp_data(
        self, otp_db: OTPDatabase[User], user_with_otp: User
    ) -> None:
        """Should clear OTP code and timestamps after verification."""
        await otp_db.verify_user(user_with_otp)

        user = await otp_db.get_by_id(user_with_otp.id)
        assert user is not None
        assert user.otp_code is None
        assert user.otp_created_at is None
        assert user.otp_attempts == 0


# ============================================================================
# Token Blacklist Tests
# ============================================================================


class TestTokenBlacklist:
    """Test suite for token blacklisting operations."""

    @pytest.mark.asyncio
    async def test_add_to_blacklist(self, otp_db: OTPDatabase[User]) -> None:
        """Should add token to blacklist."""
        jti = "test-jwt-id-123"
        expires_at = datetime.now(UTC) + timedelta(days=7)

        await otp_db.add_to_blacklist(
            jti=jti,
            token_type="refresh",
            expires_at=expires_at,
        )

        # Token should now be blacklisted
        is_blacklisted = await otp_db.is_blacklisted(jti)
        assert is_blacklisted is True

    @pytest.mark.asyncio
    async def test_is_blacklisted_returns_false_for_new_token(
        self, otp_db: OTPDatabase[User]
    ) -> None:
        """Should return False for non-blacklisted token."""
        is_blacklisted = await otp_db.is_blacklisted("unknown-jti")
        assert is_blacklisted is False

    @pytest.mark.asyncio
    async def test_blacklist_different_tokens(
        self, otp_db: OTPDatabase[User]
    ) -> None:
        """Should track multiple blacklisted tokens independently."""
        jti1 = "token-1"
        jti2 = "token-2"
        expires = datetime.now(UTC) + timedelta(days=7)

        await otp_db.add_to_blacklist(jti1, "access", expires)

        # Only jti1 should be blacklisted
        assert await otp_db.is_blacklisted(jti1) is True
        assert await otp_db.is_blacklisted(jti2) is False

        # Blacklist jti2
        await otp_db.add_to_blacklist(jti2, "refresh", expires)

        # Both should be blacklisted
        assert await otp_db.is_blacklisted(jti1) is True
        assert await otp_db.is_blacklisted(jti2) is True


# ============================================================================
# Blacklist Cleanup Tests
# ============================================================================


class TestBlacklistCleanup:
    """Test suite for expired token cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_removes_expired_tokens(
        self, otp_db: OTPDatabase[User]
    ) -> None:
        """Should remove expired tokens from blacklist."""
        expired_jti = "expired-token"
        valid_jti = "valid-token"

        # Add expired token
        await otp_db.add_to_blacklist(
            jti=expired_jti,
            token_type="refresh",
            expires_at=datetime.now(UTC) - timedelta(hours=1),  # Already expired
        )

        # Add valid token
        await otp_db.add_to_blacklist(
            jti=valid_jti,
            token_type="refresh",
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )

        # Cleanup should remove expired token
        removed_count = await otp_db.cleanup_blacklist()

        assert removed_count == 1
        assert await otp_db.is_blacklisted(expired_jti) is False
        assert await otp_db.is_blacklisted(valid_jti) is True

    @pytest.mark.asyncio
    async def test_cleanup_returns_count(
        self, otp_db: OTPDatabase[User]
    ) -> None:
        """Should return number of removed tokens."""
        # Add multiple expired tokens
        for i in range(3):
            await otp_db.add_to_blacklist(
                jti=f"expired-{i}",
                token_type="refresh",
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            )

        removed_count = await otp_db.cleanup_blacklist()
        assert removed_count == 3

    @pytest.mark.asyncio
    async def test_cleanup_with_no_expired_tokens(
        self, otp_db: OTPDatabase[User]
    ) -> None:
        """Should handle cleanup when no tokens are expired."""
        # Add only valid token
        await otp_db.add_to_blacklist(
            jti="valid-token",
            token_type="refresh",
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )

        removed_count = await otp_db.cleanup_blacklist()
        assert removed_count == 0
