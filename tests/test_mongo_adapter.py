"""Tests for MongoDB adapter operations."""

from datetime import UTC, datetime, timedelta

import pytest
from mongomock_motor import AsyncMongoMockClient
from pydantic import Field

from fastapi_otp_authentication.db.mongodb.adapter import MongoDBAdapter
from fastapi_otp_authentication.db.mongodb.models import (
    BaseOTPUserDocument,
)


# Test user model
class User(BaseOTPUserDocument):
    """Test user model."""

    username: str = Field(..., max_length=50)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
async def mongo_db() -> AsyncMongoMockClient:
    """Create mock MongoDB database."""
    client = AsyncMongoMockClient()
    db = client["test_db"]
    # Create unique index on email
    await db["users"].create_index("email", unique=True)
    return db


@pytest.fixture
async def mongo_adapter(mongo_db: AsyncMongoMockClient) -> MongoDBAdapter[User]:
    """Create MongoDB adapter instance."""
    return MongoDBAdapter(
        database=mongo_db,
        user_collection_name="users",
        blacklist_collection_name="token_blacklist",
        user_model_class=User,
    )


@pytest.fixture
async def test_user(mongo_adapter: MongoDBAdapter[User]) -> User:
    """Create a test user for testing."""
    return await mongo_adapter.create_user(
        email="test@example.com",
        username="testuser",
    )


@pytest.fixture
async def user_with_otp(mongo_adapter: MongoDBAdapter[User], test_user: User) -> User:
    """Create a user with OTP code set."""
    await mongo_adapter.update_otp(test_user, "123456")
    return test_user


@pytest.fixture
async def verified_user(mongo_adapter: MongoDBAdapter[User]) -> User:
    """Create a verified user."""
    user = await mongo_adapter.create_user(
        email="verified@example.com",
        username="verifieduser",
    )
    await mongo_adapter.verify_user(user)
    return user


# ============================================================================
# User Retrieval Tests
# ============================================================================


class TestUserRetrieval:
    """Test suite for user retrieval operations."""

    @pytest.mark.asyncio
    async def test_get_by_email_existing_user(
        self, mongo_adapter: MongoDBAdapter[User], test_user: User
    ) -> None:
        """Should retrieve existing user by email."""
        user = await mongo_adapter.get_by_email("test@example.com")
        assert user is not None
        assert user.email == "test@example.com"
        assert user.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_by_email_nonexistent_user(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should return None for non-existent email."""
        user = await mongo_adapter.get_by_email("nonexistent@example.com")
        assert user is None

    @pytest.mark.asyncio
    async def test_get_by_id_existing_user(
        self, mongo_adapter: MongoDBAdapter[User], test_user: User
    ) -> None:
        """Should retrieve existing user by ID."""
        assert test_user.id is not None
        user = await mongo_adapter.get_by_id(test_user.id)
        assert user is not None
        assert user.id == test_user.id
        assert user.email == test_user.email

    @pytest.mark.asyncio
    async def test_get_by_id_nonexistent_user(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should return None for non-existent ID."""
        user = await mongo_adapter.get_by_id("507f1f77bcf86cd799439011")
        assert user is None

    @pytest.mark.asyncio
    async def test_get_by_id_with_string_id(
        self, mongo_adapter: MongoDBAdapter[User], test_user: User
    ) -> None:
        """Should handle string ObjectId."""
        assert test_user.id is not None
        user = await mongo_adapter.get_by_id(str(test_user.id))
        assert user is not None
        assert str(user.id) == str(test_user.id)


# ============================================================================
# User Creation Tests
# ============================================================================


class TestUserCreation:
    """Test suite for user creation operations."""

    @pytest.mark.asyncio
    async def test_create_user_basic(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should create a new user with basic fields."""
        user = await mongo_adapter.create_user(
            email="new@example.com",
            username="newuser",
        )

        assert user.email == "new@example.com"
        assert user.username == "newuser"
        assert user.is_verified is False
        assert user.otp_code is None
        assert user.otp_attempts == 0
        assert user.id is not None  # MongoDB should assign _id

    @pytest.mark.asyncio
    async def test_create_user_persists(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Created user should be retrievable from database."""
        user = await mongo_adapter.create_user(
            email="persistent@example.com",
            username="persistent",
        )

        # Retrieve by email
        retrieved = await mongo_adapter.get_by_email("persistent@example.com")
        assert retrieved is not None
        assert retrieved.id == user.id

    @pytest.mark.asyncio
    async def test_create_user_with_extra_fields(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should support additional fields via kwargs."""
        user = await mongo_adapter.create_user(
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
        self, mongo_adapter: MongoDBAdapter[User], test_user: User
    ) -> None:
        """Should set OTP code on user."""
        await mongo_adapter.update_otp(test_user, "123456")

        assert test_user.id is not None
        user = await mongo_adapter.get_by_id(test_user.id)
        assert user is not None
        assert user.otp_code == "123456"

    @pytest.mark.asyncio
    async def test_update_otp_sets_created_at(
        self, mongo_adapter: MongoDBAdapter[User], test_user: User
    ) -> None:
        """Should set OTP creation timestamp."""
        before = datetime.now(UTC)
        await mongo_adapter.update_otp(test_user, "123456")
        after = datetime.now(UTC)

        assert test_user.id is not None
        user = await mongo_adapter.get_by_id(test_user.id)
        assert user is not None
        assert user.otp_created_at is not None
        # Allow for mongomock's millisecond precision (truncation)
        assert before.replace(microsecond=0) <= user.otp_created_at <= after

    @pytest.mark.asyncio
    async def test_update_otp_resets_attempts(
        self, mongo_adapter: MongoDBAdapter[User], test_user: User
    ) -> None:
        """Should reset attempt counter to 0."""
        # Manually set some attempts first
        test_user.otp_attempts = 3
        await mongo_adapter.user_collection.update_one(
            {"_id": test_user.id},
            {"$set": {"otp_attempts": 3}},
        )

        # Update OTP should reset
        await mongo_adapter.update_otp(test_user, "123456")

        assert test_user.id is not None
        user = await mongo_adapter.get_by_id(test_user.id)
        assert user is not None
        assert user.otp_attempts == 0

    @pytest.mark.asyncio
    async def test_update_otp_sets_request_time(
        self, mongo_adapter: MongoDBAdapter[User], test_user: User
    ) -> None:
        """Should set last request timestamp for rate limiting."""
        before = datetime.now(UTC)
        await mongo_adapter.update_otp(test_user, "123456")
        after = datetime.now(UTC)

        assert test_user.id is not None
        user = await mongo_adapter.get_by_id(test_user.id)
        assert user is not None
        assert user.last_otp_request_at is not None
        # Allow for mongomock's millisecond precision (truncation)
        assert before.replace(microsecond=0) <= user.last_otp_request_at <= after

    @pytest.mark.asyncio
    async def test_clear_otp_removes_code(
        self, mongo_adapter: MongoDBAdapter[User], user_with_otp: User
    ) -> None:
        """Should clear OTP code from user."""
        await mongo_adapter.clear_otp(user_with_otp)

        assert user_with_otp.id is not None
        user = await mongo_adapter.get_by_id(user_with_otp.id)
        assert user is not None
        assert user.otp_code is None
        assert user.otp_created_at is None
        assert user.otp_attempts == 0

    @pytest.mark.asyncio
    async def test_clear_otp_keeps_verification_status(
        self, mongo_adapter: MongoDBAdapter[User], verified_user: User
    ) -> None:
        """Should not change verification status when clearing OTP."""
        # Set OTP on verified user
        await mongo_adapter.update_otp(verified_user, "123456")
        assert verified_user.is_verified is True

        # Clear should not affect verification
        await mongo_adapter.clear_otp(verified_user)

        assert verified_user.id is not None
        user = await mongo_adapter.get_by_id(verified_user.id)
        assert user is not None
        assert user.is_verified is True


# ============================================================================
# OTP Attempt Tracking Tests
# ============================================================================


class TestOTPAttempts:
    """Test suite for OTP verification attempt tracking."""

    @pytest.mark.asyncio
    async def test_increment_attempts_increases_counter(
        self, mongo_adapter: MongoDBAdapter[User], user_with_otp: User
    ) -> None:
        """Should increment attempt counter by 1."""
        initial_attempts = user_with_otp.otp_attempts
        await mongo_adapter.increment_otp_attempts(user_with_otp)

        assert user_with_otp.id is not None
        user = await mongo_adapter.get_by_id(user_with_otp.id)
        assert user is not None
        assert user.otp_attempts == initial_attempts + 1

    @pytest.mark.asyncio
    async def test_increment_attempts_multiple_times(
        self, mongo_adapter: MongoDBAdapter[User], user_with_otp: User
    ) -> None:
        """Should track multiple failed attempts."""
        for i in range(1, 5):
            await mongo_adapter.increment_otp_attempts(user_with_otp)
            assert user_with_otp.id is not None
            user = await mongo_adapter.get_by_id(user_with_otp.id)
            assert user is not None
            assert user.otp_attempts == i


# ============================================================================
# User Verification Tests
# ============================================================================


class TestUserVerification:
    """Test suite for user verification operations."""

    @pytest.mark.asyncio
    async def test_verify_user_sets_verified_flag(
        self, mongo_adapter: MongoDBAdapter[User], user_with_otp: User
    ) -> None:
        """Should mark user as verified."""
        await mongo_adapter.verify_user(user_with_otp)

        assert user_with_otp.id is not None
        user = await mongo_adapter.get_by_id(user_with_otp.id)
        assert user is not None
        assert user.is_verified is True

    @pytest.mark.asyncio
    async def test_verify_user_clears_otp_data(
        self, mongo_adapter: MongoDBAdapter[User], user_with_otp: User
    ) -> None:
        """Should clear OTP code and timestamps after verification."""
        await mongo_adapter.verify_user(user_with_otp)

        assert user_with_otp.id is not None
        user = await mongo_adapter.get_by_id(user_with_otp.id)
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
    async def test_add_to_blacklist(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should add token to blacklist."""
        jti = "test-jwt-id-123"
        expires_at = datetime.now(UTC) + timedelta(days=7)

        await mongo_adapter.add_to_blacklist(
            jti=jti,
            token_type="refresh",
            expires_at=expires_at,
        )

        # Token should now be blacklisted
        is_blacklisted = await mongo_adapter.is_blacklisted(jti)
        assert is_blacklisted is True

    @pytest.mark.asyncio
    async def test_is_blacklisted_returns_false_for_new_token(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should return False for non-blacklisted token."""
        is_blacklisted = await mongo_adapter.is_blacklisted("unknown-jti")
        assert is_blacklisted is False

    @pytest.mark.asyncio
    async def test_blacklist_different_tokens(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should track multiple blacklisted tokens independently."""
        jti1 = "token-1"
        jti2 = "token-2"
        expires = datetime.now(UTC) + timedelta(days=7)

        await mongo_adapter.add_to_blacklist(jti1, "access", expires)

        # Only jti1 should be blacklisted
        assert await mongo_adapter.is_blacklisted(jti1) is True
        assert await mongo_adapter.is_blacklisted(jti2) is False

        # Blacklist jti2
        await mongo_adapter.add_to_blacklist(jti2, "refresh", expires)

        # Both should be blacklisted
        assert await mongo_adapter.is_blacklisted(jti1) is True
        assert await mongo_adapter.is_blacklisted(jti2) is True


# ============================================================================
# Blacklist Cleanup Tests
# ============================================================================


class TestBlacklistCleanup:
    """Test suite for expired token cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_removes_expired_tokens(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should remove expired tokens from blacklist."""
        expired_jti = "expired-token"
        valid_jti = "valid-token"

        # Add expired token
        await mongo_adapter.add_to_blacklist(
            jti=expired_jti,
            token_type="refresh",
            expires_at=datetime.now(UTC) - timedelta(hours=1),  # Already expired
        )

        # Add valid token
        await mongo_adapter.add_to_blacklist(
            jti=valid_jti,
            token_type="refresh",
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )

        # Cleanup should remove expired token
        removed_count = await mongo_adapter.cleanup_blacklist()

        assert removed_count == 1
        assert await mongo_adapter.is_blacklisted(expired_jti) is False
        assert await mongo_adapter.is_blacklisted(valid_jti) is True

    @pytest.mark.asyncio
    async def test_cleanup_returns_count(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should return number of removed tokens."""
        # Add multiple expired tokens
        for i in range(3):
            await mongo_adapter.add_to_blacklist(
                jti=f"expired-{i}",
                token_type="refresh",
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            )

        removed_count = await mongo_adapter.cleanup_blacklist()
        assert removed_count == 3

    @pytest.mark.asyncio
    async def test_cleanup_with_no_expired_tokens(
        self, mongo_adapter: MongoDBAdapter[User]
    ) -> None:
        """Should handle cleanup when no tokens are expired."""
        # Add only valid token
        await mongo_adapter.add_to_blacklist(
            jti="valid-token",
            token_type="refresh",
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )

        removed_count = await mongo_adapter.cleanup_blacklist()
        assert removed_count == 0
