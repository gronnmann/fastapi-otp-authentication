"""Test configuration and fixtures."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Integer, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastapi_otp_authentication.config import OTPAuthConfig
from fastapi_otp_authentication.db.sqlalchemy.adapter import SQLAlchemyAdapter
from fastapi_otp_authentication.db.sqlalchemy.models import BaseOTPUserTable, TokenBlacklist

# ============================================================================
# Database Models for Testing
# ============================================================================


class Base(DeclarativeBase):
    """Base class for test database models."""



class User(BaseOTPUserTable[int], Base):
    """Test user model."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str | None] = mapped_column(String(50), nullable=True)


class Blacklist(TokenBlacklist, Base):
    """Test blacklist model."""

    __tablename__ = "token_blacklist"


# ============================================================================
# Test Configuration
# ============================================================================


class MockOTPConfig(OTPAuthConfig):
    """Mock OTP authentication configuration for testing."""

    secret_key = "test-secret-key-minimum-32-chars-long"
    access_token_lifetime = timedelta(hours=1)
    refresh_token_lifetime = timedelta(days=7)
    otp_expiry = timedelta(minutes=10)
    otp_length = 6
    max_otp_attempts = 5
    otp_rate_limit_seconds = 60
    developer_mode = True  # For testing
    cookie_secure = False

    def __init__(self) -> None:
        """Initialize test config."""
        self.sent_otps: list[tuple[str, str]] = []
        super().__init__()

    async def send_otp(self, email: str, code: str) -> None:
        """Store sent OTPs for testing instead of actually sending."""
        self.sent_otps.append((email, code))

    async def create_user(self, email: str) -> dict[str, Any]:
        """Create user data for new users."""
        return {"username": email.split("@")[0]}


# ============================================================================
# Basic Fixtures
# ============================================================================


@pytest.fixture
def test_secret() -> str:
    """Provide a test secret key."""
    return "test-secret-key-minimum-32-chars-long"


@pytest.fixture
def test_config() -> MockOTPConfig:
    """Provide a test configuration."""
    return MockOTPConfig()


@pytest.fixture
def current_time() -> datetime:
    """Provide current UTC time."""
    return datetime.now(UTC)


# ============================================================================
# Database Fixtures
# ============================================================================


@pytest.fixture
async def async_engine():  # type: ignore[no-untyped-def]
    """Create an async SQLite engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def async_session(async_engine) -> AsyncSession:  # type: ignore[no-untyped-def]
    """Create an async database session."""
    async_session_maker = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session_maker() as session:
        yield session


@pytest.fixture
async def otp_db(async_session: AsyncSession) -> SQLAlchemyAdapter[User]:
    """Create a SQLAlchemyAdapter instance."""
    return SQLAlchemyAdapter(async_session, User, Blacklist)


@pytest.fixture
async def test_user(otp_db: SQLAlchemyAdapter[User]) -> User:
    """Create a test user."""
    return await otp_db.create_user(
        email="test@example.com",
        username="testuser",
    )


@pytest.fixture
async def verified_user(otp_db: SQLAlchemyAdapter[User]) -> User:
    """Create a verified test user."""
    user = await otp_db.create_user(
        email="verified@example.com",
        username="verified",
    )
    await otp_db.verify_user(user)
    return user


@pytest.fixture
async def user_with_otp(
    otp_db: SQLAlchemyAdapter[User], test_user: User
) -> User:
    """Create a test user with an active OTP."""
    await otp_db.update_otp(test_user, "123456")
    return test_user
