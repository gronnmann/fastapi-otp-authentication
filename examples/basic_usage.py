"""Example FastAPI application with OTP authentication.

This example demonstrates:
- Setting up a user model with BaseOTPUserTable
- Creating database session and OTPDatabase adapter
- Configuring OTP authentication with custom send_otp implementation
- Registering auth router
- Using protected endpoints with authentication dependencies
"""
import typing
from collections.abc import AsyncGenerator
from datetime import timedelta

from fastapi import Depends, FastAPI
from sqlalchemy import Integer, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastapi_otp_authentication import (
    BaseOTPUserTable,
    OTPAuthConfig,
    OTPDatabase,
    TokenBlacklist,
    get_auth_router,
    get_current_user_dependency,
    get_custom_claims_dependency,
    get_verified_user_dependency,
)

# Database configuration
DATABASE_URL = "sqlite+aiosqlite:///./test.db"


# Create declarative base
class Base(DeclarativeBase):
    pass


# User model with OTP support
class User(BaseOTPUserTable[int], Base):
    """User model with additional custom fields."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(100), nullable=True)


# Token blacklist model
class Blacklist(TokenBlacklist, Base):
    """Token blacklist model."""


# Create async engine and session maker
engine = create_async_engine(DATABASE_URL, echo=True)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def create_db_and_tables() -> None:
    """Create database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session."""
    async with async_session_maker() as session:
        yield session


async def get_otp_db(
    session: AsyncSession = Depends(get_async_session),
) -> AsyncGenerator[OTPDatabase[User], None]:
    """Dependency to get OTP database adapter."""
    yield OTPDatabase(session, User, Blacklist)


# OTP configuration
class MyOTPConfig(OTPAuthConfig):
    """Custom OTP configuration."""

    # Security settings
    secret_key = "your-secret-key-min-32-chars-long-generate-with-openssl"
    developer_mode = False  # Set to False in production!

    # Token lifetimes
    access_token_lifetime = timedelta(hours=1)
    refresh_token_lifetime = timedelta(days=7)

    # OTP settings
    otp_length = 6
    otp_expiry = timedelta(minutes=10)
    max_otp_attempts = 5

    async def send_otp(self, email: str, code: str) -> None:
        """
        Send OTP code to user's email.

        In production, implement actual email sending here.
        """
        print(f"\n📧 Sending OTP to {email}: {code}\n")
        # In production, use an email service:
        # await send_email(to=email, subject="Your OTP Code", body=f"Code: {code}")

    async def create_user(self, email: str) -> dict[str, str]:
        """
        Define additional fields when auto-creating users.

        Called when a user requests OTP for the first time.
        """
        return {
            "username": email.split("@")[0],
            "full_name": "",
        }

    def get_additional_claims(self, user: User) -> dict[str, str]:
        """Add custom claims to JWT tokens."""
        return {
            "username": user.username,
            "email": user.email,
        }


# Initialize FastAPI app
app = FastAPI(
    title="FastAPI OTP Authentication Example",
    description="Example application demonstrating OTP-based authentication",
)

# Initialize config
config = MyOTPConfig()

# Create and register auth router
auth_router = get_auth_router(get_otp_db, config)
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])

# Create dependencies for protected routes
current_user = Depends(get_current_user_dependency(get_otp_db, config))
verified_user = Depends(get_verified_user_dependency(get_otp_db, config))
additional_claims = Depends(get_custom_claims_dependency(config))


@app.on_event("startup")
async def startup() -> None:
    """Initialize database on startup."""
    await create_db_and_tables()

    # Create a test user if it doesn't exist
    async with async_session_maker() as session:
        db = OTPDatabase(session, User, Blacklist)
        existing_user = await db.get_by_email("test@example.com")

        if not existing_user:
            user = User(
                username="testuser",
                email="test@example.com",
                full_name="Test User",
            )
            session.add(user)
            await session.commit()
            print("\n✅ Created test user: test@example.com\n")


@app.get("/")
async def root() -> dict[str, str]:
    """Public endpoint."""
    return {
        "message": "Welcome to FastAPI OTP Authentication",
        "docs": "/docs",
    }


@app.get("/protected")
async def protected_route(user: User = current_user) -> dict[str, str]:
    """Protected endpoint - requires authentication."""
    return {
        "message": "This is a protected route",
        "user_id": str(user.id),
        "email": user.email,
        "username": user.username,
    }


@app.get("/verified-only")
async def verified_only_route(user: User = verified_user) -> dict[str, str | bool]:
    """Protected endpoint - requires verified user."""
    return {
        "message": "This route requires OTP verification",
        "user_id": str(user.id),
        "email": user.email,
        "username": user.username,
        "is_verified": user.is_verified,
    }

@app.get("/claims")
async def claims_route(claims: dict[str, str] = additional_claims) -> dict[str, str | typing.Any]:
    """Endpoint to view custom JWT claims."""
    return {
        "message": "Custom JWT Claims",
        "claims": claims,
    }

if __name__ == "__main__":
    import uvicorn

    print("""
    🚀 Starting FastAPI OTP Authentication Example

    📝 Try the following flow:

    1. Request OTP:
       POST http://localhost:8000/auth/request-otp
       {"email": "test@example.com"}

    2. Verify OTP (developer mode code is 000000):
       POST http://localhost:8000/auth/verify-otp
       {"email": "test@example.com", "code": "000000"}
       → Copy the access_token from the response

    3. Click the "Authorize" 🔓 button at the top of Swagger UI

    4. Paste your access_token in the "Value" field and click "Authorize"

    5. Now all protected endpoints will automatically use your token!

    📚 API Docs: http://localhost:8000/docs
    """)

    uvicorn.run(app, host="0.0.0.0", port=8000)
