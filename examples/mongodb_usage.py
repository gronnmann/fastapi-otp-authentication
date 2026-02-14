"""Example FastAPI application with OTP authentication using MongoDB.

This example demonstrates:
- Setting up a user model with BaseOTPUserDocument (Pydantic)
- Creating MongoDB connection and MongoDBAdapter
- Configuring OTP authentication with custom send_otp implementation
- Registering auth router
- Using protected endpoints with authentication dependencies
- Creating necessary MongoDB indexes
"""
import typing
from datetime import timedelta
from typing import ClassVar

from fastapi import Depends, FastAPI
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pydantic import Field

from fastapi_otp_authentication import (
    BaseOTPUserDocument,
    MongoDBAdapter,
    OTPAuthConfig,
    TokenBlacklistDocument,
    get_auth_router,
    get_current_user_dependency,
    get_custom_claims_dependency,
    get_verified_user_dependency,
)

# MongoDB configuration
MONGODB_URL = "mongodb://localhost:27017"
DATABASE_NAME = "fastapi_otp_example"

# MongoDB client
client: AsyncIOMotorClient = AsyncIOMotorClient(MONGODB_URL)
database: AsyncIOMotorDatabase = client[DATABASE_NAME]


# User model with OTP support
class User(BaseOTPUserDocument):
    """User model with additional custom fields."""

    username: str = Field(..., description="Username", max_length=50)
    full_name: str | None = Field(None, description="Full name", max_length=100)

    model_config: ClassVar[dict] = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "username": "johndoe",
                "full_name": "John Doe",
            }
        }
    }


# Blacklist model (uses default TokenBlacklistDocument)
class Blacklist(TokenBlacklistDocument):
    """Token blacklist model."""


async def get_otp_db() -> MongoDBAdapter[User]:
    """Dependency to get OTP database adapter."""
    return MongoDBAdapter(
        database=database,
        user_collection_name="users",
        blacklist_collection_name="token_blacklist",
        user_model_class=User,
    )


# OTP configuration
class MyOTPConfig(OTPAuthConfig):
    """Custom OTP configuration."""

    # Security settings
    secret_key = "your-secret-key-min-32-chars-long-generate-with-openssl"
    developer_mode = True  # Set to False in production!

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
            "email": str(user.email),
        }


# Initialize FastAPI app
app = FastAPI(
    title="FastAPI OTP Authentication Example (MongoDB)",
    description="Example application demonstrating OTP-based authentication with MongoDB",
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
    # Create indexes for better performance
    users_collection = database["users"]
    blacklist_collection = database["token_blacklist"]

    # Unique index on email
    await users_collection.create_index("email", unique=True)

    # Index on jti for blacklist lookups
    await blacklist_collection.create_index("jti", unique=True)

    # TTL index to auto-delete expired blacklist entries after they expire
    await blacklist_collection.create_index(
        "expires_at", expireAfterSeconds=0
    )

    print("\n✅ MongoDB indexes created\n")

    # Create a test user if it doesn't exist
    db = await get_otp_db()
    existing_user = await db.get_by_email("test@example.com")

    if not existing_user:
        await db.create_user(
            email="test@example.com",
            username="testuser",
            full_name="Test User",
        )
        print("✅ Created test user: test@example.com\n")


@app.on_event("shutdown")
async def shutdown() -> None:
    """Close MongoDB connection on shutdown."""
    client.close()
    print("\n👋 MongoDB connection closed\n")


@app.get("/")
async def root() -> dict[str, str]:
    """Public endpoint."""
    return {
        "message": "Welcome to FastAPI OTP Authentication with MongoDB",
        "docs": "/docs",
        "database": "MongoDB",
    }


@app.get("/protected")
async def protected_route(user: User = current_user) -> dict[str, str]:
    """Protected endpoint - requires authentication."""
    return {
        "message": "This is a protected route",
        "user_id": str(user.id) if user.id else "N/A",
        "email": str(user.email),
        "username": user.username,
    }


@app.get("/verified-only")
async def verified_only_route(user: User = verified_user) -> dict[str, str | bool]:
    """Protected endpoint - requires verified user."""
    return {
        "message": "This route requires OTP verification",
        "user_id": str(user.id) if user.id else "N/A",
        "email": str(user.email),
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
    🚀 Starting FastAPI OTP Authentication Example with MongoDB

    📝 Prerequisites:
       - MongoDB must be running on localhost:27017
       - Run: mongod (or use Docker: docker run -d -p 27017:27017 mongo)

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
    🍃 Database: MongoDB
    """)

    uvicorn.run(app, host="0.0.0.0", port=8000)
