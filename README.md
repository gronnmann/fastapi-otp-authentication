# FastAPI OTP Authentication

A flexible, type-safe library for adding OTP (One-Time Password) based authentication to FastAPI applications with minimal configuration.

[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![Type Checked](https://img.shields.io/badge/type--checked-mypy-blue.svg)](http://mypy-lang.org/)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-black.svg)](https://github.com/astral-sh/ruff)

## Features

- 🔐 **Cryptographically Secure**: Uses `secrets` module for OTP generation
- 🍪 **HTTP-Only Cookies**: Refresh tokens stored securely
- 🚫 **Token Blacklisting**: Revoke tokens on logout
- 💯 **100% Type Safe**: Full mypy strict mode compliance
- 🎯 **Flexible**: Extend abstract classes to customize behavior
- 🧑‍💻 **Developer Mode**: Testing mode with predictable OTP codes
- 🔧 **SQLAlchemy Async**: Modern async/await patterns
- 📝 **Custom Claims**: Add your own JWT claims
- ⚡ **Production Ready**: Secret validation and security best practices

## Installation

```bash
# Install the library
uv add git+https://github.com/gronnmann/fastapi-otp-authentication.git

# Install your database driver (choose one)
uv add asyncpg  # PostgreSQL
uv add aiomysql  # MySQL
uv add aiosqlite  # SQLite
```

## Quick Start

### 1. Create Your User Model and Register Blacklist table

```python
from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from fastapi_otp_authentication import BaseOTPUserTable
from fastapi_otp_authentication import TokenBlacklist


class Base(DeclarativeBase):
    pass

class User(BaseOTPUserTable[int], Base):
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)

class Blacklist(TokenBlacklist, Base):
    pass
```

### 2. Configure OTP Authentication

You configure the library by extending the `OTPAuthConfig` abstract class:

```python
from datetime import timedelta
from fastapi_otp_authentication import OTPAuthConfig

class MyOTPConfig(OTPAuthConfig):
    # Security - REQUIRED
    secret_key = "your-secret-key-generate-with-openssl-rand-hex-32"
    
    # Optional: Developer mode for testing (default: False)
    developer_mode = False
    
    cookie_secure = True  # Use secure cookies (https) in production
    
    # Token lifetimes
    access_token_lifetime = timedelta(hours=1)
    refresh_token_lifetime = timedelta(days=7)
    
    # OTP settings
    otp_length = 6
    otp_expiry = timedelta(minutes=10)
    max_otp_attempts = 5
    
    async def send_otp(self, email: str, code: str) -> None:
        """Implement your OTP delivery method."""
        # Send via email, SMS, etc.
        print(f"OTP for {email}: {code}")
    
    def get_additional_claims(self, user: User) -> dict[str, Any]:
        """Add custom claims to JWT tokens."""
        return {"username": user.username}
```

### 3. Set Up Database and Dependencies

```python
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from fastapi_otp_authentication import OTPDatabase

# Database setup
engine = create_async_engine("sqlite+aiosqlite:///./app.db")
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

async def get_async_session():
    async with async_session_maker() as session:
        yield session

async def get_otp_db(session: AsyncSession = Depends(get_async_session)):
    yield OTPDatabase(session, User)
```

### 4. Register Authentication Router

```python
from fastapi import FastAPI
from fastapi_otp_authentication import get_auth_router

app = FastAPI()
config = MyOTPConfig()

auth_router = get_auth_router(get_otp_db, config)
app.include_router(auth_router, prefix="/auth", tags=["auth"])
```

### 5. Protect Your Routes

```python
from fastapi import Depends
from fastapi_otp_authentication import (
    get_current_user_dependency,
    get_verified_user_dependency,
    get_custom_claims_dependency,
)

# Create dependencies
current_user = Depends(get_current_user_dependency(get_otp_db, config))
verified_user = Depends(get_verified_user_dependency(get_otp_db, config))
custom_claims = Depends(get_custom_claims_dependency(config))

@app.get("/protected")
async def protected_route(user: User = current_user):
    return {"user_id": user.id, "email": user.email}

@app.get("/verified-only")
async def verified_only(user: User = verified_user):
    return {"message": "Access granted to verified user"}

@app.get("/check-claims")
async def check_claims(claims: dict = custom_claims):
    return {"custom_claims": claims}
```

## API Endpoints

The auth router provides these endpoints:

### `POST /auth/request-otp`
Request OTP code to be sent to user's email.

```json
{
  "email": "user@example.com"
}
```

### `POST /auth/verify-otp`
Verify OTP code and receive authentication tokens.

```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer"
}
```

The refresh token is set in an HTTP-only cookie.

### `POST /auth/refresh`
Refresh access token using refresh token from cookie.

### `POST /auth/logout`
Blacklist tokens and clear refresh cookie.

## Security Best Practices

### Generate Secure Secret Key

```bash
openssl rand -hex 32
```

The library validates that your secret key is at least 32 characters long (unless in developer mode).

### Developer Mode

For testing, enable developer mode:

```python
class MyOTPConfig(OTPAuthConfig):
    developer_mode = True
    secret_key = "any-key-allowed-in-dev-mode"
```

In developer mode:
- OTP codes are always `000000` (or length of zeros)
- Secret key validation is relaxed

⚠️ **Never use developer mode in production!**

## Advanced Usage

### Custom Claims

Add custom data to JWT tokens:

```python
class MyOTPConfig(OTPAuthConfig):
    def get_additional_claims(self, user: User) -> dict[str, Any]:
        return {
            "role": user.role,
            "permissions": user.permissions,
            "organization_id": user.organization_id,
        }
```

Access custom claims in your routes:

```python
from fastapi_otp_authentication import get_custom_claims_dependency

custom_claims = Depends(get_custom_claims_dependency(config))

@app.get("/admin-check")
async def admin_check(claims: dict = custom_claims):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"message": "Admin access granted"}
```

### Rate Limiting

OTP verification attempts are tracked automatically. Configure max attempts:

```python
class MyOTPConfig(OTPAuthConfig):
    max_otp_attempts = 3  # Stricter rate limiting
```

### Custom OTP Length

```python
class MyOTPConfig(OTPAuthConfig):
    otp_length = 8  # 8-digit OTP codes
```

### Token Blacklist Cleanup

Periodically clean up expired blacklisted tokens:

```python
async def cleanup_expired_tokens():
    async with async_session_maker() as session:
        db = OTPDatabase(session, User)
        removed = await db.cleanup_blacklist()
        print(f"Removed {removed} expired tokens")
```
## Example Application

See [examples/basic_usage.py](examples/basic_usage.py) for a complete working example.

Run it:

```bash
uv run python examples/basic_usage.py
```

Then visit http://localhost:8000/docs to try the API.

## Testing

Run the test suite:

```bash
uv run pytest tests/ -v
```

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `pytest tests/`
2. Code is type-safe: `mypy . --strict`
3. Code is linted: `ruff check .`
4. Code is formatted: `black .`
