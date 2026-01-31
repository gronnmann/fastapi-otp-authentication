"""Security utilities for OTP generation and JWT token management."""

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, status  # type: ignore[import-untyped]
from jose import JWTError, jwt  # type: ignore[import-untyped]


def generate_otp(length: int, developer_mode: bool) -> str:
    """
    Generate a cryptographically secure OTP code.

    In developer mode, returns a code consisting of zeros for easy testing.

    Args:
        length: Length of the OTP code (typically 4-8 digits)
        developer_mode: If True, return test code of all zeros

    Returns:
        OTP code as a string

    Example:
        >>> generate_otp(6, False)
        '482913'
        >>> generate_otp(6, True)
        '000000'
    """
    if developer_mode:
        return "0" * length

    # Use secrets.randbelow for cryptographically secure random numbers
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def create_access_token(
    user_id: Any,  # noqa: ANN401
    additional_claims: dict[str, Any],
    secret_key: str,
    algorithm: str,
    lifetime: timedelta,
) -> str:
    """
    Create a JWT access token.

    Args:
        user_id: User identifier
        additional_claims: Additional claims to include in token
        secret_key: Secret key for signing token
        algorithm: JWT algorithm (e.g., 'HS256')
        lifetime: Token lifetime

    Returns:
        Encoded JWT token string

    Example:
        >>> token = create_access_token(
        ...     user_id=123,
        ...     additional_claims={'role': 'admin'},
        ...     secret_key='secret',
        ...     algorithm='HS256',
        ...     lifetime=timedelta(hours=1)
        ... )
    """
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + lifetime,
        **additional_claims,
    }
    return jwt.encode(claims, secret_key, algorithm=algorithm)


def create_refresh_token(
    user_id: Any,  # noqa: ANN401
    secret_key: str,
    algorithm: str,
    lifetime: timedelta,
) -> str:
    """
    Create a JWT refresh token.

    Args:
        user_id: User identifier
        secret_key: Secret key for signing token
        algorithm: JWT algorithm (e.g., 'HS256')
        lifetime: Token lifetime

    Returns:
        Encoded JWT token string

    Example:
        >>> token = create_refresh_token(
        ...     user_id=123,
        ...     secret_key='secret',
        ...     algorithm='HS256',
        ...     lifetime=timedelta(days=7)
        ... )
    """
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + lifetime,
    }
    return jwt.encode(claims, secret_key, algorithm=algorithm)


def decode_token(token: str, secret_key: str, algorithm: str) -> dict[str, Any]:
    """
    Decode and verify a JWT token.

    Args:
        token: JWT token string
        secret_key: Secret key for verification
        algorithm: Expected JWT algorithm

    Returns:
        Decoded token claims as dictionary

    Raises:
        InvalidTokenException: If token is invalid or expired

    Example:
        >>> claims = decode_token(token, 'secret', 'HS256')
        >>> user_id = claims['sub']
    """
    try:
        return jwt.decode(
            token,
            secret_key,
            algorithms=[algorithm],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "require_exp": True,
                "require_iat": True,
            },
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
        ) from e


def verify_otp_code(
    stored_code: str,
    input_code: str,
    created_at: datetime,
    expiry: timedelta,
    max_attempts: int,
    current_attempts: int,
) -> bool:
    """
    Verify an OTP code with timing and attempt checks.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        stored_code: OTP code stored in database
        input_code: OTP code provided by user
        created_at: Timestamp when OTP was created
        expiry: Maximum age of OTP
        max_attempts: Maximum allowed verification attempts
        current_attempts: Current number of attempts

    Returns:
        True if code is valid and not expired, False otherwise

    Raises:
        HTTPException: 429 if max attempts exceeded
        HTTPException: 401 if OTP has expired
    """
    # Check attempt limit
    if current_attempts >= max_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many OTP attempts. Please request a new code.",
        )

    # Check expiration
    now = datetime.now(UTC)
    if now - created_at > expiry:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP code has expired",
        )

    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(stored_code, input_code)
