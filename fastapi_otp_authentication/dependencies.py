"""FastAPI dependencies for OTP authentication."""

from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, status  # type: ignore[import-untyped]
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # type: ignore[import-untyped]

from fastapi_otp_authentication.config import OTPAuthConfig
from fastapi_otp_authentication.db.adapter import OTPDatabase
from fastapi_otp_authentication.security import decode_token
from fastapi_otp_authentication.types import UserType

# HTTP Bearer scheme for token extraction
http_bearer_scheme = HTTPBearer()


def get_current_user_dependency(
    get_otp_db: Callable[[], OTPDatabase[UserType]],
    config: OTPAuthConfig,
) -> Callable[[str, OTPDatabase[UserType]], Any]:
    """
    Create a dependency for getting the current authenticated user.

    Args:
        get_otp_db: Callable that returns OTPDatabase instance
        config: OTP authentication configuration

    Returns:
        FastAPI dependency function

    Example:
        ```python
        config = MyOTPConfig()

        current_user = Depends(
            get_current_user_dependency(get_otp_db, config)
        )

        @app.get("/protected")
        async def protected_route(user = current_user):
            return {"user_id": user.id}
        ```
    """

    async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(http_bearer_scheme),
        db: OTPDatabase[UserType] = Depends(get_otp_db),
    ) -> UserType:
        """
        Dependency that validates token and returns user.

        Args:
            credentials: HTTP Authorization credentials with bearer token
            db: Database adapter instance

        Returns:
            Current authenticated user

        Raises:
            InvalidTokenException: If token is invalid
            HTTPException: 401 if token is blacklisted
            HTTPException: 404 if user not found
        """
        # Decode and verify token
        token = credentials.credentials
        try:
            claims = decode_token(token, config.secret_key, config.algorithm)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired token: {e}",
            ) from e

        # Check token type
        if claims.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )

        # Check if token is blacklisted
        jti = claims.get("jti")
        if jti and await db.is_blacklisted(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )

        # Get user
        user_id = claims.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing subject claim",
            )

        user = await db.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return user

    return get_current_user


def get_verified_user_dependency(
    get_otp_db: Callable[[], OTPDatabase[UserType]],
    config: OTPAuthConfig,
) -> Callable[[str, OTPDatabase[UserType]], Any]:
    """
    Create a dependency for getting a verified authenticated user.

    Similar to get_current_user_dependency but also checks if user
    has completed OTP verification.

    Args:
        get_otp_db: Callable that returns OTPDatabase instance
        config: OTP authentication configuration

    Returns:
        FastAPI dependency function

    Example:
        ```python
        config = MyOTPConfig()

        verified_user = Depends(
            get_verified_user_dependency(get_otp_db, config)
        )

        @app.get("/sensitive")
        async def sensitive_route(user = verified_user):
            return {"user_id": user.id}
        ```
    """
    get_current_user = get_current_user_dependency(get_otp_db, config)

    async def get_verified_user(
        user: UserType = Depends(get_current_user),
    ) -> UserType:
        """
        Dependency that ensures user is verified.

        Args:
            user: User from get_current_user dependency

        Returns:
            Verified user

        Raises:
            UserNotVerifiedException: If user hasn't completed OTP verification
        """
        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User has not completed OTP verification",
            )

        return user

    return get_verified_user


def get_custom_claims_dependency(
    config: OTPAuthConfig,
) -> Callable[[str], dict[str, Any]]:
    """
    Create a dependency for extracting custom claims from JWT token.

    Returns all custom claims added via get_additional_claims(),
    excluding standard JWT claims (sub, exp, iat, jti, type).

    Args:
        config: OTP authentication configuration

    Returns:
        FastAPI dependency function

    Example:
        ```python
        config = MyOTPConfig()

        custom_claims = Depends(
            get_custom_claims_dependency(config)
        )

        @app.get("/check-role")
        async def check_role(claims: dict = custom_claims):
            return {"role": claims.get("role"), "permissions": claims.get("permissions")}
        ```
    """

    async def get_custom_claims(
        credentials: HTTPAuthorizationCredentials = Depends(http_bearer_scheme),
    ) -> dict[str, Any]:
        """
        Dependency that extracts custom claims from token.

        Args:
            credentials: HTTP Authorization credentials with bearer token

        Returns:
            Dictionary containing custom claims

        Raises:
            HTTPException: 401 if token is invalid or expired
        """
        # Decode and verify token
        token = credentials.credentials
        try:
            claims = decode_token(token, config.secret_key, config.algorithm)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired token: {e}",
            ) from e

        # Check token type
        if claims.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )

        # Filter out standard JWT claims
        standard_claims = {"sub", "exp", "iat", "jti", "type"}
        custom_claims = {k: v for k, v in claims.items() if k not in standard_claims}

        return custom_claims

    return get_custom_claims
