"""API router for OTP authentication endpoints."""

from collections.abc import Callable
from datetime import datetime

from fastapi import (  # type: ignore[import-untyped]
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)

from fastapi_otp_authentication.config import OTPAuthConfig
from fastapi_otp_authentication.db.adapter import OTPDatabase
from fastapi_otp_authentication.schemas import (
    MessageResponse,
    OTPRequest,
    OTPVerify,
    TokenResponse,
)
from fastapi_otp_authentication.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    verify_otp_code,
)
from fastapi_otp_authentication.types import UserType


def get_auth_router(
    get_otp_db: Callable[[], OTPDatabase[UserType]],
    config: OTPAuthConfig,
) -> APIRouter:
    """
    Create an APIRouter with OTP authentication endpoints.

    Args:
        get_otp_db: Callable that returns OTPDatabase instance
        config: OTP authentication configuration

    Returns:
        Configured APIRouter instance

    Example:
        ```python
        from fastapi import FastAPI

        app = FastAPI()
        config = MyOTPConfig()

        auth_router = get_auth_router(get_otp_db, config)
        app.include_router(auth_router, prefix="/auth", tags=["auth"])
        ```
    """
    router = APIRouter()

    @router.post(
        "/request-otp",
        response_model=MessageResponse,
        status_code=status.HTTP_200_OK,
        summary="Request OTP code",
        description="Generate and send OTP code to user's email",
    )
    async def request_otp(
        request: OTPRequest,
        db: OTPDatabase[UserType] = Depends(get_otp_db),
    ) -> MessageResponse:
        """
        Request an OTP code to be sent to the user's email.

        Args:
            request: OTP request with email
            db: Database adapter

        Returns:
            Success message

        Raises:
            HTTPException: 404 if user not found and auto_create_user is False
            HTTPException: 429 if OTP requested too frequently
        """
        # Get user by email
        user = await db.get_by_email(request.email)

        # Check rate limiting if user exists and has requested OTP before
        if user and hasattr(user, "last_otp_request_at") and user.last_otp_request_at:
            time_since_last_request = (
                datetime.now() - user.last_otp_request_at
            ).total_seconds()
            if time_since_last_request < config.otp_rate_limit_seconds:
                wait_time = int(config.otp_rate_limit_seconds - time_since_last_request)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Please wait {wait_time} seconds before requesting a new OTP code.",
                )

        if not user:
            if config.auto_create_user:
                # Auto-create user if enabled
                user_data = await config.create_user(request.email)
                user = await db.create_user(request.email, **user_data)
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No user found with email: {request.email}",
                )

        # Generate OTP code
        code = generate_otp(config.otp_length, config.developer_mode)

        # Save OTP to database
        await db.update_otp(user, code)

        # Send OTP via configured method
        await config.send_otp(request.email, code)

        return MessageResponse(
            message=(
                "OTP code has been sent to your email"
                if not config.developer_mode
                else f"Developer mode: OTP code is {code}"
            )
        )

    @router.post(
        "/verify-otp",
        response_model=TokenResponse,
        status_code=status.HTTP_200_OK,
        summary="Verify OTP code",
        description="Verify OTP code and receive access token with refresh token "
        "in HTTP-only cookie",
    )
    async def verify_otp(
        request: OTPVerify,
        response: Response,
        db: OTPDatabase[UserType] = Depends(get_otp_db),
    ) -> TokenResponse:
        """
        Verify OTP code and issue authentication tokens.

        Args:
            request: OTP verification request with email and code
            response: FastAPI Response object for setting cookies
            db: Database adapter

        Returns:
            Access token response

        Raises:
            HTTPException: 404 if user not found
            HTTPException: 401 if OTP code is invalid, expired, or not found
            HTTPException: 429 if too many verification attempts
        """
        # Get user by email
        user = await db.get_by_email(request.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No user found with email: {request.email}",
            )

        # Check if OTP exists
        if not user.otp_code or not user.otp_created_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No OTP code found. Please request a new one.",
            )

        # Verify OTP code
        is_valid = verify_otp_code(
            stored_code=user.otp_code,
            input_code=request.code,
            created_at=user.otp_created_at,
            expiry=config.otp_expiry,
            max_attempts=config.max_otp_attempts,
            current_attempts=user.otp_attempts,
        )

        if not is_valid:
            # Increment attempts on failure
            await db.increment_otp_attempts(user)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OTP code",
            )

        # Mark user as verified
        await db.verify_user(user)

        # Get additional claims
        additional_claims = config.get_additional_claims(user)

        # Create tokens
        access_token = create_access_token(
            user_id=user.id,
            additional_claims=additional_claims,
            secret_key=config.secret_key,
            algorithm=config.algorithm,
            lifetime=config.access_token_lifetime,
        )

        refresh_token = create_refresh_token(
            user_id=user.id,
            secret_key=config.secret_key,
            algorithm=config.algorithm,
            lifetime=config.refresh_token_lifetime,
        )

        # Set refresh token in HTTP-only cookie
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=int(config.refresh_token_lifetime.total_seconds()),
            httponly=True,
            secure=not config.developer_mode,  # Use secure cookies in production
            samesite="lax",
        )

        return TokenResponse(access_token=access_token, token_type="bearer")

    @router.post(
        "/refresh",
        response_model=TokenResponse,
        status_code=status.HTTP_200_OK,
        summary="Refresh access token",
        description="Get a new access token using refresh token from HTTP-only cookie",
    )
    async def refresh_token(
        request: Request,
        db: OTPDatabase[UserType] = Depends(get_otp_db),
    ) -> TokenResponse:
        """
        Refresh access token using refresh token from cookie.

        Args:
            request: FastAPI Request object
            db: Database adapter

        Returns:
            New access token

        Raises:
            HTTPException: 401 if token is blacklisted or invalid
            HTTPException: 404 if user not found
        """
        # Extract refresh token from cookies
        refresh_token = request.cookies.get("refresh_token")

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found in cookies",
            )

        # Decode refresh token
        claims = decode_token(refresh_token, config.secret_key, config.algorithm)

        # Verify token type
        if claims.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )

        # Check if blacklisted
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
                detail="Invalid token claims",
            )

        user = await db.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Get additional claims
        additional_claims = config.get_additional_claims(user)

        # Create new access token
        access_token = create_access_token(
            user_id=user.id,
            additional_claims=additional_claims,
            secret_key=config.secret_key,
            algorithm=config.algorithm,
            lifetime=config.access_token_lifetime,
        )

        return TokenResponse(access_token=access_token, token_type="bearer")

    @router.post(
        "/logout",
        response_model=MessageResponse,
        status_code=status.HTTP_200_OK,
        summary="Logout user",
        description="Blacklist refresh token and clear refresh token cookie",
    )
    async def logout(
        request: Request,
        response: Response,
        db: OTPDatabase[UserType] = Depends(get_otp_db),
    ) -> MessageResponse:
        """
        Logout user by blacklisting refresh token.

        Args:
            request: FastAPI Request object
            response: FastAPI Response object
            db: Database adapter

        Returns:
            Success message
        """
        # Extract refresh token from cookies
        refresh_token = request.cookies.get("refresh_token")

        # Decode and blacklist refresh token if present
        if refresh_token:
            try:
                refresh_claims = decode_token(
                    refresh_token, config.secret_key, config.algorithm
                )
                refresh_jti = refresh_claims.get("jti")
                refresh_exp = refresh_claims.get("exp")

                if refresh_jti and refresh_exp:
                    await db.add_to_blacklist(
                        jti=refresh_jti,
                        token_type="refresh",
                        expires_at=datetime.fromtimestamp(refresh_exp),
                    )
            except Exception:
                pass  # Token might already be invalid

        # Clear refresh token cookie
        response.delete_cookie(
            key="refresh_token",
            httponly=True,
            secure=not config.developer_mode,
            samesite="lax",
        )

        return MessageResponse(message="Successfully logged out")

    return router
