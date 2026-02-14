"""Tests for API router endpoints."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_otp_authentication.db.sqlalchemy.adapter import SQLAlchemyAdapter
from fastapi_otp_authentication.router import get_auth_router
from fastapi_otp_authentication.security import create_refresh_token
from tests.conftest import MockOTPConfig, User

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def app(otp_db: SQLAlchemyAdapter[User], test_config: MockOTPConfig) -> FastAPI:
    """Create FastAPI application with auth router."""
    app_instance = FastAPI()

    def get_db() -> SQLAlchemyAdapter[User]:
        return otp_db

    auth_router = get_auth_router(get_db, test_config)
    app_instance.include_router(auth_router, prefix="/auth")

    return app_instance


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create test client."""
    return TestClient(app)


# ============================================================================
# Request OTP Tests
# ============================================================================


class TestRequestOTP:
    """Test suite for POST /auth/request-otp endpoint."""

    def test_request_otp_for_existing_user(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        test_user: User,
    ) -> None:
        """Should send OTP code to existing user."""
        response = client.post(
            "/auth/request-otp",
            json={"email": test_user.email},
        )

        assert response.status_code == 200
        data = response.json()
        assert "OTP code" in data["message"]

        # In developer mode, should show the code
        assert "000000" in data["message"]

        # OTP should be tracked in config
        assert len(test_config.sent_otps) == 1
        assert test_config.sent_otps[0][0] == test_user.email

    @pytest.mark.asyncio
    async def test_request_otp_auto_creates_user(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Should auto-create user when auto_create_user is True."""
        new_email = "newuser@example.com"

        response = client.post(
            "/auth/request-otp",
            json={"email": new_email},
        )

        assert response.status_code == 200

        # User should be created
        user = await otp_db.get_by_email(new_email)
        assert user is not None
        assert user.email == new_email

    def test_request_otp_rejects_nonexistent_user_when_disabled(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
    ) -> None:
        """Should return 404 when auto_create_user is False."""
        test_config.auto_create_user = False

        response = client.post(
            "/auth/request-otp",
            json={"email": "nonexistent@example.com"},
        )

        assert response.status_code == 404
        assert "no user found" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_request_otp_enforces_rate_limit(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        test_user: User,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Should enforce rate limiting on OTP requests."""
        # First request succeeds
        response1 = client.post(
            "/auth/request-otp",
            json={"email": test_user.email},
        )
        assert response1.status_code == 200

        # Update user to have recent request
        test_user.last_otp_request_at = datetime.now(UTC)
        await otp_db.session.commit()

        # Second request should be rate limited
        response2 = client.post(
            "/auth/request-otp",
            json={"email": test_user.email},
        )
        assert response2.status_code == 429
        assert "wait" in response2.json()["detail"].lower()

    def test_request_otp_invalid_email_format(
        self,
        client: TestClient,
    ) -> None:
        """Should validate email format."""
        response = client.post(
            "/auth/request-otp",
            json={"email": "not-an-email"},
        )

        # FastAPI validation should reject invalid email
        assert response.status_code == 422


# ============================================================================
# Verify OTP Tests
# ============================================================================


class TestVerifyOTP:
    """Test suite for POST /auth/verify-otp endpoint."""

    @pytest.mark.asyncio
    async def test_verify_otp_success(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        test_user: User,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Should verify valid OTP and return tokens."""
        # Set OTP for user
        await otp_db.update_otp(test_user, "000000")

        response = client.post(
            "/auth/verify-otp",
            json={
                "email": test_user.email,
                "code": "000000",
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Should return access token
        assert "access_token" in data
        assert data["token_type"] == "bearer"

        # Should set refresh token cookie
        assert "refresh_token" in response.cookies

        # User should be verified
        user = await otp_db.get_by_id(test_user.id)
        assert user is not None
        assert user.is_verified is True
        assert user.otp_code is None

    @pytest.mark.asyncio
    async def test_verify_otp_wrong_code(
        self,
        client: TestClient,
        test_user: User,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Should reject incorrect OTP code."""
        await otp_db.update_otp(test_user, "123456")

        response = client.post(
            "/auth/verify-otp",
            json={
                "email": test_user.email,
                "code": "999999",
            },
        )

        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()

        # Attempts should be incremented
        user = await otp_db.get_by_id(test_user.id)
        assert user is not None
        assert user.otp_attempts == 1

    @pytest.mark.asyncio
    async def test_verify_otp_expired_code(
        self,
        client: TestClient,
        test_user: User,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Should reject expired OTP code."""
        await otp_db.update_otp(test_user, "123456")

        # Manually set creation time to past
        test_user.otp_created_at = datetime.now(UTC) - timedelta(minutes=15)
        await otp_db.session.commit()

        response = client.post(
            "/auth/verify-otp",
            json={
                "email": test_user.email,
                "code": "123456",
            },
        )

        assert response.status_code == 401
        assert "expired" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_verify_otp_too_many_attempts(
        self,
        client: TestClient,
        test_user: User,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Should reject after max attempts reached."""
        await otp_db.update_otp(test_user, "123456")

        # Set attempts to max
        test_user.otp_attempts = 5
        await otp_db.session.commit()

        response = client.post(
            "/auth/verify-otp",
            json={
                "email": test_user.email,
                "code": "123456",
            },
        )

        assert response.status_code == 429
        assert "too many" in response.json()["detail"].lower()

    def test_verify_otp_nonexistent_user(
        self,
        client: TestClient,
    ) -> None:
        """Should return 404 for non-existent user."""
        response = client.post(
            "/auth/verify-otp",
            json={
                "email": "nonexistent@example.com",
                "code": "123456",
            },
        )

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_verify_otp_no_code_requested(
        self,
        client: TestClient,
        test_user: User,
    ) -> None:
        """Should reject when no OTP has been requested."""
        # User exists but has no OTP
        response = client.post(
            "/auth/verify-otp",
            json={
                "email": test_user.email,
                "code": "123456",
            },
        )

        assert response.status_code == 401
        assert "no otp" in response.json()["detail"].lower()


# ============================================================================
# Refresh Token Tests
# ============================================================================


class TestRefreshToken:
    """Test suite for POST /auth/refresh endpoint."""

    @pytest.mark.asyncio
    async def test_refresh_with_valid_token(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        verified_user: User,
    ) -> None:
        """Should issue new access token with valid refresh token."""
        # Create refresh token
        refresh_token = create_refresh_token(
            user_id=verified_user.id,
            secret_key=test_config.secret_key,
            algorithm=test_config.algorithm,
            lifetime=test_config.refresh_token_lifetime,
        )

        # Set refresh token cookie
        client.cookies.set("refresh_token", refresh_token)

        response = client.post("/auth/refresh")

        assert response.status_code == 200
        data = response.json()

        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_refresh_without_cookie(
        self,
        client: TestClient,
    ) -> None:
        """Should reject when refresh token cookie is missing."""
        response = client.post("/auth/refresh")

        assert response.status_code == 401
        assert "not found" in response.json()["detail"].lower()

    def test_refresh_with_invalid_token(
        self,
        client: TestClient,
    ) -> None:
        """Should reject invalid refresh token."""
        client.cookies.set("refresh_token", "invalid.token.here")

        response = client.post("/auth/refresh")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_with_blacklisted_token(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        verified_user: User,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Should reject blacklisted refresh token."""
        from fastapi_otp_authentication.security import decode_token

        # Create and blacklist token
        refresh_token = create_refresh_token(
            user_id=verified_user.id,
            secret_key=test_config.secret_key,
            algorithm=test_config.algorithm,
            lifetime=test_config.refresh_token_lifetime,
        )

        claims = decode_token(
            refresh_token, test_config.secret_key, test_config.algorithm
        )
        await otp_db.add_to_blacklist(
            jti=claims["jti"],
            token_type="refresh",
            expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC),
        )

        client.cookies.set("refresh_token", refresh_token)

        response = client.post("/auth/refresh")

        assert response.status_code == 401
        assert "revoked" in response.json()["detail"].lower()

    def test_refresh_with_wrong_token_type(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        verified_user: User,
    ) -> None:
        """Should reject access token used as refresh token."""
        from fastapi_otp_authentication.security import create_access_token

        # Create access token instead of refresh token
        access_token = create_access_token(
            user_id=verified_user.id,
            additional_claims={},
            secret_key=test_config.secret_key,
            algorithm=test_config.algorithm,
            lifetime=test_config.access_token_lifetime,
        )

        client.cookies.set("refresh_token", access_token)

        response = client.post("/auth/refresh")

        assert response.status_code == 401
        assert "type" in response.json()["detail"].lower()


# ============================================================================
# Logout Tests
# ============================================================================


class TestLogout:
    """Test suite for POST /auth/logout endpoint."""

    @pytest.mark.asyncio
    async def test_logout_blacklists_token(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        verified_user: User,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Should blacklist refresh token on logout."""
        from fastapi_otp_authentication.security import decode_token

        # Create refresh token
        refresh_token = create_refresh_token(
            user_id=verified_user.id,
            secret_key=test_config.secret_key,
            algorithm=test_config.algorithm,
            lifetime=test_config.refresh_token_lifetime,
        )

        claims = decode_token(
            refresh_token, test_config.secret_key, test_config.algorithm
        )

        client.cookies.set("refresh_token", refresh_token)

        response = client.post("/auth/logout")

        assert response.status_code == 200
        assert "logged out" in response.json()["message"].lower()

        # Token should be blacklisted
        is_blacklisted = await otp_db.is_blacklisted(claims["jti"])
        assert is_blacklisted is True

    def test_logout_clears_cookie(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        verified_user: User,
    ) -> None:
        """Should clear refresh token cookie."""
        # Create refresh token
        refresh_token = create_refresh_token(
            user_id=verified_user.id,
            secret_key=test_config.secret_key,
            algorithm=test_config.algorithm,
            lifetime=test_config.refresh_token_lifetime,
        )

        client.cookies.set("refresh_token", refresh_token)

        response = client.post("/auth/logout")

        assert response.status_code == 200

        # Cookie should be deleted
        set_cookie = response.headers.get("set-cookie", "")
        assert "refresh_token=" in set_cookie
        # Deletion is indicated by max-age=0 or expires in the past

    def test_logout_without_token(
        self,
        client: TestClient,
    ) -> None:
        """Should handle logout without refresh token gracefully."""
        response = client.post("/auth/logout")

        # Should still succeed even without token
        assert response.status_code == 200

    def test_logout_with_invalid_token(
        self,
        client: TestClient,
    ) -> None:
        """Should handle logout with invalid token gracefully."""
        client.cookies.set("refresh_token", "invalid.token")

        response = client.post("/auth/logout")

        # Should still succeed and clear cookie
        assert response.status_code == 200


# ============================================================================
# Integration Tests
# ============================================================================


class TestFullAuthenticationFlow:
    """Test suite for complete authentication flows."""

    @pytest.mark.asyncio
    async def test_complete_authentication_flow(
        self,
        client: TestClient,
        test_config: MockOTPConfig,
        otp_db: SQLAlchemyAdapter[User],
    ) -> None:
        """Test complete flow: request OTP -> verify -> refresh -> logout."""
        email = "complete@example.com"

        # Step 1: Request OTP
        response1 = client.post("/auth/request-otp", json={"email": email})
        assert response1.status_code == 200

        # Step 2: Verify OTP
        response2 = client.post(
            "/auth/verify-otp",
            json={"email": email, "code": "000000"},
        )
        assert response2.status_code == 200
        access_token = response2.json()["access_token"]
        assert "refresh_token" in response2.cookies

        # Step 3: Refresh access token
        response3 = client.post("/auth/refresh")
        assert response3.status_code == 200
        new_access_token = response3.json()["access_token"]
        assert new_access_token != access_token  # Should be different

        # Step 4: Logout
        response4 = client.post("/auth/logout")
        assert response4.status_code == 200

        # Step 5: Refresh should fail after logout
        response5 = client.post("/auth/refresh")
        assert response5.status_code in [401, 422]  # Unauthorized or cookie issue
