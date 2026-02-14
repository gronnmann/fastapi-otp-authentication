import typing
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_otp_authentication.db.protocols import OTPUserProtocol


class SQLAlchemyAdapter[UserType: OTPUserProtocol]:
    """
    SQLAlchemy implementation of the DatabaseAdapter protocol.

    Wraps an AsyncSession and provides methods for user OTP management
    and token blacklisting operations using SQLAlchemy ORM.

    Example:
        ```python
        from sqlalchemy.ext.asyncio import AsyncSession
        from fastapi import Depends

        async def get_otp_db(
            session: AsyncSession = Depends(get_async_session)
        ) -> SQLAlchemyAdapter[User]:
            return SQLAlchemyAdapter(session, User, Blacklist)
        ```
    """

    def __init__(
        self,
        session: AsyncSession,
        user_model: type[UserType],
        blacklist_model: type[typing.Any],
    ) -> None:
        """
        Initialize the database adapter.

        Args:
            session: SQLAlchemy async session
            user_model: User model class inheriting from BaseOTPUserTable
            blacklist_model: Token blacklist model class inheriting from TokenBlacklist
        """
        self.session = session
        self.user_model = user_model
        self.blacklist_model = blacklist_model

    async def get_by_email(self, email: str) -> UserType | None:
        """
        Retrieve user by email address.

        Args:
            email: Email address to search for

        Returns:
            User object if found, None otherwise
        """
        statement = select(self.user_model).where(self.user_model.email == email)  # type: ignore[arg-type]
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: int | str) -> UserType | None:
        """
        Retrieve user by ID.

        Args:
            user_id: User ID to search for

        Returns:
            User object if found, None otherwise
        """
        return await self.session.get(self.user_model, user_id)

    async def create_user(self, email: str, **kwargs: object) -> UserType:
        """
        Create a new user with the given email and additional fields.

        Args:
            email: User's email address
            **kwargs: Additional user fields

        Returns:
            Created user object
        """
        user = self.user_model(email=email, **kwargs)  # type: ignore[call-arg]
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def update_otp(self, user: UserType, code: str) -> None:
        """
        Update user's OTP code and reset attempt counter.

        Args:
            user: User object to update
            code: New OTP code to set
        """
        now = datetime.now(UTC)
        user.otp_code = code
        user.otp_created_at = now
        user.otp_attempts = 0
        user.last_otp_request_at = now
        await self.session.commit()
        await self.session.refresh(user)

    async def increment_otp_attempts(self, user: UserType) -> None:
        """
        Increment the OTP verification attempt counter.

        Args:
            user: User object to update
        """
        user.otp_attempts += 1
        await self.session.commit()
        await self.session.refresh(user)

    async def verify_user(self, user: UserType) -> None:
        """
        Mark user as verified and clear OTP data.

        Args:
            user: User object to verify
        """
        user.is_verified = True
        user.otp_code = None
        user.otp_created_at = None
        user.otp_attempts = 0
        await self.session.commit()
        await self.session.refresh(user)

    async def clear_otp(self, user: UserType) -> None:
        """
        Clear OTP data from user without marking as verified.

        Args:
            user: User object to clear OTP from
        """
        user.otp_code = None
        user.otp_created_at = None
        user.otp_attempts = 0
        await self.session.commit()
        await self.session.refresh(user)

    async def add_to_blacklist(
        self, jti: str, token_type: str, expires_at: datetime
    ) -> None:
        """
        Add a token to the blacklist.

        Args:
            jti: JWT ID (jti claim from token)
            token_type: Type of token ("access" or "refresh")
            expires_at: Token expiration timestamp
        """
        blacklist_entry = self.blacklist_model(
            jti=jti,
            token_type=token_type,
            blacklisted_at=datetime.now(UTC),
            expires_at=expires_at,
        )
        self.session.add(blacklist_entry)
        await self.session.commit()

    async def is_blacklisted(self, jti: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            jti: JWT ID to check

        Returns:
            True if token is blacklisted, False otherwise
        """
        statement = select(self.blacklist_model).where(self.blacklist_model.jti == jti)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none() is not None

    async def cleanup_blacklist(self) -> int:
        """
        Remove expired tokens from the blacklist.

        Returns:
            Number of tokens removed
        """
        now = datetime.now(UTC)
        statement = select(self.blacklist_model).where(
            self.blacklist_model.expires_at < now
        )
        result = await self.session.execute(statement)
        expired_tokens = result.scalars().all()

        count = len(expired_tokens)
        for token in expired_tokens:
            await self.session.delete(token)

        await self.session.commit()
        return count
