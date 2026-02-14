"""MongoDB adapter for OTP authentication operations."""

import contextlib
from datetime import UTC, datetime
from typing import Any

try:
    from bson import ObjectId  # type: ignore[import-untyped]
    from motor.motor_asyncio import AsyncIOMotorDatabase  # type: ignore[import-untyped]
except ImportError as e:
    raise ImportError(
        "MongoDB support requires motor and pymongo. "
        "Install with: pip install fastapi-otp-authentication[mongodb]"
    ) from e


class MongoDBAdapter[UserType]:
    """
    MongoDB implementation of the DatabaseAdapter protocol.

    Wraps a Motor AsyncIOMotorDatabase and provides methods for user OTP management
    and token blacklisting operations using MongoDB collections.

    Example:
        ```python
        from motor.motor_asyncio import AsyncIOMotorClient
        from fastapi import Depends

        async def get_otp_db() -> MongoDBAdapter[User]:
            client = AsyncIOMotorClient("mongodb://localhost:27017")
            db = client.myapp
            return MongoDBAdapter(
                database=db,
                user_collection_name="users",
                blacklist_collection_name="token_blacklist",
                user_model_class=User
            )
        ```
    """

    def __init__(
        self,
        database: AsyncIOMotorDatabase,
        user_collection_name: str,
        blacklist_collection_name: str,
        user_model_class: type[UserType],
    ) -> None:
        """
        Initialize the MongoDB adapter.

        Args:
            database: Motor AsyncIOMotorDatabase instance
            user_collection_name: Name of the users collection
            blacklist_collection_name: Name of the token blacklist collection
            user_model_class: Pydantic model class for user documents
        """
        self.database = database
        self.user_collection = database[user_collection_name]
        self.blacklist_collection = database[blacklist_collection_name]
        self.user_model_class = user_model_class

    def _deserialize_user(self, doc: dict[str, Any] | None) -> UserType | None:
        """
        Convert a MongoDB document to a Pydantic user model.

        Args:
            doc: MongoDB document dictionary

        Returns:
            User model instance or None if doc is None
        """
        if doc is None:
            return None

        # Convert ObjectId to string for Pydantic
        if "_id" in doc and isinstance(doc["_id"], ObjectId):
            doc["_id"] = str(doc["_id"])

        # Ensure datetime fields have timezone info (for mongomock compatibility)
        datetime_fields = ["otp_created_at", "otp_expires_at", "last_otp_request_at"]
        for field in datetime_fields:
            if (
                field in doc
                and doc[field] is not None
                and isinstance(doc[field], datetime)
                and doc[field].tzinfo is None
            ):
                doc[field] = doc[field].replace(tzinfo=UTC)

        return self.user_model_class.model_validate(doc)

    def _serialize_user(self, user: UserType) -> dict[str, Any]:
        """
        Convert a Pydantic user model to a MongoDB document.

        Args:
            user: User model instance

        Returns:
            MongoDB document dictionary
        """
        doc = user.model_dump(by_alias=True, exclude_none=False)

        # Convert string _id back to ObjectId if present
        if "_id" in doc and doc["_id"] is not None and isinstance(doc["_id"], str):
            try:
                doc["_id"] = ObjectId(doc["_id"])
            except Exception:
                # If conversion fails, keep as string or remove if empty
                if not doc["_id"]:
                    doc.pop("_id", None)

        return doc

    async def get_by_email(self, email: str) -> UserType | None:
        """
        Retrieve user by email address.

        Args:
            email: Email address to search for

        Returns:
            User object if found, None otherwise
        """
        doc = await self.user_collection.find_one({"email": email})
        return self._deserialize_user(doc)

    async def get_by_id(self, user_id: int | str) -> UserType | None:
        """
        Retrieve user by ID.

        Args:
            user_id: User ID to search for (string or ObjectId)

        Returns:
            User object if found, None otherwise
        """
        # Try to convert to ObjectId if it's a valid ObjectId string
        query_id: Any = user_id
        if isinstance(user_id, str):
            with contextlib.suppress(Exception):
                query_id = ObjectId(user_id)

        doc = await self.user_collection.find_one({"_id": query_id})
        return self._deserialize_user(doc)

    async def create_user(self, email: str, **kwargs: object) -> UserType:
        """
        Create a new user with the given email and additional fields.

        Args:
            email: User's email address
            **kwargs: Additional user fields

        Returns:
            Created user object
        """
        # Create user document with defaults
        user_data = {
            "email": email,
            "is_verified": False,
            "otp_code": None,
            "otp_created_at": None,
            "otp_expires_at": None,
            "otp_attempts": 0,
            "last_otp_request_at": None,
            **kwargs,
        }

        # Insert and get the generated _id
        result = await self.user_collection.insert_one(user_data)
        user_data["_id"] = str(result.inserted_id)

        # Return as Pydantic model
        return self.user_model_class.model_validate(user_data)

    async def update_otp(self, user: UserType, code: str) -> None:
        """
        Update user's OTP code and reset attempt counter.

        Args:
            user: User object to update
            code: New OTP code to set
        """
        now = datetime.now(UTC)

        # Get user _id
        user_dict = user.model_dump(by_alias=True)
        user_id = user_dict.get("_id")

        if user_id and isinstance(user_id, str):
            with contextlib.suppress(Exception):
                user_id = ObjectId(user_id)

        # Update document
        await self.user_collection.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "otp_code": code,
                    "otp_created_at": now,
                    "otp_attempts": 0,
                    "last_otp_request_at": now,
                }
            },
        )

        # Update the user object in-place
        user.otp_code = code  # type: ignore[attr-defined]
        user.otp_created_at = now  # type: ignore[attr-defined]
        user.otp_attempts = 0  # type: ignore[attr-defined]
        user.last_otp_request_at = now  # type: ignore[attr-defined]

    async def increment_otp_attempts(self, user: UserType) -> None:
        """
        Increment the OTP verification attempt counter.

        Args:
            user: User object to update
        """
        # Get user _id
        user_dict = user.model_dump(by_alias=True)
        user_id = user_dict.get("_id")

        if user_id and isinstance(user_id, str):
            with contextlib.suppress(Exception):
                user_id = ObjectId(user_id)

        # Increment attempts
        await self.user_collection.update_one(
            {"_id": user_id}, {"$inc": {"otp_attempts": 1}}
        )

        # Update the user object in-place
        user.otp_attempts += 1  # type: ignore[attr-defined]

    async def verify_user(self, user: UserType) -> None:
        """
        Mark user as verified and clear OTP data.

        Args:
            user: User object to verify
        """
        # Get user _id
        user_dict = user.model_dump(by_alias=True)
        user_id = user_dict.get("_id")

        if user_id and isinstance(user_id, str):
            with contextlib.suppress(Exception):
                user_id = ObjectId(user_id)

        # Update document
        await self.user_collection.update_one(
            {"_id": user_id},
            {
                "$set": {"is_verified": True, "otp_attempts": 0},
                "$unset": {
                    "otp_code": "",
                    "otp_created_at": "",
                    "otp_expires_at": "",
                },
            },
        )

        # Update the user object in-place
        user.is_verified = True  # type: ignore[attr-defined]
        user.otp_code = None  # type: ignore[attr-defined]
        user.otp_created_at = None  # type: ignore[attr-defined]
        user.otp_attempts = 0  # type: ignore[attr-defined]

    async def clear_otp(self, user: UserType) -> None:
        """
        Clear OTP data from user without marking as verified.

        Args:
            user: User object to clear OTP from
        """
        # Get user _id
        user_dict = user.model_dump(by_alias=True)
        user_id = user_dict.get("_id")

        if user_id and isinstance(user_id, str):
            with contextlib.suppress(Exception):
                user_id = ObjectId(user_id)

        # Clear OTP fields
        await self.user_collection.update_one(
            {"_id": user_id},
            {
                "$set": {"otp_attempts": 0},
                "$unset": {
                    "otp_code": "",
                    "otp_created_at": "",
                    "otp_expires_at": "",
                },
            },
        )

        # Update the user object in-place
        user.otp_code = None  # type: ignore[attr-defined]
        user.otp_created_at = None  # type: ignore[attr-defined]
        user.otp_attempts = 0  # type: ignore[attr-defined]

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
        blacklist_entry = {
            "jti": jti,
            "token_type": token_type,
            "blacklisted_at": datetime.now(UTC),
            "expires_at": expires_at,
        }
        await self.blacklist_collection.insert_one(blacklist_entry)

    async def is_blacklisted(self, jti: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            jti: JWT ID to check

        Returns:
            True if token is blacklisted, False otherwise
        """
        doc = await self.blacklist_collection.find_one({"jti": jti})
        return doc is not None

    async def cleanup_blacklist(self) -> int:
        """
        Remove expired tokens from the blacklist.

        Returns:
            Number of tokens removed
        """
        now = datetime.now(UTC)
        result = await self.blacklist_collection.delete_many(
            {"expires_at": {"$lt": now}}
        )
        return result.deleted_count
