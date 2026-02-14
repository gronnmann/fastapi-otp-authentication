"""Custom SQLAlchemy types for timezone-aware datetime handling."""

from datetime import UTC, datetime

from sqlalchemy import types
from sqlalchemy.engine import Dialect


class UTCDateTime(types.TypeDecorator):
    """
    Timezone-aware DateTime type that always stores and retrieves UTC datetimes.

    This type decorator ensures that:
    1. All datetimes stored in the database are in UTC
    2. All datetimes retrieved from the database are timezone-aware (UTC)
    3. Works consistently across all database backends, including SQLite

    Naive datetimes are assumed to be in UTC and are converted to timezone-aware.
    Timezone-aware datetimes are converted to UTC before storage.

    Example:
        ```python
        from sqlalchemy.orm import Mapped, mapped_column

        class MyModel(Base):
            created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
        ```
    """

    impl = types.DateTime
    cache_ok = True

    def process_bind_param(
        self, value: datetime | None, _dialect: Dialect
    ) -> datetime | None:
        """
        Process datetime before storing in database.

        Converts timezone-aware datetimes to UTC and treats naive datetimes as UTC.

        Args:
            value: Datetime value to store
            dialect: Database dialect

        Returns:
            UTC datetime without timezone info (for database storage)
        """
        if value is None:
            return None

        if value.tzinfo is None:
            # Treat naive datetime as UTC
            return value

        # Convert timezone-aware datetime to UTC and remove tzinfo
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(
        self, value: datetime | None, _dialect: Dialect
    ) -> datetime | None:
        """
        Process datetime loaded from database.

        Ensures all retrieved datetimes are timezone-aware in UTC.

        Args:
            value: Datetime value from database
            dialect: Database dialect

        Returns:
            UTC timezone-aware datetime
        """
        if value is None:
            return None

        if value.tzinfo is None:
            # Database returned naive datetime, assume it's UTC
            return value.replace(tzinfo=UTC)

        # Database returned timezone-aware datetime, convert to UTC
        return value.astimezone(UTC)
