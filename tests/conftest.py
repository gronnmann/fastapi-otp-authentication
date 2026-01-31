"""Test configuration."""

import pytest


@pytest.fixture
def test_secret() -> str:
    """Provide a test secret key."""
    return "test-secret-key-minimum-32-chars-long"
