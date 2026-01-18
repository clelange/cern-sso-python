"""Tests for token types."""

from datetime import datetime, timezone

from cern_sso.tokens import TokenResult


class TestTokenResult:
    """Tests for TokenResult class."""

    def test_basic_creation(self):
        """Test basic token creation."""
        token = TokenResult(
            {
                "access_token": "eyJ...",
                "token_type": "Bearer",
            }
        )
        assert token.access_token == "eyJ..."
        assert token.token_type == "Bearer"

    def test_dict_compatibility(self):
        """Test token is dict-compatible."""
        token = TokenResult(
            {
                "access_token": "abc",
                "token_type": "Bearer",
                "custom_field": "value",
            }
        )

        # Dict access
        assert token["access_token"] == "abc"
        assert token["custom_field"] == "value"

        # Dict methods
        assert "access_token" in token
        assert len(token) == 3
        assert list(token.keys()) == ["access_token", "token_type", "custom_field"]

    def test_default_token_type(self):
        """Test default token type is Bearer."""
        token = TokenResult({"access_token": "abc"})
        assert token.token_type == "Bearer"

    def test_optional_fields_none(self):
        """Test optional fields return None when missing."""
        token = TokenResult({"access_token": "abc"})
        assert token.refresh_token is None
        assert token.scope is None
        assert token.expires_in is None
        assert token.expires_at is None

    def test_expires_at_computation(self):
        """Test expires_at is computed correctly."""
        fetched_at = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        token = TokenResult(
            {"access_token": "abc", "expires_in": 7200},
            fetched_at=fetched_at,
        )

        expected = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        assert token.expires_at == expected

    def test_is_expired_false(self):
        """Test is_expired returns False for valid token."""
        # Token that expires in 1 hour
        token = TokenResult(
            {
                "access_token": "abc",
                "expires_in": 3600,
            }
        )
        assert not token.is_expired

    def test_is_expired_true(self):
        """Test is_expired returns True for expired token."""
        # Token that was fetched in the past and has expired
        past = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        token = TokenResult(
            {"access_token": "abc", "expires_in": 1},
            fetched_at=past,
        )
        assert token.is_expired

    def test_is_expired_no_expiry(self):
        """Test is_expired returns False when no expiry set."""
        token = TokenResult({"access_token": "abc"})
        assert not token.is_expired

    def test_repr(self):
        """Test string representation."""
        token = TokenResult(
            {
                "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
            }
        )
        repr_str = repr(token)
        assert "TokenResult" in repr_str
        assert "access_token=" in repr_str
        assert "..." in repr_str  # Token is truncated

    def test_with_refresh_token(self):
        """Test token with refresh token."""
        token = TokenResult(
            {
                "access_token": "abc",
                "refresh_token": "xyz",
                "scope": "openid profile",
            }
        )
        assert token.refresh_token == "xyz"
        assert token.scope == "openid profile"
