from datetime import datetime, timedelta, timezone
from typing import Any, Optional


class TokenResult(dict):
    """OAuth2 token response, dict-compatible with oauthlib.OAuth2Token.

    This class inherits from dict so it can be used directly with
    requests-oauthlib and other OAuth libraries that expect token dicts.

    Example:
        >>> token = get_token(client_id="my-app", redirect_uri="https://...")
        >>> token["access_token"]  # Dict access
        'eyJ...'
        >>> token.access_token     # Property access
        'eyJ...'
        >>> token.expires_at       # Computed datetime
        datetime.datetime(2024, 1, 1, 12, 0, 0)
    """

    def __init__(self, data: dict[str, Any], fetched_at: Optional[datetime] = None):
        """Initialize token result.

        Args:
            data: Token response dictionary from CLI.
            fetched_at: When the token was fetched (defaults to now).
        """
        super().__init__(data)
        self._fetched_at = fetched_at or datetime.now(timezone.utc)

    @property
    def access_token(self) -> str:
        """The access token string."""
        return self["access_token"]

    @property
    def token_type(self) -> str:
        """Token type, typically 'Bearer'."""
        return self.get("token_type", "Bearer")

    @property
    def expires_in(self) -> Optional[int]:
        """Token lifetime in seconds, if provided."""
        return self.get("expires_in")

    @property
    def refresh_token(self) -> Optional[str]:
        """Refresh token, if provided."""
        return self.get("refresh_token")

    @property
    def scope(self) -> Optional[str]:
        """Token scope, if provided."""
        return self.get("scope")

    @property
    def expires_at(self) -> Optional[datetime]:
        """Computed expiration datetime, or None if expires_in not set."""
        if self.expires_in is None:
            return None
        return self._fetched_at + timedelta(seconds=self.expires_in)

    @property
    def is_expired(self) -> bool:
        """Check if token has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def __repr__(self) -> str:
        expires = f", expires_at={self.expires_at}" if self.expires_at else ""
        return f"TokenResult(access_token='{self.access_token[:20]}...'{expires})"
