"""Data models for CERN SSO Python wrapper."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class WebAuthnDevice:
    """Represents a FIDO2/WebAuthn device.

    Attributes:
        index: Device index for use with webauthn_device_index parameter.
        product: Product name (e.g., "YubiKey 5").
        path: System path to the device.
    """

    index: int
    product: str
    path: str


@dataclass
class CookieStatusEntry:
    """Status of a single cookie.

    Attributes:
        domain: Cookie domain.
        name: Cookie name.
        expires: Expiration datetime (None if session cookie).
        valid: Whether the cookie is still valid (not expired).
    """

    domain: str
    name: str
    expires: Optional[datetime]
    valid: bool


@dataclass
class CookieStatus:
    """Status of cookies in a file.

    Attributes:
        entries: List of individual cookie statuses.
        verified: Whether HTTP verification was performed.
        verified_valid: Whether cookies were verified as working (only meaningful if verified=True).
    """

    entries: list[CookieStatusEntry]
    verified: bool
    verified_valid: bool

    @property
    def has_valid_cookies(self) -> bool:
        """Check if any cookies are still valid."""
        return any(entry.valid for entry in self.entries)

    @property
    def all_valid(self) -> bool:
        """Check if all cookies are valid."""
        return all(entry.valid for entry in self.entries)


@dataclass
class HarborSecret:
    """Harbor CLI secret for Docker login.

    Attributes:
        username: Harbor username.
        secret: CLI secret for docker login.

    Example:
        >>> secret = get_harbor_secret()
        >>> print(f"docker login registry.cern.ch -u {secret.username} -p {secret.secret}")
    """

    username: str
    secret: str


@dataclass
class OpenShiftLogin:
    """OpenShift login credentials.

    Attributes:
        command: Full oc login command.
        token: API token (sha256~...).
        server: API server URL.

    Example:
        >>> login = get_openshift_token()
        >>> print(login.command)  # oc login --token=... --server=...
    """

    command: str
    token: str
    server: str
