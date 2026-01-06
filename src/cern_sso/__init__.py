"""CERN SSO Python - Authentication wrapper for cern-sso-cli.

This package provides a Pythonic interface to cern-sso-cli for
CERN SSO authentication, cookie management, and OAuth2 token retrieval.

Quick Start:
    >>> from cern_sso import get_cookies, get_token, device_flow
    >>>
    >>> # Get cookies for a URL
    >>> jar = get_cookies("https://gitlab.cern.ch", otp="123456")
    >>>
    >>> # Get an OAuth2 access token
    >>> token = get_token(client_id="my-app", redirect_uri="https://...")
    >>>
    >>> # Device flow for headless environments
    >>> token = device_flow(client_id="my-app")
"""

from http.cookiejar import MozillaCookieJar
from pathlib import Path
from typing import Optional, Union

from .client import CERNSSOClient, _get_default_client
from .cookies import load_cookies, to_requests_jar
from .exceptions import (
    AuthenticationError,
    CERNSSOError,
    CLINotFoundError,
    CLIVersionError,
    CookieError,
)
from .tokens import TokenResult

__version__ = "0.1.0"

__all__ = [
    # Main functions
    "get_cookies",
    "get_token",
    "device_flow",
    "load_cookies",
    # Classes
    "CERNSSOClient",
    "TokenResult",
    # Utilities
    "to_requests_jar",
    # Exceptions
    "CERNSSOError",
    "CLINotFoundError",
    "CLIVersionError",
    "AuthenticationError",
    "CookieError",
]


def get_cookies(
    url: str,
    *,
    file: Union[str, Path, None] = None,
    user: Optional[str] = None,
    otp: Optional[str] = None,
    otp_command: Optional[str] = None,
    otp_retries: Optional[int] = None,
    use_otp: bool = False,
    use_webauthn: bool = False,
    webauthn_pin: Optional[str] = None,
    webauthn_device: Optional[str] = None,
    force: bool = False,
    insecure: bool = False,
    auth_host: str = "auth.cern.ch",
) -> MozillaCookieJar:
    """Authenticate and get cookies for a URL.

    This is a convenience function that uses the default client.
    For more control, use CERNSSOClient directly.

    Args:
        url: Target URL to authenticate against.
        file: Output cookie file path. If None, uses a temp file.
        user: Kerberos username (e.g., "alice" or "alice@CERN.CH").
        otp: OTP code for 2FA.
        otp_command: Command to get OTP (e.g., "op item get CERN --otp").
        otp_retries: Max OTP retry attempts.
        use_otp: Force OTP method even if WebAuthn is default.
        use_webauthn: Force WebAuthn method even if OTP is default.
        webauthn_pin: PIN for FIDO2 security key.
        webauthn_device: Path to specific FIDO2 device.
        force: Force re-authentication even if cookies exist.
        insecure: Skip certificate validation.
        auth_host: Authentication hostname.

    Returns:
        MozillaCookieJar containing the session cookies.

    Raises:
        CLINotFoundError: If cern-sso-cli is not installed.
        AuthenticationError: If authentication fails.

    Example:
        >>> jar = get_cookies("https://gitlab.cern.ch", otp="123456")
        >>> len(jar)
        5
    """
    return _get_default_client().get_cookies(
        url,
        file=file,
        user=user,
        otp=otp,
        otp_command=otp_command,
        otp_retries=otp_retries,
        use_otp=use_otp,
        use_webauthn=use_webauthn,
        webauthn_pin=webauthn_pin,
        webauthn_device=webauthn_device,
        force=force,
        insecure=insecure,
        auth_host=auth_host,
    )


def get_token(
    client_id: str,
    redirect_uri: str,
    *,
    user: Optional[str] = None,
    otp: Optional[str] = None,
    otp_command: Optional[str] = None,
    otp_retries: Optional[int] = None,
    use_otp: bool = False,
    use_webauthn: bool = False,
    webauthn_pin: Optional[str] = None,
    webauthn_device: Optional[str] = None,
    insecure: bool = False,
    auth_host: str = "auth.cern.ch",
    realm: str = "cern",
) -> TokenResult:
    """Get an OIDC access token via Authorization Code flow.

    This is a convenience function that uses the default client.
    For more control, use CERNSSOClient directly.

    Args:
        client_id: OAuth client ID.
        redirect_uri: OAuth redirect URI.
        user: Kerberos username.
        otp: OTP code for 2FA.
        otp_command: Command to get OTP.
        otp_retries: Max OTP retry attempts.
        use_otp: Force OTP method even if WebAuthn is default.
        use_webauthn: Force WebAuthn method even if OTP is default.
        webauthn_pin: PIN for FIDO2 security key.
        webauthn_device: Path to specific FIDO2 device.
        insecure: Skip certificate validation.
        auth_host: Authentication hostname.
        realm: Authentication realm.

    Returns:
        TokenResult containing the access token.

    Raises:
        CLINotFoundError: If cern-sso-cli is not installed.
        AuthenticationError: If authentication fails.

    Example:
        >>> token = get_token("my-app", "https://my-app/callback")
        >>> token.access_token
        'eyJ...'
    """
    return _get_default_client().get_token(
        client_id,
        redirect_uri,
        user=user,
        otp=otp,
        otp_command=otp_command,
        otp_retries=otp_retries,
        use_otp=use_otp,
        use_webauthn=use_webauthn,
        webauthn_pin=webauthn_pin,
        webauthn_device=webauthn_device,
        insecure=insecure,
        auth_host=auth_host,
        realm=realm,
    )


def device_flow(
    client_id: str,
    *,
    insecure: bool = False,
    auth_host: str = "auth.cern.ch",
    realm: str = "cern",
) -> TokenResult:
    """Get tokens via Device Authorization Grant flow.

    This flow is for headless environments where the user authenticates
    in a browser on another device. The CLI will display a URL and code
    for the user to visit.

    This is a convenience function that uses the default client.
    For more control, use CERNSSOClient directly.

    Args:
        client_id: OAuth client ID.
        insecure: Skip certificate validation.
        auth_host: Authentication hostname.
        realm: Authentication realm.

    Returns:
        TokenResult containing access and refresh tokens.

    Raises:
        CLINotFoundError: If cern-sso-cli is not installed.
        AuthenticationError: If authentication fails.

    Example:
        >>> token = device_flow("my-app")
        # Go to https://auth.cern.ch/device and enter code: XXXX-YYYY
        >>> token.access_token
        'eyJ...'
        >>> token.refresh_token
        'eyJ...'
    """
    return _get_default_client().device_flow(
        client_id,
        insecure=insecure,
        auth_host=auth_host,
        realm=realm,
    )
