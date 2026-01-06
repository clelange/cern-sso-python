from http.cookiejar import MozillaCookieJar
from pathlib import Path
from typing import Union

from .exceptions import CookieError


def load_cookies(path: Union[str, Path]) -> MozillaCookieJar:
    """Load cookies from a Netscape-format cookie file.

    Args:
        path: Path to the cookie file (typically created by cern-sso-cli).

    Returns:
        A MozillaCookieJar containing the loaded cookies.

    Raises:
        CookieError: If the file cannot be loaded.

    Example:
        >>> jar = load_cookies("cookies.txt")
        >>> len(jar)
        5
    """
    path = Path(path)
    if not path.exists():
        raise CookieError(f"Cookie file not found: {path}")

    jar = MozillaCookieJar(str(path))
    try:
        jar.load(ignore_discard=True, ignore_expires=True)
    except Exception as e:
        raise CookieError(f"Failed to load cookies from {path}: {e}") from e

    return jar


def to_requests_jar(jar: MozillaCookieJar):
    """Convert a MozillaCookieJar to a requests-compatible jar.

    This requires the `requests` package to be installed.

    Args:
        jar: A MozillaCookieJar to convert.

    Returns:
        A requests.cookies.RequestsCookieJar.

    Raises:
        ImportError: If requests is not installed.

    Example:
        >>> jar = load_cookies("cookies.txt")
        >>> req_jar = to_requests_jar(jar)
        >>> requests.get("https://example.com", cookies=req_jar)
    """
    try:
        from requests.cookies import RequestsCookieJar
    except ImportError as e:
        raise ImportError(
            "The 'requests' package is required for to_requests_jar(). "
            "Install it with: pip install requests"
        ) from e

    req_jar = RequestsCookieJar()
    for cookie in jar:
        req_jar.set_cookie(cookie)
    return req_jar
