"""Custom exceptions for cern-sso-python."""

from typing import Optional


class CERNSSOError(Exception):
    """Base exception for all cern-sso-python errors."""

    pass


class CLINotFoundError(CERNSSOError):
    """Raised when cern-sso-cli executable is not found."""

    def __init__(self, message: Optional[str] = None):
        super().__init__(
            message
            or "cern-sso-cli not found. Install from: https://github.com/clelange/cern-sso-cli"
        )


class CLIVersionError(CERNSSOError):
    """Raised when cern-sso-cli version is incompatible."""

    def __init__(self, required: str, found: str):
        self.required = required
        self.found = found
        super().__init__(f"cern-sso-cli version {required} or higher required, found {found}")


class AuthenticationError(CERNSSOError):
    """Raised when authentication fails."""

    def __init__(self, message: str, stderr: Optional[str] = None):
        self.stderr = stderr
        super().__init__(message)


class CookieError(CERNSSOError):
    """Raised when cookie operations fail."""

    pass
