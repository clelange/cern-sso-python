"""CERN SSO client - subprocess wrapper for cern-sso-cli."""

import json
import shutil
import subprocess
import tempfile
from http.cookiejar import MozillaCookieJar
from pathlib import Path
from typing import Optional, Union

from .cookies import load_cookies
from .exceptions import AuthenticationError, CLINotFoundError, CLIVersionError
from .tokens import TokenResult

# Minimum CLI version required for JSON output
MIN_CLI_VERSION = "0.21.0"


class CERNSSOClient:
    """Client for CERN SSO authentication via cern-sso-cli.

    This class wraps the cern-sso-cli binary and provides a Pythonic interface
    for authentication operations.

    Example:
        >>> client = CERNSSOClient()
        >>> jar = client.get_cookies("https://gitlab.cern.ch")
        >>> token = client.get_token(client_id="my-app", redirect_uri="https://...")
    """

    def __init__(
        self,
        cli_path: Optional[str] = None,
        quiet: bool = True,
        verify_version: bool = True,
    ):
        """Initialize the CERN SSO client.

        Args:
            cli_path: Path to cern-sso-cli executable. If None, searches PATH.
            quiet: If True, suppress CLI output (pass --quiet flag).
            verify_version: If True, verify CLI version on first use.
        """
        self._cli_path = cli_path
        self._quiet = quiet
        self._verify_version = verify_version
        self._version_checked = False

    @property
    def cli_path(self) -> str:
        """Get the path to cern-sso-cli, finding it if necessary."""
        if self._cli_path is None:
            self._cli_path = shutil.which("cern-sso-cli")
            if self._cli_path is None:
                raise CLINotFoundError()
        return self._cli_path

    def _check_version(self) -> None:
        """Check CLI version meets minimum requirements."""
        if not self._verify_version or self._version_checked:
            return

        try:
            result = subprocess.run(
                [self.cli_path, "--version"],
                capture_output=True,
                text=True,
                check=True,
            )
            # Parse version from output like "cern-sso-cli version v0.21.0"
            version_str = result.stdout.strip().split()[-1]
            if version_str == "dev":
                # Development version, skip check
                self._version_checked = True
                return

            # Strip leading 'v' if present (e.g., v0.21.0 -> 0.21.0)
            version_str = version_str.lstrip("v")

            # Simple version comparison (assumes semver)
            version_parts = [int(x) for x in version_str.split(".")]
            min_parts = [int(x) for x in MIN_CLI_VERSION.split(".")]

            if version_parts < min_parts:
                raise CLIVersionError(MIN_CLI_VERSION, version_str)

            self._version_checked = True
        except subprocess.CalledProcessError as e:
            raise CLINotFoundError(f"Failed to get CLI version: {e.stderr}") from e
        except (ValueError, IndexError):
            # Can't parse version, assume it's fine
            self._version_checked = True

    def _run_cli(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run cern-sso-cli with the given arguments.

        Args:
            args: Command arguments (without the executable).
            check: If True, raise on non-zero exit.

        Returns:
            CompletedProcess with stdout/stderr.

        Raises:
            AuthenticationError: If the command fails.
            KeyboardInterrupt: Propagated after terminating child process.
        """
        self._check_version()

        cmd = [self.cli_path] + args
        if self._quiet:
            cmd.insert(1, "--quiet")

        import os
        import signal

        # Always capture stdout (for JSON output parsing)
        # Let stderr go to terminal so user sees prompts and errors
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=None,  # stderr goes to terminal
            text=True,
            start_new_session=True,  # Creates new process group
        )

        interrupted = False
        original_handler = signal.getsignal(signal.SIGINT)

        def sigint_handler(signum, frame):
            nonlocal interrupted
            interrupted = True
            # Terminate the entire process group immediately
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass

        # Install our handler
        signal.signal(signal.SIGINT, sigint_handler)

        try:
            stdout, _ = proc.communicate()
        finally:
            # Restore original handler
            signal.signal(signal.SIGINT, original_handler)

        if interrupted:
            # Clean up if needed
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
                proc.wait()
            raise KeyboardInterrupt()

        if check and proc.returncode != 0:
            raise AuthenticationError(
                f"Authentication failed (exit code {proc.returncode}). See error above.",
                stderr="",
            )

        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, "")

    def get_cookies(
        self,
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
            AuthenticationError: If authentication fails.

        Example:
            >>> jar = client.get_cookies("https://gitlab.cern.ch", otp="123456")
            >>> len(jar)
            5
        """
        # Use temp file if no path specified
        use_temp = file is None
        if use_temp:
            fd, file = tempfile.mkstemp(suffix=".txt", prefix="cern_sso_cookies_")
            import os
            os.close(fd)

        file = Path(file)

        args = ["cookie", "--url", url, "--file", str(file), "--auth-host", auth_host]

        if user:
            args.extend(["--user", user])
        if otp:
            args.extend(["--otp", otp])
        if otp_command:
            args.extend(["--otp-command", otp_command])
        if otp_retries is not None:
            args.extend(["--otp-retries", str(otp_retries)])
        if use_otp:
            args.append("--use-otp")
        if use_webauthn:
            args.append("--use-webauthn")
        if webauthn_pin:
            args.extend(["--webauthn-pin", webauthn_pin])
        if webauthn_device:
            args.extend(["--webauthn-device", webauthn_device])
        if force:
            args.append("--force")
        if insecure:
            args.append("--insecure")

        self._run_cli(args)

        # Load the cookies
        jar = load_cookies(file)

        # Clean up temp file after loading
        if use_temp:
            file.unlink(missing_ok=True)

        return jar

    def get_token(
        self,
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
            AuthenticationError: If authentication fails.

        Example:
            >>> token = client.get_token("my-app", "https://my-app/callback")
            >>> token.access_token
            'eyJ...'
        """
        args = [
            "token",
            "--client-id", client_id,
            "--url", redirect_uri,
            "--auth-host", auth_host,
            "--realm", realm,
            "--json",
        ]

        if user:
            args.extend(["--user", user])
        if otp:
            args.extend(["--otp", otp])
        if otp_command:
            args.extend(["--otp-command", otp_command])
        if otp_retries is not None:
            args.extend(["--otp-retries", str(otp_retries)])
        if use_otp:
            args.append("--use-otp")
        if use_webauthn:
            args.append("--use-webauthn")
        if webauthn_pin:
            args.extend(["--webauthn-pin", webauthn_pin])
        if webauthn_device:
            args.extend(["--webauthn-device", webauthn_device])
        if insecure:
            args.append("--insecure")

        result = self._run_cli(args)

        try:
            data = json.loads(result.stdout.strip())
        except json.JSONDecodeError as e:
            raise AuthenticationError(f"Failed to parse token response: {e}") from e

        return TokenResult(data)

    def device_flow(
        self,
        client_id: str,
        *,
        insecure: bool = False,
        auth_host: str = "auth.cern.ch",
        realm: str = "cern",
    ) -> TokenResult:
        """Get tokens via Device Authorization Grant flow.

        This flow is for headless environments where the user authenticates
        in a browser on another device.

        Args:
            client_id: OAuth client ID.
            insecure: Skip certificate validation.
            auth_host: Authentication hostname.
            realm: Authentication realm.

        Returns:
            TokenResult containing access and refresh tokens.

        Raises:
            AuthenticationError: If authentication fails.

        Example:
            >>> token = client.device_flow("my-app")
            # User authenticates in browser...
            >>> token.access_token
            'eyJ...'
        """
        args = [
            "device",
            "--client-id", client_id,
            "--auth-host", auth_host,
            "--realm", realm,
            "--json",
        ]

        if insecure:
            args.append("--insecure")

        # Don't use quiet mode for device flow - user needs to see the URL
        old_quiet = self._quiet
        self._quiet = False
        try:
            result = self._run_cli(args)
        finally:
            self._quiet = old_quiet

        try:
            data = json.loads(result.stdout.strip())
        except json.JSONDecodeError as e:
            raise AuthenticationError(f"Failed to parse token response: {e}") from e

        return TokenResult(data)


# Default client instance for convenience functions
_default_client: Optional[CERNSSOClient] = None


def _get_default_client() -> CERNSSOClient:
    """Get or create the default client instance."""
    global _default_client
    if _default_client is None:
        _default_client = CERNSSOClient()
    return _default_client
