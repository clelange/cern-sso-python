"""Tests for CERNSSOClient."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cern_sso import CERNSSOClient
from cern_sso.exceptions import (
    CLINotFoundError,
    CLIVersionError,
)
from cern_sso.tokens import TokenResult


class TestCERNSSOClient:
    """Tests for CERNSSOClient class."""

    def test_cli_not_found(self):
        """Test CLINotFoundError when CLI is not in PATH."""
        with patch("shutil.which", return_value=None):
            client = CERNSSOClient()
            with pytest.raises(CLINotFoundError):
                _ = client.cli_path

    def test_cli_path_from_which(self):
        """Test CLI path is found via shutil.which."""
        with patch("shutil.which", return_value="/usr/local/bin/cern-sso-cli"):
            client = CERNSSOClient()
            assert client.cli_path == "/usr/local/bin/cern-sso-cli"

    def test_cli_path_explicit(self):
        """Test explicit CLI path is used."""
        client = CERNSSOClient(cli_path="/custom/path/cern-sso-cli")
        assert client.cli_path == "/custom/path/cern-sso-cli"

    def test_version_check_dev(self):
        """Test version check passes for dev version."""
        mock_result = MagicMock()
        mock_result.stdout = "cern-sso-cli version dev"

        with patch("subprocess.run", return_value=mock_result):
            client = CERNSSOClient(cli_path="/usr/bin/cern-sso-cli")
            client._check_version()
            assert client._version_checked

    def test_version_check_valid(self):
        """Test version check passes for valid version."""
        mock_result = MagicMock()
        mock_result.stdout = "cern-sso-cli version 1.2.3"

        with patch("subprocess.run", return_value=mock_result):
            client = CERNSSOClient(cli_path="/usr/bin/cern-sso-cli")
            client._check_version()
            assert client._version_checked

    def test_version_check_too_old(self):
        """Test version check fails for old version."""
        mock_result = MagicMock()
        mock_result.stdout = "cern-sso-cli version 0.1.0"

        with patch("subprocess.run", return_value=mock_result):
            client = CERNSSOClient(cli_path="/usr/bin/cern-sso-cli")
            with pytest.raises(CLIVersionError) as exc_info:
                client._check_version()
            assert exc_info.value.found == "0.1.0"


class TestGetCookies:
    """Tests for get_cookies function."""

    def test_get_cookies_basic(self, tmp_path: Path):
        """Test basic cookie retrieval."""
        cookie_file = tmp_path / "cookies.txt"
        # Create a minimal Netscape cookie file
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession\tabc123\n"
        )

        def mock_run_cli(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                jar = client.get_cookies("https://example.com", file=str(cookie_file))
                assert len(jar) == 1

    def test_get_cookies_with_otp(self, tmp_path: Path):
        """Test cookie retrieval with OTP."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\txyz789\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    otp="123456",
                    user="testuser",
                )

        # Check that OTP and user were passed
        cmd = commands_run[-1]
        assert "--otp" in cmd
        assert "123456" in cmd
        assert "--user" in cmd
        assert "testuser" in cmd

    def test_get_cookies_with_keytab(self, tmp_path: Path):
        """Test cookie retrieval with keytab."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\tkeytab123\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    keytab="/path/to/keytab",
                )

        cmd = commands_run[-1]
        assert "--keytab" in cmd
        assert "/path/to/keytab" in cmd

    def test_get_cookies_with_use_keytab(self, tmp_path: Path):
        """Test cookie retrieval with use_keytab flag."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\tkeytab123\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    use_keytab=True,
                )

        cmd = commands_run[-1]
        assert "--use-keytab" in cmd

    def test_get_cookies_with_use_password(self, tmp_path: Path):
        """Test cookie retrieval with use_password flag."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\tpass123\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    use_password=True,
                )

        cmd = commands_run[-1]
        assert "--use-password" in cmd

    def test_get_cookies_with_use_ccache(self, tmp_path: Path):
        """Test cookie retrieval with use_ccache flag."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\tccache123\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    use_ccache=True,
                )

        cmd = commands_run[-1]
        assert "--use-ccache" in cmd

    def test_get_cookies_with_krb5_config(self, tmp_path: Path):
        """Test cookie retrieval with krb5_config parameter."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\tkrb5123\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    krb5_config="/path/to/krb5.conf",
                )

        cmd = commands_run[-1]
        assert "--krb5-config" in cmd
        assert "/path/to/krb5.conf" in cmd


class TestGetToken:
    """Tests for get_token function."""

    def test_get_token_basic(self):
        """Test basic token retrieval."""
        token_response = {
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "Bearer",
        }

        def mock_run_cli(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, json.dumps(token_response), "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                token = client.get_token("my-client", "https://redirect")

                assert token.access_token == token_response["access_token"]
                assert token.token_type == "Bearer"
                assert token["access_token"] == token_response["access_token"]

    def test_get_token_with_expiry(self):
        """Test token with expiry time."""
        token_response = {
            "access_token": "eyJ...",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        def mock_run_cli(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, json.dumps(token_response), "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                token = client.get_token("my-client", "https://redirect")

                assert token.expires_in == 3600
                assert token.expires_at is not None
                assert not token.is_expired

    def test_get_token_with_keytab(self):
        """Test token retrieval with keytab parameter."""
        token_response = {
            "access_token": "eyJ...",
            "token_type": "Bearer",
        }

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps(token_response), "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_token("my-client", "https://redirect", keytab="/path/to/keytab")

        cmd = commands_run[-1]
        assert "--keytab" in cmd
        assert "/path/to/keytab" in cmd


class TestDeviceFlow:
    """Tests for device_flow function."""

    def test_device_flow_basic(self):
        """Test basic device flow."""
        token_response = {
            "access_token": "eyJ...",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "eyJref...",
        }

        def mock_run_cli(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, json.dumps(token_response), "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                token = client.device_flow("my-client")

                assert token.access_token == "eyJ..."
                assert token.refresh_token == "eyJref..."

    def test_device_flow_not_quiet(self):
        """Test device flow disables quiet mode."""
        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(
                args, 0, '{"access_token": "test", "token_type": "Bearer"}', ""
            )

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False, quiet=True)
                client.device_flow("my-client")

        # Device flow should not include --quiet
        cmd = commands_run[-1]
        assert "--quiet" not in cmd

    def test_device_flow_with_keytab(self):
        """Test device flow with keytab parameter."""
        token_response = {
            "access_token": "eyJ...",
            "token_type": "Bearer",
        }

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps(token_response), "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.device_flow("my-client", keytab="/path/to/keytab")

        cmd = commands_run[-1]
        assert "--keytab" in cmd
        assert "/path/to/keytab" in cmd


class TestTokenResult:
    """Tests for TokenResult class."""

    def test_dict_access(self):
        """Test dict-style access."""
        token = TokenResult({"access_token": "abc", "token_type": "Bearer"})
        assert token["access_token"] == "abc"
        assert token["token_type"] == "Bearer"

    def test_property_access(self):
        """Test property-style access."""
        token = TokenResult({"access_token": "abc", "token_type": "Bearer"})
        assert token.access_token == "abc"
        assert token.token_type == "Bearer"

    def test_optional_fields(self):
        """Test optional fields return None."""
        token = TokenResult({"access_token": "abc", "token_type": "Bearer"})
        assert token.refresh_token is None
        assert token.scope is None
        assert token.expires_in is None

    def test_expires_at_computed(self):
        """Test expires_at is computed from expires_in."""
        from datetime import datetime, timezone

        fetched_at = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = TokenResult(
            {"access_token": "abc", "token_type": "Bearer", "expires_in": 3600},
            fetched_at=fetched_at,
        )

        expected = datetime(2024, 1, 1, 13, 0, 0, tzinfo=timezone.utc)
        assert token.expires_at == expected


class TestNewParameters:
    """Tests for new CLI parameters."""

    def test_get_cookies_with_browser(self, tmp_path: Path):
        """Test cookie retrieval with browser flag."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\tbrowser123\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    browser=True,
                )

        cmd = commands_run[-1]
        assert "--browser" in cmd

    def test_get_cookies_with_webauthn_device_index(self, tmp_path: Path):
        """Test cookie retrieval with webauthn_device_index."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\tdevice123\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    webauthn_device_index=0,
                )

        cmd = commands_run[-1]
        assert "--webauthn-device-index" in cmd
        assert "0" in cmd

    def test_get_cookies_with_webauthn_timeout(self, tmp_path: Path):
        """Test cookie retrieval with webauthn_timeout."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n"
            ".gitlab.cern.ch\tTRUE\t/\tFALSE\t0\t_shibsession\ttimeout123\n"
        )

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_cookies(
                    "https://gitlab.cern.ch",
                    file=str(cookie_file),
                    webauthn_timeout=60,
                )

        cmd = commands_run[-1]
        assert "--webauthn-timeout" in cmd
        assert "60" in cmd

    def test_get_token_with_browser(self):
        """Test token retrieval with browser flag."""
        token_response = {
            "access_token": "eyJ...",
            "token_type": "Bearer",
        }

        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps(token_response), "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                client.get_token("my-client", "https://redirect", browser=True)

        cmd = commands_run[-1]
        assert "--browser" in cmd


class TestListWebAuthnDevices:
    """Tests for list_webauthn_devices function."""

    def test_list_devices_empty(self):
        """Test listing devices when none are found."""

        def mock_run_cli(args, **kwargs):
            # Simulate no devices output
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                devices = client.list_webauthn_devices()

        assert devices == []

    def test_list_devices_with_devices(self):
        """Test listing devices when devices are found."""
        output = "INDEX  PRODUCT  PATH\n0  YubiKey  /dev/usb1\n1  SoloKey  /dev/usb2\n"

        def mock_run_cli(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, output, "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                devices = client.list_webauthn_devices()

        assert len(devices) == 2
        assert devices[0].index == 0
        assert devices[0].product == "YubiKey"
        assert devices[0].path == "/dev/usb1"
        assert devices[1].index == 1
        assert devices[1].product == "SoloKey"


class TestCheckStatus:
    """Tests for check_status function."""

    def test_check_status_basic(self, tmp_path: Path):
        """Test basic status check."""
        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "[]", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                status = client.check_status("cookies.txt")

        cmd = commands_run[-1]
        assert "status" in cmd
        assert "--json" in cmd
        assert status.verified is False
        assert status.entries == []

    def test_check_status_with_url(self, tmp_path: Path):
        """Test status check with URL verification."""
        commands_run = []

        def mock_run_cli(args, **kwargs):
            commands_run.append(args)
            return subprocess.CompletedProcess(args, 0, "[]", "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False)
                status = client.check_status("cookies.txt", url="https://gitlab.cern.ch")

        cmd = commands_run[-1]
        assert "--url" in cmd
        assert "https://gitlab.cern.ch" in cmd
        assert status.verified is True


class TestModels:
    """Tests for new model classes."""

    def test_webauthn_device(self):
        """Test WebAuthnDevice dataclass."""
        from cern_sso.models import WebAuthnDevice

        device = WebAuthnDevice(index=0, product="YubiKey 5", path="/dev/usb1")
        assert device.index == 0
        assert device.product == "YubiKey 5"
        assert device.path == "/dev/usb1"

    def test_cookie_status_has_valid_cookies(self):
        """Test CookieStatus has_valid_cookies property."""
        from datetime import datetime, timezone

        from cern_sso.models import CookieStatus, CookieStatusEntry

        future = datetime.now(timezone.utc).replace(year=2099)
        entries = [
            CookieStatusEntry(domain=".example.com", name="session", expires=future, valid=True),
            CookieStatusEntry(domain=".example.com", name="old", expires=None, valid=False),
        ]
        status = CookieStatus(entries=entries, verified=False, verified_valid=False)

        assert status.has_valid_cookies is True
        assert status.all_valid is False

    def test_cookie_status_all_valid(self):
        """Test CookieStatus all_valid property."""
        from datetime import datetime, timezone

        from cern_sso.models import CookieStatus, CookieStatusEntry

        future = datetime.now(timezone.utc).replace(year=2099)
        entries = [
            CookieStatusEntry(domain=".example.com", name="session", expires=future, valid=True),
            CookieStatusEntry(domain=".example.com", name="other", expires=future, valid=True),
        ]
        status = CookieStatus(entries=entries, verified=False, verified_valid=False)

        assert status.has_valid_cookies is True
        assert status.all_valid is True
