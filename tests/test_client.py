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
            "# Netscape HTTP Cookie File\n"
            ".example.com\tTRUE\t/\tFALSE\t0\tsession\tabc123\n"
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
            return subprocess.CompletedProcess(args, 0, '{"access_token": "test", "token_type": "Bearer"}', "")

        with patch("cern_sso.CERNSSOClient._run_cli", side_effect=mock_run_cli):
            with patch("shutil.which", return_value="/usr/bin/cern-sso-cli"):
                client = CERNSSOClient(verify_version=False, quiet=True)
                client.device_flow("my-client")

        # Device flow should not include --quiet
        cmd = commands_run[-1]
        assert "--quiet" not in cmd


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
