"""Tests for cookie utilities."""

from pathlib import Path

import pytest

from cern_sso.cookies import load_cookies
from cern_sso.exceptions import CookieError


class TestLoadCookies:
    """Tests for load_cookies function."""

    def test_load_valid_cookies(self, tmp_path: Path):
        """Test loading valid Netscape cookie file."""
        cookie_file = tmp_path / "cookies.txt"
        # Netscape format: domain, domain_specified, path, secure, expires, name, value
        cookie_file.write_text(
            "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsession_id\tabc123\n"
        )

        jar = load_cookies(cookie_file)
        assert len(jar) >= 1

    def test_load_empty_file(self, tmp_path: Path):
        """Test loading empty cookie file."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text("# Netscape HTTP Cookie File\n")

        jar = load_cookies(cookie_file)
        assert len(jar) == 0

    def test_load_missing_file(self, tmp_path: Path):
        """Test loading non-existent file raises error."""
        with pytest.raises(CookieError, match="not found"):
            load_cookies(tmp_path / "nonexistent.txt")

    def test_load_with_string_path(self, tmp_path: Path):
        """Test loading with string path."""
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text("# Netscape HTTP Cookie File\n")

        jar = load_cookies(str(cookie_file))
        assert len(jar) == 0


class TestToRequestsJar:
    """Tests for to_requests_jar function."""

    def test_to_requests_jar_missing_requests(self, tmp_path: Path):
        """Test error when requests not installed."""
        from cern_sso.cookies import to_requests_jar

        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text("# Netscape HTTP Cookie File\n")
        jar = load_cookies(cookie_file)

        # Mock requests not being installed
        import sys

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "requests", None)
            mp.setitem(sys.modules, "requests.cookies", None)
            with pytest.raises(ImportError, match="'requests' package is required"):
                to_requests_jar(jar)
