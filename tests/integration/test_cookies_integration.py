"""Integration tests for cookie retrieval with real CLI."""

import os

import pytest

from cern_sso import CERNSSOClient


@pytest.mark.integration
class TestGetCookiesIntegration:
    """Integration tests for get_cookies with real CLI."""

    def test_get_cookies_gitlab(self, kinit_from_password):
        """Test getting cookies for GitLab (no 2FA required for service account)."""
        client = CERNSSOClient(quiet=True)
        jar = client.get_cookies("https://gitlab.cern.ch")

        # Should have cookies
        assert len(jar) > 0

        # Should have session-related cookies
        cookie_names = [c.name for c in jar]
        # Check for common session cookie patterns
        assert any("session" in name.lower() or "shib" in name.lower() for name in cookie_names), (
            f"Expected session cookie, got: {cookie_names}"
        )

    def test_get_cookies_with_file(self, kinit_from_password, tmp_path):
        """Test saving cookies to a file."""
        cookie_file = tmp_path / "cookies.txt"

        client = CERNSSOClient(quiet=True)
        client.get_cookies(
            "https://gitlab.cern.ch",
            file=str(cookie_file),
        )

        # File should exist
        assert cookie_file.exists()

        # File should contain Netscape format header
        content = cookie_file.read_text()
        assert "# Netscape HTTP Cookie File" in content or "# HTTP Cookie File" in content

    def test_get_cookies_custom_client(self, kinit_from_password):
        """Test using CERNSSOClient directly."""
        client = CERNSSOClient(quiet=True)
        jar = client.get_cookies("https://gitlab.cern.ch")

        assert len(jar) > 0

    def test_get_cookies_with_keytab(self, keytab_file):
        """Test getting cookies using keytab."""
        client = CERNSSOClient(quiet=True)
        jar = client.get_cookies("https://gitlab.cern.ch", keytab=keytab_file)

        # Should have cookies
        assert len(jar) > 0

        # Should have session-related cookies
        cookie_names = [c.name for c in jar]
        assert any("session" in name.lower() or "shib" in name.lower() for name in cookie_names), (
            f"Expected session cookie, got: {cookie_names}"
        )

    def test_get_cookies_with_use_keytab(self, keytab_file):
        """Test getting cookies with use_keytab flag."""
        os.environ["KRB5_KTNAME"] = keytab_file

        try:
            client = CERNSSOClient(quiet=True)
            jar = client.get_cookies("https://gitlab.cern.ch", use_keytab=True)

            # Should have cookies
            assert len(jar) > 0
        finally:
            # Clean up environment variable
            os.environ.pop("KRB5_KTNAME", None)
