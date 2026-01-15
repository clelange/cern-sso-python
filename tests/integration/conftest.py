"""Pytest fixtures for integration tests."""

import base64
import os
import subprocess
import tempfile

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (require CLI and secrets)"
    )


@pytest.fixture(scope="session")
def has_secrets():
    """Check if required secrets are available."""
    return all(
        [
            os.environ.get("KRB_USERNAME"),
            os.environ.get("KRB_PASSWORD"),
        ]
    )


@pytest.fixture(scope="session")
def skip_if_no_secrets(has_secrets):
    """Skip test if secrets are not available."""
    if not has_secrets:
        pytest.skip("Integration test secrets not available (KRB_USERNAME, KRB_PASSWORD)")


@pytest.fixture(scope="session")
def krb_username():
    """Get Kerberos username from environment."""
    return os.environ.get("KRB_USERNAME", "")


@pytest.fixture(scope="session")
def has_keytab():
    """Check if keytab is available."""
    keytab_env = os.environ.get("KRB_KEYTAB")
    return keytab_env is not None and len(keytab_env) > 0


@pytest.fixture(scope="session")
def skip_if_no_keytab(has_keytab):
    """Skip test if keytab is not available."""
    if not has_keytab:
        pytest.skip("Keytab not available (KRB_KEYTAB)")


@pytest.fixture(scope="function")
def keytab_file(has_keytab, skip_if_no_keytab):
    """Create temporary keytab file from KRB_KEYTAB environment variable."""
    keytab_env = os.environ.get("KRB_KEYTAB", "")

    # Check if it's a base64-encoded string (common in GitHub Actions)
    try:
        # Try to decode as base64
        keytab_bytes = base64.b64decode(keytab_env)
    except Exception:
        # Not base64, treat as file path
        keytab_bytes = keytab_env.encode()

    # Create temporary keytab file
    fd, keytab_path = tempfile.mkstemp(suffix=".keytab")
    try:
        os.write(fd, keytab_bytes)
        os.close(fd)
        yield keytab_path
    finally:
        # Cleanup
        try:
            os.unlink(keytab_path)
        except OSError:
            pass


@pytest.fixture(scope="session")
def kinit_from_password(krb_username, skip_if_no_secrets):
    """Initialize Kerberos ticket from password."""
    password = os.environ.get("KRB_PASSWORD", "")
    if not password:
        pytest.skip("KRB_PASSWORD not available")

    principal = f"{krb_username}@CERN.CH"

    # Initialize Kerberos ticket using password
    proc = subprocess.Popen(
        ["kinit", principal],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate(input=password + "\n")

    if proc.returncode != 0:
        pytest.fail(f"kinit failed: {stderr}")

    # Verify ticket
    result = subprocess.run(["klist"], capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(f"klist failed: {result.stderr}")

    yield

    # Cleanup: destroy ticket
    subprocess.run(["kdestroy"], capture_output=True)
