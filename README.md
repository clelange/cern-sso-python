# cern-sso-python

Python wrapper for [cern-sso-cli](https://github.com/clelange/cern-sso-cli) - CERN SSO authentication.

## Installation

1. **Install the CLI** (v0.21.0+): See [cern-sso-cli installation instructions](https://github.com/clelange/cern-sso-cli#installation)

2. **Install the Python package**:
   ```bash
   pip install cern-sso-python
   ```

## Quick Start

```python
from cern_sso import get_cookies, get_token, device_flow

# Get cookies for a URL (requires Kerberos ticket or will prompt)
jar = get_cookies("https://gitlab.cern.ch")

# With 2FA OTP
jar = get_cookies("https://gitlab.cern.ch", otp="123456")

# Get an OAuth2 access token
token = get_token(client_id="my-app", redirect_uri="https://my-app/callback")

# Device flow for headless servers
token = device_flow(client_id="my-app")
```

## Usage

### Cookies

```python
from cern_sso import get_cookies, load_cookies

# Authenticate and get cookies
jar = get_cookies("https://gitlab.cern.ch", otp="123456")

# Use with urllib
import urllib.request
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar)
)
response = opener.open("https://gitlab.cern.ch/api/v4/user")

# Save cookies to file
jar = get_cookies("https://gitlab.cern.ch", file="cookies.txt")

# Load existing cookies
jar = load_cookies("cookies.txt")
```

### With requests

```python
from cern_sso import get_cookies, to_requests_jar
import requests

jar = get_cookies("https://gitlab.cern.ch")
req_jar = to_requests_jar(jar)  # Requires: pip install requests
response = requests.get("https://gitlab.cern.ch/api/v4/user", cookies=req_jar)
```

### OAuth2 Tokens

```python
from cern_sso import get_token

token = get_token(client_id="my-app", redirect_uri="https://my-app/callback")

# Access token properties
print(token.access_token)
print(token.token_type)      # "Bearer"
print(token.expires_at)      # datetime when token expires
print(token.is_expired)      # bool

# Dict access (oauthlib compatible)
print(token["access_token"])

# Use with requests-oauthlib
from requests_oauthlib import OAuth2Session
session = OAuth2Session(token=token)
```

### Device Flow

For headless servers without Kerberos:

```python
from cern_sso import device_flow

token = device_flow(client_id="my-app")
# CLI will print: Go to https://auth.cern.ch/device and enter code: XXXX-YYYY
# After authenticating in browser, token is returned

print(token.access_token)
print(token.refresh_token)
```

### Advanced: Custom Client

```python
from cern_sso import CERNSSOClient

client = CERNSSOClient(
    cli_path="/custom/path/cern-sso-cli",
    quiet=False,  # Show CLI output
)
jar = client.get_cookies("https://gitlab.cern.ch")
```

### 2FA Options

```python
from cern_sso import get_cookies

# Force OTP method (even if WebAuthn is default)
jar = get_cookies("https://gitlab.cern.ch", use_otp=True)

# Force WebAuthn with PIN
jar = get_cookies("https://gitlab.cern.ch", use_webauthn=True, webauthn_pin="1234")

# Specify user and OTP together
jar = get_cookies("https://gitlab.cern.ch", user="alice", otp="123456")

# Use 1Password CLI to get OTP
jar = get_cookies("https://gitlab.cern.ch", otp_command="op item get CERN --otp")
```

| Parameter | Description |
|-----------|-------------|
| `user` | Kerberos username |
| `otp` | 6-digit OTP code |
| `otp_command` | Command to fetch OTP |
| `otp_retries` | Max retry attempts |
| `use_otp` | Force OTP method |
| `use_webauthn` | Force WebAuthn method |
| `webauthn_pin` | FIDO2 key PIN |
| `webauthn_device` | Path to FIDO2 device |

## API Reference

### `get_cookies(url, **kwargs) -> MozillaCookieJar`

Authenticate and return session cookies.

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | `str` | Target URL to authenticate against |
| `file` | `str \| Path` | Save cookies to file (optional) |
| `user` | `str` | Kerberos username |
| `otp` | `str` | 6-digit OTP code |
| `otp_command` | `str` | Command to fetch OTP |
| `use_otp` | `bool` | Force OTP method |
| `use_webauthn` | `bool` | Force WebAuthn (security key) method |
| `webauthn_pin` | `str` | FIDO2 security key PIN |
| `force` | `bool` | Force re-authentication |
| `insecure` | `bool` | Skip certificate validation |

### `get_token(client_id, redirect_uri, **kwargs) -> TokenResult`

Get OAuth2 access token via Authorization Code flow. Accepts same authentication parameters as `get_cookies`.

### `device_flow(client_id, **kwargs) -> TokenResult`

Get OAuth2 tokens via Device Authorization Grant (for headless environments).

### `CERNSSOClient(cli_path=None, quiet=True)`

Low-level client for direct CLI invocation.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cli_path` | `str` | Path to cern-sso-cli binary (auto-detect if None) |
| `quiet` | `bool` | Suppress CLI progress output (default: True) |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `CERNSSOError` | Base exception |
| `CLINotFoundError` | cern-sso-cli not found in PATH |
| `CLIVersionError` | CLI version too old (requires ≥0.21.0) |
| `AuthenticationError` | Authentication failed |
| `CookieError` | Cookie file operations failed |

## Requirements

- Python 3.9+
- [cern-sso-cli](https://github.com/clelange/cern-sso-cli) v0.21.0 or later

## License

GPL-3.0 - see [LICENSE](LICENSE)
