# cern-sso-python

Python wrapper for [cern-sso-cli](https://github.com/clelange/cern-sso-cli) - CERN SSO authentication.

## Installation

```bash
pip install cern-sso-python
```

**Prerequisite**: You must have `cern-sso-cli` v0.21.0 or later installed and available in your PATH. Install from [cern-sso-cli releases](https://github.com/clelange/cern-sso-cli/releases).

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

## API Reference

### Functions

| Function | Description |
|----------|-------------|
| `get_cookies(url, ...)` | Authenticate and return cookies as `MozillaCookieJar` |
| `get_token(client_id, redirect_uri, ...)` | Get OAuth2 token via Authorization Code flow |
| `device_flow(client_id, ...)` | Get OAuth2 token via Device Authorization Grant |
| `load_cookies(path)` | Load cookies from Netscape-format file |
| `to_requests_jar(jar)` | Convert to requests-compatible cookie jar |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `CERNSSOError` | Base exception |
| `CLINotFoundError` | cern-sso-cli not found in PATH |
| `CLIVersionError` | CLI version too old |
| `AuthenticationError` | Authentication failed |
| `CookieError` | Cookie file operations failed |

## Requirements

- Python 3.9+
- [cern-sso-cli](https://github.com/clelange/cern-sso-cli) v0.21.0 or later

## License

GPL-3.0 - see [LICENSE](LICENSE)
