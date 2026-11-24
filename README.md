# kiberjwt

`kiberjwt` is a lightweight Python CLI for decoding JWTs, checking common
security misconfigurations, optionally verifying signatures, and exporting an
audit report as JSON.

## Installation

Requires Python 3.10 or later.

```bash
python -m pip install -r requirements.txt
```

Run it from this directory with `python main.py`.

## Usage

Inspect a token without verifying its signature:

```bash
python main.py 'eyJhbGciOi...'
```

Verify an HMAC token with its shared secret:

```bash
python main.py 'eyJhbGciOi...' --secret 'your-high-entropy-secret'
```

Verify an RSA/ECDSA token with a PEM public key, and export the report:

```bash
python main.py 'eyJhbGciOi...' --public-key ./public.pem --export report.json
```

The terminal view shows the decoded header and payload side by side, followed
by color-coded audit findings. Unverified header and payload claims are
untrusted input; use `--secret` or `--public-key` when signature integrity
needs to be checked. Reports can contain token claims, so store exported JSON
securely.
