# KiberJWT

`KiberJWT` is a lightweight Python CLI tool for decoding JSON Web Tokens (JWT), auditing common security misconfigurations, verifying cryptographic signatures, and exporting structured JSON audit reports.

![KiberJWT CLI Demo]<img width="2525" height="1174" alt="image" src="https://github.com/user-attachments/assets/c99f55fe-9c24-4073-b9fe-718c04c13a3a" />


## Features

- Side-by-side decoded **Header** and **Payload** inspection
- Automated security checks (`Algorithm`, `Expiration`, `Issued-at`, `Lifetime`, `Sensitive data`, `Signature`)
- Optional signature verification for symmetric (`--secret`) and asymmetric (`--public-key`) algorithms
- JSON report export (`--export`) for pentest documentation and CI/CD pipelines

## Installation

Requires **Python 3.10** or later. Setting up an isolated virtual environment (`venv`) is recommended:

```bash
git clone https://github.com/sheyxov/KiberJWT.git
cd KiberJWT

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
