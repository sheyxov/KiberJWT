from __future__ import annotations

import math
import re
import time
from pathlib import Path
from typing import Any, Optional

import jwt

MAX_LIFETIME_SECONDS = 24 * 60 * 60
HMAC_ALGORITHMS = {"HS256", "HS384", "HS512"}
ASYMMETRIC_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
}
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"email|(?:internal|employee|customer|account|user)[_-]?id)",
    re.IGNORECASE,
)


def _finding(severity: str, check: str, message: str) -> dict[str, str]:
    return {"severity": severity, "check": check, "message": message}


def _numeric_date(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        converted = float(value)
    except OverflowError:
        return None
    return converted if math.isfinite(converted) else None


def _sensitive_paths(value: Any, path: str = "$") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if SENSITIVE_KEY_PATTERN.search(str(key)):
                paths.append(child_path)
            paths.extend(_sensitive_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_sensitive_paths(child, f"{path}[{index}]"))
    elif isinstance(value, str) and EMAIL_PATTERN.search(value):
        paths.append(path)
    return paths


def analyze_token(token: str) -> dict[str, Any]:
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_iat": False,
            "verify_nbf": False,
            "verify_aud": False,
            "verify_iss": False,
        },
    )
    findings: list[dict[str, str]] = []
    algorithm = header.get("alg")

    if not isinstance(algorithm, str) or not algorithm:
        findings.append(_finding("CRITICAL", "Algorithm", "The token has no valid alg header."))
    elif algorithm.lower() == "none":
        findings.append(
            _finding("CRITICAL", "Algorithm", "The token uses alg=none and has no signature.")
        )
    elif algorithm in HMAC_ALGORITHMS:
        findings.append(
            _finding(
                "WARN",
                "Algorithm",
                f"{algorithm} uses a shared secret; protect it and use a high-entropy key.",
            )
        )
    elif algorithm in ASYMMETRIC_ALGORITHMS:
        findings.append(_finding("SAFE", "Algorithm", f"Token declares {algorithm}."))
    else:
        findings.append(
            _finding("CRITICAL", "Algorithm", f"Unsupported signing algorithm: {algorithm}.")
        )

    now = time.time()
    expiration = _numeric_date(payload.get("exp"))
    if "exp" not in payload:
        findings.append(_finding("WARN", "Expiration", "No exp claim; the token does not expire."))
    elif expiration is None:
        findings.append(_finding("CRITICAL", "Expiration", "The exp claim is not a numeric date."))
    elif expiration <= now:
        findings.append(_finding("CRITICAL", "Expiration", "The token has expired."))
    else:
        findings.append(_finding("SAFE", "Expiration", "The token is currently unexpired."))

    issued_at = _numeric_date(payload.get("iat"))
    if "iat" not in payload:
        findings.append(_finding("WARN", "Issued-at", "No iat claim is present."))
    elif issued_at is None:
        findings.append(_finding("CRITICAL", "Issued-at", "The iat claim is not a numeric date."))
    elif issued_at > now:
        findings.append(_finding("WARN", "Issued-at", "The token's iat claim is in the future."))
    else:
        findings.append(_finding("SAFE", "Issued-at", "The iat claim is not in the future."))

    if expiration is not None and issued_at is not None:
        lifetime = expiration - issued_at
        if lifetime > MAX_LIFETIME_SECONDS:
            findings.append(
                _finding(
                    "WARN",
                    "Lifetime",
                    f"Token lifetime is {lifetime / 86400:.1f} days; the audit threshold is 1 day.",
                )
            )
        elif lifetime <= 0:
            findings.append(
                _finding("CRITICAL", "Lifetime", "exp must be later than iat.")
            )
        else:
            findings.append(_finding("SAFE", "Lifetime", "Token lifetime is at most 1 day."))

    sensitive = sorted(set(_sensitive_paths(payload)))
    if sensitive:
        findings.append(
            _finding(
                "WARN",
                "Sensitive data",
                "Potentially sensitive claims found at: " + ", ".join(sensitive),
            )
        )
    else:
        findings.append(_finding("SAFE", "Sensitive data", "No common sensitive claims detected."))

    return {
        "header": header,
        "payload": payload,
        "signature": {"verified": False, "status": "not_checked"},
        "findings": findings
        + [
            _finding(
                "WARN",
                "Signature",
                "Signature not checked; provide --secret or --public-key to verify integrity.",
            )
        ],
    }


def verify_signature(
    token: str,
    header: dict[str, Any],
    secret: Optional[str],
    public_key: Optional[Path],
) -> dict[str, Any]:
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm.lower() == "none":
        message = "Cannot verify a token without a supported signing algorithm."
        return {
            "verified": False,
            "status": "failed",
            "finding": _finding("CRITICAL", "Signature", message),
        }

    if secret is not None:
        if algorithm not in HMAC_ALGORITHMS:
            message = "A shared secret can only verify HS256, HS384, or HS512 tokens."
            return {
                "verified": False,
                "status": "failed",
                "finding": _finding("CRITICAL", "Signature", message),
            }
        key: str | bytes = secret
    else:
        if public_key is None:
            message = "No verification key was provided."
            return {
                "verified": False,
                "status": "failed",
                "finding": _finding("CRITICAL", "Signature", message),
            }
        if algorithm not in ASYMMETRIC_ALGORITHMS:
            message = "A public key can only verify a supported asymmetric algorithm."
            return {
                "verified": False,
                "status": "failed",
                "finding": _finding("CRITICAL", "Signature", message),
            }
        try:
            key = public_key.read_bytes()
        except OSError as error:
            message = f"Could not read public key: {error}"
            return {
                "verified": False,
                "status": "failed",
                "finding": _finding("CRITICAL", "Signature", message),
            }

    try:
        jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            options={
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except (jwt.PyJWTError, ValueError, TypeError) as error:
        message = f"Signature verification failed: {error}"
        return {
            "verified": False,
            "status": "failed",
            "finding": _finding("CRITICAL", "Signature", message),
        }
    return {
        "verified": True,
        "status": "verified",
        "finding": _finding("SAFE", "Signature", "Signature verified successfully."),
    }
