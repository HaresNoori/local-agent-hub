"""Authentication and redaction helpers for the loopback broker."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str


def authenticate(token: str | None) -> Principal | None:
    """Resolve an opaque bearer token from environment variables.

    Coordinator token is HUB_COORDINATOR_TOKEN. Worker tokens are a
    comma-separated HUB_WORKER_TOKENS list. Values are never logged or stored.
    """
    if not token:
        return None
    coordinator = os.environ.get("HUB_COORDINATOR_TOKEN", "")
    if coordinator and hmac.compare_digest(token, coordinator):
        return Principal("coordinator", "coordinator")
    relay = os.environ.get("HUB_RELAY_TOKEN", "")
    if os.environ.get("HUB_ENABLE_RELAY", "0") == "1" and relay and hmac.compare_digest(token, relay):
        return Principal("relay", "relay")
    workers = [v.strip() for v in os.environ.get("HUB_WORKER_TOKENS", "").split(",") if v.strip()]
    for index, candidate in enumerate(workers):
        if hmac.compare_digest(token, candidate):
            return Principal(f"worker-{index + 1}", "worker")
    # Stable opaque identity for rate limiting; never expose token material.
    return None


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


_SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\b(?:sk|ghp|gho|github_pat|xox[baprs])-[A-Za-z0-9_-]{12,}\b", re.I),
)


def redact(value):
    """Recursively redact common credentials from persisted task data."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if re.search(r"(?i)(token|secret|password|api.?key|credential)", str(key)):
                out[str(key)] = "[REDACTED]"
            else:
                out[str(key)] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        known_tokens = [os.environ.get(name, "") for name in (
            "HUB_COORDINATOR_TOKEN", "HUB_RELAY_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "AGENT_HUB_GITHUB_TOKEN")]
        known_tokens.extend(v.strip() for v in os.environ.get("HUB_WORKER_TOKENS", "").split(","))
        for token in sorted((item for item in known_tokens if item), key=len, reverse=True):
            value = value.replace(token, "[REDACTED]")
        for pattern in _SECRET_PATTERNS:
            value = pattern.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", value)
        return value
    return value
