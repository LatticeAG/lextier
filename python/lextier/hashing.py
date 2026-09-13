"""SHA-256 hashing with domain separation — parity with src/core/hash.ts."""

import hashlib
import re

from .canonical import canonical_bytes

DOMAIN = {
    "ACTION": "LEXTIER-ACTION/1",
    "AUDIT": "LEXTIER-AUDIT/1",
    "SIGN": "LEXTIER-SIGN/1",
    "HEAD": "LEXTIER-HEAD/1",
    "ROTATE": "LEXTIER-ROTATE/1",
}

ZERO_HASH = "0" * 64


class RE:
    hash = re.compile(r"^[0-9a-f]{64}$")
    signature = re.compile(r"^[0-9a-f]{128}$")
    public_key = re.compile(r"^[0-9a-f]{64}$")
    reason = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
    rule_id = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
    tool_name = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    idempotency_key = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
    version = re.compile(r"^[\x20-\x7e]{1,128}$")
    principal_id = re.compile(r"^ltp_[A-Za-z0-9_-]{21}$")


def sha256_hex(b) -> str:
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def hash_json(x) -> str:
    return sha256_hex(canonical_bytes(x))


def hash_domain(domain: str, payload) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    h = hashlib.sha256()
    h.update(domain.encode("utf-8"))
    h.update(b"\x00")
    h.update(payload)
    return h.hexdigest()


def hash_domain_json(domain: str, x) -> str:
    return hash_domain(domain, canonical_bytes(x))
