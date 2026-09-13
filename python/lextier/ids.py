"""Entity IDs — parity with src/core/ids.ts. Nanoid alphabet
`_-0-9a-zA-Z` (64 symbols), 21 random symbols, locked prefix."""

import re
import secrets

from .errors import err

ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

PREFIX = {
    "tenant": "ltt_", "gateway": "ltg_", "principal": "ltp_", "action": "lta_",
    "card": "ltc_", "decision": "ltd_", "event": "lte_", "key": "ltk_",
    "outbox": "lto_", "reaudit": "ltr_",
}

_ID_RES = {k: re.compile(f"^{p}[A-Za-z0-9_-]{{21}}$") for k, p in PREFIX.items()}


def is_id(kind: str, v) -> bool:
    return isinstance(v, str) and bool(_ID_RES[kind].match(v))


def csprng_id_gen():
    def gen(kind: str) -> str:
        return PREFIX[kind] + "".join(ALPHABET[b & 63] for b in secrets.token_bytes(21))
    return gen


def fixture_id_gen():
    counters: dict[str, int] = {}

    def gen(kind: str) -> str:
        counters[kind] = counters.get(kind, 0) + 1
        return PREFIX[kind] + str(counters[kind]).zfill(21)
    return gen


def require_id(kind: str, v, code="SCHEMA_INVALID") -> str:
    if not is_id(kind, v):
        raise err(code)
    return v
