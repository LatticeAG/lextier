"""Audit protocol primitives (spec §7) — parity with src/core/audit.ts:
event bodies, hash-chained signing, signed heads, key rotation, offline
chain verification. Ed25519 via `cryptography` (RFC 8032 deterministic)."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.exceptions import InvalidSignature

from .canonical import canonical_bytes
from .hashing import DOMAIN, RE, ZERO_HASH, hash_domain, sha256_hex
from .ids import is_id
from .errors import err

EVENT_TYPES = [
    "POLICY_ACTIVATED", "ACTION_CREATED", "ACTION_DENIED", "REVIEW_VIEWED",
    "DECISION_RECORDED", "ACTION_EXPIRED", "DRIFT_DETECTED", "ACTION_CANCELED",
    "DISPATCH_STARTED", "DISPATCH_SUCCEEDED", "DISPATCH_FAILED", "DISPATCH_UNKNOWN",
    "DISPATCH_RECONCILED", "RECONCILE_OBSERVED", "REAUDIT_OPENED", "REAUDIT_CLOSED",
    "REAUDIT_CANCELED", "KEY_ROTATED", "GATEWAY_PAUSED", "GATEWAY_RESUMED",
]

TERMINAL_STATES = {"SUCCEEDED", "FAILED", "DENIED", "REJECTED",
                   "EXPIRED", "STALE", "CANCELED"}

# Legal state transitions for full-history verification (facts.previous_state -> state)
LEGAL = {
    "null": {"PENDING", "DENIED"},
    "PENDING": {"STOPPED", "READY", "REJECTED", "EXPIRED", "CANCELED", "DENIED", "STALE", "PENDING"},
    "STOPPED": {"PENDING", "READY", "REJECTED", "EXPIRED", "CANCELED", "DENIED", "STALE", "STOPPED"},
    "READY": {"DISPATCHING", "EXPIRED", "CANCELED", "DENIED", "STALE"},
    "DISPATCHING": {"SUCCEEDED", "FAILED", "UNKNOWN", "EXPIRED"},
    "UNKNOWN": {"SUCCEEDED", "FAILED"},
}


def event_hash(body: dict) -> str:
    return hash_domain(DOMAIN["AUDIT"], canonical_bytes(body))


def sign_message(entry_hash: str) -> bytes:
    return DOMAIN["SIGN"].encode() + b"\x00" + bytes.fromhex(entry_hash)


def _head_message(body: dict) -> bytes:
    return DOMAIN["HEAD"].encode() + b"\x00" + canonical_bytes(body)


def _rotation_message(r: dict) -> bytes:
    j = {k: r[k] for k in ("old_key_id", "new_key_id", "new_public_key", "first_seq")}
    return DOMAIN["ROTATE"].encode() + b"\x00" + canonical_bytes(j)


def _priv(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_from_seed(seed: bytes) -> bytes:
    return _priv(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _pub(public_key_hex: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))


def ed_sign(seed: bytes, message: bytes) -> bytes:
    return _priv(seed).sign(message)


def ed_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_entry(seed: bytes, entry_hash_hex: str) -> str:
    return ed_sign(seed, sign_message(entry_hash_hex)).hex()


def sign_head(seed: bytes, body: dict) -> str:
    return ed_sign(seed, _head_message(body)).hex()


def sign_rotation(seed: bytes, r: dict) -> str:
    return ed_sign(seed, _rotation_message(r)).hex()


def verify_entry_sig(entry_hash_hex: str, signature_hex: str, public_key_hex: str) -> bool:
    try:
        return ed_verify(bytes.fromhex(public_key_hex), sign_message(entry_hash_hex), bytes.fromhex(signature_hex))
    except ValueError:
        return False


def verify_head_sig(body: dict, signature_hex: str, public_key_hex: str) -> bool:
    try:
        return ed_verify(bytes.fromhex(public_key_hex), _head_message(body), bytes.fromhex(signature_hex))
    except ValueError:
        return False


def verify_rotation_sig(r: dict, sig_hex: str, public_key_hex: str) -> bool:
    try:
        return ed_verify(bytes.fromhex(public_key_hex), _rotation_message(r), bytes.fromhex(sig_hex))
    except ValueError:
        return False


def _key_for_seq(keys, seq):
    for k in keys:
        if seq >= k["first_seq"] and (k["last_seq"] is None or seq <= k["last_seq"]):
            return k
    return None


_ENTRY_KEYS = {"action_id", "actor", "event_id", "facts", "gateway",
               "prev_hash", "seq", "tenant", "time_ms", "type", "v"}


def _is_entry_shape(e) -> bool:
    if not isinstance(e, dict):
        return False
    if set(e.keys()) != {"body", "hash", "key_id", "signature"}:
        return False
    if not isinstance(e["hash"], str) or not RE.hash.match(e["hash"]):
        return False
    if not isinstance(e["key_id"], str) or not is_id("key", e["key_id"]):
        return False
    if not isinstance(e["signature"], str) or not RE.signature.match(e["signature"]):
        return False
    b = e["body"]
    return isinstance(b, dict) and set(b.keys()) == _ENTRY_KEYS


def verify_chain(entries, head, keys, anchor=None, tenant=None, gateway=None,
                 check_transitions=False, evidence=None):
    """Verify an exported audit chain. `entries` must be contiguous starting at
    anchor.seq + 1 (or seq 1 for a full export with no anchor).
    `evidence`: optional callable hash -> body for KEY_ROTATED trust extension.
    Returns {"valid": bool, "code": str, "extended": [intervals]}."""
    def inv(code):
        return {"valid": False, "code": code}

    hb = head.get("body") if isinstance(head, dict) else None
    if not isinstance(hb, dict):
        return inv("HASH_MISMATCH")
    if set(hb.keys()) != {"gateway", "hash", "key_id", "seq", "tenant", "v"}:
        return inv("HASH_MISMATCH")
    if hb["v"] != 1:
        return inv("UNSUPPORTED_VERSION")

    first_seq = entries[0]["body"]["seq"] if entries else (anchor["seq"] + 1 if anchor else 1)
    if entries and first_seq > 1:
        if anchor is None:
            return inv("ANCHOR_REQUIRED")
        if anchor["seq"] != first_seq - 1 or anchor["hash"] != entries[0]["body"]["prev_hash"]:
            return inv("HASH_MISMATCH")
    if not entries and anchor is None and hb["seq"] != 0 and hb["seq"] > 0:
        return inv("ANCHOR_REQUIRED")

    keys = [dict(k) for k in keys]
    extended = []
    missing_rotation = False

    prev_hash = anchor["hash"] if anchor else ZERO_HASH
    prev_time = 0
    action_state = {}
    complete_history = (anchor is None or anchor["seq"] == 0) and first_seq == 1

    for i, e in enumerate(entries):
        if not _is_entry_shape(e):
            return inv("HASH_MISMATCH")
        b = e["body"]
        if tenant is not None and b["tenant"] != tenant:
            return inv("HASH_MISMATCH")
        if gateway is not None and b["gateway"] != gateway:
            return inv("HASH_MISMATCH")
        if hb["tenant"] != b["tenant"] or hb["gateway"] != b["gateway"]:
            return inv("HASH_MISMATCH")
        if event_hash(b) != e["hash"]:
            return inv("HASH_MISMATCH")
        if b["prev_hash"] != prev_hash:
            return inv("HASH_MISMATCH")
        expected_seq = (anchor["seq"] if anchor else 0) + i + 1
        if b["seq"] != expected_seq:
            return inv("HASH_MISMATCH")
        if b["time_ms"] < prev_time:
            return inv("HASH_MISMATCH")
        prev_time = b["time_ms"]

        ki = _key_for_seq(keys, b["seq"])
        if ki is None or ki["key_id"] != e["key_id"]:
            return inv("INCOMPLETE_EVIDENCE" if missing_rotation else "HASH_MISMATCH")
        if not verify_entry_sig(e["hash"], e["signature"], ki["public_key"]):
            return inv("HASH_MISMATCH")

        if b["type"] == "KEY_ROTATED" and b["facts"].get("detail_hash"):
            rot = evidence(b["facts"]["detail_hash"]) if evidence else None
            if rot is None:
                missing_rotation = True
            else:
                if sha256_hex(canonical_bytes(rot)) != b["facts"]["detail_hash"]:
                    return inv("HASH_MISMATCH")
                rkeys = set(rot.keys())
                if (rkeys != {"first_seq", "new_key_id", "new_key_proof", "new_public_key", "old_key_id"}
                        or rot["old_key_id"] != e["key_id"]
                        or not is_id("key", rot["new_key_id"])
                        or not isinstance(rot["new_public_key"], str)
                        or not RE.public_key.match(rot["new_public_key"])
                        or rot["first_seq"] != b["seq"] + 1
                        or not isinstance(rot["new_key_proof"], str)
                        or not verify_rotation_sig(
                            {"old_key_id": rot["old_key_id"], "new_key_id": rot["new_key_id"],
                             "new_public_key": rot["new_public_key"], "first_seq": rot["first_seq"]},
                            rot["new_key_proof"], rot["new_public_key"])):
                    return inv("HASH_MISMATCH")
                old_i = _key_for_seq(keys, b["seq"])
                if old_i is None or old_i["key_id"] != e["key_id"]:
                    return inv("HASH_MISMATCH")
                old_i["last_seq"] = b["seq"]
                ni = {"key_id": rot["new_key_id"], "public_key": rot["new_public_key"],
                      "first_seq": rot["first_seq"], "last_seq": None}
                keys.append(ni)
                extended.append(ni)

        if check_transitions and complete_history and b["action_id"] and b["facts"].get("state"):
            prev = action_state.get(b["action_id"])
            prev_key = "null" if prev is None else prev
            if b["facts"].get("previous_state") != prev:
                return inv("HASH_MISMATCH")
            legal = LEGAL.get(prev_key)
            if legal is not None and b["facts"]["state"] not in legal:
                return inv("HASH_MISMATCH")
            action_state[b["action_id"]] = b["facts"]["state"]
        elif b["action_id"] and b["facts"].get("state"):
            action_state[b["action_id"]] = b["facts"]["state"]

        prev_hash = e["hash"]

    last_seq = entries[-1]["body"]["seq"] if entries else (anchor["seq"] if anchor else 0)
    if hb["seq"] != last_seq:
        return inv("HASH_MISMATCH")
    if entries and hb["hash"] != entries[-1]["hash"]:
        return inv("HASH_MISMATCH")

    hki = _key_for_seq(keys, hb["seq"])
    if hki is None or hki["key_id"] != hb["key_id"]:
        return inv("INCOMPLETE_EVIDENCE" if missing_rotation else "HASH_MISMATCH")
    if not verify_head_sig(hb, head["signature"], hki["public_key"]):
        return inv("HASH_MISMATCH")

    return {"valid": True, "code": "OK", "extended": extended}


def content_hash(b) -> str:
    return sha256_hex(b)
