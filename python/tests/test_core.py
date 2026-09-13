"""Python-core unit tests — edges not covered by the vector subset."""

import pytest

from lextier.audit import (event_hash, sign_entry, sign_head, sign_rotation,
                           verify_chain, public_key_from_seed)
from lextier.canonical import canonical_bytes, canonicalize
from lextier.errors import LexError
from lextier.hashing import ZERO_HASH
from lextier.ids import fixture_id_gen, is_id
from lextier.strictjson import parse_json_strict
from lextier.yamlparse import parse_yaml

SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PUB = public_key_from_seed(bytes.fromhex(SEED)).hex()
TENANT = "ltt_000000000000000000001"
GATEWAY = "ltg_000000000000000000001"
K1 = "ltk_000000000000000000001"
K2 = "ltk_000000000000000000002"
SEED2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
PUB2 = public_key_from_seed(bytes.fromhex(SEED2)).hex()


def _entry(seed, key_id, seq, prev, event_id, etype="ACTION_CREATED",
           facts_extra=None, action_id="lta_000000000000000000001", time_ms=1000 + 0):
    body = {
        "v": 1, "tenant": TENANT, "gateway": GATEWAY, "seq": seq,
        "event_id": event_id, "time_ms": 1000 * seq,
        "type": etype, "actor": "ltp_000000000000000000003", "action_id": action_id,
        "prev_hash": prev,
        "facts": {"action_hash": None, "policy_revision": 1, "previous_state": None,
                  "state": None, "reason": etype, "detail_hash": None,
                  "latency_ms": None, "verdict": None, **(facts_extra or {})},
    }
    h = event_hash(body)
    return {"body": body, "hash": h, "key_id": key_id,
            "signature": sign_entry(seed, h)}


def _head(seed, key_id, seq, h):
    hb = {"v": 1, "tenant": TENANT, "gateway": GATEWAY, "seq": seq, "hash": h, "key_id": key_id}
    return {"body": hb, "signature": sign_head(seed, hb)}


def test_ids():
    gen = fixture_id_gen()
    assert gen("action") == "lta_000000000000000000001"
    assert gen("action") == "lta_000000000000000000002"
    assert is_id("action", "lta_000000000000000000001")
    assert not is_id("action", "lta_1")
    assert not is_id("principal", "lta_000000000000000000001")


def test_strict_limits():
    with pytest.raises(LexError) as e:
        parse_json_strict('"' + "a" * 70000 + '"')
    assert e.value.code == "INVALID_JSON"
    with pytest.raises(LexError) as e:
        parse_json_strict("9007199254740993")
    assert e.value.code == "INVALID_JSON"


def test_canonical_utf16_sort():
    # 'z' (U+007A) sorts before U+0080 in UTF-16 order
    assert canonical_bytes({"\u0080": 1, "z": 2}) == b'{"z":2,"\xc2\x80":1}'


def test_yaml_multi_doc_rejected():
    with pytest.raises(LexError) as e:
        parse_yaml("a: 1\n---\nb: 2\n")
    assert e.value.code == "YAML_FEATURE_FORBIDDEN"


def test_chain_full_verify():
    e1 = _entry(bytes.fromhex(SEED), K1, 1, ZERO_HASH, "lte_000000000000000000001")
    e2 = _entry(bytes.fromhex(SEED), K1, 2, e1["hash"], "lte_000000000000000000002")
    head = _head(bytes.fromhex(SEED), K1, 2, e2["hash"])
    keys = [{"key_id": K1, "public_key": PUB, "first_seq": 1, "last_seq": None}]
    res = verify_chain([e1, e2], head, keys, tenant=TENANT, gateway=GATEWAY)
    assert res["valid"] is True


def test_chain_gap_needs_anchor():
    e1 = _entry(bytes.fromhex(SEED), K1, 1, ZERO_HASH, "lte_000000000000000000001")
    e2 = _entry(bytes.fromhex(SEED), K1, 2, e1["hash"], "lte_000000000000000000002")
    head = _head(bytes.fromhex(SEED), K1, 2, e2["hash"])
    keys = [{"key_id": K1, "public_key": PUB, "first_seq": 1, "last_seq": None}]
    res = verify_chain([e2], head, keys, tenant=TENANT, gateway=GATEWAY)
    assert res["valid"] is False and res["code"] == "ANCHOR_REQUIRED"
    res = verify_chain([e2], head, keys, anchor={"seq": 1, "hash": e1["hash"]},
                       tenant=TENANT, gateway=GATEWAY)
    assert res["valid"] is True


def test_chain_key_rotation_extends_trust():
    e1 = _entry(bytes.fromhex(SEED), K1, 1, ZERO_HASH, "lte_000000000000000000001")
    # rotation event signed by old key at seq 2; new key signs from seq 3
    rot_body = {"old_key_id": K1, "new_key_id": K2, "new_public_key": PUB2, "first_seq": 3}
    proof = sign_rotation(bytes.fromhex(SEED2), rot_body)
    rot = {**rot_body, "new_key_proof": proof}
    from lextier.canonical import canonical_bytes as cb
    from lextier.hashing import sha256_hex
    detail = sha256_hex(cb(rot))
    e2 = _entry(bytes.fromhex(SEED), K1, 2, e1["hash"], "lte_000000000000000000002",
                etype="KEY_ROTATED", facts_extra={"detail_hash": detail})
    e3 = _entry(bytes.fromhex(SEED2), K2, 3, e2["hash"], "lte_000000000000000000003")
    head = _head(bytes.fromhex(SEED2), K2, 3, e3["hash"])
    keys = [{"key_id": K1, "public_key": PUB, "first_seq": 1, "last_seq": None}]
    evidence = lambda h: rot if h == detail else None
    res = verify_chain([e1, e2, e3], head, keys, tenant=TENANT, gateway=GATEWAY,
                       evidence=evidence)
    assert res["valid"] is True and len(res["extended"]) == 1
    # without evidence the new-key entries are unverifiable
    res2 = verify_chain([e1, e2, e3], head, [{"key_id": K1, "public_key": PUB,
                                              "first_seq": 1, "last_seq": None}],
                        tenant=TENANT, gateway=GATEWAY)
    assert res2["valid"] is False
