"""Conformance vectors runnable against the pure Python core — the same
conformance/vectors.json the TS harness executes (spec §15: run all numbered
vectors in both runtimes where applicable). Engine-bound vectors (admit,
decide, dispatch, race, submit_twice, inbox_delivery, blast, effects,
get_action, reaudit_effects, and the audit_verify entry fixture produced by a
live gateway) are exercised by the TS harness."""

import json
import os

import pytest

from lextier.audit import (event_hash, sign_entry, sign_head, verify_chain,
                           public_key_from_seed)
from lextier.canonical import canonical_bytes
from lextier.errors import LexError
from lextier.hashing import DOMAIN, ZERO_HASH, hash_domain_json
from lextier.policy import compile_policy, evaluate, policy_hash
from lextier.registry import validate_call_args, REGISTRY_HASH
from lextier.stats import compute_reviewer_stats
from lextier.strictjson import parse_json_strict
from lextier.yamlparse import parse_yaml

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
VECTORS = json.load(open(os.path.join(ROOT, "conformance", "vectors.json")))

TENANT = "ltt_000000000000000000001"
GATEWAY = "ltg_000000000000000000001"
U = "ltp_000000000000000000001"
H = "ltp_000000000000000000002"
ADMIN = "ltp_000000000000000000003"
KEY_ID = "ltk_000000000000000000001"
SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
AUDIT_PUB = public_key_from_seed(bytes.fromhex(SEED)).hex()

P = {
    "v": 1, "revision": 1, "mode": "ENFORCE", "review_ttl_ms": 120000,
    "dispatch_ttl_ms": 5000, "reviewers": [H],
    "rules": [
        {"id": "read-public", "tool": "fs.read_text",
         "when": [{"path": "/path", "op": "path_under", "value": "/workspace/public"}], "tier": "allow"},
        {"id": "write-drafts", "tool": "fs.write_text",
         "when": [{"path": "/path", "op": "path_under", "value": "/workspace/drafts"}], "tier": "async_review"},
        {"id": "select-products", "tool": "db.select_rows",
         "when": [{"path": "/table", "op": "eq", "value": "products"}], "tier": "allow"},
    ],
    "hard_denies": [
        {"id": "private-files", "tool": "fs.read_text",
         "when": [{"path": "/path", "op": "path_under", "value": "/workspace/private"}]},
    ],
}

R_CALL = {"tool": "fs.write_text", "args": {"path": "/workspace/drafts/a.txt",
                                            "text": "hello", "expected_version": "7"}}
R_TARGET = {"resource": "file:/workspace/drafts/a.txt", "version": "7",
            "digest": "cba06b5736faf67e54b07b561eae94395e774c517a7d910a54369e1263ccfbd4"}
SHIELD_HASH = "6d061f948257926c3602ee1647d1203780c3d255ec5a9eb156b68fea27a371c6"

R_COMMIT = {
    "v": 1, "tenant": TENANT, "gateway": GATEWAY,
    "action_id": "lta_000000000000000000001", "actor": U, "auth_epoch": 1,
    "call": R_CALL, "registry_hash": REGISTRY_HASH, "policy_hash": policy_hash(P),
    "shield_hash": SHIELD_HASH, "blast_hash": None, "target": R_TARGET,
    "created_ms": 1000000, "expires_ms": 1120000,
}

PURE_OPS = {"evaluate", "validate_call", "parse_json", "compile_yaml", "canonical",
            "hash_action", "compare_action_hash", "signature_verify", "stats",
            "audit_genesis"}


def _policy_with_overrides(input_):
    import copy
    base = copy.deepcopy(P)
    if "mode" in input_:
        base["mode"] = input_["mode"]
    if "append_rule" in input_:
        base["rules"] = base["rules"] + [input_["append_rule"]]
    return compile_policy(base)


def _genesis_entry(input_):
    body = {
        "v": 1, "tenant": input_["tenant"], "gateway": input_["gateway"], "seq": 1,
        "event_id": input_["event_id"], "time_ms": input_["time_ms"],
        "type": "POLICY_ACTIVATED", "actor": input_["actor"], "action_id": None,
        "prev_hash": ZERO_HASH,
        "facts": {
            "action_hash": None, "policy_revision": 1, "previous_state": None,
            "state": None, "reason": "POLICY_ACTIVATED",
            "detail_hash": policy_hash(P), "latency_ms": None, "verdict": None,
        },
    }
    h = event_hash(body)
    sig = sign_entry(bytes.fromhex(SEED), h)
    hb = {"v": 1, "tenant": body["tenant"], "gateway": body["gateway"],
          "seq": 1, "hash": h, "key_id": KEY_ID}
    return {"body": body, "hash": h, "key_id": KEY_ID, "signature": sig}, \
        {"body": hb, "signature": sign_head(bytes.fromhex(SEED), hb)}


def run_op(input_):
    op = input_["op"]
    if op == "evaluate":
        pol = _policy_with_overrides(input_)
        try:
            return evaluate(pol, input_["call"])
        except LexError as e:
            return {"tier": None, "reason": e.code, "matched_rules": [],
                    "dispatchable": False, "scope_checked": False}
    if op == "validate_call":
        call = input_["call"]
        try:
            validate_call_args(call["tool"], call["args"])
            return {"valid": True, "code": "OK"}
        except LexError as e:
            return {"valid": False, "code": e.code}
    if op == "parse_json":
        try:
            parse_json_strict(input_["raw"])
            return {"valid": True, "code": "OK"}
        except LexError as e:
            return {"valid": False, "code": e.code}
    if op == "compile_yaml":
        try:
            doc = parse_yaml(input_["raw"])
            compile_policy(doc)
            return {"valid": True, "code": "OK"}
        except LexError as e:
            return {"valid": False, "code": e.code}
    if op == "canonical":
        return {"utf8": canonical_bytes(input_["value"]).decode("utf-8")}
    if op == "hash_action":
        assert input_["commit"] == "R"
        return {"hash": hash_domain_json(DOMAIN["ACTION"], R_COMMIT)}
    if op == "compare_action_hash":
        left = dict(R_COMMIT)
        right = {**left, **input_["right_replace"]}
        return {"equal": hash_domain_json(DOMAIN["ACTION"], left)
                == hash_domain_json(DOMAIN["ACTION"], right)}
    if op == "signature_verify":
        from lextier.audit import ed_verify
        return {"valid": ed_verify(bytes.fromhex(input_["public_key"]),
                                   bytes.fromhex(input_["message_hex"]),
                                   bytes.fromhex(input_["signature"]))}
    if op == "audit_genesis":
        entry, _head = _genesis_entry(input_)
        return {"hash": entry["hash"], "signature": entry["signature"]}
    if op == "audit_verify":
        keys = [{"key_id": KEY_ID, "public_key": AUDIT_PUB, "first_seq": 1, "last_seq": None}]
        if input_["fixture"] == "genesis_from_TV-L--37":
            entry, head = _genesis_entry({
                "tenant": TENANT, "gateway": GATEWAY, "actor": ADMIN,
                "event_id": "lte_000000000000000000001", "time_ms": 1000000,
                "policy": "P"})
            mut = input_.get("mutate")
            if mut:
                for path, val in mut.items():
                    if path == "body.time_ms":
                        entry["body"]["time_ms"] = val
            res = verify_chain([entry], head, keys, tenant=TENANT, gateway=GATEWAY)
            return {"valid": res["valid"], "code": res["code"]}
        pytest.skip("entry fixture requires the live TS gateway")
    if op == "stats":
        decisions = []
        t = 1000000
        seq = 0
        for r in input_["runs"]:
            for _ in range(r["count"]):
                seq += 1
                decisions.append({"reviewer": H, "received_ms": t, "seq": seq,
                                  "approved": r["verdict"] == "approve",
                                  "latency_ms": r["latency_ms"]})
                t += 10000
        rows = compute_reviewer_stats(0, 100000000, decisions, [H])
        r0 = next(r for r in rows if r["reviewer"] == H)
        return {k: r0[k] for k in ("decisions", "approved", "rejected", "approval_bps",
                                   "median_latency_ms", "subsecond_bps",
                                   "prior_approval_bps", "prior_median_latency_ms", "flag")}
    raise ValueError(f"unknown op {op}")


def _pure(v):
    return (v["input"]["op"] in PURE_OPS
            or (v["input"]["op"] == "audit_verify"
                and v["input"].get("fixture") == "genesis_from_TV-L--37"))


CASES = [v for v in VECTORS if _pure(v)]
IDS = [v["id"] for v in CASES]


@pytest.mark.parametrize("v", CASES, ids=IDS)
def test_vector(v):
    actual = run_op(v["input"])
    assert actual == v["expected"], f"{v['id']}: expected {v['expected']} got {actual}"


def test_coverage():
    assert len(CASES) == 23, f"expected 23 pure vectors, found {len(CASES)}"
