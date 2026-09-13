"""Policy compile + static evaluator — parity with src/core/policy.ts
(spec §4.2–4.3). Pure over the registry; never inspects enabled_tools."""

import re

from .errors import err
from .canonical import canonical_bytes, is_safe_int
from .hashing import RE, hash_json
from .registry import (BUILTIN_DENIED, is_registered_tool, valid_path,
                       validate_call_args, TOOL_SPECS, TIER_RANK, sort_by_bytes)

MAX_POLICY_BYTES = 65536
MAX_RULES = 100
MAX_DENIES = 100
MAX_PREDS = 8
MAX_REVIEWERS = 64

EVAL_REASONS = {"HARD_DENY", "UNKNOWN_TOOL", "TOOL_FLOOR", "ALLOW_ALL",
                "DEFAULT_STOP", "RULE_ALLOW", "RULE_REVIEW", "RULE_STOP"}


def _is_uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and is_safe_int(v) and v >= 0


def _cmp_bytes(a: str, b: str) -> int:
    x, y = a.encode("utf-8"), b.encode("utf-8")
    if x == y:
        return 0
    return -1 if x < y else 1


def _ascending_unique(ids) -> bool:
    for i in range(1, len(ids)):
        if ids[i - 1].encode("utf-8") >= ids[i].encode("utf-8"):
            return False
    return True


OPS_BY_KIND = {
    "path": {"eq", "in", "path_under"},
    "string": {"eq", "in"},
    "uint": {"eq", "in", "int_lte"},
    "ids": set(),
    "columns": set(),
}


def _compile_predicate(tool: str, raw):
    if not isinstance(raw, dict):
        raise err("POLICY_INVALID")
    if set(raw.keys()) != {"path", "op", "value"}:
        raise err("POLICY_INVALID")
    path, op, value = raw["path"], raw["op"], raw["value"]
    if not isinstance(path, str) or not re.match(r"^/[A-Za-z_][A-Za-z0-9_]*$", path):
        raise err("POLICY_INVALID")
    if op not in ("eq", "in", "path_under", "int_lte"):
        raise err("POLICY_INVALID")
    field = path[1:]
    spec = TOOL_SPECS.get(tool)
    if spec is None or field not in spec["args"]:
        raise err("POLICY_INVALID")
    fkind = spec["args"][field]["kind"]
    if op not in OPS_BY_KIND[fkind]:
        raise err("POLICY_INVALID")
    lit_ok = (lambda v: _is_uint(v)) if fkind == "uint" else (lambda v: isinstance(v, str))
    if op == "eq":
        if not lit_ok(value):
            raise err("POLICY_INVALID")
    elif op == "in":
        if not isinstance(value, list) or len(value) < 1 or len(value) > 32:
            raise err("POLICY_INVALID")
        seen = set()
        for v in value:
            key = (type(v).__name__, v)
            if not lit_ok(v) or key in seen:
                raise err("POLICY_INVALID")
            seen.add(key)
    elif op == "path_under":
        if not valid_path(value):
            raise err("POLICY_INVALID")
    else:  # int_lte
        if not _is_uint(value):
            raise err("POLICY_INVALID")
    return {"path": path, "op": op, "value": value}


def compile_policy(raw) -> dict:
    """Validate + compile a policy object. Raises LexError."""
    if not isinstance(raw, dict):
        raise err("SCHEMA_INVALID")
    want = {"dispatch_ttl_ms", "hard_denies", "mode", "review_ttl_ms",
            "reviewers", "revision", "rules", "v"}
    if set(raw.keys()) != want:
        raise err("SCHEMA_INVALID")
    o = raw
    if o["v"] != 1:
        raise err("UNSUPPORTED_VERSION")
    if not _is_uint(o["revision"]) or o["revision"] < 1:
        raise err("POLICY_INVALID")
    if o["mode"] not in ("ENFORCE", "ALLOW_ALL"):
        raise err("POLICY_INVALID")
    if not _is_uint(o["review_ttl_ms"]) or not (30000 <= o["review_ttl_ms"] <= 300000):
        raise err("POLICY_INVALID")
    if not _is_uint(o["dispatch_ttl_ms"]) or not (1000 <= o["dispatch_ttl_ms"] <= 5000):
        raise err("POLICY_INVALID")
    reviewers = o["reviewers"]
    if not isinstance(reviewers, list) or len(reviewers) < 1 or len(reviewers) > MAX_REVIEWERS:
        raise err("POLICY_INVALID")
    for r in reviewers:
        if not isinstance(r, str) or not RE.principal_id.match(r):
            raise err("POLICY_INVALID")
    if not _ascending_unique(reviewers):
        raise err("POLICY_INVALID")
    rules_raw, denies_raw = o["rules"], o["hard_denies"]
    if not isinstance(rules_raw, list) or len(rules_raw) > MAX_RULES:
        raise err("POLICY_INVALID")
    if not isinstance(denies_raw, list) or len(denies_raw) > MAX_DENIES:
        raise err("POLICY_INVALID")

    rule_ids = set()
    rules = []
    for rr in rules_raw:
        if not isinstance(rr, dict) or set(rr.keys()) != {"id", "tier", "tool", "when"}:
            raise err("POLICY_INVALID")
        if not isinstance(rr["id"], str) or not RE.rule_id.match(rr["id"]) or rr["id"] in rule_ids:
            raise err("POLICY_INVALID")
        rule_ids.add(rr["id"])
        if not isinstance(rr["tool"], str) or not is_registered_tool(rr["tool"]):
            raise err("POLICY_INVALID")
        if rr["tier"] not in ("allow", "async_review", "hard_stop"):
            raise err("POLICY_INVALID")
        if not isinstance(rr["when"], list) or len(rr["when"]) > MAX_PREDS:
            raise err("POLICY_INVALID")
        rules.append({"id": rr["id"], "tool": rr["tool"],
                      "when": [_compile_predicate(rr["tool"], p) for p in rr["when"]],
                      "tier": rr["tier"]})

    deny_ids = set()
    hard_denies = []
    for dd in denies_raw:
        if not isinstance(dd, dict) or set(dd.keys()) != {"id", "tool", "when"}:
            raise err("POLICY_INVALID")
        if not isinstance(dd["id"], str) or not RE.rule_id.match(dd["id"]) or dd["id"] in deny_ids:
            raise err("POLICY_INVALID")
        deny_ids.add(dd["id"])
        if not isinstance(dd["tool"], str) or not isinstance(dd["when"], list) or len(dd["when"]) > MAX_PREDS:
            raise err("POLICY_INVALID")
        if not is_registered_tool(dd["tool"]):
            if dd["tool"] not in BUILTIN_DENIED or len(dd["when"]) != 0:
                raise err("POLICY_INVALID")
            hard_denies.append({"id": dd["id"], "tool": dd["tool"], "when": []})
            continue
        hard_denies.append({"id": dd["id"], "tool": dd["tool"],
                            "when": [_compile_predicate(dd["tool"], p) for p in dd["when"]]})

    policy = {"v": 1, "revision": o["revision"], "mode": o["mode"],
              "review_ttl_ms": o["review_ttl_ms"], "dispatch_ttl_ms": o["dispatch_ttl_ms"],
              "reviewers": reviewers, "rules": rules, "hard_denies": hard_denies}
    if len(canonical_bytes(policy)) > MAX_POLICY_BYTES:
        raise err("POLICY_INVALID")
    return policy


def policy_hash(p: dict) -> str:
    return hash_json(p)


def _field_value(call: dict, path: str):
    field = path[1:]
    return (True, call["args"][field]) if field in call["args"] else (False, None)


def _match_predicate(p: dict, call: dict) -> bool:
    present, v = _field_value(call, p["path"])
    if not present:
        return False  # missing fields never match
    op = p["op"]
    if op == "eq":
        return type(v) is type(p["value"]) and v == p["value"]
    if op == "in":
        return any(type(x) is type(v) and x == v for x in p["value"])
    if op == "path_under":
        if not isinstance(v, str):
            return False
        prefix = p["value"] + "/"
        if not v.startswith(prefix):
            return False
        suffix = v[len(prefix):]
        if len(suffix) == 0:
            return False
        if not re.match(r"^[A-Za-z0-9/._-]+$", suffix) or suffix.endswith("/") or "//" in suffix:
            return False
        return all(s not in ("", ".", "..") for s in suffix.split("/"))
    if op == "int_lte":
        return _is_uint(v) and v <= p["value"]
    return False


def _all_match(preds, call) -> bool:
    return all(_match_predicate(p, call) for p in preds)


def _eval_null(reason: str, matched) -> dict:
    return {"tier": None, "reason": reason, "matched_rules": matched,
            "dispatchable": False, "scope_checked": False}


def evaluate(policy: dict, call: dict) -> dict:
    """Static evaluation (§4.2). Schema-invalid args of a registered tool raise
    SCHEMA_INVALID (an error, not an Evaluation)."""
    tool = call["tool"]
    if tool in BUILTIN_DENIED:
        return _eval_null("HARD_DENY", [])
    spec = TOOL_SPECS.get(tool)
    if spec is None:
        return _eval_null("UNKNOWN_TOOL", [])
    validate_call_args(tool, call["args"])

    deny_ids = [d["id"] for d in policy["hard_denies"]
                if d["tool"] == tool and _all_match(d["when"], call)]
    if deny_ids:
        return _eval_null("HARD_DENY", sort_by_bytes(deny_ids))

    matched = [r for r in policy["rules"] if r["tool"] == tool and _all_match(r["when"], call)]
    matched_ids = sort_by_bytes([r["id"] for r in matched])

    if policy["mode"] == "ALLOW_ALL":
        computed = "allow"
    elif len(matched) == 0:
        computed = "hard_stop"
    else:
        computed = "allow"
        for r in matched:
            if TIER_RANK[r["tier"]] > TIER_RANK[computed]:
                computed = r["tier"]

    floor = spec["floor"]
    tier = floor if TIER_RANK[floor] > TIER_RANK[computed] else computed

    if TIER_RANK[floor] > TIER_RANK[computed]:
        reason = "TOOL_FLOOR"
    elif policy["mode"] == "ALLOW_ALL":
        reason = "ALLOW_ALL"
    elif len(matched) == 0:
        reason = "DEFAULT_STOP"
    else:
        reason = {"allow": "RULE_ALLOW", "async_review": "RULE_REVIEW",
                  "hard_stop": "RULE_STOP"}[tier]

    return {"tier": tier, "reason": reason, "matched_rules": matched_ids,
            "dispatchable": False, "scope_checked": False}
