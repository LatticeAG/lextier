"""The six locked tool profiles and call validation — parity with
src/core/registry.ts (spec §4.1)."""

import re

from .errors import err
from .hashing import RE, hash_json

TOOL_NAMES = ["db.delete_rows", "db.select_rows", "fs.read_text",
              "fs.remove_file", "fs.write_text", "payments.send"]

REGISTRY_DESCRIPTOR = {
    "profile": "known-tools-1",
    "version": 1,
    "tools": TOOL_NAMES,
}
REGISTRY_HASH = hash_json(REGISTRY_DESCRIPTOR)

BUILTIN_DENIED = frozenset(["shell.exec", "fs.remove_tree", "db.drop_table"])

TIER_RANK = {"allow": 0, "async_review": 1, "hard_stop": 2}

TOOL_SPECS = {
    "fs.read_text": {
        "floor": "allow",
        "args": {"path": {"kind": "path"}},
    },
    "fs.write_text": {
        "floor": "async_review",
        "args": {
            "path": {"kind": "path"},
            "text": {"kind": "string", "max_bytes": 8192},
            "expected_version": {"kind": "string", "pattern": RE.version},
        },
    },
    "fs.remove_file": {
        "floor": "hard_stop",
        "args": {
            "path": {"kind": "path"},
            "expected_version": {"kind": "string", "pattern": RE.version},
        },
    },
    "db.select_rows": {
        "floor": "allow",
        "args": {
            "table": {"kind": "string", "enum": ["products", "sandbox_jobs"]},
            "ids": {"kind": "ids"},
            "columns": {"kind": "columns"},
        },
    },
    "db.delete_rows": {
        "floor": "hard_stop",
        "args": {
            "table": {"kind": "string", "enum": ["sandbox_jobs"]},
            "ids": {"kind": "ids"},
            "expected_version": {"kind": "string", "pattern": RE.version},
        },
    },
    "payments.send": {
        "floor": "hard_stop",
        "args": {
            "recipient_id": {"kind": "string", "pattern": re.compile(r"^recipient_[a-z0-9_-]{1,48}$")},
            "amount_minor": {"kind": "uint"},
            "currency": {"kind": "string", "enum": ["USD"]},
            "expected_version": {"kind": "string", "pattern": RE.version},
        },
    },
}


def valid_path(p) -> bool:
    """Path grammar (§4.1): /workspace/ prefix, segment rules, no ambiguity."""
    if not isinstance(p, str):
        return False
    b = p.encode("utf-8")
    if len(b) > 256 or len(b) == 0:
        return False
    if not p.startswith("/workspace/"):
        return False
    if p.endswith("/"):
        return False
    if not re.match(r"^[A-Za-z0-9/._-]+$", p):
        return False
    if "//" in p:
        return False
    for s in p.split("/")[2:]:
        if s in ("", ".", ".."):
            return False
    return True


def _valid_ids(v) -> bool:
    if not isinstance(v, list) or len(v) < 1 or len(v) > 100:
        return False
    prev = ""
    for i in v:
        if not isinstance(i, str) or not re.match(r"^[a-z0-9_-]{1,64}$", i):
            return False
        if prev != "" and i <= prev:
            return False
        prev = i
    return True


COLUMN_ALLOWLIST = ["id", "name", "status"]


def _valid_columns(v) -> bool:
    if not isinstance(v, list) or len(v) < 1 or len(v) > len(COLUMN_ALLOWLIST):
        return False
    prev = ""
    for c in v:
        if not isinstance(c, str) or c not in COLUMN_ALLOWLIST:
            return False
        if prev != "" and c <= prev:
            return False
        prev = c
    return True


def _is_uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 9007199254740991


def validate_call_shape(raw) -> dict:
    """Envelope + call shape validation (§3.3). Unknown names not decided here."""
    if not isinstance(raw, dict):
        raise err("SCHEMA_INVALID")
    if set(raw.keys()) != {"tool", "args"}:
        raise err("SCHEMA_INVALID")
    t = raw["tool"]
    if not isinstance(t, str) or len(t.encode("utf-8")) > 64 or not RE.tool_name.match(t):
        raise err("SCHEMA_INVALID")
    if not isinstance(raw["args"], dict):
        raise err("SCHEMA_INVALID")
    return {"tool": t, "args": raw["args"]}


def is_registered_tool(name: str) -> bool:
    return name in TOOL_SPECS


def validate_call_args(tool: str, args: dict) -> None:
    spec = TOOL_SPECS.get(tool)
    if spec is None:
        raise err("UNKNOWN_TOOL")
    expected = set(spec["args"].keys())
    for k in args.keys():
        if k not in expected:
            raise err("SCHEMA_INVALID", f"unknown arg {k}")
    for k in expected:
        if k not in args:
            raise err("SCHEMA_INVALID", f"missing arg {k}")
        f = spec["args"][k]
        v = args[k]
        kind = f["kind"]
        if kind == "path":
            if not valid_path(v):
                raise err("SCHEMA_INVALID", "bad path")
        elif kind == "string":
            if not isinstance(v, str):
                raise err("SCHEMA_INVALID")
            if "max_bytes" in f and len(v.encode("utf-8")) > f["max_bytes"]:
                raise err("SCHEMA_INVALID")
            if "pattern" in f and not f["pattern"].match(v):
                raise err("SCHEMA_INVALID")
            if "enum" in f and v not in f["enum"]:
                raise err("SCHEMA_INVALID")
        elif kind == "uint":
            if not _is_uint(v):
                raise err("SCHEMA_INVALID")
        elif kind == "ids":
            if not _valid_ids(v):
                raise err("SCHEMA_INVALID")
        elif kind == "columns":
            if not _valid_columns(v):
                raise err("SCHEMA_INVALID")


def validate_call(raw) -> dict:
    call = validate_call_shape(raw)
    if not is_registered_tool(call["tool"]):
        raise err("UNKNOWN_TOOL")
    validate_call_args(call["tool"], call["args"])
    return call


def sort_by_bytes(ids):
    """Canonical byte-wise ascending order for id lists."""
    return sorted(ids, key=lambda s: s.encode("utf-8"))
