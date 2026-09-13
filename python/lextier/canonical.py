"""Canonical JSON (RFC 8785 / JCS) over the lextier/1 domain — parity with
src/core/canonical.ts. Numbers are safe integers only; strings are valid
Unicode (no lone surrogates); objects have unique keys."""

import json as _json

MAX_SAFE = 9007199254740991

Json = None | bool | int | str | list | dict


def is_safe_int(n) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and abs(n) <= MAX_SAFE


def _check_string(s: str) -> None:
    i = 0
    while i < len(s):
        c = ord(s[i])
        if 0xD800 <= c <= 0xDBFF:
            if i + 1 >= len(s) or not (0xDC00 <= ord(s[i + 1]) <= 0xDFFF):
                raise ValueError("canonicalize: lone surrogate")
            i += 1
        elif 0xDC00 <= c <= 0xDFFF:
            raise ValueError("canonicalize: lone surrogate")
        i += 1


def _utf16_key(k: str) -> bytes:
    return k.encode("utf-16-be")


def _ser(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, bool):
        raise ValueError("canonicalize: unreachable")
    if isinstance(v, int):
        if not is_safe_int(v):
            raise ValueError("canonicalize: non-safe-integer number")
        return str(v)
    if isinstance(v, float):
        raise ValueError("canonicalize: non-safe-integer number")
    if isinstance(v, str):
        _check_string(v)
        # json.dumps(ensure_ascii=False) emits exactly the RFC 8785 escape set
        # (" \\ \b \f \n \r \t plus \u00xx for other C0 controls, lowercase hex).
        return _json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v.keys():
            if not isinstance(k, str):
                raise ValueError("canonicalize: non-string key")
            _check_string(k)
        keys = sorted(v.keys(), key=_utf16_key)
        out = "{"
        for i, k in enumerate(keys):
            val = v[k]
            if i > 0:
                out += ","
            out += _json.dumps(k, ensure_ascii=False) + ":" + _ser(val)
        return out + "}"
    raise ValueError(f"canonicalize: non-JSON type {type(v).__name__}")


def canonicalize(value) -> str:
    return _ser(value)


def canonical_bytes(value) -> bytes:
    return _ser(value).encode("utf-8")
