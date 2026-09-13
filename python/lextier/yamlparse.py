"""Restricted YAML 1.2 parser producing the lextier/1 JSON domain — parity
with src/core/yaml.ts. Supports block mappings/sequences by indentation,
`key: value`, flow collections, plain/single/double-quoted scalars, comments,
literal/folded block scalars, a single optional leading `---`.
Forbidden (YAML_FEATURE_FORBIDDEN): directives, anchors, aliases, merge keys,
explicit/verbatim tags, multiple documents, explicit-key syntax.
Scalar resolution: `on`/`off`/`yes`/`no` and timestamps remain strings; only
null/bool/int/float resolve."""

import re

from .errors import err

MAX_DEPTH = 16
MAX_SAFE = 9007199254740991


def _forbidden():
    raise err("YAML_FEATURE_FORBIDDEN")


def _bad(msg):
    raise err("YAML_INVALID", msg)


def _strip_comment(raw: str) -> str:
    out = []
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == "#" and (i == 0 or raw[i - 1] == " "):
            break
        if c == "'":
            k = i + 1
            while True:
                m = raw.find("'", k)
                if m < 0:
                    k = n
                    break
                if m + 1 < n and raw[m + 1] == "'":
                    k = m + 2
                    continue
                k = m + 1
                break
            out.append(raw[i:k])
            i = k
            continue
        if c == '"':
            k = i + 1
            while k < n:
                if raw[k] == "\\":
                    k += 2
                    continue
                if raw[k] == '"':
                    k += 1
                    break
                k += 1
            out.append(raw[i:k])
            i = k
            continue
        out.append(c)
        i += 1
    return "".join(out).rstrip()


class _Line:
    __slots__ = ("indent", "text")

    def __init__(self, indent, text):
        self.indent = indent
        self.text = text


def _to_lines(src: str):
    out = []
    raw_lines = re.sub(r"\r\n?", "\n", src).split("\n")
    saw_doc_start = False
    for raw in raw_lines:
        first_nonspace = re.search(r"\S|$", raw).start()
        if re.search(r"\t", raw[:first_nonspace]):
            _bad("tab indentation")
        expanded = raw.replace("\t", " ")
        stripped = _strip_comment(expanded)
        nolead = stripped.lstrip(" ")
        if nolead == "":
            continue
        indent = len(stripped) - len(nolead)
        if nolead.startswith("%"):
            _forbidden()
        if nolead == "---":
            if saw_doc_start or len(out) > 0:
                _forbidden()
            saw_doc_start = True
            continue
        if nolead.startswith("--- "):
            if saw_doc_start or len(out) > 0:
                _forbidden()
            saw_doc_start = True
            out.append(_Line(indent + 4, nolead[4:]))
            continue
        if nolead == "..." or nolead.startswith("... "):
            _forbidden()
        if nolead == "?" or nolead.startswith("? ") or nolead == ":" or nolead.startswith(": "):
            _forbidden()
        out.append(_Line(indent, nolead))
    return out


def _safe_int(und: str) -> int:
    if re.match(r"^[-+]?0x", und, re.I):
        v = int(und, 16)
    elif re.match(r"^[-+]?0o", und, re.I):
        neg = und.startswith("-")
        v = int("0o" + re.sub(r"^[-+]?", "", und), 8)
        if neg:
            v = -v
    else:
        v = int(und)
    if v > MAX_SAFE or v < -MAX_SAFE:
        _bad("unsafe integer")
    return v


def _resolve_plain(t: str):
    if t in ("", "~", "null", "Null", "NULL"):
        return None
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if re.match(r"^[-+]?\.(inf|Inf|INF)$", t) or re.match(r"^\.(nan|NaN|NAN)$", t):
        _bad("non-finite number")
    und = t.replace("_", "")
    if re.match(r"^[-+]?[0-9]+$", und):
        return _safe_int(und)
    if re.match(r"^[-+]?0x[0-9a-fA-F]+$", und):
        return _safe_int(und)
    if re.match(r"^[-+]?0o[0-7]+$", und):
        return _safe_int(und)
    if re.match(r"^[-+]?[0-9]+(\.[0-9]*)?([eE][-+]?[0-9]+)?$", und) and re.search(r"[.eE]", und):
        f = float(und)
        if f != f or f in (float("inf"), float("-inf")):
            _bad("non-finite number")
        return f
    if re.match(r"^[-+]?\.[0-9]+([eE][-+]?[0-9]+)?$", und):
        f = float(und)
        if f != f or f in (float("inf"), float("-inf")):
            _bad("non-finite number")
        return f
    return t


_DQ_ESC = {
    "0": "\0", "a": "\x07", "b": "\b", "t": "\t", "n": "\n", "v": "\x0b",
    "f": "\f", "r": "\r", "e": "\x1b", '"': '"', "/": "/", "\\": "\\",
    "_": " ", "N": "", "L": " ", "P": " ",
}


def _parse_double_quoted(s: str, i: int):
    out = []
    i += 1
    while True:
        if i >= len(s):
            _bad("unterminated string")
        c = s[i]
        if c == '"':
            return "".join(out), i + 1
        if c == "\\":
            if i + 1 >= len(s):
                _bad("unterminated escape")
            e = s[i + 1]
            if e in ("x", "u", "U"):
                n = 2 if e == "x" else (4 if e == "u" else 8)
                h = s[i + 2:i + 2 + n]
                if len(h) != n or not re.match(r"^[0-9a-fA-F]+$", h):
                    _bad("bad escape")
                cp = int(h, 16)
                if 0xD800 <= cp <= 0xDFFF:
                    _bad("unpaired surrogate escape")
                if cp > 0x10FFFF:
                    _bad("escape out of range")
                out.append(chr(cp))
                i += 2 + n
                continue
            rep = _DQ_ESC.get(e)
            if rep is None:
                _bad("unknown escape")
            out.append(rep)
            i += 2
            continue
        code = ord(c)
        if code < 0x20:
            _bad("raw control char")
        if 0xD800 <= code <= 0xDFFF:
            _bad("lone surrogate")
        out.append(c)
        i += 1


def _parse_single_quoted(s: str, i: int):
    out = []
    i += 1
    while True:
        if i >= len(s):
            _bad("unterminated string")
        c = s[i]
        if c == "'":
            if i + 1 < len(s) and s[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            return "".join(out), i + 1
        code = ord(c)
        if 0xD800 <= code <= 0xDFFF:
            _bad("lone surrogate")
        out.append(c)
        i += 1


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _scalar_key(v):
    if isinstance(v, str):
        return v
    if v is None or isinstance(v, bool) or isinstance(v, (int, float)):
        import json as _j
        return _j.dumps(v)
    _bad("non-scalar mapping key")


def _parse_flow_scalar(s: str, i: int):
    c = s[i] if i < len(s) else ""
    if c == '"':
        v, i = _parse_double_quoted(s, i)
        return v, i
    if c == "'":
        v, i = _parse_single_quoted(s, i)
        return v, i
    if c in ("*", "&", "!"):
        _forbidden()
    start = i
    while i < len(s) and s[i] not in ",]{}":
        if s[i] == "#" and s[i - 1] == " ":
            break
        i += 1
    return _resolve_plain(s[start:i].strip()), i


def _parse_flow(s: str, i: int, depth: int):
    if depth > MAX_DEPTH:
        _bad("nesting too deep")
    c = s[i] if i < len(s) else ""
    if c == "[":
        i += 1
        arr = []
        while True:
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == "]":
                return arr, i + 1
            if len(arr) > 0:
                if i >= len(s) or s[i] != ",":
                    _bad("flow syntax")
                i += 1
                i = _skip_ws(s, i)
                if i < len(s) and s[i] == "]":
                    return arr, i + 1
            if i < len(s) and s[i] in "[{":
                v, i = _parse_flow(s, i, depth + 1)
            else:
                v, i = _parse_flow_scalar(s, i)
            arr.append(v)
    if c == "{":
        i += 1
        obj = {}
        while True:
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == "}":
                return obj, i + 1
            if len(obj) > 0:
                if i >= len(s) or s[i] != ",":
                    _bad("flow syntax")
                i += 1
                i = _skip_ws(s, i)
                if i < len(s) and s[i] == "}":
                    return obj, i + 1
            if i < len(s) and s[i] in "[{":
                kv, i2 = _parse_flow(s, i, depth + 1)
            else:
                kv, i2 = _parse_flow_scalar(s, i)
            i = _skip_ws(s, i2)
            if i >= len(s) or s[i] != ":":
                _bad("flow mapping needs ':'")
            i += 1
            i = _skip_ws(s, i)
            if i < len(s) and s[i] in "[{":
                vv, i = _parse_flow(s, i, depth + 1)
            else:
                vv, i = _parse_flow_scalar(s, i)
            key = _scalar_key(kv)
            if key in obj:
                raise err("DUPLICATE_KEY")
            obj[key] = vv
    _bad("expected flow collection")


def _parse_block_scalar(lines, start_idx, parent_indent, header):
    folded = header.startswith(">")
    if not re.match(r"^[|>][+-]?[1-9]?$", header.strip()):
        _bad("bad block scalar header")
    i = start_idx
    collected = []
    block_indent = -1
    while i < len(lines) and lines[i].indent > parent_indent:
        if block_indent < 0:
            block_indent = lines[i].indent
        if lines[i].indent < block_indent:
            break
        collected.append(lines[i])
        i += 1
    if not collected:
        return "", i
    texts = [l.text if l.text else "" for l in collected]
    body = "\n".join(texts) + "\n" if not folded else " ".join(texts) + "\n"
    m = header.strip()[1] if len(header.strip()) > 1 else ""
    if m == "-":
        body = re.sub(r"\n+$", "", body)
    elif m != "+":
        body = re.sub(r"\n+$", "", body) + "\n"
    return body, i


def _is_seq_item(l: _Line, indent: int) -> bool:
    return l.indent == indent and (l.text == "-" or l.text.startswith("- "))


def _split_key(text: str):
    if text and text[0] in "\"'":
        v, i = (_parse_double_quoted if text[0] == '"' else _parse_single_quoted)(text, 0)
        after = text[i:]
        if not after.startswith(":"):
            _bad("bad mapping key")
        return v, after[1:]
    m = re.match(r"^([^:]+?)(:)(.*)$", text, re.S)
    if not m:
        return None
    key_text = m.group(1)
    if key_text.strip() == "<<":
        _forbidden()
    if "&" in key_text or "!" in key_text or "*" in key_text:
        _forbidden()
    v = _resolve_plain(key_text.strip())
    return _scalar_key(v), m.group(3)


def _parse_block(lines, idx, indent, depth):
    if depth > MAX_DEPTH:
        _bad("nesting too deep")
    if idx >= len(lines):
        return None, idx
    first = lines[idx]
    if first.indent < indent:
        return None, idx

    if _is_seq_item(first, indent):
        arr = []
        i = idx
        while i < len(lines) and _is_seq_item(lines[i], indent):
            l = lines[i]
            rest = "" if l.text == "-" else l.text[2:]
            rest_trim = rest.lstrip(" ")
            rest_indent = l.indent + (len(l.text) - len(rest_trim))
            if rest_trim == "":
                if i + 1 < len(lines) and lines[i + 1].indent > indent:
                    v, nxt = _parse_block(lines, i + 1, lines[i + 1].indent, depth + 1)
                    arr.append(v)
                    i = nxt
                else:
                    arr.append(None)
                    i += 1
            else:
                synthetic = [_Line(rest_indent, rest_trim)] + lines[i + 1:]
                v, nxt = _parse_block(synthetic, 0, rest_indent, depth + 1)
                arr.append(v)
                i = i + nxt
        return arr, i

    kv = _split_key(first.text)
    if kv is not None:
        obj = {}
        i = idx
        while i < len(lines):
            l = lines[i]
            if l.indent != indent:
                break
            kvv = _split_key(l.text)
            if kvv is None:
                break
            if l.text == "-" or l.text.startswith("- "):
                break
            key = kvv[0]
            if key in obj:
                raise err("DUPLICATE_KEY")
            rest = kvv[1]
            if rest == "" or re.match(r"^ +$", rest):
                if i + 1 < len(lines) and lines[i + 1].indent > indent:
                    v, nxt = _parse_block(lines, i + 1, lines[i + 1].indent, depth + 1)
                    obj[key] = v
                    i = nxt
                else:
                    obj[key] = None
                    i += 1
            else:
                inline = rest.lstrip(" ")
                c0 = inline[0]
                if c0 in "|>":
                    v, nxt = _parse_block_scalar(lines, i + 1, indent, inline)
                    obj[key] = v
                    i = nxt
                elif c0 in "&*!":
                    _forbidden()
                elif c0 in "[{":
                    v, nconsumed = _parse_flow(inline, 0, depth + 1)
                    tail = inline[nconsumed:].strip()
                    if tail != "" and not tail.startswith("#"):
                        _bad("trailing content after flow")
                    obj[key] = v
                    i += 1
                elif c0 in "\"'":
                    v, nconsumed = (_parse_double_quoted if c0 == '"' else _parse_single_quoted)(inline, 0)
                    tail = inline[nconsumed:].strip()
                    if tail != "":
                        _bad("trailing content after quoted scalar")
                    obj[key] = v
                    i += 1
                else:
                    obj[key] = _resolve_plain(inline.strip())
                    i += 1
        return obj, i

    i = idx
    parts = []
    while i < len(lines) and lines[i].indent >= indent:
        l = lines[i]
        if _split_key(l.text) is not None or _is_seq_item(l, l.indent):
            break
        parts.append(l.text)
        i += 1
    if not parts:
        _bad("unexpected content")
    joined = " ".join(parts)
    c0 = joined[0]
    if c0 in "&*!":
        _forbidden()
    if c0 == '"':
        v, _ = _parse_double_quoted(joined, 0)
        return v, i
    if c0 == "'":
        v, _ = _parse_single_quoted(joined, 0)
        return v, i
    if c0 in "[{":
        v, _ = _parse_flow(joined, 0, depth + 1)
        return v, i
    return _resolve_plain(joined), i


def parse_yaml(src: str):
    lines = _to_lines(src)
    if not lines:
        return None
    v, nxt = _parse_block(lines, 0, lines[0].indent, 0)
    if nxt != len(lines):
        _bad("trailing content")
    return v


def compile_yaml(src: str):
    try:
        return {"valid": True, "value": parse_yaml(src)}
    except Exception as e:
        code = e.code if isinstance(e, Exception) and hasattr(e, "code") else "YAML_INVALID"
        return {"valid": False, "code": code}
