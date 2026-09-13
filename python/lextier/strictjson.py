"""Strict JSON parser for lextier/1 wire bodies — parity with
src/core/strict_json.ts. Rejects duplicate keys, non-integer/non-safe-integer
numbers, unpaired surrogates, raw control characters, depth > 16, objects >
128 keys, arrays > 256 elements, strings over the byte cap, trailing input."""

from .errors import err

MAX_DEPTH = 16
MAX_KEYS = 128
MAX_ARRAY = 256
MAX_STRING_BYTES = 8192
MAX_SAFE = 9007199254740991


class _P:
    def __init__(self, s: str, max_depth=MAX_DEPTH, max_keys=MAX_KEYS,
                 max_array=MAX_ARRAY, max_string_bytes=MAX_STRING_BYTES):
        self.s = s
        self.i = 0
        self.max_depth = max_depth
        self.max_keys = max_keys
        self.max_array = max_array
        self.max_string_bytes = max_string_bytes

    def ws(self):
        while self.i < len(self.s):
            c = self.s[self.i]
            if c in " \t\n\r":
                self.i += 1
            else:
                break

    def fail(self, code="INVALID_JSON"):
        raise err(code, f"strict JSON: {code} at offset {self.i}")

    def value(self, depth):
        self.ws()
        if self.i >= len(self.s):
            self.fail()
        c = self.s[self.i]
        if c == "{":
            return self.object(depth)
        if c == "[":
            return self.array(depth)
        if c == '"':
            return self.string()
        if c == "t":
            self.lit("true")
            return True
        if c == "f":
            self.lit("false")
            return False
        if c == "n":
            self.lit("null")
            return None
        if c == "-" or ("0" <= c <= "9"):
            return self.number()
        self.fail()

    def lit(self, w):
        if not self.s.startswith(w, self.i):
            self.fail()
        self.i += len(w)

    def object(self, depth):
        if depth >= self.max_depth:
            self.fail()
        self.i += 1
        out = {}
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == "}":
            self.i += 1
            return out
        while True:
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != '"':
                self.fail()
            k = self.string()
            if k in out:
                self.fail("DUPLICATE_KEY")
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != ":":
                self.fail()
            self.i += 1
            out[k] = self.value(depth + 1)
            if len(out) > self.max_keys:
                self.fail()
            self.ws()
            if self.i >= len(self.s):
                self.fail()
            c = self.s[self.i]
            if c == ",":
                self.i += 1
                continue
            if c == "}":
                self.i += 1
                return out
            self.fail()

    def array(self, depth):
        if depth >= self.max_depth:
            self.fail()
        self.i += 1
        out = []
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            out.append(self.value(depth + 1))
            if len(out) > self.max_array:
                self.fail()
            self.ws()
            if self.i >= len(self.s):
                self.fail()
            c = self.s[self.i]
            if c == ",":
                self.i += 1
                continue
            if c == "]":
                self.i += 1
                return out
            self.fail()

    def string(self):
        self.i += 1
        nbytes = 0
        out = []
        while True:
            if self.i >= len(self.s):
                self.fail()
            c = ord(self.s[self.i])
            if c == 0x22:
                self.i += 1
                break
            if c == 0x5C:
                self.i += 1
                if self.i >= len(self.s):
                    self.fail()
                e = self.s[self.i]
                self.i += 1
                if e == '"':
                    out.append('"'); nbytes += 1
                elif e == "\\":
                    out.append("\\"); nbytes += 1
                elif e == "/":
                    out.append("/"); nbytes += 1
                elif e == "b":
                    out.append("\b"); nbytes += 1
                elif e == "f":
                    out.append("\f"); nbytes += 1
                elif e == "n":
                    out.append("\n"); nbytes += 1
                elif e == "r":
                    out.append("\r"); nbytes += 1
                elif e == "t":
                    out.append("\t"); nbytes += 1
                elif e == "u":
                    cp = self.hex4()
                    if 0xD800 <= cp <= 0xDBFF:
                        if self.i + 1 < len(self.s) and self.s[self.i] == "\\" and self.s[self.i + 1] == "u":
                            self.i += 2
                            lo = self.hex4()
                            if 0xDC00 <= lo <= 0xDFFF:
                                full = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                                out.append(chr(full))
                                nbytes += 4
                            else:
                                self.fail()
                        else:
                            self.fail()
                    elif 0xDC00 <= cp <= 0xDFFF:
                        self.fail()
                    else:
                        out.append(chr(cp))
                        nbytes += 1 if cp < 0x80 else (2 if cp < 0x800 else 3)
                else:
                    self.fail()
            else:
                if c < 0x20:
                    self.fail()
                if 0xD800 <= c <= 0xDBFF:
                    if self.i + 1 < len(self.s):
                        lo = ord(self.s[self.i + 1])
                        if 0xDC00 <= lo <= 0xDFFF:
                            out.append(self.s[self.i:self.i + 2])
                            nbytes += 4
                            self.i += 2
                            continue
                    self.fail()
                if 0xDC00 <= c <= 0xDFFF:
                    self.fail()
                out.append(self.s[self.i])
                nbytes += 1 if c < 0x80 else (2 if c < 0x800 else (3 if c < 0x10000 else 4))
                self.i += 1
            if nbytes > self.max_string_bytes:
                self.fail()
        return "".join(out)

    def hex4(self):
        h = self.s[self.i:self.i + 4]
        if len(h) != 4 or not all(ch in "0123456789abcdefABCDEF" for ch in h):
            self.fail()
        self.i += 4
        return int(h, 16)

    def number(self):
        start = self.i
        if self.s[self.i] == "-":
            self.i += 1
        if self.i >= len(self.s):
            self.fail()
        if self.s[self.i] == "0":
            self.i += 1
        elif "1" <= self.s[self.i] <= "9":
            while self.i < len(self.s) and "0" <= self.s[self.i] <= "9":
                self.i += 1
        else:
            self.fail()
        if self.i < len(self.s) and self.s[self.i] in ".eE":
            self.fail()
        lit = self.s[start:self.i]
        v = int(lit)
        if v > MAX_SAFE or v < -MAX_SAFE:
            self.fail()
        return v


def parse_json_strict(raw: str, max_depth=MAX_DEPTH, max_keys=MAX_KEYS,
                      max_array=MAX_ARRAY, max_string_bytes=MAX_STRING_BYTES):
    p = _P(raw, max_depth, max_keys, max_array, max_string_bytes)
    v = p.value(0)
    p.ws()
    if p.i != len(raw):
        p.fail()
    return v


def parse_json_bytes(raw: bytes, **limits):
    text = raw.decode("utf-8", errors="strict")
    return parse_json_strict(text, **limits)
