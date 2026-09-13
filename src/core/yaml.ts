/**
 * Restricted YAML 1.2 parser producing the lextier/1 JSON domain (spec §3.2).
 * Supported: block mappings/sequences by indentation, `key: value`,
 * flow collections [ ] { }, plain/single/double-quoted scalars, comments,
 * literal/folded block scalars, a single optional leading `---`.
 * Forbidden (YAML_FEATURE_FORBIDDEN): directives, anchors, aliases, merge
 * keys, explicit/verbatim tags, multiple documents.
 * Scalar resolution follows a fixed core schema: `on`/`off`/`yes`/`no` and
 * timestamps remain strings; only null/bool/int/float resolve.
 */

import { err } from "./errors.ts";
import type { Json } from "./canonical.ts";

const MAX_DEPTH = 16;

function forbidden(): never { throw err("YAML_FEATURE_FORBIDDEN"); }
function bad(msg: string): never { throw err("YAML_INVALID", null, msg); }

interface Line { indent: number; text: string }

function stripComment(raw: string): string {
  // Remove ` #`-style comments outside quotes; a leading # comments the line.
  let s = "", i = 0;
  const n = raw.length;
  while (i < n) {
    const c = raw[i]!;
    if (c === "#" && (i === 0 || raw[i - 1] === " ")) break;
    if (c === "'" ) {
      const j = raw.indexOf("'", i + 1);
      // handle '' escape
      let k = i + 1;
      for (;;) {
        const m = raw.indexOf("'", k);
        if (m < 0) { k = n; break; }
        if (raw[m + 1] === "'") { k = m + 2; continue; }
        k = m + 1; break;
      }
      s += raw.slice(i, k); i = k; continue;
    }
    if (c === '"') {
      let k = i + 1;
      while (k < n) {
        if (raw[k] === "\\") { k += 2; continue; }
        if (raw[k] === '"') { k++; break; }
        k++;
      }
      s += raw.slice(i, k); i = k; continue;
    }
    s += c; i++;
  }
  return s.replace(/\s+$/, "");
}

function toLines(src: string): Line[] {
  const out: Line[] = [];
  const rawLines = src.replace(/\r\n?/g, "\n").split("\n");
  let sawDocStart = false;
  for (let li = 0; li < rawLines.length; li++) {
    const raw = rawLines[li]!;
    if (/^\t| \t|\t /.test(raw.slice(0, raw.search(/\S|$/) + 1))) bad("tab indentation");
    const expanded = raw.replace(/\t/g, " "); // safety: tabs already rejected in indent
    const stripped = stripComment(expanded);
    const nolead = stripped.replace(/^ +/, "");
    if (nolead === "") continue;
    const indent = stripped.length - nolead.length;
    if (nolead.startsWith("%")) forbidden(); // directives
    if (nolead === "---") {
      if (sawDocStart || out.length > 0) forbidden(); // second document
      sawDocStart = true;
      continue;
    }
    if (nolead.startsWith("--- ")) {
      if (sawDocStart || out.length > 0) forbidden();
      sawDocStart = true;
      out.push({ indent: indent + 4, text: nolead.slice(4) });
      continue;
    }
    if (nolead === "..." || nolead.startsWith("... ")) forbidden();
    if (nolead === "?" || nolead.startsWith("? ") || nolead === ":" || nolead.startsWith(": ")) forbidden(); // explicit-key syntax
    out.push({ indent, text: nolead });
  }
  return out;
}

// ---------- scalar resolution ----------

function resolvePlain(t: string): Json {
  if (t === "" || t === "~" || t === "null" || t === "Null" || t === "NULL") return null;
  if (t === "true" || t === "True" || t === "TRUE") return true;
  if (t === "false" || t === "False" || t === "FALSE") return false;
  if (/^[-+]?(\.inf|\.Inf|\.INF)$/.test(t) || /^\.(nan|NaN|NAN)$/.test(t)) bad("non-finite number");
  const und = t.replace(/_/g, "");
  if (/^[-+]?[0-9]+$/.test(und)) return safeInt(und);
  if (/^[-+]?0x[0-9a-fA-F]+$/.test(und)) return safeInt(und);
  if (/^[-+]?0o[0-7]+$/.test(und)) return safeInt(und);
  if (/^[-+]?[0-9]+(\.[0-9]*)?([eE][-+]?[0-9]+)?$/.test(und) && /[.eE]/.test(und)) {
    const f = Number(und);
    if (!Number.isFinite(f)) bad("non-finite number");
    return f;
  }
  if (/^[-+]?\.[0-9]+([eE][-+]?[0-9]+)?$/.test(und)) {
    const f = Number(und);
    if (!Number.isFinite(f)) bad("non-finite number");
    return f;
  }
  return t; // strings: `on`, `yes`, timestamps, etc. stay strings
}

function safeInt(und: string): number {
  let v: bigint;
  if (/^[-+]?0x/i.test(und)) v = BigInt(und);
  else if (/^[-+]?0o/i.test(und)) {
    const neg = und.startsWith("-");
    v = BigInt("0o" + und.replace(/^[-+]?/, ""));
    if (neg) v = -v;
  } else v = BigInt(und);
  if (v > 9007199254740991n || v < -9007199254740991n) bad("unsafe integer");
  return Number(v);
}

const DQ_ESC: Record<string, string> = {
  "0": "\0", a: "\x07", b: "\b", t: "\t", n: "\n", v: "\x0b", f: "\f", r: "\r",
  e: "\x1b", '"': '"', "/": "/", "\\": "\\", _: "\u00a0", N: "\u0085", L: "\u2028", P: "\u2029",
};

function parseDoubleQuoted(s: string, i: number): { v: string; i: number } {
  let out = "";
  i++; // opening "
  for (;;) {
    if (i >= s.length) bad("unterminated string");
    const c = s[i]!;
    if (c === '"') return { v: out, i: i + 1 };
    if (c === "\\") {
      const e = s[i + 1];
      if (e === undefined) bad("unterminated escape");
      if (e === "x" || e === "u" || e === "U") {
        const n = e === "x" ? 2 : e === "u" ? 4 : 8;
        const h = s.slice(i + 2, i + 2 + n);
        if (!/^[0-9a-fA-F]+$/.test(h) || h.length !== n) bad("bad escape");
        const cp = parseInt(h, 16);
        if (cp >= 0xd800 && cp <= 0xdfff) bad("unpaired surrogate escape");
        if (cp > 0x10ffff) bad("escape out of range");
        out += String.fromCodePoint(cp);
        i += 2 + n;
        continue;
      }
      const rep = DQ_ESC[e];
      if (rep === undefined) bad("unknown escape");
      out += rep;
      i += 2;
      continue;
    }
    const code = s.codePointAt(i)!;
    if (code < 0x20) bad("raw control char");
    if (code >= 0xd800 && code <= 0xdfff) bad("lone surrogate");
    out += String.fromCodePoint(code);
    i += code > 0xffff ? 2 : 1;
  }
}

function parseSingleQuoted(s: string, i: number): { v: string; i: number } {
  let out = "";
  i++;
  for (;;) {
    if (i >= s.length) bad("unterminated string");
    const c = s[i]!;
    if (c === "'") {
      if (s[i + 1] === "'") { out += "'"; i += 2; continue; }
      return { v: out, i: i + 1 };
    }
    const code = s.codePointAt(i)!;
    if (code >= 0xd800 && code <= 0xdfff) bad("lone surrogate");
    out += String.fromCodePoint(code);
    i += code > 0xffff ? 2 : 1;
  }
}

// ---------- flow parsing ----------

function parseFlowScalar(s: string, i: number): { v: Json; i: number } {
  const c = s[i];
  if (c === '"') { const r = parseDoubleQuoted(s, i); return { v: r.v, i: r.i }; }
  if (c === "'") { const r = parseSingleQuoted(s, i); return { v: r.v, i: r.i }; }
  if (c === "*" || c === "&" || c === "!") forbidden();
  const start = i;
  while (i < s.length && !",]{}".includes(s[i]!)) {
    if (s[i] === "#" && s[i - 1] === " ") break;
    i++;
  }
  return { v: resolvePlain(s.slice(start, i).trim()), i };
}

function parseFlow(s: string, i: number, depth: number): { v: Json; i: number } {
  if (depth > MAX_DEPTH) bad("nesting too deep");
  const c = s[i];
  if (c === "[") {
    i++;
    const arr: Json[] = [];
    for (;;) {
      i = skipWs(s, i);
      if (s[i] === "]") return { v: arr, i: i + 1 };
      if (arr.length > 0) {
        if (s[i] !== ",") bad("flow syntax");
        i++; i = skipWs(s, i);
        if (s[i] === "]") return { v: arr, i: i + 1 };
      }
      const r = s[i] === "[" || s[i] === "{" ? parseFlow(s, i, depth + 1) : parseFlowScalar(s, i);
      arr.push(r.v); i = r.i;
    }
  }
  if (c === "{") {
    i++;
    const obj: Record<string, Json> = {};
    for (;;) {
      i = skipWs(s, i);
      if (s[i] === "}") return { v: obj, i: i + 1 };
      if (Object.keys(obj).length > 0) {
        if (s[i] !== ",") bad("flow syntax");
        i++; i = skipWs(s, i);
        if (s[i] === "}") return { v: obj, i: i + 1 };
      }
      const kr = s[i] === "[" || s[i] === "{" ? parseFlow(s, i, depth + 1) : parseFlowScalar(s, i);
      i = skipWs(s, kr.i);
      if (s[i] !== ":") bad("flow mapping needs ':'");
      i++; i = skipWs(s, i);
      const vr = s[i] === "[" || s[i] === "{" ? parseFlow(s, i, depth + 1) : parseFlowScalar(s, i);
      i = vr.i;
      const key = scalarKey(kr.v);
      if (Object.prototype.hasOwnProperty.call(obj, key)) throw err("DUPLICATE_KEY");
      obj[key] = vr.v;
    }
  }
  bad("expected flow collection");
}

function skipWs(s: string, i: number): number {
  while (i < s.length && (s[i] === " " || s[i] === "\t")) i++;
  return i;
}

function scalarKey(v: Json): string {
  if (typeof v === "string") return v;
  if (v === null || typeof v === "boolean" || typeof v === "number") return JSON.stringify(v);
  bad("non-scalar mapping key");
}

// ---------- block scalar ----------

function parseBlockScalar(lines: Line[], startIdx: number, parentIndent: number, header: string): { v: string; next: number } {
  // header is everything after the key colon, e.g. "|", ">-", "|+2"
  const folded = header.startsWith(">");
  if (!/^[|>][+-]?[1-9]?$/.test(header.trim())) bad("bad block scalar header");
  let i = startIdx;
  const collected: Line[] = [];
  let blockIndent = -1;
  while (i < lines.length && lines[i]!.indent > parentIndent) {
    if (blockIndent < 0) blockIndent = lines[i]!.indent;
    if (lines[i]!.indent < blockIndent) break;
    collected.push(lines[i]!);
    i++;
  }
  if (collected.length === 0) return { v: "", next: i };
  const texts = collected.map((l) => l.text.length ? l.text : "");
  // Preserve blank lines: a Line with empty text can't occur (we dropped them),
  // so re-derive: empty between? approximation — treat each collected line as content.
  let body: string;
  if (!folded) {
    body = texts.join("\n") + "\n";
  } else {
    body = texts.join(" ") + "\n";
  }
  const m = header.trim()[1];
  if (m === "-") body = body.replace(/\n+$/, "");
  else if (m !== "+") body = body.replace(/\n+$/, "") + "\n";
  return { v: body, next: i };
}

// ---------- block parsing ----------

function isSeqItem(l: Line, indent: number): boolean {
  return l.indent === indent && (l.text === "-" || l.text.startsWith("- "));
}

function splitKey(text: string): { key: string; rest: string } | null {
  // key may be quoted or plain; find the `:` that ends the key
  if (text[0] === '"' || text[0] === "'") {
    const r = text[0] === '"' ? parseDoubleQuoted(text, 0) : parseSingleQuoted(text, 0);
    const after = text.slice(r.i);
    if (!after.startsWith(":")) bad("bad mapping key");
    return { key: r.v, rest: after.slice(1) };
  }
  const m = text.match(/^([^:]+?)(:)(.*)$/s);
  if (!m) return null;
  const keyText = m[1]!;
  if (keyText.trim() === "<<") forbidden(); // merge key
  if (keyText.includes("&") || keyText.includes("!") || keyText.includes("*")) forbidden();
  const v = resolvePlain(keyText.trim());
  return { key: scalarKey(v), rest: m[3]! };
}

function parseBlock(lines: Line[], idx: number, indent: number, depth: number): { v: Json; next: number } {
  if (depth > MAX_DEPTH) bad("nesting too deep");
  if (idx >= lines.length) return { v: null, next: idx };
  const first = lines[idx]!;
  if (first.indent < indent) return { v: null, next: idx };

  if (isSeqItem(first, indent)) {
    const arr: Json[] = [];
    let i = idx;
    while (i < lines.length && isSeqItem(lines[i]!, indent)) {
      const l = lines[i]!;
      const rest = l.text === "-" ? "" : l.text.slice(2);
      const restTrim = rest.replace(/^ +/, "");
      const restIndent = l.indent + (l.text.length - restTrim.length);
      if (restTrim === "") {
        // nested block or null
        if (i + 1 < lines.length && lines[i + 1]!.indent > indent) {
          const r = parseBlock(lines, i + 1, lines[i + 1]!.indent, depth + 1);
          arr.push(r.v); i = r.next;
        } else { arr.push(null); i++; }
      } else {
        // treat remainder as the first line of a nested block at restIndent
        const synthetic: Line[] = [{ indent: restIndent, text: restTrim }, ...lines.slice(i + 1)];
        const r = parseBlock(synthetic, 0, restIndent, depth + 1);
        arr.push(r.v);
        i = i + r.next; // r.next counts lines consumed from synthetic incl. line 0
      }
    }
    return { v: arr, next: i };
  }

  const kv = splitKey(first.text);
  if (kv !== null) {
    const obj: Record<string, Json> = {};
    let i = idx;
    while (i < lines.length) {
      const l = lines[i]!;
      if (l.indent !== indent) break;
      const kvv = splitKey(l.text);
      if (kvv === null) break;
      if (l.text === "-" || l.text.startsWith("- ")) break;
      const key = kvv.key;
      if (Object.prototype.hasOwnProperty.call(obj, key)) throw err("DUPLICATE_KEY");
      const rest = kvv.rest;
      if (rest === "" || /^ +$/.test(rest)) {
        // value is a nested block or null
        if (i + 1 < lines.length && lines[i + 1]!.indent > indent) {
          const r = parseBlock(lines, i + 1, lines[i + 1]!.indent, depth + 1);
          obj[key] = r.v; i = r.next;
        } else { obj[key] = null; i++; }
      } else {
        const inline = rest.replace(/^ +/, "");
        const c0 = inline[0]!;
        if (c0 === "|" || c0 === ">") {
          const r = parseBlockScalar(lines, i + 1, indent, inline);
          obj[key] = r.v; i = r.next;
        } else if (c0 === "&" || c0 === "*" || c0 === "!") {
          forbidden();
        } else if (c0 === "[" || c0 === "{") {
          const r = parseFlow(inline, 0, depth + 1);
          const tail = inline.slice(r.i).trim();
          if (tail !== "" && !tail.startsWith("#")) bad("trailing content after flow");
          obj[key] = r.v; i++;
        } else if (c0 === '"' || c0 === "'") {
          const r = c0 === '"' ? parseDoubleQuoted(inline, 0) : parseSingleQuoted(inline, 0);
          const tail = inline.slice(r.i).trim();
          if (tail !== "") bad("trailing content after quoted scalar");
          obj[key] = r.v; i++;
        } else {
          obj[key] = resolvePlain(inline.trim());
          i++;
        }
      }
    }
    return { v: obj, next: i };
  }

  // plain scalar (possibly multi-line folded)
  let i = idx;
  const parts: string[] = [];
  while (i < lines.length && lines[i]!.indent >= indent) {
    const l = lines[i]!;
    if (splitKey(l.text) !== null || isSeqItem(l, l.indent)) break;
    parts.push(l.text);
    i++;
  }
  if (parts.length === 0) bad("unexpected content");
  const joined = parts.join(" ");
  const c0 = joined[0]!;
  if (c0 === "&" || c0 === "*" || c0 === "!") forbidden();
  if (c0 === '"' ) return { v: parseDoubleQuoted(joined, 0).v, next: i };
  if (c0 === "'") return { v: parseSingleQuoted(joined, 0).v, next: i };
  if (c0 === "[" || c0 === "{") {
    const r = parseFlow(joined, 0, depth + 1);
    return { v: r.v, next: i };
  }
  return { v: resolvePlain(joined), next: i };
}

/** Parse restricted YAML text into the JSON domain. */
export function parseYaml(src: string): Json {
  const lines = toLines(src);
  if (lines.length === 0) return null;
  const r = parseBlock(lines, 0, lines[0]!.indent, 0);
  if (r.next !== lines.length) bad("trailing content");
  return r.v;
}

/** Parse YAML then run a validator; any failure -> {valid:false,code}. */
export function compileYaml(src: string): { valid: true; value: Json } | { valid: false; code: string } {
  try {
    return { valid: true, value: parseYaml(src) };
  } catch (e) {
    const code = e instanceof Error && "code" in e ? String((e as { code: string }).code) : "YAML_INVALID";
    return { valid: false, code };
  }
}
