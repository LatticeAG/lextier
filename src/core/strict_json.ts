/**
 * Strict JSON parser for lextier/1 wire bodies (spec §3.2–3.3).
 * Rejects: duplicate object keys, non-integer / non-safe-integer numbers,
 * unpaired surrogates, raw control characters, depth > 16, objects > 128
 * keys, arrays > 256 elements (configurable for AuditPage), strings over the
 * byte cap, and any trailing input.
 */

import { err } from "./errors.ts";
import type { Json } from "./canonical.ts";

const MAX_DEPTH = 16;
const MAX_KEYS = 128;
const MAX_ARRAY = 256;
const MAX_STRING_BYTES = 8192;
const MAX_SAFE = 9007199254740991n;

export interface ParseLimits {
  maxDepth?: number;
  maxKeys?: number;
  maxArray?: number;
  maxStringBytes?: number;
}

class P {
  i = 0;
  readonly s: string;
  readonly lim: Required<ParseLimits>;
  constructor(s: string, lim: Required<ParseLimits>) {
    this.s = s; this.lim = lim;
  }

  ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  fail(code = "INVALID_JSON"): never {
    throw err(code, null, `strict JSON: ${code} at offset ${this.i}`);
  }

  value(depth: number): Json {
    this.ws();
    if (this.i >= this.s.length) this.fail();
    const c = this.s[this.i]!;
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') return this.string();
    if (c === "t") { this.lit("true"); return true; }
    if (c === "f") { this.lit("false"); return false; }
    if (c === "n") { this.lit("null"); return null; }
    if (c === "-" || (c >= "0" && c <= "9")) return this.number();
    this.fail();
  }

  lit(w: string): void {
    if (!this.s.startsWith(w, this.i)) this.fail();
    this.i += w.length;
  }

  object(depth: number): Json {
    if (depth >= this.lim.maxDepth) this.fail();
    this.i++; // {
    const out: Record<string, Json> = {};
    this.ws();
    if (this.s[this.i] === "}") { this.i++; return out; }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') this.fail();
      const k = this.string();
      if (Object.prototype.hasOwnProperty.call(out, k)) this.fail("DUPLICATE_KEY");
      this.ws();
      if (this.s[this.i] !== ":") this.fail();
      this.i++;
      out[k] = this.value(depth + 1);
      if (Object.keys(out).length > this.lim.maxKeys) this.fail();
      this.ws();
      const c = this.s[this.i];
      if (c === ",") { this.i++; continue; }
      if (c === "}") { this.i++; return out; }
      this.fail();
    }
  }

  array(depth: number): Json {
    if (depth >= this.lim.maxDepth) this.fail();
    this.i++; // [
    const out: Json[] = [];
    this.ws();
    if (this.s[this.i] === "]") { this.i++; return out; }
    for (;;) {
      out.push(this.value(depth + 1));
      if (out.length > this.lim.maxArray) this.fail();
      this.ws();
      const c = this.s[this.i];
      if (c === ",") { this.i++; continue; }
      if (c === "]") { this.i++; return out; }
      this.fail();
    }
  }

  string(): string {
    this.i++; // opening "
    let bytes = 0;
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) this.fail();
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) { this.i++; break; }
      if (c === 0x5c) {
        this.i++;
        const e = this.s[this.i];
        this.i++;
        switch (e) {
          case '"': out += '"'; bytes += 1; break;
          case "\\": out += "\\"; bytes += 1; break;
          case "/": out += "/"; bytes += 1; break;
          case "b": out += "\b"; bytes += 1; break;
          case "f": out += "\f"; bytes += 1; break;
          case "n": out += "\n"; bytes += 1; break;
          case "r": out += "\r"; bytes += 1; break;
          case "t": out += "\t"; bytes += 1; break;
          case "u": {
            const cp = this.hex4();
            if (cp >= 0xd800 && cp <= 0xdbff) {
              // must be followed by \uDC00–\uDFFF
              if (this.s[this.i] === "\\" && this.s[this.i + 1] === "u") {
                this.i += 2;
                const lo = this.hex4();
                if (lo >= 0xdc00 && lo <= 0xdfff) {
                  const full = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                  out += String.fromCodePoint(full);
                  bytes += 4;
                  break;
                }
                this.fail();
              }
              this.fail();
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
              this.fail(); // unpaired low surrogate
            } else {
              out += String.fromCharCode(cp);
              bytes += cp < 0x80 ? 1 : cp < 0x800 ? 2 : 3;
            }
            break;
          }
          default: this.fail();
        }
      } else {
        if (c < 0x20) this.fail();
        if (c >= 0xd800 && c <= 0xdbff) {
          const lo = this.s.charCodeAt(this.i + 1);
          if (!(lo >= 0xdc00 && lo <= 0xdfff)) this.fail();
          out += this.s.slice(this.i, this.i + 2);
          bytes += 4; this.i += 2; continue;
        }
        if (c >= 0xdc00 && c <= 0xdfff) this.fail();
        out += this.s[this.i];
        bytes += c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
        this.i++;
      }
      if (bytes > this.lim.maxStringBytes) this.fail();
    }
    return out;
  }

  hex4(): number {
    const h = this.s.slice(this.i, this.i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) this.fail();
    this.i += 4;
    return parseInt(h, 16);
  }

  number(): number {
    const start = this.i;
    if (this.s[this.i] === "-") this.i++;
    if (this.s[this.i] === "0") this.i++;
    else if (this.s[this.i]! >= "1" && this.s[this.i]! <= "9") {
      while (this.s[this.i]! >= "0" && this.s[this.i]! <= "9") this.i++;
    } else this.fail();
    // protocol numbers are integers only: no fraction, no exponent
    if (this.s[this.i] === "." || this.s[this.i] === "e" || this.s[this.i] === "E") this.fail();
    const lit = this.s.slice(start, this.i);
    const v = BigInt(lit);
    if (v > MAX_SAFE || v < -MAX_SAFE) this.fail();
    return Number(v);
  }
}

export function parseJsonStrict(raw: string, limits: ParseLimits = {}): Json {
  const lim = {
    maxDepth: limits.maxDepth ?? MAX_DEPTH,
    maxKeys: limits.maxKeys ?? MAX_KEYS,
    maxArray: limits.maxArray ?? MAX_ARRAY,
    maxStringBytes: limits.maxStringBytes ?? MAX_STRING_BYTES,
  };
  const p = new P(raw, lim);
  const v = p.value(0);
  p.ws();
  if (p.i !== raw.length) p.fail();
  return v;
}

/** Strict UTF-8 decode (reject malformed) then strict JSON parse. */
export function parseJsonBytes(raw: Uint8Array, limits: ParseLimits = {}): Json {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  return parseJsonStrict(text, limits);
}
