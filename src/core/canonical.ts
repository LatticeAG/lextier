/**
 * J(x): RFC 8785 (JSON Canonicalization Scheme) serialization over the
 * restricted JSON domain of lextier/1: all numbers are safe integers, all
 * strings are valid Unicode (no lone surrogates), objects have unique keys.
 *
 * Property ordering uses UTF-16 code-unit order, exactly as ECMAScript
 * Array.prototype.sort does on the raw strings.
 */

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

const MAX_SAFE = 9007199254740991;

export function isSafeInt(n: number): boolean {
  return typeof n === "number" && Number.isInteger(n) && Math.abs(n) <= MAX_SAFE;
}

/** Serialize a Json domain value to canonical UTF-8 text (returned as string). */
export function canonicalize(value: Json): string {
  return ser(value);
}

/** Canonical bytes (UTF-8). */
export function canonicalBytes(value: Json): Uint8Array {
  return new TextEncoder().encode(ser(value));
}

function ser(v: Json): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!isSafeInt(v)) throw new Error("canonicalize: non-safe-integer number");
    // JSON.stringify emits the ES Number-to-String form which is the JCS
    // required form for integers in range; -0 canonicalizes to 0.
    return JSON.stringify(v === 0 ? 0 : v);
  }
  if (typeof v === "string") {
    // reject lone surrogates: unrepresentable in strict JSON/UTF-8 domain
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const lo = v.charCodeAt(i + 1);
        if (!(lo >= 0xdc00 && lo <= 0xdfff)) throw new Error("canonicalize: lone surrogate");
        i++;
      } else if (c >= 0xdc00 && c <= 0xdfff) throw new Error("canonicalize: lone surrogate");
    }
    // JSON.stringify produces exactly the RFC 8785 escape set
    // (\" \\ \b \f \n \r \t plus \u00xx for other C0 controls, lowercase hex).
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    let out = "[";
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out += ",";
      out += ser(v[i]!);
    }
    return out + "]";
  }
  if (typeof v !== "object") throw new Error(`canonicalize: non-JSON type ${typeof v}`);
  const keys = Object.keys(v).sort(); // UTF-16 code-unit order
  let out = "{";
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i]!;
    const val = v[k]!;
    if (val === undefined) throw new Error("canonicalize: undefined value");
    if (i > 0) out += ",";
    out += JSON.stringify(k) + ":" + ser(val);
  }
  return out + "}";
}
