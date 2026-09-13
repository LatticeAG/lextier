/**
 * H(b): lowercase-hex SHA-256 over bytes, plus the lextier/1 domain-separated
 * hashing helpers (spec §3.2, §7).
 */

import { createHash } from "node:crypto";
import { canonicalBytes, type Json } from "./canonical.ts";

export function sha256Hex(b: Uint8Array | string): string {
  return createHash("sha256").update(b).digest("hex");
}

const U8 = (s: string) => new TextEncoder().encode(s);

/** H(J(x)) — canonical-JSON object hashing. */
export function hashJson(x: Json): string {
  return sha256Hex(canonicalBytes(x));
}

/** H(UTF8(domain) || 0x00 || payload-bytes). */
export function hashDomain(domain: string, payload: Uint8Array): string {
  const h = createHash("sha256");
  h.update(U8(domain));
  h.update(new Uint8Array([0]));
  h.update(payload);
  return h.digest("hex");
}

/** H(UTF8(domain) || 0x00 || J(x)). */
export function hashDomainJson(domain: string, x: Json): string {
  return hashDomain(domain, canonicalBytes(x));
}

export const DOMAIN = {
  ACTION: "LEXTIER-ACTION/1",
  AUDIT: "LEXTIER-AUDIT/1",
  SIGN: "LEXTIER-SIGN/1",
  HEAD: "LEXTIER-HEAD/1",
  ROTATE: "LEXTIER-ROTATE/1",
} as const;

export const ZERO_HASH = "0".repeat(64);

export const RE = {
  hash: /^[0-9a-f]{64}$/,
  signature: /^[0-9a-f]{128}$/,
  publicKey: /^[0-9a-f]{64}$/,
  reason: /^[A-Z][A-Z0-9_]{0,63}$/,
  ruleId: /^[a-z][a-z0-9-]{0,63}$/,
  toolName: /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/,
  idempotencyKey: /^[A-Za-z0-9_-]{16,64}$/,
  version: /^[\x20-\x7e]{1,128}$/,
  principalId: /^ltp_[A-Za-z0-9_-]{21}$/,
};
