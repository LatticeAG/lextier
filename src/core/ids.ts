/**
 * Entity IDs: nanoid alphabet `_-0-9a-zA-Z` (64 symbols), 21 random symbols,
 * locked prefix (spec §3.1). Generated from a CSPRNG; callers may inject a
 * deterministic source for fixtures.
 */

import { randomBytes } from "node:crypto";
import { err } from "./errors.ts";

export const ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

export const PREFIX = {
  tenant: "ltt_", gateway: "ltg_", principal: "ltp_", action: "lta_",
  card: "ltc_", decision: "ltd_", event: "lte_", key: "ltk_",
  outbox: "lto_", reaudit: "ltr_",
} as const;

export type IdKind = keyof typeof PREFIX;

export function idRegex(kind: IdKind): RegExp {
  return new RegExp(`^${PREFIX[kind]}[A-Za-z0-9_-]{21}$`);
}

export function isId(kind: IdKind, v: unknown): v is string {
  return typeof v === "string" && idRegex(kind).test(v);
}

export type IdGen = (kind: IdKind) => string;

/** CSPRNG-backed ID generator (production path). */
export function csprngIdGen(): IdGen {
  return (kind) => {
    const bytes = randomBytes(21);
    let s = "";
    for (let i = 0; i < 21; i++) s += ALPHABET[bytes[i]! & 63];
    return PREFIX[kind] + s;
  };
}

/** Deterministic generator for conformance fixtures: zero-padded decimal. */
export function fixtureIdGen(): IdGen {
  const counters = new Map<string, number>();
  return (kind) => {
    const n = (counters.get(kind) ?? 0) + 1;
    counters.set(kind, n);
    return PREFIX[kind] + String(n).padStart(21, "0");
  };
}

export function requireId(kind: IdKind, v: unknown, code = "SCHEMA_INVALID"): string {
  if (!isId(kind, v)) throw err(code);
  return v;
}
