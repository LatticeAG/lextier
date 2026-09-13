/**
 * Audit protocol primitives (spec §7): event bodies, hash-chained signing,
 * signed heads, key rotation, and offline chain verification.
 */

import { err } from "./errors.ts";
import { canonicalBytes, type Json } from "./canonical.ts";
import { hashDomain, hashDomainJson, sha256Hex, RE, DOMAIN, ZERO_HASH } from "./hash.ts";
import { edSign, edVerify, edPublicKeyValid, hexToBytes } from "./ed25519.ts";
import { isId } from "./ids.ts";

export const EVENT_TYPES = [
  "POLICY_ACTIVATED", "ACTION_CREATED", "ACTION_DENIED", "REVIEW_VIEWED",
  "DECISION_RECORDED", "ACTION_EXPIRED", "DRIFT_DETECTED", "ACTION_CANCELED",
  "DISPATCH_STARTED", "DISPATCH_SUCCEEDED", "DISPATCH_FAILED", "DISPATCH_UNKNOWN",
  "DISPATCH_RECONCILED", "RECONCILE_OBSERVED", "REAUDIT_OPENED", "REAUDIT_CLOSED",
  "REAUDIT_CANCELED", "KEY_ROTATED", "GATEWAY_PAUSED", "GATEWAY_RESUMED",
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export type State =
  | "PENDING" | "STOPPED" | "READY" | "DISPATCHING" | "SUCCEEDED"
  | "FAILED" | "UNKNOWN" | "DENIED" | "REJECTED" | "EXPIRED" | "STALE" | "CANCELED";

export const TERMINAL_STATES: ReadonlySet<State> = new Set([
  "SUCCEEDED", "FAILED", "DENIED", "REJECTED", "EXPIRED", "STALE", "CANCELED",
]);

export const REVIEWABLE_STATES: ReadonlySet<State> = new Set(["PENDING", "STOPPED"]);

export interface AuditFacts {
  action_hash: string | null;
  policy_revision: number;
  previous_state: State | null;
  state: State | null;
  reason: string;
  detail_hash: string | null;
  latency_ms: number | null;
  verdict: "approve" | "reject" | "release" | null;
}

export interface AuditBody {
  v: 1; tenant: string; gateway: string; seq: number; event_id: string;
  time_ms: number; type: EventType; actor: string | null; action_id: string | null;
  prev_hash: string; facts: AuditFacts;
}

export interface AuditEntry { body: AuditBody; hash: string; key_id: string; signature: string }
export interface HeadBody { v: 1; tenant: string; gateway: string; seq: number; hash: string; key_id: string }
export interface SignedHead { body: HeadBody; signature: string }
export interface KeyRotation { old_key_id: string; new_key_id: string; new_public_key: string; first_seq: number; new_key_proof: string }

export function eventHash(body: AuditBody): string {
  return hashDomainJson(DOMAIN.AUDIT, body as unknown as Json);
}

/** Message bytes for entry signing: UTF8("LEXTIER-SIGN/1") || 0x00 || raw32(hash). */
export function signMessage(entryHash: string): Uint8Array {
  const d = new TextEncoder().encode(DOMAIN.SIGN);
  const h = hexToBytes(entryHash);
  const out = new Uint8Array(d.length + 1 + 32);
  out.set(d, 0); out[d.length] = 0; out.set(h, d.length + 1);
  return out;
}

export function headMessage(body: HeadBody): Uint8Array {
  return canonicalBytes(body as unknown as Json) as Uint8Array;
}

export function rotationMessage(r: { old_key_id: string; new_key_id: string; new_public_key: string; first_seq: number }): Uint8Array {
  return canonicalBytes(r as unknown as Json);
}

/** Sign `payload` under the given domain via the seed (fixture/local signer path). */
export function signWithSeed(domain: string, payload: Uint8Array, seed: Uint8Array): string {
  const d = new TextEncoder().encode(domain);
  const msg = new Uint8Array(d.length + 1 + payload.length);
  msg.set(d, 0); msg[d.length] = 0; msg.set(payload, d.length + 1);
  return Buffer.from(edSign(seed, msg)).toString("hex");
}

export function verifyWithKey(domain: string, payload: Uint8Array, signatureHex: string, publicKeyHex: string): boolean {
  if (!RE.signature.test(signatureHex) || !RE.publicKey.test(publicKeyHex)) return false;
  if (!edPublicKeyValid(hexToBytes(publicKeyHex))) return false;
  const d = new TextEncoder().encode(domain);
  const msg = new Uint8Array(d.length + 1 + payload.length);
  msg.set(d, 0); msg[d.length] = 0; msg.set(payload, d.length + 1);
  return edVerify(hexToBytes(publicKeyHex), msg, hexToBytes(signatureHex));
}

export function signEntry(seed: Uint8Array, entryHash: string): string {
  return signWithSeed(DOMAIN.SIGN, hexToBytes(entryHash), seed);
}
export function signHead(seed: Uint8Array, body: HeadBody): string {
  return signWithSeed(DOMAIN.HEAD, canonicalBytes(body as unknown as Json), seed);
}
export function signRotation(seed: Uint8Array, r: { old_key_id: string; new_key_id: string; new_public_key: string; first_seq: number }): string {
  return signWithSeed(DOMAIN.ROTATE, canonicalBytes(r as unknown as Json), seed);
}
export function verifyEntrySig(entryHash: string, signatureHex: string, publicKeyHex: string): boolean {
  return verifyWithKey(DOMAIN.SIGN, hexToBytes(entryHash), signatureHex, publicKeyHex);
}
export function verifyHeadSig(body: HeadBody, signatureHex: string, publicKeyHex: string): boolean {
  return verifyWithKey(DOMAIN.HEAD, canonicalBytes(body as unknown as Json), signatureHex, publicKeyHex);
}
export function verifyRotationSig(r: { old_key_id: string; new_key_id: string; new_public_key: string; first_seq: number }, sigHex: string, publicKeyHex: string): boolean {
  return verifyWithKey(DOMAIN.ROTATE, canonicalBytes(r as unknown as Json), sigHex, publicKeyHex);
}

/** Legal state transitions (§6.2) for chain verification replay. */
const LEGAL: Record<string, Set<string>> = {
  "null": new Set(["READY", "PENDING", "STOPPED", "DENIED"]),
  PENDING: new Set(["READY", "REJECTED", "EXPIRED", "STALE", "DENIED", "CANCELED", "PENDING"]),
  STOPPED: new Set(["READY", "REJECTED", "EXPIRED", "STALE", "DENIED", "CANCELED", "STOPPED"]),
  READY: new Set(["DISPATCHING", "EXPIRED", "STALE", "DENIED", "CANCELED"]),
  DISPATCHING: new Set(["SUCCEEDED", "FAILED", "UNKNOWN"]),
  UNKNOWN: new Set(["SUCCEEDED", "FAILED", "UNKNOWN"]),
};

export interface KeyInterval { key_id: string; public_key: string; first_seq: number; last_seq: number | null }

export interface VerifyInput {
  entries: AuditEntry[];
  head: SignedHead;
  keys: KeyInterval[];           // trusted key intervals (may grow via rotation events)
  anchor?: { seq: number; hash: string } | null;
  tenant?: string; gateway?: string;
  checkTransitions?: boolean;    // legal state transitions when history complete
  /** resolve evidence bodies by hash for KEY_ROTATED trust extension */
  evidence?: (hash: string) => Json | null;
}

export interface VerifyResult {
  valid: boolean; code: string;
  /** key intervals learned from verified KEY_ROTATED events */
  extended?: KeyInterval[];
}

function keyForSeq(keys: KeyInterval[], seq: number): KeyInterval | null {
  return keys.find((k) => seq >= k.first_seq && (k.last_seq === null || seq <= k.last_seq)) ?? null;
}

function isEntryShape(e: unknown): e is AuditEntry {
  if (typeof e !== "object" || e === null || Array.isArray(e)) return false;
  const o = e as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== "body,hash,key_id,signature") return false;
  if (typeof o.hash !== "string" || !RE.hash.test(o.hash)) return false;
  if (typeof o.key_id !== "string" || !isId("key", o.key_id)) return false;
  if (typeof o.signature !== "string" || !RE.signature.test(o.signature)) return false;
  const b = o.body;
  if (typeof b !== "object" || b === null || Array.isArray(b)) return false;
  const bb = b as Record<string, unknown>;
  const bk = Object.keys(bb).sort().join(",");
  if (bk !== "action_id,actor,event_id,facts,gateway,prev_hash,seq,tenant,time_ms,type,v") return false;
  return true;
}

/**
 * Verify an exported audit chain. `entries` must be contiguous starting at
 * `anchor.seq + 1` (or seq 1 for a full export with no anchor).
 */
export function verifyChain(input: VerifyInput): VerifyResult {
  const { entries, head } = input;
  const anchor = input.anchor ?? null;

  // head shape
  const hb = head?.body;
  if (!hb || typeof hb !== "object") return { valid: false, code: "HASH_MISMATCH" };
  const hKeys = Object.keys(hb).sort().join(",");
  if (hKeys !== "gateway,hash,key_id,seq,tenant,v") return { valid: false, code: "HASH_MISMATCH" };
  if (hb.v !== 1) return { valid: false, code: "UNSUPPORTED_VERSION" };

  const firstSeq = entries.length > 0 ? entries[0]!.body.seq : (anchor ? anchor.seq + 1 : 1);
  if (entries.length > 0 && firstSeq > 1) {
    if (anchor === null) return { valid: false, code: "ANCHOR_REQUIRED" };
    if (anchor.seq !== firstSeq - 1 || anchor.hash !== entries[0]!.body.prev_hash) {
      return { valid: false, code: "HASH_MISMATCH" };
    }
  }
  if (entries.length === 0 && anchor === null && hb.seq !== 0) {
    // a head above seq 0 with no entries requires an anchor or full history
    if (hb.seq > 0) return { valid: false, code: "ANCHOR_REQUIRED" };
  }

  // extendable key intervals: clone so rotation events can add
  const keys: KeyInterval[] = input.keys.map((k) => ({ ...k }));
  const extended: KeyInterval[] = [];
  let missingRotation = false;

  let prevHash = anchor ? anchor.hash : ZERO_HASH;
  let prevTime = 0;
  const actionState = new Map<string, string>();
  const completeHistory = anchor === null || anchor.seq === 0 ? firstSeq === 1 : false;

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    if (!isEntryShape(e)) return { valid: false, code: "HASH_MISMATCH" };
    const b = e.body;
    if (input.tenant && b.tenant !== input.tenant) return { valid: false, code: "HASH_MISMATCH" };
    if (input.gateway && b.gateway !== input.gateway) return { valid: false, code: "HASH_MISMATCH" };
    if (hb.tenant !== b.tenant || hb.gateway !== b.gateway) return { valid: false, code: "HASH_MISMATCH" };
    if (eventHash(b) !== e.hash) return { valid: false, code: "HASH_MISMATCH" };
    if (b.prev_hash !== prevHash) return { valid: false, code: "HASH_MISMATCH" };
    const expectedSeq = (anchor ? anchor.seq : 0) + i + 1;
    if (b.seq !== expectedSeq) return { valid: false, code: "HASH_MISMATCH" };
    if (b.time_ms < prevTime) return { valid: false, code: "HASH_MISMATCH" }; // non-monotone time
    prevTime = b.time_ms;

    // key validity for this sequence
    const ki = keyForSeq(keys, b.seq);
    if (ki === null || ki.key_id !== e.key_id) {
      return { valid: false, code: missingRotation ? "INCOMPLETE_EVIDENCE" : "HASH_MISMATCH" };
    }
    if (!verifyEntrySig(e.hash, e.signature, ki.public_key)) return { valid: false, code: "HASH_MISMATCH" };

    // a verified KEY_ROTATED event (signed under the old key) extends trust to
    // the new key for seq >= first_seq once its proof verifies
    if (b.type === "KEY_ROTATED" && b.facts.detail_hash) {
      const rot = input.evidence ? input.evidence(b.facts.detail_hash) : null;
      if (rot === null) {
        missingRotation = true;
      } else {
        if (sha256Hex(canonicalBytes(rot)) !== b.facts.detail_hash) return { valid: false, code: "HASH_MISMATCH" };
        const r = rot as unknown as Record<string, unknown>;
        const rkeys = Object.keys(r).sort().join(",");
        if (rkeys !== "first_seq,new_key_id,new_key_proof,new_public_key,old_key_id"
          || r.old_key_id !== e.key_id || !isId("key", r.new_key_id)
          || typeof r.new_public_key !== "string" || !/^[0-9a-f]{64}$/.test(r.new_public_key)
          || r.first_seq !== b.seq + 1
          || typeof r.new_key_proof !== "string"
          || !verifyRotationSig(
            { old_key_id: r.old_key_id as string, new_key_id: r.new_key_id as string, new_public_key: r.new_public_key, first_seq: r.first_seq as number },
            r.new_key_proof, r.new_public_key)) {
          return { valid: false, code: "HASH_MISMATCH" };
        }
        const oldI = keyForSeq(keys, b.seq);
        if (oldI === null || oldI.key_id !== e.key_id) return { valid: false, code: "HASH_MISMATCH" };
        oldI.last_seq = b.seq;
        const ni: KeyInterval = { key_id: r.new_key_id as string, public_key: r.new_public_key, first_seq: r.first_seq as number, last_seq: null };
        keys.push(ni);
        extended.push(ni);
      }
    }

    // legal transitions when we have complete history
    if (input.checkTransitions && completeHistory && b.action_id && b.facts.state) {
      const prev = actionState.get(b.action_id) ?? null;
      const prevKey = prev === null ? "null" : prev;
      if (b.facts.previous_state !== prev) return { valid: false, code: "HASH_MISMATCH" };
      const legal = LEGAL[prevKey];
      if (legal && !legal.has(b.facts.state)) return { valid: false, code: "HASH_MISMATCH" };
      actionState.set(b.action_id, b.facts.state);
    } else if (b.action_id && b.facts.state) {
      actionState.set(b.action_id, b.facts.state);
    }

    prevHash = e.hash;
  }

  const lastSeq = entries.length > 0 ? entries[entries.length - 1]!.body.seq : (anchor ? anchor.seq : 0);
  if (hb.seq !== lastSeq) return { valid: false, code: "HASH_MISMATCH" };
  if (entries.length > 0 && hb.hash !== entries[entries.length - 1]!.hash) return { valid: false, code: "HASH_MISMATCH" };

  const hki = keyForSeq(keys, hb.seq);
  if (hki === null || hki.key_id !== hb.key_id) return { valid: false, code: "HASH_MISMATCH" };
  if (!verifyHeadSig(hb, head.signature, hki.public_key)) return { valid: false, code: "HASH_MISMATCH" };

  return { valid: true, code: "OK", extended };
}

/** Content hash for content-addressed storage (raw bytes). */
export function contentHash(b: Uint8Array | string): string {
  return sha256Hex(b);
}
