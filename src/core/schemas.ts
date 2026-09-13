/**
 * Wire-schema validators (spec §3.1, §5, §8.1). Closed objects: additional
 * properties are rejected recursively; null and absent are distinct.
 * Every validator throws a LexError (SCHEMA_INVALID unless otherwise noted).
 */

import { err } from "./errors.ts";
import { isSafeInt, type Json } from "./canonical.ts";
import { RE } from "./hash.ts";
import { isId, type IdKind } from "./ids.ts";

export function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function closed(v: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!isObj(v)) throw err("SCHEMA_INVALID");
  const want = [...fields].sort().join(",");
  if (Object.keys(v).sort().join(",") !== want) throw err("SCHEMA_INVALID");
  return v;
}

export function uInt(v: unknown): number {
  if (typeof v !== "number" || !isSafeInt(v) || v < 0) throw err("SCHEMA_INVALID");
  return v;
}
export function str(v: unknown, maxBytes = 8192): string {
  if (typeof v !== "string" || new TextEncoder().encode(v).length > maxBytes) throw err("SCHEMA_INVALID");
  return v;
}
export function bool(v: unknown): boolean {
  if (typeof v !== "boolean") throw err("SCHEMA_INVALID");
  return v;
}
export function hashF(v: unknown): string {
  if (typeof v !== "string" || !RE.hash.test(v)) throw err("SCHEMA_INVALID");
  return v;
}
export function hashOrNull(v: unknown): string | null {
  if (v === null) return null;
  return hashF(v);
}
export function sigF(v: unknown): string {
  if (typeof v !== "string" || !RE.signature.test(v)) throw err("SCHEMA_INVALID");
  return v;
}
export function pubKeyF(v: unknown): string {
  if (typeof v !== "string" || !RE.publicKey.test(v)) throw err("SCHEMA_INVALID");
  return v;
}
export function idF(kind: IdKind): (v: unknown) => string {
  return (v) => {
    if (!isId(kind, v)) throw err("SCHEMA_INVALID");
    return v;
  };
}
export function enumF<T extends string>(...vals: readonly T[]): (v: unknown) => T {
  return (v) => {
    if (typeof v !== "string" || !vals.includes(v as T)) throw err("SCHEMA_INVALID");
    return v as T;
  };
}
export function jsonF(v: unknown): Json {
  return v as Json;
}
export function arrF<T>(item: (v: unknown) => T, max = 256): (v: unknown) => T[] {
  return (v) => {
    if (!Array.isArray(v) || v.length > max) throw err("SCHEMA_INVALID");
    return v.map(item);
  };
}

// ---------- domain types ----------

export type Verdict = "approve" | "reject" | "release";
export type DecisionReason = "reviewed" | "unsafe" | "insufficient_context";

export interface Target { resource: string; version: string; digest: string }
export function targetF(v: unknown): Target {
  const o = closed(v, ["resource", "version", "digest"]);
  const resource = str(o.resource, 512);
  if (new TextEncoder().encode(resource).length > 512 || resource.length < 1) throw err("SCHEMA_INVALID");
  const version = str(o.version);
  if (!RE.version.test(version)) throw err("SCHEMA_INVALID");
  return { resource, version, digest: hashF(o.digest) };
}
export function targetOrNull(v: unknown): Target | null {
  return v === null ? null : targetF(v);
}

export interface BlastCard {
  status: "known" | "partial" | "unknown";
  target: Target;
  files: number | null;
  rows: number | null;
  money: { currency: "USD"; amount_minor: number } | null;
  undo: { kind: "none" | "manual"; instruction: string };
  observed_ms: number;
  evidence_hash: string;
}
export function blastF(v: unknown): BlastCard {
  const o = closed(v, ["evidence_hash", "files", "money", "observed_ms", "rows", "status", "target", "undo"]);
  const status = enumF("known", "partial", "unknown")(o.status);
  const files = o.files === null ? null : uInt(o.files);
  const rows = o.rows === null ? null : uInt(o.rows);
  let money: BlastCard["money"] = null;
  if (o.money !== null) {
    const m = closed(o.money, ["amount_minor", "currency"]);
    money = { currency: enumF("USD")(m.currency), amount_minor: uInt(m.amount_minor) };
  }
  const u = closed(o.undo, ["instruction", "kind"]);
  const instr = str(u.instruction);
  if (new TextEncoder().encode(instr).length > 512 || instr.length < 1) throw err("SCHEMA_INVALID");
  return {
    status, target: targetF(o.target), files, rows, money,
    undo: { kind: enumF("none", "manual")(u.kind), instruction: instr },
    observed_ms: uInt(o.observed_ms), evidence_hash: hashF(o.evidence_hash),
  };
}
export function blastOrNull(v: unknown): BlastCard | null {
  return v === null ? null : blastF(v);
}

export interface ToolResult {
  status: "succeeded" | "failed" | "unknown" | "not_executed";
  code: string;
  output: Json | null;
  provider_ref: string | null;
}
export function toolResultF(v: unknown): ToolResult {
  const o = closed(v, ["code", "output", "provider_ref", "status"]);
  const status = enumF("succeeded", "failed", "unknown", "not_executed")(o.status);
  const code = str(o.code);
  if (!RE.reason.test(code)) throw err("SCHEMA_INVALID");
  let pr: string | null = null;
  if (o.provider_ref !== null) {
    pr = str(o.provider_ref);
    if (!/^[\x20-\x7e]{1,128}$/.test(pr)) throw err("SCHEMA_INVALID");
  }
  return { status, code, output: (o.output as Json) ?? null, provider_ref: pr };
}
export function toolResultOrNull(v: unknown): ToolResult | null {
  return v === null ? null : toolResultF(v);
}

export type ActionState =
  | "PENDING" | "STOPPED" | "READY" | "DISPATCHING" | "SUCCEEDED"
  | "FAILED" | "UNKNOWN" | "DENIED" | "REJECTED" | "EXPIRED" | "STALE" | "CANCELED";

export interface ActionCommit {
  v: 1; tenant: string; gateway: string; action_id: string; actor: string;
  auth_epoch: number; call: { tool: string; args: Record<string, Json> };
  registry_hash: string; policy_hash: string; shield_hash: string | null;
  blast_hash: string | null; target: Target | null; created_ms: number; expires_ms: number;
}

export interface ActionHandle {
  action_id: string; action_hash: string; state: ActionState; revision: number;
  tier: "allow" | "async_review" | "hard_stop" | null; reason: string;
  expires_ms: number; dispatch_deadline_ms: number | null; card_id: string | null;
}

export interface DecisionInput {
  expected_revision: number; action_hash: string; card_id: string;
  verdict: Verdict; confirm_hash: string | null; reason: DecisionReason;
}
export function decisionInputF(v: unknown): DecisionInput {
  const o = closed(v, ["action_hash", "card_id", "confirm_hash", "expected_revision", "reason", "verdict"]);
  return {
    expected_revision: uInt(o.expected_revision),
    action_hash: hashF(o.action_hash),
    card_id: idF("card")(o.card_id),
    verdict: enumF("approve", "reject", "release")(o.verdict),
    confirm_hash: hashOrNull(o.confirm_hash),
    reason: enumF("reviewed", "unsafe", "insufficient_context")(o.reason),
  };
}

export interface Decision {
  decision_id: string; action_id: string; action_hash: string; card_id: string;
  reviewer: string; auth_epoch: number; verdict: Verdict; reason: DecisionReason;
  received_ms: number; first_view_ms: number; latency_ms: number; queue_latency_ms: number;
}

export interface ViewInput { action_hash: string; card_id: string }
export function viewInputF(v: unknown): ViewInput {
  const o = closed(v, ["action_hash", "card_id"]);
  return { action_hash: hashF(o.action_hash), card_id: idF("card")(o.card_id) };
}

export interface CancelInput { expected_revision: number; reason: "requester_cancel" | "operator_cancel" }
export function cancelInputF(v: unknown): CancelInput {
  const o = closed(v, ["expected_revision", "reason"]);
  return {
    expected_revision: uInt(o.expected_revision),
    reason: enumF("requester_cancel", "operator_cancel")(o.reason),
  };
}

export interface PolicyPut { expected_revision: number; policy: Json }
export function policyPutF(v: unknown): PolicyPut {
  const o = closed(v, ["expected_revision", "policy"]);
  return { expected_revision: uInt(o.expected_revision), policy: o.policy as Json };
}

export interface ReauditOpen { action_id: string; reviewer: string; reason: "manual_sample" | "manual_rotation" }
export function reauditOpenF(v: unknown): ReauditOpen {
  const o = closed(v, ["action_id", "reason", "reviewer"]);
  return {
    action_id: idF("action")(o.action_id),
    reviewer: idF("principal")(o.reviewer),
    reason: enumF("manual_sample", "manual_rotation")(o.reason),
  };
}

export interface ReauditClose { verdict: "uphold" | "question" }
export function reauditCloseF(v: unknown): ReauditClose {
  const o = closed(v, ["verdict"]);
  return { verdict: enumF("uphold", "question")(o.verdict) };
}

export interface RotateKey { expected_head_seq: number; new_key_id: string; new_public_key: string }
export function rotateKeyF(v: unknown): RotateKey {
  const o = closed(v, ["expected_head_seq", "new_key_id", "new_public_key"]);
  return {
    expected_head_seq: uInt(o.expected_head_seq),
    new_key_id: idF("key")(o.new_key_id),
    new_public_key: pubKeyF(o.new_public_key),
  };
}

export interface Reaudit {
  reaudit_id: string; action_id: string; reviewer: string; created_ms: number;
  state: "OPEN" | "CLOSED" | "CANCELED"; verdict: "uphold" | "question" | null;
  reason: "manual_sample" | "manual_rotation"; closed_ms: number | null;
}

export interface Card {
  card_id: string; action: ActionHandle; principal: string; call: { tool: string; args: Record<string, Json> };
  policy_revision: number; mode: "ENFORCE" | "ALLOW_ALL";
  blast: BlastCard | null; actions: ("approve" | "reject" | "release")[];
}

// ---------- binding types (spec §9) ----------

export interface AuthResult {
  tenant: string; principal: string;
  kind: "human" | "agent" | "service";
  roles: ("invoke" | "review" | "audit" | "admin")[];
  epoch: number; verified_ms: number;
}
export interface ScopeSnapshot { revision: number; verdict: "allow" | "deny"; reason: string }
export interface InspectResult { target: Target; permitted: boolean; reason: string; blast: BlastCard | null }
export interface ExecuteInput {
  action_id: string; action_hash: string;
  call: { tool: string; args: Record<string, Json> };
  target: Target; not_after_ms: number;
}
export interface LookupInput { action_id: string; action_hash: string }
