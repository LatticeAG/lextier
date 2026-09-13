/**
 * Policy schema, predicate compile checks, and the static evaluator
 * (spec §4.2–4.3). Pure over the registry: evaluation needs no deployment
 * state, never performs I/O, and never inspects enabled_tools.
 */

import { err } from "./errors.ts";
import { canonicalBytes, isSafeInt, type Json } from "./canonical.ts";
import { hashJson, RE } from "./hash.ts";
import {
  BUILTIN_DENIED, isRegisteredTool, validPath, validateCallArgs, TOOL_SPECS, TIER_RANK,
  type FieldKind, type Tier, type ToolCall,
} from "./registry.ts";

export type Predicate =
  | { path: string; op: "eq"; value: string | boolean | number }
  | { path: string; op: "in"; value: (string | boolean | number)[] }
  | { path: string; op: "path_under"; value: string }
  | { path: string; op: "int_lte"; value: number };

export interface Rule { id: string; tool: string; when: Predicate[]; tier: Tier }
export interface DenyRule { id: string; tool: string; when: Predicate[] }

export interface Policy {
  v: 1; revision: number; mode: "ENFORCE" | "ALLOW_ALL";
  review_ttl_ms: number; dispatch_ttl_ms: number; reviewers: string[];
  rules: Rule[]; hard_denies: DenyRule[];
}

export interface Evaluation {
  tier: Tier | null; reason: string; matched_rules: string[];
  dispatchable: false; scope_checked: false;
}

export const EVAL_REASONS = new Set([
  "HARD_DENY", "UNKNOWN_TOOL", "TOOL_FLOOR", "ALLOW_ALL",
  "DEFAULT_STOP", "RULE_ALLOW", "RULE_REVIEW", "RULE_STOP",
]);

const MAX_POLICY_BYTES = 65536;
const MAX_RULES = 100;
const MAX_DENIES = 100;
const MAX_PREDS = 8;
const MAX_REVIEWERS = 64;

function isUInt(v: unknown): v is number {
  return typeof v === "number" && isSafeInt(v) && v >= 0;
}

function cmpBytes(a: string, b: string): number {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return x.length - y.length;
}

export function sortByBytes(ids: string[]): string[] {
  return [...ids].sort(cmpBytes);
}

function ascendingUnique(ids: string[]): boolean {
  for (let i = 1; i < ids.length; i++) if (cmpBytes(ids[i - 1]!, ids[i]!) >= 0) return false;
  return true;
}

/** Allowed predicate ops per argument field kind (non-scalar fields: none). */
const OPS_BY_KIND: Record<FieldKind, ReadonlySet<string>> = {
  path: new Set(["eq", "in", "path_under"]),
  string: new Set(["eq", "in"]),
  uint: new Set(["eq", "in", "int_lte"]),
  ids: new Set(),
  columns: new Set(),
};

function compilePredicate(tool: string, raw: unknown): Predicate {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw err("POLICY_INVALID");
  const o = raw as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (keys.join(",") !== "op,path,value") throw err("POLICY_INVALID");
  const { path, op, value } = o as { path: unknown; op: unknown; value: unknown };
  if (typeof path !== "string" || !/^\/[A-Za-z_][A-Za-z0-9_]*$/.test(path)) throw err("POLICY_INVALID");
  if (op !== "eq" && op !== "in" && op !== "path_under" && op !== "int_lte") throw err("POLICY_INVALID");
  const field = path.slice(1);
  const spec = TOOL_SPECS[tool];
  if (!spec || !(field in spec.args)) throw err("POLICY_INVALID"); // absent field
  const fkind = spec.args[field]!.kind;
  if (!OPS_BY_KIND[fkind].has(op)) throw err("POLICY_INVALID"); // non-scalar or op mismatch

  const litType = fkind === "uint" ? "number" : "string";
  const litOk = (v: unknown) =>
    litType === "number" ? isUInt(v) : typeof v === "string";

  if (op === "eq") {
    if (!litOk(value)) throw err("POLICY_INVALID");
  } else if (op === "in") {
    if (!Array.isArray(value) || value.length < 1 || value.length > 32) throw err("POLICY_INVALID");
    const seen = new Set<unknown>();
    for (const v of value) {
      if (!litOk(v) || seen.has(v)) throw err("POLICY_INVALID");
      seen.add(v);
    }
  } else if (op === "path_under") {
    if (!validPath(value)) throw err("POLICY_INVALID"); // satisfies path grammar incl. /workspace/
  } else { // int_lte
    if (!isUInt(value)) throw err("POLICY_INVALID");
  }
  return { path, op, value } as Predicate;
}

/** Validate + compile a policy object. Throws POLICY_INVALID / SCHEMA_INVALID. */
export function compilePolicy(raw: unknown): Policy {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw err("SCHEMA_INVALID");
  const o = raw as Record<string, unknown>;
  const want = ["dispatch_ttl_ms", "hard_denies", "mode", "review_ttl_ms", "reviewers", "revision", "rules", "v"];
  if (Object.keys(o).sort().join(",") !== want.join(",")) throw err("SCHEMA_INVALID");
  if (o.v !== 1) throw err("UNSUPPORTED_VERSION");
  if (!isUInt(o.revision) || o.revision < 1) throw err("POLICY_INVALID");
  if (o.mode !== "ENFORCE" && o.mode !== "ALLOW_ALL") throw err("POLICY_INVALID");
  if (!isUInt(o.review_ttl_ms) || o.review_ttl_ms < 30000 || o.review_ttl_ms > 300000) throw err("POLICY_INVALID");
  if (!isUInt(o.dispatch_ttl_ms) || o.dispatch_ttl_ms < 1000 || o.dispatch_ttl_ms > 5000) throw err("POLICY_INVALID");
  const reviewers = o.reviewers;
  if (!Array.isArray(reviewers) || reviewers.length < 1 || reviewers.length > MAX_REVIEWERS) throw err("POLICY_INVALID");
  for (const r of reviewers) {
    if (typeof r !== "string" || !RE.principalId.test(r)) throw err("POLICY_INVALID");
  }
  if (!ascendingUnique(reviewers as string[])) throw err("POLICY_INVALID");

  const rulesRaw = o.rules, deniesRaw = o.hard_denies;
  if (!Array.isArray(rulesRaw) || rulesRaw.length > MAX_RULES) throw err("POLICY_INVALID");
  if (!Array.isArray(deniesRaw) || deniesRaw.length > MAX_DENIES) throw err("POLICY_INVALID");

  const ruleIds = new Set<string>();
  const rules: Rule[] = [];
  for (const rr of rulesRaw) {
    if (typeof rr !== "object" || rr === null || Array.isArray(rr)) throw err("POLICY_INVALID");
    const r = rr as Record<string, unknown>;
    if (Object.keys(r).sort().join(",") !== "id,tier,tool,when") throw err("POLICY_INVALID");
    if (typeof r.id !== "string" || !RE.ruleId.test(r.id) || ruleIds.has(r.id)) throw err("POLICY_INVALID");
    ruleIds.add(r.id);
    if (typeof r.tool !== "string" || !isRegisteredTool(r.tool)) throw err("POLICY_INVALID");
    if (r.tier !== "allow" && r.tier !== "async_review" && r.tier !== "hard_stop") throw err("POLICY_INVALID");
    if (!Array.isArray(r.when) || r.when.length > MAX_PREDS) throw err("POLICY_INVALID");
    rules.push({ id: r.id, tool: r.tool, when: r.when.map((p) => compilePredicate(r.tool as string, p)), tier: r.tier });
  }

  const denyIds = new Set<string>();
  const hard_denies: DenyRule[] = [];
  for (const dd of deniesRaw) {
    if (typeof dd !== "object" || dd === null || Array.isArray(dd)) throw err("POLICY_INVALID");
    const d = dd as Record<string, unknown>;
    if (Object.keys(d).sort().join(",") !== "id,tool,when") throw err("POLICY_INVALID");
    if (typeof d.id !== "string" || !RE.ruleId.test(d.id) || denyIds.has(d.id)) throw err("POLICY_INVALID");
    denyIds.add(d.id);
    if (typeof d.tool !== "string") throw err("POLICY_INVALID");
    if (!Array.isArray(d.when) || d.when.length > MAX_PREDS) throw err("POLICY_INVALID");
    if (!isRegisteredTool(d.tool)) {
      // a hard-deny may name a built-in denied tool only with an empty list
      if (!BUILTIN_DENIED.has(d.tool) || d.when.length !== 0) throw err("POLICY_INVALID");
      hard_denies.push({ id: d.id, tool: d.tool, when: [] });
      continue;
    }
    hard_denies.push({ id: d.id, tool: d.tool, when: d.when.map((p) => compilePredicate(d.tool as string, p)) });
  }

  const policy: Policy = {
    v: 1, revision: o.revision, mode: o.mode,
    review_ttl_ms: o.review_ttl_ms, dispatch_ttl_ms: o.dispatch_ttl_ms,
    reviewers: reviewers as string[], rules, hard_denies,
  };
  if (canonicalBytes(policy as unknown as Json).length > MAX_POLICY_BYTES) throw err("POLICY_INVALID");
  return policy;
}

export function policyHash(p: Policy): string {
  return hashJson(p as unknown as Json);
}

function fieldValue(call: ToolCall, path: string): Json | undefined {
  return call.args[path.slice(1)];
}

function matchPredicate(p: Predicate, call: ToolCall): boolean {
  const v = fieldValue(call, p.path);
  if (v === undefined) return false; // missing fields never match
  switch (p.op) {
    case "eq":
      return typeof v === typeof p.value && v === p.value;
    case "in":
      return (p.value as (string | boolean | number)[]).some(
        (x) => typeof x === typeof v && x === v,
      );
    case "path_under": {
      if (typeof v !== "string") return false;
      const prefix = (p.value as string) + "/";
      if (!v.startsWith(prefix)) return false;
      const suffix = v.slice(prefix.length);
      if (suffix.length === 0) return false;
      // suffix must be a valid relative tail: nonempty segments, charset
      if (!/^[A-Za-z0-9/._-]+$/.test(suffix) || suffix.endsWith("/") || suffix.includes("//")) return false;
      for (const s of suffix.split("/")) if (s === "" || s === "." || s === "..") return false;
      return true;
    }
    case "int_lte":
      return isUInt(v) && v <= p.value;
  }
}

function allMatch(preds: Predicate[], call: ToolCall): boolean {
  return preds.every((p) => matchPredicate(p, call));
}

function evalNull(reason: string, matched: string[]): Evaluation {
  return { tier: null, reason, matched_rules: matched, dispatchable: false, scope_checked: false };
}

/**
 * Static evaluation (§4.2). The caller is responsible for args schema
 * validation of registered tools first (SCHEMA_INVALID is an error, not an
 * Evaluation).
 */
export function evaluate(policy: Policy, call: ToolCall): Evaluation {
  if (BUILTIN_DENIED.has(call.tool)) return evalNull("HARD_DENY", []);
  const spec = TOOL_SPECS[call.tool];
  if (!spec) return evalNull("UNKNOWN_TOOL", []);
  // Schema-invalid arguments of a registered tool are an error, not an Evaluation.
  validateCallArgs(call.tool, call.args);

  const denyIds = policy.hard_denies
    .filter((d) => d.tool === call.tool && allMatch(d.when, call))
    .map((d) => d.id);
  if (denyIds.length > 0) return evalNull("HARD_DENY", sortByBytes(denyIds));

  const matched = policy.rules.filter((r) => r.tool === call.tool && allMatch(r.when, call));
  const matchedIds = sortByBytes(matched.map((r) => r.id));

  let computed: Tier;
  if (policy.mode === "ALLOW_ALL") computed = "allow";
  else if (matched.length === 0) computed = "hard_stop";
  else computed = matched.reduce<Tier>((a, r) => (TIER_RANK[r.tier] > TIER_RANK[a] ? r.tier : a), "allow");

  const floor = spec.floor;
  const tier = TIER_RANK[floor] > TIER_RANK[computed] ? floor : computed;

  let reason: string;
  if (TIER_RANK[floor] > TIER_RANK[computed]) reason = "TOOL_FLOOR";
  else if (policy.mode === "ALLOW_ALL") reason = "ALLOW_ALL";
  else if (matched.length === 0) reason = "DEFAULT_STOP";
  else reason = tier === "allow" ? "RULE_ALLOW" : tier === "async_review" ? "RULE_REVIEW" : "RULE_STOP";

  return { tier, reason, matched_rules: matchedIds, dispatchable: false, scope_checked: false };
}
