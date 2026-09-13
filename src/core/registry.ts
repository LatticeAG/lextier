/**
 * The immutable known-tools-1 registry (spec §4.1): six locked tool profiles,
 * immutable minimum tiers, argument schemas, and the built-in denied names.
 */

import { err } from "./errors.ts";
import type { Json } from "./canonical.ts";
import { hashJson, RE } from "./hash.ts";

export type Tier = "allow" | "async_review" | "hard_stop";
export const TIER_RANK: Record<Tier, number> = { allow: 0, async_review: 1, hard_stop: 2 };

export interface ToolCall { tool: string; args: { [key: string]: Json } }

export const REGISTRY_DESCRIPTOR = {
  profile: "known-tools-1",
  version: 1,
  tools: ["db.delete_rows", "db.select_rows", "fs.read_text", "fs.remove_file", "fs.write_text", "payments.send"],
} as const;

export const REGISTRY_HASH = hashJson(REGISTRY_DESCRIPTOR as unknown as Json);

/** Names denied regardless of policy; aliases to them are prohibited. */
export const BUILTIN_DENIED: ReadonlySet<string> = new Set(["shell.exec", "fs.remove_tree", "db.drop_table"]);

/** Field kinds drive both schema validation and predicate compile checks. */
export type FieldKind = "path" | "string" | "uint" | "ids" | "columns";

export interface FieldSpec {
  kind: FieldKind;
  maxBytes?: number;
  pattern?: RegExp;
  enum?: readonly string[];
  min?: number;
  max?: number;
}

export interface ToolSpec {
  floor: Tier;
  args: Record<string, FieldSpec>;
}

export const TOOL_SPECS: Record<string, ToolSpec> = {
  "fs.read_text": {
    floor: "allow",
    args: { path: { kind: "path" } },
  },
  "fs.write_text": {
    floor: "async_review",
    args: {
      path: { kind: "path" },
      text: { kind: "string", maxBytes: 8192 },
      expected_version: { kind: "string", pattern: RE.version },
    },
  },
  "fs.remove_file": {
    floor: "hard_stop",
    args: {
      path: { kind: "path" },
      expected_version: { kind: "string", pattern: RE.version },
    },
  },
  "db.select_rows": {
    floor: "allow",
    args: {
      table: { kind: "string", enum: ["products", "sandbox_jobs"] },
      ids: { kind: "ids" },
      columns: { kind: "columns" },
    },
  },
  "db.delete_rows": {
    floor: "hard_stop",
    args: {
      table: { kind: "string", enum: ["sandbox_jobs"] },
      ids: { kind: "ids" },
      expected_version: { kind: "string", pattern: RE.version },
    },
  },
  "payments.send": {
    floor: "hard_stop",
    args: {
      recipient_id: { kind: "string", pattern: /^recipient_[a-z0-9_-]{1,48}$/ },
      amount_minor: { kind: "uint" },
      currency: { kind: "string", enum: ["USD"] },
      expected_version: { kind: "string", pattern: RE.version },
    },
  },
};

const U8 = (s: string) => new TextEncoder().encode(s);

/** Path grammar (§4.1): /workspace/ prefix, segment rules, no ambiguity. */
export function validPath(p: unknown): p is string {
  if (typeof p !== "string") return false;
  const bytes = U8(p);
  if (bytes.length > 256 || bytes.length === 0) return false;
  if (!p.startsWith("/workspace/")) return false;
  if (p.endsWith("/")) return false;
  if (!/^[A-Za-z0-9/._-]+$/.test(p)) return false; // excludes %, backslash, NUL
  if (p.includes("//")) return false;
  const segs = p.split("/").slice(2); // after "" and "workspace"
  for (const s of segs) {
    if (s === "" || s === "." || s === "..") return false;
  }
  return true;
}

function validIds(v: unknown): v is string[] {
  if (!Array.isArray(v) || v.length < 1 || v.length > 100) return false;
  let prev = "";
  for (const id of v) {
    if (typeof id !== "string" || !/^[a-z0-9_-]{1,64}$/.test(id)) return false;
    if (prev !== "" && id <= prev) return false; // unique ascending (byte order)
    prev = id;
  }
  return true;
}

const COLUMN_ALLOWLIST = ["id", "name", "status"];

function validColumns(v: unknown): v is string[] {
  if (!Array.isArray(v) || v.length < 1 || v.length > COLUMN_ALLOWLIST.length) return false;
  let prev = "";
  for (const c of v) {
    if (typeof c !== "string" || !COLUMN_ALLOWLIST.includes(c)) return false;
    if (prev !== "" && c <= prev) return false;
    prev = c;
  }
  return true;
}

function isUInt(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 9007199254740991;
}

/**
 * Envelope + call schema validation (rejection order §3.3):
 * malformed tool name or args shape -> SCHEMA_INVALID.
 * Unknown-but-well-formed name is NOT decided here (callers handle).
 */
export function validateCallShape(raw: unknown): ToolCall {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw err("SCHEMA_INVALID");
  const o = raw as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 2 || !("tool" in o) || !("args" in o)) throw err("SCHEMA_INVALID");
  const t = o.tool;
  if (typeof t !== "string" || U8(t).length > 64 || !RE.toolName.test(t)) throw err("SCHEMA_INVALID");
  if (typeof o.args !== "object" || o.args === null || Array.isArray(o.args)) throw err("SCHEMA_INVALID");
  return { tool: t, args: o.args as Record<string, Json> };
}

export function isRegisteredTool(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(TOOL_SPECS, name);
}

/** Validate args against the named tool's closed schema. Throws SCHEMA_INVALID. */
export function validateCallArgs(tool: string, args: Record<string, Json>): void {
  const spec = TOOL_SPECS[tool];
  if (!spec) throw err("UNKNOWN_TOOL");
  const expected = Object.keys(spec.args);
  for (const k of Object.keys(args)) {
    if (!expected.includes(k)) throw err("SCHEMA_INVALID", null, `unknown arg ${k}`);
  }
  for (const k of expected) {
    if (!(k in args)) throw err("SCHEMA_INVALID", null, `missing arg ${k}`);
    const f = spec.args[k]!;
    const v = args[k];
    switch (f.kind) {
      case "path":
        if (!validPath(v)) throw err("SCHEMA_INVALID", null, `bad path`);
        break;
      case "string": {
        if (typeof v !== "string") throw err("SCHEMA_INVALID");
        if (f.maxBytes !== undefined && U8(v).length > f.maxBytes) throw err("SCHEMA_INVALID");
        if (f.pattern && !f.pattern.test(v)) throw err("SCHEMA_INVALID");
        if (f.enum && !f.enum.includes(v)) throw err("SCHEMA_INVALID");
        break;
      }
      case "uint":
        if (!isUInt(v)) throw err("SCHEMA_INVALID");
        break;
      case "ids":
        if (!validIds(v)) throw err("SCHEMA_INVALID");
        break;
      case "columns":
        if (!validColumns(v)) throw err("SCHEMA_INVALID");
        break;
    }
  }
}

/** Full call validation: shape + registered + args. */
export function validateCall(raw: unknown): ToolCall {
  const call = validateCallShape(raw);
  if (!isRegisteredTool(call.tool)) throw err("UNKNOWN_TOOL");
  validateCallArgs(call.tool, call.args);
  return call;
}
