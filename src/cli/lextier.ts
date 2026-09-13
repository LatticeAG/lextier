#!/usr/bin/env node
/**
 * lextier — LexTier CLI (spec §10). Noninteractive; stdout carries exactly one
 * canonical JSON result (or an explicitly requested JSONL artifact written to
 * --out). Diagnostics go to stderr. Exit codes per spec §10.
 */

import { readFileSync, writeFileSync, openSync, closeSync, linkSync, unlinkSync, mkdirSync, renameSync, existsSync, chmodSync } from "node:fs";
import { randomBytes, createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { canonicalBytes, type Json } from "../core/canonical.ts";
import { parseJsonBytes, parseJsonStrict } from "../core/strict_json.ts";
import { parseYaml } from "../core/yaml.ts";
import { sha256Hex } from "../core/hash.ts";
import { compilePolicy, policyHash, evaluate } from "../core/policy.ts";
import { verifyChain, type AuditEntry, type SignedHead, type KeyInterval, type KeyRotation, verifyRotationSig, eventHash } from "../core/audit.ts";
import { computeReviewerStats, type DecisionPoint } from "../core/stats.ts";
import { isId } from "../core/ids.ts";
import { RE } from "../core/hash.ts";
import { validateCallShape, type ToolCall } from "../core/registry.ts";
import { loadConfigFile, loadPolicyFile, buildGateway, boot } from "../engine/factory.ts";
import { FixtureAuth } from "../engine/bindings.ts";
import { Router } from "../http/router.ts";
import { serve } from "../http/server.ts";

const VERSION = "1.0.0";
const TERMINAL = new Set(["SUCCEEDED", "FAILED", "UNKNOWN", "DENIED", "REJECTED", "EXPIRED", "STALE", "CANCELED"]);

// ---------------------------------------------------------------------------
// exit codes (spec §10)
// ---------------------------------------------------------------------------
const EXIT = { OK: 0, USAGE: 2, DENIED: 3, PENDING: 4, NETWORK: 5, AUTH: 6, EVIDENCE: 7, UNKNOWN_OUT: 8, FAILED: 9, CONFLICT: 10, SIGINT: 130 };

function codeToExit(code: string): number {
  switch (code) {
    case "SCHEMA_INVALID": case "POLICY_INVALID": case "YAML_FEATURE_FORBIDDEN":
    case "YAML_INVALID": case "UNSUPPORTED_VERSION": case "CONFIRM_REQUIRED":
    case "NOT_JSON": case "ID_INVALID": case "UTF8_INVALID": case "TRAILING_DATA":
      return EXIT.USAGE;
    case "DENIED": case "EXPIRED": case "TOOL_NOT_ENABLED": case "EVALUATION_DENIED":
      return EXIT.DENIED;
    case "DEPENDENCY_UNAVAILABLE": case "AUDIT_UNAVAILABLE": case "CLOCK_UNSAFE":
    case "CAPACITY": case "RATE_LIMIT": case "UNSUPPORTED_ADAPTER":
    case "ADAPTER_PROTOCOL": case "INTERNAL":
      return EXIT.NETWORK;
    case "UNAUTHENTICATED": case "FORBIDDEN": case "AUTH_REVOKED": case "NOT_FOUND":
    case "HUMAN_REQUIRED": case "SELF_REVIEW":
      return EXIT.AUTH;
    case "ANCHOR_REQUIRED": case "HASH_MISMATCH": case "INCOMPLETE_EVIDENCE":
    case "PAYLOAD_GONE": case "ROTATION_INVALID": case "CHAIN_INVALID":
      return EXIT.EVIDENCE;
    case "STATE_CONFLICT": case "REVISION_CONFLICT": case "IDEMPOTENCY_CONFLICT":
    case "VIEW_REQUIRED":
      return EXIT.CONFLICT;
    default:
      return EXIT.NETWORK;
  }
}

function stateToExit(state: string): number {
  switch (state) {
    case "SUCCEEDED": return EXIT.OK;
    case "PENDING": case "STOPPED": case "READY": case "DISPATCHING": return EXIT.PENDING;
    case "DENIED": case "REJECTED": case "CANCELED": case "STALE": case "EXPIRED": return EXIT.DENIED;
    case "UNKNOWN": return EXIT.UNKNOWN_OUT;
    case "FAILED": return EXIT.FAILED;
    default: return EXIT.OK;
  }
}

class CliError extends Error {
  readonly code: string; readonly exit: number;
  constructor(code: string, exitCode?: number, message?: string) {
    super(message ?? code); this.code = code; this.exit = exitCode ?? codeToExit(code);
  }
}

// ---------------------------------------------------------------------------
// output helpers
// ---------------------------------------------------------------------------
function out(v: unknown): void { process.stdout.write(Buffer.from(canonicalBytes(v as Json)).toString("utf8") + "\n"); }
function diag(msg: string): void { process.stderr.write(msg + "\n"); }
function dieUsage(msg: string): never { diag(`error: ${msg}`); process.exit(EXIT.USAGE); }

// ---------------------------------------------------------------------------
// argument parsing
// ---------------------------------------------------------------------------
interface ParsedArgs { cmd: string[]; flags: Map<string, string>; }

function parseArgs(argv: string[], spec: Record<string, { value: boolean }>): ParsedArgs {
  const cmd: string[] = [];
  const flags = new Map<string, string>();
  let i = 0;
  for (; i < argv.length; i++) {
    const t = argv[i]!;
    if (!t.startsWith("--")) {
      if (cmd.length < 2) { cmd.push(t); continue; }
      dieUsage(`trailing argument '${t}'`);
    }
    const eq = t.indexOf("=");
    const name = eq === -1 ? t.slice(2) : t.slice(2, eq);
    const def = spec[name];
    if (!def) dieUsage(`unknown flag '--${name}'`);
    if (flags.has(name)) dieUsage(`duplicate flag '--${name}'`);
    if (!def.value) {
      if (eq !== -1) dieUsage(`flag '--${name}' takes no value`);
      flags.set(name, "true");
    } else {
      let v: string;
      if (eq !== -1) v = t.slice(eq + 1);
      else { i++; if (i >= argv.length) dieUsage(`flag '--${name}' requires a value`); v = argv[i]!; if (v.startsWith("--")) dieUsage(`flag '--${name}' requires a value`); }
      flags.set(name, v);
    }
  }
  return { cmd, flags };
}

function req(flags: Map<string, string>, name: string): string {
  const v = flags.get(name);
  if (v === undefined) dieUsage(`missing required flag '--${name}'`);
  return v;
}
function uintFlag(flags: Map<string, string>, name: string, dflt?: number): number {
  const v = flags.get(name);
  if (v === undefined) { if (dflt !== undefined) return dflt; dieUsage(`missing required flag '--${name}'`); }
  if (!/^(0|[1-9][0-9]{0,14})$/.test(v)) dieUsage(`flag '--${name}' must be a UInt`);
  return Number(v);
}

function readInput(path: string): Uint8Array {
  if (path === "-") return new Uint8Array(readFileSync(0));
  return new Uint8Array(readFileSync(path));
}
function readJsonFlag(flags: Map<string, string>, name = "file"): Json {
  const raw = readInput(req(flags, name));
  try { return parseJsonBytes(raw) as Json; }
  catch { throw new CliError("SCHEMA_INVALID", EXIT.USAGE, `${name === "file" ? "input file" : name} is not strict JSON`); }
}
function readPolicyDoc(path: string): unknown {
  const raw = readFileSync(path);
  if (path.endsWith(".yaml") || path.endsWith(".yml")) return parseYaml(raw.toString("utf8"));
  return parseJsonBytes(new Uint8Array(raw));
}

// ---------------------------------------------------------------------------
// client config + HTTP client
// ---------------------------------------------------------------------------
interface ClientConfig { v: 1; base_url: string; credential_env: string; timeout_ms: number; trust_file: string }

function loadClientConfig(path: string): ClientConfig {
  let raw: Uint8Array;
  try { raw = new Uint8Array(readFileSync(path)); }
  catch { throw new CliError("SCHEMA_INVALID", EXIT.USAGE, `cannot read config '${path}'`); }
  let o: unknown;
  try { o = parseJsonBytes(raw); } catch { throw new CliError("SCHEMA_INVALID", EXIT.USAGE, `config '${path}' is not strict JSON`); }
  if (typeof o !== "object" || o === null || Array.isArray(o)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "config must be an object");
  const c = o as Record<string, unknown>;
  const keys = Object.keys(c).sort().join(",");
  if (keys !== "base_url,credential_env,timeout_ms,trust_file,v") throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "config has unknown/missing fields");
  if (c.v !== 1) throw new CliError("UNSUPPORTED_VERSION", EXIT.USAGE, "config v must be 1");
  if (typeof c.base_url !== "string" || !/^https?:\/\/[A-Za-z0-9._:-]+$/.test(c.base_url)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad base_url");
  if (typeof c.credential_env !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(c.credential_env)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad credential_env");
  if (typeof c.trust_file !== "string" || c.trust_file.length === 0) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad trust_file");
  if (typeof c.timeout_ms !== "number" || !Number.isInteger(c.timeout_ms) || c.timeout_ms < 1 || c.timeout_ms > 120000) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad timeout_ms");
  return { v: 1, base_url: c.base_url, credential_env: c.credential_env, timeout_ms: c.timeout_ms, trust_file: c.trust_file };
}

interface ApiResp { status: number; body: Json }

class Client {
  private cfg: ClientConfig; private token: string; private timeout: number;
  constructor(cfg: ClientConfig, timeoutMs: number | null) {
    this.cfg = cfg;
    const tok = process.env[cfg.credential_env];
    if (typeof tok !== "string" || tok.length === 0) {
      throw new CliError("UNAUTHENTICATED", EXIT.AUTH, `credential env '${cfg.credential_env}' is not set`);
    }
    this.token = tok; this.timeout = timeoutMs ?? cfg.timeout_ms;
  }
  async req(method: string, path: string, opts: { body?: Json; idem?: boolean; query?: Record<string, string> } = {}): Promise<ApiResp> {
    const q = opts.query ? "?" + new URLSearchParams(opts.query).toString() : "";
    const headers: Record<string, string> = { authorization: `Bearer ${this.token}` };
    if (opts.body !== undefined) headers["content-type"] = "application/json";
    if (opts.idem) headers["idempotency-key"] = randomBytes(24).toString("base64url");
    let res: Response;
    try {
      res = await fetch(this.cfg.base_url + path + q, {
        method, headers,
        body: opts.body !== undefined ? Buffer.from(canonicalBytes(opts.body)).toString("utf8") : null,
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (e) {
      throw new CliError("DEPENDENCY_UNAVAILABLE", EXIT.NETWORK, `request failed: ${(e as Error).message}`);
    }
    let body: Json = null;
    const text = await res.text();
    if (text.length > 0) {
      try { body = parseJsonStrict(text) as Json; }
      catch { throw new CliError("ADAPTER_PROTOCOL", EXIT.NETWORK, "response is not strict JSON"); }
    }
    if (res.status >= 400) {
      const e = (body as { error?: { code?: string } })?.error;
      throw new CliError(typeof e?.code === "string" ? e.code : "INTERNAL");
    }
    return { status: res.status, body };
  }
  get(p: string, query?: Record<string, string>) { return this.req("GET", p, query ? { query } : {}); }
  post(p: string, body: Json, idem = true) { return this.req("POST", p, { body, idem }); }
  put(p: string, body: Json) { return this.req("PUT", p, { body, idem: true }); }
}

// ---------------------------------------------------------------------------
// audit export file parsing (shared by verify / stats --audit / reaudit sample)
// ---------------------------------------------------------------------------
interface ExportFile { anchor: { seq: number; hash: string } | null; entries: AuditEntry[]; head: SignedHead }

function parseExportFile(path: string): ExportFile {
  let text: string;
  try { text = readFileSync(path).toString("utf8"); } catch { throw new CliError("SCHEMA_INVALID", EXIT.USAGE, `cannot read '${path}'`); }
  const lines = text.split("\n").filter((l) => l.length > 0);
  let anchor: { seq: number; hash: string } | null = null;
  const entries: AuditEntry[] = [];
  let head: SignedHead | null = null;
  for (const [idx, line] of lines.entries()) {
    let rec: unknown;
    try { rec = parseJsonStrict(line); } catch { throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, `line ${idx + 1}: not strict JSON`); }
    if (typeof rec !== "object" || rec === null || Array.isArray(rec)) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, `line ${idx + 1}: bad record`);
    const r = rec as Record<string, unknown>;
    if (r.kind === "anchor") {
      if (idx !== 0 || anchor !== null) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "anchor line misplaced");
      if (typeof r.seq !== "number" || !Number.isInteger(r.seq) || typeof r.hash !== "string" || !RE.hash.test(r.hash))
        throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "bad anchor record");
      anchor = { seq: r.seq, hash: r.hash };
    } else if (r.kind === "entry") {
      if (head !== null) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "entry after head");
      entries.push(r.entry as AuditEntry);
    } else if (r.kind === "head") {
      if (idx !== lines.length - 1) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "head must be the final line");
      head = r.head as SignedHead;
    } else {
      throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, `line ${idx + 1}: unknown kind`);
    }
  }
  if (head === null) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "missing final head line");
  return { anchor, entries, head };
}

interface TrustFile { v: 1; tenant: string; gateway: string; keys: KeyInterval[] }

function loadTrust(path: string): TrustFile {
  let raw: Uint8Array;
  try { raw = new Uint8Array(readFileSync(path)); } catch { throw new CliError("SCHEMA_INVALID", EXIT.USAGE, `cannot read trust file '${path}'`); }
  let o: unknown;
  try { o = parseJsonBytes(raw); } catch { throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "trust file is not strict JSON"); }
  if (typeof o !== "object" || o === null || Array.isArray(o)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "trust file must be an object");
  const t = o as Record<string, unknown>;
  if (t.v !== 1) throw new CliError("UNSUPPORTED_VERSION", EXIT.USAGE, "trust v must be 1");
  if (!isId("tenant", t.tenant) || !isId("gateway", t.gateway)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad tenant/gateway in trust file");
  if (!Array.isArray(t.keys) || t.keys.length < 1) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "trust keys must be a nonempty array");
  const keys: KeyInterval[] = [];
  const seenIds = new Set<string>();
  for (const k of t.keys) {
    if (typeof k !== "object" || k === null || Array.isArray(k)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad key interval");
    const kk = k as Record<string, unknown>;
    if (Object.keys(kk).sort().join(",") !== "first_seq,key_id,last_seq,public_key") throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad key interval fields");
    if (!isId("key", kk.key_id) || seenIds.has(kk.key_id as string)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad key_id");
    if (typeof kk.public_key !== "string" || !RE.publicKey.test(kk.public_key)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad public_key");
    if (typeof kk.first_seq !== "number" || !Number.isInteger(kk.first_seq) || kk.first_seq < 1) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad first_seq");
    if (kk.last_seq !== null && (typeof kk.last_seq !== "number" || !Number.isInteger(kk.last_seq) || (kk.last_seq as number) < (kk.first_seq as number)))
      throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "bad last_seq");
    seenIds.add(kk.key_id as string);
    keys.push({ key_id: kk.key_id as string, public_key: kk.public_key, first_seq: kk.first_seq, last_seq: kk.last_seq as number | null });
  }
  // intervals for distinct keys must not overlap
  const sorted = [...keys].sort((a, b) => a.first_seq - b.first_seq);
  for (let i = 0; i + 1 < sorted.length; i++) {
    const cur = sorted[i]!, nxt = sorted[i + 1]!;
    if (cur.last_seq === null || cur.last_seq >= nxt.first_seq) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "overlapping trust intervals");
  }
  return { v: 1, tenant: t.tenant as string, gateway: t.gateway as string, keys };
}

/** Resolve an evidence body from a --replay-evidence directory of {hash}.json EvidenceResponses. */
function evidenceResolver(dir: string | null): { get: (hash: string) => Json | null; missing: Set<string> } {
  const missing = new Set<string>();
  const cache = new Map<string, Json | null>();
  const get = (hash: string): Json | null => {
    if (cache.has(hash)) return cache.get(hash)!;
    let body: Json | null = null;
    try {
      const raw = readFileSync(resolve(dir!, `${hash}.json`));
      const resp = parseJsonBytes(raw) as { hash?: string; data?: { kind?: string; body?: Json } };
      if (resp.hash !== hash || typeof resp.data?.body !== "object" || resp.data.body === null) {
        throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, `evidence ${hash}: malformed response`);
      }
      if (sha256Hex(canonicalBytes(resp.data.body)) !== hash) {
        throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, `evidence ${hash}: content hash mismatch`);
      }
      body = resp.data.body;
    } catch (e) {
      if (e instanceof CliError) throw e;
      body = null; missing.add(hash);
    }
    cache.set(hash, body);
    return body;
  };
  return { get, missing };
}

/** Collect evidence hashes referenced by an audit entry or an evidence body. */
function referencedHashes(node: unknown, into: Set<string>): void {
  if (typeof node !== "object" || node === null) return;
  if (Array.isArray(node)) { for (const v of node) referencedHashes(v, into); return; }
  const o = node as Record<string, unknown>;
  for (const [k, v] of Object.entries(o)) {
    if ((k === "detail_hash" || k === "policy_hash" || k === "registry_hash" || k === "shield_hash"
      || k === "blast_hash" || k === "evidence_hash" || k === "commit_hash")
      && typeof v === "string" && RE.hash.test(v)) into.add(v);
    else referencedHashes(v, into);
  }
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------
async function cmdPolicyLint(flags: Map<string, string>): Promise<number> {
  const path = req(flags, "file");
  let raw: unknown;
  try { raw = readPolicyDoc(path); } catch (e) { throw new CliError(e instanceof CliError ? e.code : "YAML_INVALID", EXIT.USAGE, (e as Error).message); }
  const pol = compilePolicy(raw); // throws LexError on invalid
  out({ valid: true, revision: pol.revision, policy_hash: policyHash(pol) });
  return EXIT.OK;
}

async function cmdPolicyEvaluate(flags: Map<string, string>): Promise<number> {
  const pol = compilePolicy(readPolicyDoc(req(flags, "policy")));
  const callRaw = readJsonFlag(flags, "file");
  const call = validateCallShape(callRaw);
  const ev = evaluate(pol, call);
  out(ev);
  return ev.tier === null ? EXIT.DENIED : EXIT.OK;
}

async function cmdSubmit(client: Client, flags: Map<string, string>): Promise<number> {
  const call = readJsonFlag(flags, "file");
  const waitMs = uintFlag(flags, "wait-ms", 0);
  const r = await client.post("/v1/actions", call);
  let handle = r.body as { action_id: string; state: string };
  const deadline = Date.now() + waitMs;
  while (!TERMINAL.has(handle.state) && Date.now() < deadline) {
    await new Promise((rs) => setTimeout(rs, Math.min(250, Math.max(1, deadline - Date.now()))));
    const g = await client.get(`/v1/actions/${handle.action_id}`);
    handle = (g.body as { action: typeof handle }).action;
  }
  out(handle);
  return stateToExit(handle.state);
}

async function cmdGet(client: Client, flags: Map<string, string>): Promise<number> {
  const id = req(flags, "action");
  if (!isId("action", id)) dieUsage("--action is not an action id");
  const r = await client.get(`/v1/actions/${id}`);
  out(r.body);
  return EXIT.OK;
}

async function cmdView(client: Client, flags: Map<string, string>): Promise<number> {
  const id = req(flags, "action");
  const hash = req(flags, "hash"); const card = req(flags, "card");
  if (!isId("action", id)) dieUsage("--action is not an action id");
  if (!RE.hash.test(hash)) dieUsage("--hash is not a hash");
  if (!isId("card", card)) dieUsage("--card is not a card id");
  // fetch and display the exact commit before recording the view
  const g = await client.get(`/v1/actions/${id}`);
  const view = g.body as { handle?: { action_hash?: string; card_id?: string | null } };
  const a = g.body as { action?: { action_hash?: string; card_id?: string | null } };
  if (a.action?.action_hash !== hash || a.action?.card_id !== card) {
    throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "supplied --hash/--card do not match the fetched action");
  }
  // display the exact fetched commit before recording the view
  process.stderr.write(Buffer.from(canonicalBytes(g.body)).toString("utf8") + "\n");
  const r = await client.req("POST", `/v1/actions/${id}/view`, { body: { action_hash: hash, card_id: card } as Json, idem: false });
  out(r.body);
  return EXIT.OK;
}

async function cmdDecide(client: Client, flags: Map<string, string>): Promise<number> {
  const id = req(flags, "action");
  if (!isId("action", id)) dieUsage("--action is not an action id");
  const input = readJsonFlag(flags, "file");
  const r = await client.post(`/v1/actions/${id}/decision`, input);
  out(r.body);
  return stateToExit((r.body as { state: string }).state);
}

async function cmdCancel(client: Client, flags: Map<string, string>): Promise<number> {
  const id = req(flags, "action");
  if (!isId("action", id)) dieUsage("--action is not an action id");
  const revision = uintFlag(flags, "revision");
  const reason = req(flags, "reason");
  if (reason !== "requester_cancel" && reason !== "operator_cancel") dieUsage("--reason must be requester_cancel|operator_cancel");
  const r = await client.post(`/v1/actions/${id}/cancel`, { expected_revision: revision, reason } as Json);
  out(r.body);
  return stateToExit((r.body as { state: string }).state);
}

async function cmdReconcile(client: Client, flags: Map<string, string>): Promise<number> {
  const id = req(flags, "action");
  if (!isId("action", id)) dieUsage("--action is not an action id");
  const r = await client.post(`/v1/actions/${id}/reconcile`, {});
  out(r.body);
  return stateToExit((r.body as { state: string }).state);
}

async function cmdPolicyShow(client: Client): Promise<number> {
  const r = await client.get("/v1/policy");
  out(r.body);
  return EXIT.OK;
}

async function cmdPolicyApply(client: Client, flags: Map<string, string>): Promise<number> {
  const expected = uintFlag(flags, "expected-revision");
  const policy = readPolicyDoc(req(flags, "file"));
  const r = await client.put("/v1/policy", { expected_revision: expected, policy: policy as Json });
  out(r.body);
  return EXIT.OK;
}

async function cmdPolicyEvaluateRemote(client: Client, flags: Map<string, string>): Promise<number> {
  const call = readJsonFlag(flags, "file");
  const r = await client.post("/v1/policy/evaluate", call, false);
  out(r.body);
  const ev = r.body as { tier?: string | null };
  return ev.tier === null ? EXIT.DENIED : EXIT.OK;
}

async function cmdAuditExport(client: Client, flags: Map<string, string>): Promise<number> {
  const after = uintFlag(flags, "after", 0);
  const through = uintFlag(flags, "through");
  const outPath = req(flags, "out");
  const evDir = flags.get("include-evidence") ?? null;
  if (existsSync(outPath)) dieUsage(`output '${outPath}' already exists`);
  if (evDir) mkdirSync(evDir, { recursive: true, mode: 0o700 });

  const entries: AuditEntry[] = [];
  let head: SignedHead | null = null;
  let cursor = after;
  for (;;) {
    const page = await client.get("/v1/audit", { after: String(cursor), through: String(through), limit: "200" });
    const p = page.body as unknown as { entries: AuditEntry[]; head: SignedHead | null; next_after: number | null };
    for (const e of p.entries) {
      // verify continuity while downloading
      const prev = entries.length > 0 ? entries[entries.length - 1]!.hash : null;
      if (prev !== null && e.body.prev_hash !== prev) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "export continuity broken");
      if (entries.length === 0 && after === 0 && e.body.seq !== 1) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "full export must start at genesis");
      if (entries.length === 0 && e.body.seq !== after + 1) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "range export does not start at after+1");
      entries.push(e);
    }
    head = p.head;
    if (p.next_after === null) break;
    cursor = p.next_after;
  }
  if (head === null) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "export returned no head");
  if (entries.length > 0 && head.body.seq !== entries[entries.length - 1]!.body.seq)
    throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "head does not match last entry");

  const tmp = `${outPath}.tmp-${randomBytes(6).toString("hex")}`;
  const lines: string[] = [];
  if (after > 0) {
    lines.push(Buffer.from(canonicalBytes({ kind: "anchor", seq: after, hash: entries[0]!.body.prev_hash } as unknown as Json)).toString("utf8"));
  }
  for (const e of entries) lines.push(Buffer.from(canonicalBytes({ kind: "entry", entry: e } as unknown as Json)).toString("utf8"));
  lines.push(Buffer.from(canonicalBytes({ kind: "head", head } as unknown as Json)).toString("utf8"));
  writeFileSync(tmp, lines.join("\n") + "\n", { mode: 0o600 });

  if (evDir) {
    const want = new Set<string>();
    for (const e of entries) referencedHashes(e.body.facts, want);
    const missing: string[] = [];
    // transitive fetch: commits/policies reference further evidence
    const queue = [...want];
    const done = new Set<string>();
    while (queue.length > 0) {
      const h = queue.shift()!;
      if (done.has(h)) continue;
      done.add(h);
      try {
        const r = await client.get(`/v1/evidence/${h}`);
        const file = resolve(evDir, `${h}.json`);
        writeFileSync(file, Buffer.from(canonicalBytes(r.body)).toString("utf8"), { mode: 0o600 });
        chmodSync(file, 0o600);
        const data = (r.body as { data?: { body?: Json } }).data?.body;
        const more = new Set<string>(); referencedHashes(data, more);
        for (const m of more) if (!done.has(m)) queue.push(m);
      } catch (e) {
        if (e instanceof CliError && (e.code === "NOT_FOUND" || e.code === "PAYLOAD_GONE")) { missing.push(h); continue; }
        unlinkSync(tmp);
        throw e;
      }
    }
    if (missing.length > 0) {
      unlinkSync(tmp);
      diag(`error: missing evidence: ${missing.sort().join(",")}`);
      return EXIT.EVIDENCE;
    }
  }

  // atomic no-overwrite install: hard-link then unlink temp
  try { linkSync(tmp, outPath); } catch { unlinkSync(tmp); dieUsage(`output '${outPath}' already exists`); }
  unlinkSync(tmp);
  out({ exported: entries.length, through: head.body.seq, out: outPath });
  return EXIT.OK;
}

async function cmdAuditVerify(flags: Map<string, string>): Promise<number> {
  const file = req(flags, "file");
  const trustPath = req(flags, "trust");
  const anchorHash = flags.get("anchor-hash") ?? null;
  const replayDir = flags.get("replay-evidence") ?? null;
  if (anchorHash !== null && !RE.hash.test(anchorHash)) dieUsage("--anchor-hash is not a hash");

  const ex = parseExportFile(file);
  const trust = loadTrust(trustPath);
  if (ex.anchor !== null) {
    if (anchorHash === null) throw new CliError("ANCHOR_REQUIRED", EXIT.EVIDENCE, "range export requires --anchor-hash");
    if (anchorHash !== ex.anchor.hash) throw new CliError("HASH_MISMATCH", EXIT.EVIDENCE, "anchor hash mismatch");
  }

  const ev = replayDir ? evidenceResolver(replayDir) : null;
  const result = verifyChain({
    entries: ex.entries, head: ex.head, keys: trust.keys,
    anchor: ex.anchor, tenant: trust.tenant, gateway: trust.gateway,
    checkTransitions: true,
    ...(ev ? { evidence: ev.get } : {}),
  });
  if (!result.valid) {
    out({ valid: false, code: result.code, through: ex.head.body.seq, scope: "chain", complete: ex.anchor === null });
    return EXIT.EVIDENCE;
  }
  if (ev) {
    // every referenced hash must resolve to validated content-addressed evidence
    const want = new Set<string>();
    for (const e of ex.entries) referencedHashes(e.body.facts, want);
    for (const h of want) ev.get(h);
    if (ev.missing.size > 0) {
      out({ valid: false, code: "INCOMPLETE_EVIDENCE", missing: [...ev.missing].sort(), through: ex.head.body.seq, scope: "chain", complete: false });
      return EXIT.EVIDENCE;
    }
    // tier replay: re-evaluate each admitted commit against its pinned policy
    for (const e of ex.entries) {
      if (e.body.type !== "ACTION_CREATED" || !e.body.facts.detail_hash) continue;
      const commit = ev.get(e.body.facts.detail_hash) as unknown as { call?: ToolCall; policy_hash?: string; tier?: string } | null;
      if (!commit || !commit.call || !commit.policy_hash) continue;
      const polBody = ev.get(commit.policy_hash) as unknown as Json | null;
      if (!polBody) continue;
      const pol = compilePolicy(polBody);
      const re = evaluate(pol, commit.call);
      const admittedTier = (e.body.facts as unknown as { tier?: string }).tier;
      if (admittedTier && re.tier !== admittedTier) {
        out({ valid: false, code: "TIER_MISMATCH", through: ex.head.body.seq, scope: "replay", complete: false });
        return EXIT.EVIDENCE;
      }
    }
  }
  // persist trust extension learned from verified rotation events
  if (result.extended && result.extended.length > 0) {
    const merged = [...trust.keys, ...result.extended];
    writeFileSync(trustPath, Buffer.from(canonicalBytes({ v: 1, tenant: trust.tenant, gateway: trust.gateway, keys: merged } as unknown as Json)).toString("utf8") + "\n", { mode: 0o600 });
  }
  out({ valid: true, through: ex.head.body.seq, scope: "chain", complete: ex.anchor === null });
  return EXIT.OK;
}

async function cmdRotateKey(client: Client, flags: Map<string, string>): Promise<number> {
  const newKeyId = req(flags, "new-key-id");
  const newPub = req(flags, "new-public-key");
  const expectedHead = uintFlag(flags, "expected-head-seq");
  if (!isId("key", newKeyId)) dieUsage("--new-key-id is not a key id");
  if (!RE.publicKey.test(newPub)) dieUsage("--new-public-key is not an Ed25519 public key");
  const r = await client.post("/v1/audit/rotate-key", {
    expected_head_seq: expectedHead, new_key_id: newKeyId, new_public_key: newPub,
  } as unknown as Json);
  out(r.body);
  return EXIT.OK;
}

async function cmdEvidenceGet(client: Client, flags: Map<string, string>): Promise<number> {
  const h = req(flags, "hash");
  if (!RE.hash.test(h)) dieUsage("--hash is not a hash");
  const r = await client.get(`/v1/evidence/${h}`);
  out(r.body);
  return EXIT.OK;
}

async function cmdStats(client: Client | null, flags: Map<string, string>): Promise<number> {
  const fromMs = uintFlag(flags, "from-ms");
  const toMs = uintFlag(flags, "to-ms");
  const auditFile = flags.get("audit") ?? null;
  const throughSeq = flags.has("through-seq") ? uintFlag(flags, "through-seq") : null;
  if (auditFile !== null && throughSeq !== null) dieUsage("--audit and --through-seq are mutually exclusive");
  if (auditFile !== null) {
    const ex = parseExportFile(auditFile);
    const points: DecisionPoint[] = [];
    for (const e of ex.entries) {
      if (e.body.type !== "DECISION_RECORDED" || !e.body.actor) continue;
      const f = e.body.facts as { verdict?: string; latency_ms?: number };
      if (typeof f.latency_ms !== "number") continue;
      points.push({
        reviewer: e.body.actor, received_ms: e.body.time_ms, seq: e.body.seq,
        approved: f.verdict === "approve" || f.verdict === "release", latency_ms: f.latency_ms,
      });
    }
    // offline roster is the union of reviewers observed in the export
    const reviewers = computeReviewerStats({ from_ms: fromMs, to_ms: toMs, decisions: points, roster: [] });
    out({ from_ms: fromMs, to_ms: toMs, through_seq: ex.head.body.seq, reviewers });
    return EXIT.OK;
  }
  if (!client) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "network stats requires client config");
  const query: Record<string, string> = { from_ms: String(fromMs), to_ms: String(toMs) };
  if (throughSeq !== null) query.through_seq = String(throughSeq);
  const r = await client.get("/v1/reviewers/stats", query);
  out(r.body);
  return EXIT.OK;
}

async function cmdReauditSample(flags: Map<string, string>): Promise<number> {
  const file = req(flags, "audit");
  const count = uintFlag(flags, "count");
  const seed = req(flags, "seed");
  if (count < 1 || count > 100) dieUsage("--count must be 1-100");
  if (!/^(0|[1-9][0-9]{0,14})$/.test(seed)) dieUsage("--seed must be a decimal UInt");
  const ex = parseExportFile(file);
  const decided = new Set<string>();
  const finalState = new Map<string, string>();
  for (const e of ex.entries) {
    const aid = e.body.action_id;
    if (!aid) continue;
    if (e.body.type === "DECISION_RECORDED" && e.body.actor) decided.add(aid);
    if (typeof e.body.facts.state === "string") finalState.set(aid, e.body.facts.state);
  }
  const eligible = [...decided].filter((a) => TERMINAL.has(finalState.get(a) ?? ""));
  const keyed = eligible.map((a) => ({
    a, k: createHash("sha256").update(Buffer.concat([Buffer.from(seed, "utf8"), Buffer.from([0]), Buffer.from(a, "utf8")])).digest("hex"),
  }));
  keyed.sort((x, y) => x.k === y.k ? (x.a < y.a ? -1 : 1) : (x.k < y.k ? -1 : 1));
  out({ action_ids: keyed.slice(0, count).map((k) => k.a) });
  return EXIT.OK;
}

async function cmdReauditOpen(client: Client, flags: Map<string, string>): Promise<number> {
  const action = req(flags, "action"); const reviewer = req(flags, "reviewer"); const reason = req(flags, "reason");
  if (!isId("action", action)) dieUsage("--action is not an action id");
  if (!isId("principal", reviewer)) dieUsage("--reviewer is not a principal id");
  if (reason !== "manual_sample" && reason !== "manual_rotation") dieUsage("--reason must be manual_sample|manual_rotation");
  const r = await client.post("/v1/re-audits", { action_id: action, reviewer, reason } as Json);
  out(r.body);
  return EXIT.OK;
}

async function cmdReauditGet(client: Client, flags: Map<string, string>): Promise<number> {
  const id = req(flags, "case");
  if (!isId("reaudit", id)) dieUsage("--case is not a re-audit id");
  const r = await client.get(`/v1/re-audits/${id}`);
  out(r.body);
  return EXIT.OK;
}

async function cmdReauditClose(client: Client, flags: Map<string, string>): Promise<number> {
  const id = req(flags, "case");
  if (!isId("reaudit", id)) dieUsage("--case is not a re-audit id");
  const verdict = req(flags, "verdict");
  if (verdict !== "uphold" && verdict !== "question") dieUsage("--verdict must be uphold|question");
  const r = await client.post(`/v1/re-audits/${id}/verdict`, { verdict } as Json);
  out(r.body);
  return EXIT.OK;
}

async function cmdStatus(client: Client): Promise<number> {
  const r = await client.get("/v1/status");
  out(r.body);
  return (r.body as { ready: boolean }).ready ? EXIT.OK : EXIT.NETWORK;
}

async function cmdServe(flags: Map<string, string>): Promise<number> {
  const gwPath = req(flags, "gateway-config");
  const port = uintFlag(flags, "port", 8787);
  if (port < 1 || port > 65535) dieUsage("--port out of range");
  const config = loadConfigFile(gwPath);
  if (config.production) {
    // §6.4/§line-338: production requires installed platform bindings (real
    // AUTH verifier, nonfixture audit signer, certified target adapters).
    // The OSS in-process fixtures cannot satisfy that; refuse to start.
    throw new CliError("CONFIG_INVALID", EXIT.USAGE,
      "production=true requires installed platform bindings; the OSS dev server only ships fixtures");
  }
  const policyRaw = loadPolicyFile(resolve(dirname(gwPath), config.policy_file));
  const built = await buildGateway(config, { dbPath: ":memory:" });
  // Dev fixture identities (loopback development only — spec §8 fixture
  // principals with well-known tokens; never usable in production).
  if (built.auth instanceof FixtureAuth) {
    built.auth.addPrincipal(config.tenant, "ltp_000000000000000000001", { kind: "agent", roles: ["invoke"], epoch: 1, verified_ms: Date.now() }, "tok-u");
    built.auth.addPrincipal(config.tenant, "ltp_000000000000000000002", { kind: "human", roles: ["review"], epoch: 1, verified_ms: Date.now() }, "tok-h");
    built.auth.addPrincipal(config.tenant, "ltp_000000000000000000003", { kind: "human", roles: ["admin", "audit"], epoch: 1, verified_ms: Date.now() }, "tok-admin");
    built.auth.addPrincipal(config.tenant, "ltp_000000000000000000004", { kind: "human", roles: ["review"], epoch: 1, verified_ms: Date.now() }, "tok-h2");
  }
  const seed = process.env.LEXTIER_AUDIT_SEED ?? null;
  if (seed !== null && !/^[0-9a-f]{64}$/.test(seed)) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "LEXTIER_AUDIT_SEED must be 32-byte hex");
  await boot(built, seed === null ? { policyRaw, adminActor: "ltp_000000000000000000000" } : { policyRaw, adminActor: "ltp_000000000000000000000", signerSeedHex: seed });
  const router = new Router(built.gw);
  const { port: bound } = await serve(router, "127.0.0.1", port);
  // The platform alarm drains the outbox in deployed mode; the dev server
  // emulates it with a 200 ms timer (dispatch + card delivery jobs).
  const drain = setInterval(() => {
    built.gw.drainOutbox().catch(() => { /* transient: next tick retries */ });
  }, 200);
  drain.unref?.();
  out({ ready: true, port: bound, production: config.production });
  await new Promise(() => { }); // run until SIGINT
  return EXIT.OK;
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------
const FLAG_SPECS: Record<string, { value: boolean }> = {
  "config": { value: true }, "json": { value: false }, "timeout-ms": { value: true },
  "help": { value: false }, "version": { value: false },
  "file": { value: true }, "policy": { value: true }, "expected-revision": { value: true },
  "wait-ms": { value: true }, "action": { value: true }, "hash": { value: true },
  "card": { value: true }, "revision": { value: true }, "reason": { value: true },
  "after": { value: true }, "through": { value: true }, "out": { value: true },
  "include-evidence": { value: true }, "trust": { value: true }, "anchor-hash": { value: true },
  "replay-evidence": { value: true }, "new-key-id": { value: true }, "new-public-key": { value: true },
  "expected-head-seq": { value: true }, "from-ms": { value: true }, "to-ms": { value: true },
  "through-seq": { value: true }, "audit": { value: true }, "count": { value: true },
  "seed": { value: true }, "reviewer": { value: true }, "case": { value: true },
  "verdict": { value: true }, "gateway-config": { value: true }, "port": { value: true },
};

const USAGE = `lextier ${VERSION} — LatticeAG LexTier CLI (protocol lextier/1)

usage: lextier [--config PATH] [--timeout-ms UINT] <command> [flags]

offline:
  policy lint --file POLICY.yaml
  policy evaluate --policy POLICY.yaml --file CALL.json
  audit verify --file AUDIT.jsonl --trust TRUST.json [--anchor-hash H] [--replay-evidence DIR]
  reaudit sample --audit AUDIT.jsonl --count N --seed UINT
  stats --from-ms A --to-ms B --audit AUDIT.jsonl
  serve --gateway-config GW.json --port N

network (requires client config + credential env):
  policy show | policy apply --file POLICY.yaml --expected-revision N
  policy evaluate-remote --file CALL.json
  submit --file CALL.json [--wait-ms N]
  get --action ID
  view --action ID --hash H --card ID
  decide --action ID --file DECISION.json
  cancel --action ID --revision N --reason requester_cancel|operator_cancel
  reconcile --action ID
  audit export --after A --through T --out FILE.jsonl [--include-evidence DIR]
  audit rotate-key --new-key-id ID --new-public-key HEX --expected-head-seq N
  evidence get --hash H
  stats --from-ms A --to-ms B [--through-seq N]
  reaudit open --action ID --reviewer ID --reason manual_sample|manual_rotation
  reaudit get --case ID
  reaudit close --case ID --verdict uphold|question
  status
`;

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const parsed = parseArgs(argv, FLAG_SPECS);
  const { cmd, flags } = parsed;

  if (flags.has("help")) { process.stdout.write(USAGE); return EXIT.OK; }
  if (flags.has("version")) { out({ version: VERSION, protocol: "lextier/1" }); return EXIT.OK; }
  void flags.get("json"); // output is always canonical JSON

  const offline = (cmd[0] === "policy" && (cmd[1] === "lint" || cmd[1] === "evaluate"))
    || (cmd[0] === "audit" && cmd[1] === "verify")
    || (cmd[0] === "reaudit" && cmd[1] === "sample")
    || cmd[0] === "serve"
    || (cmd[0] === "stats" && flags.has("audit"));

  let cfg: ClientConfig | null = null;
  if (!offline) {
    cfg = loadClientConfig(flags.get("config") ?? "./lextier-client.json");
  }
  const timeoutMs = flags.has("timeout-ms") ? uintFlag(flags, "timeout-ms") : null;
  const client = cfg ? new Client(cfg, timeoutMs) : null;

  const need = (c: Client | null): Client => { if (!c) throw new CliError("SCHEMA_INVALID", EXIT.USAGE, "command requires client config"); return c; };
  const key = cmd.join(" ");
  switch (key) {
    case "policy lint": return await cmdPolicyLint(flags);
    case "policy evaluate": return await cmdPolicyEvaluate(flags);
    case "policy evaluate-remote": return await cmdPolicyEvaluateRemote(need(client), flags);
    case "policy show": return await cmdPolicyShow(need(client));
    case "policy apply": return await cmdPolicyApply(need(client), flags);
    case "submit": return await cmdSubmit(need(client), flags);
    case "get": return await cmdGet(need(client), flags);
    case "view": return await cmdView(need(client), flags);
    case "decide": return await cmdDecide(need(client), flags);
    case "cancel": return await cmdCancel(need(client), flags);
    case "reconcile": return await cmdReconcile(need(client), flags);
    case "audit export": return await cmdAuditExport(need(client), flags);
    case "audit verify": return await cmdAuditVerify(flags);
    case "audit rotate-key": return await cmdRotateKey(need(client), flags);
    case "evidence get": return await cmdEvidenceGet(need(client), flags);
    case "stats": return await cmdStats(client, flags);
    case "reaudit sample": return await cmdReauditSample(flags);
    case "reaudit open": return await cmdReauditOpen(need(client), flags);
    case "reaudit get": return await cmdReauditGet(need(client), flags);
    case "reaudit close": return await cmdReauditClose(need(client), flags);
    case "status": return await cmdStatus(need(client));
    case "serve": return await cmdServe(flags);
    default:
      dieUsage(`unknown command '${key || "?"}' (try --help)`);
  }
}

process.on("SIGINT", () => { process.exitCode = EXIT.SIGINT; process.exit(EXIT.SIGINT); });

main().then((code) => process.exit(code)).catch((e) => {
  if (e instanceof CliError) {
    out({ error: { code: e.code, retryable: false, action_id: null } });
    diag(`error: ${e.message}`);
    process.exit(e.exit);
  }
  if (e && typeof e === "object" && "code" in e && typeof (e as { code: unknown }).code === "string") {
    const code = (e as { code: string }).code;
    out({ error: { code, retryable: false, action_id: (e as { actionId?: string | null }).actionId ?? null } });
    diag(`error: ${code}`);
    process.exit(codeToExit(code));
  }
  diag(`error: ${(e as Error).message ?? e}`);
  process.exit(EXIT.USAGE);
});
