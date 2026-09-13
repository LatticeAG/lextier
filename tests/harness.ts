/**
 * Conformance harness for the lextier/1 numbered vectors (spec §15).
 * Each vector is an independent reset: a fresh engine, fresh bindings,
 * deterministic ids and clock. Fixture names (P, R, FRESH, READY, STOP,
 * SUCCEEDED_FROM_READY, U, H, A, C) expand to real produced values only.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonicalBytes, type Json } from "../src/core/canonical.ts";
import { parseJsonStrict } from "../src/core/strict_json.ts";
import { parseYaml } from "../src/core/yaml.ts";
import { err, LexError, toErrorBody } from "../src/core/errors.ts";
import { hashDomainJson, hashJson, DOMAIN, ZERO_HASH } from "../src/core/hash.ts";
import { fixtureIdGen } from "../src/core/ids.ts";
import { edVerify, hexToBytes, edPublicKeyFromSeed, bytesToHex, edSign } from "../src/core/ed25519.ts";
import { validateCallArgs, type ToolCall, REGISTRY_HASH } from "../src/core/registry.ts";
import { compilePolicy, evaluate, policyHash, type Policy } from "../src/core/policy.ts";
import {
  eventHash, signMessage, verifyChain, signEntry, signHead,
  type AuditBody, type AuditEntry, type SignedHead, type HeadBody,
} from "../src/core/audit.ts";
import { computeReviewerStats, type DecisionPoint } from "../src/core/stats.ts";
import { gatewayConfigF } from "../src/core/config.ts";
import type { ActionCommit, AuthResult, BlastCard } from "../src/core/schemas.ts";
import { Store } from "../src/engine/store.ts";
import { FixtureAuth, FixtureShield, FixtureTools, FixtureInbox, LocalSigner } from "../src/engine/bindings.ts";
import { TenantGateway } from "../src/engine/gateway.ts";

export const TENANT = "ltt_000000000000000000001";
export const GATEWAY = "ltg_000000000000000000001";
export const U = "ltp_000000000000000000001";
export const H = "ltp_000000000000000000002";
export const ADMIN = "ltp_000000000000000000003";
export const H2 = "ltp_000000000000000000004";
export const KEY_ID = "ltk_000000000000000000001";
export const CONFORMANCE_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
export const AUDIT_PUB = bytesToHex(edPublicKeyFromSeed(hexToBytes(CONFORMANCE_SEED)));

/** P: the exact policy of spec §4.3. */
export const P: Policy = {
  v: 1, revision: 1, mode: "ENFORCE", review_ttl_ms: 120000, dispatch_ttl_ms: 5000,
  reviewers: [H],
  rules: [
    { id: "read-public", tool: "fs.read_text", when: [{ path: "/path", op: "path_under", value: "/workspace/public" }], tier: "allow" },
    { id: "write-drafts", tool: "fs.write_text", when: [{ path: "/path", op: "path_under", value: "/workspace/drafts" }], tier: "async_review" },
    { id: "select-products", tool: "db.select_rows", when: [{ path: "/table", op: "eq", value: "products" }], tier: "allow" },
  ],
  hard_denies: [
    { id: "private-files", tool: "fs.read_text", when: [{ path: "/path", op: "path_under", value: "/workspace/private" }] },
  ],
};

/** R.call / R.commit: the exact §8.4 exchange fixture. */
export const R_CALL: ToolCall = { tool: "fs.write_text", args: { path: "/workspace/drafts/a.txt", text: "hello", expected_version: "7" } };
export const R_TARGET = { resource: "file:/workspace/drafts/a.txt", version: "7", digest: "cba06b5736faf67e54b07b561eae94395e774c517a7d910a54369e1263ccfbd4" };

export function rCommit(): ActionCommit {
  return {
    v: 1, tenant: TENANT, gateway: GATEWAY,
    action_id: "lta_000000000000000000001", actor: U, auth_epoch: 1,
    call: R_CALL, registry_hash: REGISTRY_HASH, policy_hash: policyHash(P),
    shield_hash: "6d061f948257926c3602ee1647d1203780c3d255ec5a9eb156b68fea27a371c6",
    blast_hash: null, target: R_TARGET, created_ms: 1000000, expires_ms: 1120000,
  };
}

export const RH = "374995bc45e1bd9b970547ff7839083e429a69e6e07e1e445ce0b30904aa5e1b";

export interface Ctx {
  gw: TenantGateway; store: Store;
  auth: FixtureAuth; shield: FixtureShield; tools: FixtureTools;
  inbox: FixtureInbox; signer: LocalSigner;
  now: number;
}

export function fixtureConfig(): ReturnType<typeof gatewayConfigF> {
  return gatewayConfigF({
    v: 1, tenant: TENANT, gateway: GATEWAY, policy_file: "lextier.yaml",
    auth_binding: "AUTH", shield_binding: "LEXSHIELD", inbox_binding: "VEKINBOX",
    tools_binding: "TOOLS", audit_signer_binding: "AUDIT_SIGNER",
    audit_key_id: KEY_ID, audit_public_key: AUDIT_PUB,
    encryption_key_binding: "ACTION_ENCRYPTION_KEY",
    registry_profile: "known-tools-1", registry_version: 1,
    enabled_tools: ["db.delete_rows", "db.select_rows", "fs.read_text", "fs.remove_file", "fs.write_text", "payments.send"],
    payload_retention_ms: 86400000, terminal_retention_ms: 7776000000,
    human_identity_max_age_ms: 300000, production: false,
  });
}

export function newCtx(): Ctx {
  const ctx: Ctx = {
    now: 999000,
    store: new Store(":memory:"),
    auth: new FixtureAuth(),
    shield: new FixtureShield(),
    tools: new FixtureTools(),
    inbox: new FixtureInbox(),
    signer: new LocalSigner(),
    gw: null as unknown as TenantGateway,
  };
  ctx.auth.addPrincipal(TENANT, U, { kind: "agent", roles: ["invoke"], epoch: 1, verified_ms: 1000000 }, "tok-u");
  ctx.auth.addPrincipal(TENANT, H, { kind: "human", roles: ["review"], epoch: 1, verified_ms: 1000000 }, "tok-h");
  ctx.auth.addPrincipal(TENANT, ADMIN, { kind: "human", roles: ["admin", "audit"], epoch: 1, verified_ms: 1000000 }, "tok-admin");
  ctx.auth.addPrincipal(TENANT, H2, { kind: "human", roles: ["review"], epoch: 1, verified_ms: 1000000 }, "tok-h2");
  ctx.signer.addKey(KEY_ID, CONFORMANCE_SEED);
  ctx.gw = new TenantGateway({
    config: fixtureConfig(), store: ctx.store,
    wall: () => ctx.now, ids: fixtureIdGen(),
    auth: ctx.auth, shield: ctx.shield, tools: ctx.tools, inbox: ctx.inbox, signer: ctx.signer,
    encKey: new Uint8Array(32).fill(7), buildHash: "0".repeat(64),
  });
  return ctx;
}

export function authFor(ctx: Ctx, principal: string): AuthResult {
  const p = (ctx.auth as unknown as { principals: Map<string, { kind: AuthResult["kind"]; roles: AuthResult["roles"]; epoch: number; verified_ms: number; tenant: string }> }).principals.get(principal)!;
  return { tenant: p.tenant, principal, kind: p.kind, roles: [...p.roles], epoch: p.epoch, verified_ms: p.verified_ms };
}

export async function boot(ctx: Ctx, policy: Policy = P): Promise<void> {
  await ctx.gw.installKeyRegistry();
  await ctx.gw.bootstrap(ADMIN, policy);
}

export interface ActionRef { id: string; hash: string; card_id: string | null }

/** FRESH: admit R.call at 1000000 (PENDING), then H views at 1001000. */
export async function fixtureFresh(ctx: Ctx, call: ToolCall = R_CALL): Promise<ActionRef> {
  await boot(ctx);
  ctx.now = 1000000;
  const r = await ctx.gw.submit(authFor(ctx, U), call as unknown as Json, "fixture-admit-00001");
  if (r.status !== 202) throw new Error(`fixture admit failed: ${JSON.stringify(r.body)}`);
  const b = r.body as { action_id: string; action_hash: string; card_id: string };
  ctx.now = 1001000;
  await ctx.gw.view(authFor(ctx, H), b.action_id, { action_hash: b.action_hash, card_id: b.card_id });
  return { id: b.action_id, hash: b.action_hash, card_id: b.card_id };
}

export async function fixtureReady(ctx: Ctx): Promise<ActionRef> {
  const a = await fixtureFresh(ctx);
  ctx.now = 1001500;
  await ctx.gw.decide(authFor(ctx, H), a.id, {
    expected_revision: 1, action_hash: a.hash, card_id: a.card_id!,
    verdict: "approve", confirm_hash: null, reason: "reviewed",
  });
  return a;
}

export async function fixtureStop(ctx: Ctx, enrichTimeout = false): Promise<ActionRef> {
  if (enrichTimeout) ctx.tools.enrichTimeout = true;
  return fixtureFresh(ctx, { tool: "fs.remove_file", args: { path: "/workspace/drafts/a.txt", expected_version: "7" } });
}

export async function fixtureSucceeded(ctx: Ctx): Promise<ActionRef> {
  const a = await fixtureReady(ctx);
  ctx.now = 1002000;
  await ctx.gw.drainOutbox("DISPATCH");
  return a;
}

function stateOf(ctx: Ctx, id: string): string {
  return ctx.store.read((q) => (q.prepare("SELECT state FROM actions WHERE id=?").get(id) as { state: string } | undefined)?.state ?? "?");
}

function actionCount(ctx: Ctx): number {
  return ctx.store.read((q) => (q.prepare("SELECT COUNT(*) n FROM actions").get() as { n: number }).n);
}

function headSeq(ctx: Ctx): number {
  return ctx.store.read((q) => ctx.gw["headRow"](q).seq);
}

function auditEntries(ctx: Ctx, from: number, to: number): AuditEntry[] {
  return ctx.store.read((q) => q.prepare("SELECT entry FROM audit WHERE seq>? AND seq<=? ORDER BY seq").all(from, to) as { entry: Uint8Array }[])
    .map((r) => JSON.parse(Buffer.from(r.entry).toString("utf8")) as AuditEntry);
}

function headAt(ctx: Ctx, seq: number): SignedHead {
  return ctx.store.read((q) => {
    const r = q.prepare("SELECT body FROM heads WHERE seq=?").get(seq) as { body: Uint8Array } | undefined;
    return JSON.parse(Buffer.from(r!.body).toString("utf8")) as SignedHead;
  });
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(canonicalSort(a)) === JSON.stringify(canonicalSort(b));
}
function canonicalSort(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonicalSort);
  if (typeof v === "object" && v !== null) {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) o[k] = canonicalSort((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}

interface V { id: string; name: string; input: Record<string, unknown>; expected: Record<string, unknown> }

export async function runVector(v: V): Promise<{ id: string; pass: boolean; actual: unknown; error?: string }> {
  try {
    const actual = await runOp(v.input);
    const pass = deepEqual(actual, v.expected);
    return { id: v.id, pass, actual };
  } catch (e) {
    return { id: v.id, pass: false, actual: null, error: e instanceof Error ? e.stack ?? e.message : String(e) };
  }
}

async function runOp(input: Record<string, unknown>): Promise<unknown> {
  const op = input.op as string;
  switch (op) {
    case "evaluate": {
      const pol = policyWithOverrides(input);
      const call = input.call as ToolCall;
      try {
        return evaluate(pol, call) as unknown as Json;
      } catch (e) {
        if (e instanceof LexError) return { tier: null, reason: e.code, matched_rules: [], dispatchable: false, scope_checked: false };
        throw e;
      }
    }
    case "admit": {
      const ctx = newCtx();
      const pol = policyWithOverrides(input);
      await boot(ctx, pol);
      ctx.now = 1000000;
      const r = await ctx.gw.submit(authFor(ctx, U), input.call as Json, "fixture-admit-00001");
      const b = r.body as { state: string; reason: string };
      return { state: b.state, reason: b.reason, dispatch_count: ctx.tools.dispatchCount };
    }
    case "validate_call": {
      const call = input.call as ToolCall;
      try {
        validateCallArgs(call.tool, call.args);
        return { valid: true, code: "OK" };
      } catch (e) {
        if (e instanceof LexError) return { valid: false, code: e.code };
        throw e;
      }
    }
    case "parse_json": {
      try { parseJsonStrict(input.raw as string); return { valid: true, code: "OK" }; }
      catch (e) { if (e instanceof LexError) return { valid: false, code: e.code }; throw e; }
    }
    case "compile_yaml": {
      try {
        const doc = parseYaml(input.raw as string);
        compilePolicy(doc);
        return { valid: true, code: "OK" };
      } catch (e) { if (e instanceof LexError) return { valid: false, code: e.code }; throw e; }
    }
    case "canonical": {
      return { utf8: Buffer.from(canonicalBytes(input.value as Json)).toString("utf8") };
    }
    case "hash_action": {
      if (input.commit !== "R") throw new Error("unknown commit ref");
      return { hash: hashDomainJson(DOMAIN.ACTION, rCommit() as unknown as Json) };
    }
    case "compare_action_hash": {
      const left = rCommit() as unknown as Record<string, unknown>;
      const right = { ...left, ...(input.right_replace as Record<string, unknown>) };
      const lh = hashDomainJson(DOMAIN.ACTION, left as Json);
      const rh = hashDomainJson(DOMAIN.ACTION, right as Json);
      return { equal: lh === rh };
    }
    case "decide": return opDecide(input);
    case "dispatch": return opDispatch(input);
    case "race": return opRace(input);
    case "submit_twice": return opSubmitTwice(input);
    case "inbox_delivery": return opInbox(input);
    case "blast": return opBlast(input);
    case "signature_verify": {
      const valid = edVerify(hexToBytes(input.public_key as string), hexToBytes(input.message_hex as string), hexToBytes(input.signature as string));
      return { valid };
    }
    case "audit_genesis": return opAuditGenesis(input);
    case "audit_verify": return opAuditVerify(input);
    case "stats": return opStats(input);
    case "effects": return opEffects(input);
    case "get_action": return opGetAction(input);
    case "reaudit_effects": return opReaudit(input);
    default: throw new Error(`unknown op ${op}`);
  }
}

function policyWithOverrides(input: Record<string, unknown>): Policy {
  const base = structuredClone(P) as Policy & Record<string, unknown>;
  if (typeof input.mode === "string") base.mode = input.mode as Policy["mode"];
  if (input.append_rule) base.rules = [...base.rules, input.append_rule as Policy["rules"][number]];
  return compilePolicy(base);
}

function expandHash(x: unknown, a: ActionRef): string {
  if (x === "RH") return RH;
  if (x === "fixture_action_hash") return a.hash;
  return x as string;
}

async function buildFixture(ctx: Ctx, name: string): Promise<ActionRef> {
  if (name === "FRESH") return fixtureFresh(ctx);
  if (name === "READY") return fixtureReady(ctx);
  if (name === "STOP") return fixtureStop(ctx, true);
  if (name === "SUCCEEDED_FROM_READY") return fixtureSucceeded(ctx);
  throw new Error(`unknown fixture ${name}`);
}

async function opDecide(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  const a = await buildFixture(ctx, input.fixture as string);
  if (input.remove_view) {
    ctx.store.tx((q) => q.prepare("DELETE FROM views WHERE action_id=?").run(a.id));
  }
  // reviewer principal + optional kind overrides
  const reviewerName = input.reviewer as string;
  const reviewer = reviewerName === "H" ? H : reviewerName === "U" ? U : reviewerName;
  if (input.reviewer_is_human === true) ctx.auth.setKind(reviewer, "human");
  if (typeof input.identity_kind === "string") ctx.auth.setKind(reviewer, input.identity_kind as "service");
  if (typeof input.target_version === "string") ctx.tools.setVersion("/workspace/drafts/a.txt", input.target_version);
  ctx.now = input.now_ms as number;
  const ra = authFor(ctx, reviewer);
  const verdict = input.verdict as "approve" | "reject" | "release";
  const row = ctx.store.read((q) => q.prepare("SELECT revision FROM actions WHERE id=?").get(a.id) as { revision: number });
  let code = "OK";
  try {
    await ctx.gw.decide(ra, a.id, {
      expected_revision: row.revision,
      action_hash: expandHash(input.hash, a),
      card_id: a.card_id!,
      verdict,
      confirm_hash: input.confirm_hash === null || input.confirm_hash === undefined ? null : expandHash(input.confirm_hash, a),
      reason: verdict === "reject" ? "unsafe" : "reviewed",
    });
  } catch (e) {
    if (e instanceof LexError) code = e.code; else throw e;
  }
  return { state: stateOf(ctx, a.id), code, dispatch_count: ctx.tools.dispatchCount };
}

async function opDispatch(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  const a = await buildFixture(ctx, input.fixture as string);
  if (typeof input.target_version === "string") ctx.tools.setVersion("/workspace/drafts/a.txt", input.target_version);
  if (input.scope) ctx.shield.snapshot = input.scope as typeof ctx.shield.snapshot;
  if (typeof input.provider === "string") ctx.tools.provider = input.provider;
  if (input.audit_signer === "unavailable") ctx.signer.unavailable = true;
  if (input.inbox === "unavailable") ctx.inbox.unavailable = true;
  if (typeof input.persisted_now_ms === "number") {
    ctx.store.tx((q) => ctx.store.metaSetInt(q, "logical_now_ms", input.persisted_now_ms as number));
  }
  if (typeof input.policy_revision === "number") {
    // install P with mode replaced as the next revision via the real route
    const cur = ctx.store.read((q) => (q.prepare("SELECT revision FROM policies ORDER BY revision DESC LIMIT 1").get() as { revision: number }).revision);
    const p2 = structuredClone(P) as Policy;
    p2.revision = cur + 1;
    if (typeof input.policy_mode === "string") p2.mode = input.policy_mode as Policy["mode"];
    await ctx.gw.putPolicy(authFor(ctx, ADMIN), { expected_revision: cur, policy: p2 as unknown as Json });
  }
  ctx.now = (input.now_ms ?? input.wall_ms) as number;
  const runs = (input.alarm_runs as number) ?? 1;
  let code = "OK";
  let sawJob = false;
  for (let i = 0; i < runs; i++) {
    try {
      const outs = await ctx.gw.drainOutbox("DISPATCH");
      const rel = outs.filter((o) => o.kind === "DISPATCH");
      if (rel.length > 0) { sawJob = true; code = rel[rel.length - 1]!.code; }
      else if (!sawJob) {
        const st = stateOf(ctx, a.id);
        code = st === "READY" ? code : st === "EXPIRED" ? "EXPIRED" : "STATE_CONFLICT";
      }
    } catch (e) {
      if (e instanceof LexError) code = e.code; else throw e;
    }
  }
  const out: Record<string, unknown> = {
    state: stateOf(ctx, a.id), code, dispatch_count: ctx.tools.dispatchCount,
  };
  if (input.provider === "atomic_version_mismatch" || input.provider === "symlink_at_effect_boundary") {
    out.effect_count = ctx.tools.effectCount;
  }
  if (input.wall_ms !== undefined || input.persisted_now_ms !== undefined) {
    out.logical_now_ms = ctx.store.read((q) => ctx.store.metaGetInt(q, "logical_now_ms"));
  }
  return out;
}

async function opRace(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  const a = await buildFixture(ctx, input.fixture as string);
  ctx.now = input.now_ms as number;
  const codes: string[] = [];
  for (const cmd of input.commit_order as string[]) {
    try {
      if (cmd === "approve_by_H") {
        const rev = ctx.store.read((q) => (q.prepare("SELECT revision FROM actions WHERE id=?").get(a.id) as { revision: number }).revision);
        await ctx.gw.decide(authFor(ctx, H), a.id, {
          expected_revision: rev, action_hash: a.hash, card_id: a.card_id!,
          verdict: "approve", confirm_hash: null, reason: "reviewed",
        });
        codes.push("OK");
      } else if (cmd === "reject_by_H") {
        const rev = ctx.store.read((q) => (q.prepare("SELECT revision FROM actions WHERE id=?").get(a.id) as { revision: number }).revision);
        await ctx.gw.decide(authFor(ctx, H), a.id, {
          expected_revision: rev, action_hash: a.hash, card_id: a.card_id!,
          verdict: "reject", confirm_hash: null, reason: "unsafe",
        });
        codes.push("OK");
      } else if (cmd === "cancel_by_U") {
        const rev = ctx.store.read((q) => (q.prepare("SELECT revision FROM actions WHERE id=?").get(a.id) as { revision: number }).revision);
        await ctx.gw.cancel(authFor(ctx, U), a.id, { expected_revision: rev, reason: "requester_cancel" });
        codes.push("OK");
      } else if (cmd === "dispatch") {
        const outs = await ctx.gw.drainOutbox("DISPATCH");
        const rel = outs.filter((o) => o.kind === "DISPATCH");
        if (rel.length > 0) codes.push(rel[rel.length - 1]!.code);
        else codes.push(stateOf(ctx, a.id) === "READY" ? "OK" : "STATE_CONFLICT");
      } else throw new Error(`race cmd ${cmd}`);
    } catch (e) {
      if (e instanceof LexError) codes.push(e.code); else throw e;
    }
  }
  const out: Record<string, unknown> = {
    state: stateOf(ctx, a.id), codes, dispatch_count: ctx.tools.dispatchCount,
  };
  if ((input.commit_order as string[]).some((c) => c.includes("_by_") && (c.startsWith("approve") || c.startsWith("reject")))) {
    out.decision_count = ctx.store.read((q) => (q.prepare("SELECT COUNT(*) n FROM decisions WHERE action_id=?").get(a.id) as { n: number }).n);
  }
  return out;
}

async function opSubmitTwice(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  await boot(ctx); // fixture name FRESH here means a fresh deployment, not a pre-admitted R
  ctx.now = 1000000;
  const key = input.key as string;
  const expand = (c: unknown) => (c === "R.call" ? (R_CALL as unknown as Json) : (c as Json));
  const r1 = await ctx.gw.submit(authFor(ctx, U), expand(input.first_call), key);
  const seqAfterFirst = headSeq(ctx);
  const r2 = await ctx.gw.submit(authFor(ctx, U), expand(input.second_call), key).catch((e) => {
    if (e instanceof LexError) return { error: e };
    throw e;
  });
  if (r2 && "error" in r2 && r2.error instanceof LexError) {
    return { action_count: actionCount(ctx), code: r2.error.code, dispatch_count: ctx.tools.dispatchCount };
  }
  const rr2 = r2 as { status: number; body: Json; replayed: boolean };
  return {
    action_count: actionCount(ctx),
    response_equal: deepEqual(rr2.body, r1.body),
    second_replayed: rr2.replayed,
    new_audit_events_on_second: headSeq(ctx) - seqAfterFirst,
  };
}

async function opInbox(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  const a = await buildFixture(ctx, input.fixture as string);
  if (input.inbox === "unavailable") ctx.inbox.unavailable = true;
  ctx.now = input.now_ms as number;
  const runs = (input.alarm_runs as number) ?? 1;
  for (let i = 0; i < runs; i++) await ctx.gw.drainOutbox("CARD_UPSERT");
  return {
    state: stateOf(ctx, a.id),
    dispatch_count: ctx.tools.dispatchCount,
    card_delivered: a.card_id ? ctx.inbox.delivered(a.card_id) : false,
  };
}

async function opBlast(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  const enrichTimeout = input.inspect_enrichment === "timeout";
  const a = await buildFixture(ctx, input.fixture === "STOP" ? "STOP" : (input.fixture as string));
  void a;
  const view = await ctx.gw.getAction(authFor(ctx, ADMIN), a.id) as unknown as {
    action: { tier: string }; blast: BlastCard | null;
  };
  const b = view.blast!;
  return { status: b.status, files: b.files, rows: b.rows, money: b.money, undo: b.undo, tier: view.action.tier };
}

function genesisEntry(input: Record<string, unknown>): { entry: AuditEntry; head: SignedHead } {
  const seed = hexToBytes(CONFORMANCE_SEED);
  const body: AuditBody = {
    v: 1, tenant: input.tenant as string, gateway: input.gateway as string, seq: 1,
    event_id: input.event_id as string, time_ms: input.time_ms as number,
    type: "POLICY_ACTIVATED", actor: input.actor as string, action_id: null,
    prev_hash: ZERO_HASH,
    facts: {
      action_hash: null, policy_revision: 1, previous_state: null, state: null,
      reason: "POLICY_ACTIVATED", detail_hash: policyHash(P), latency_ms: null, verdict: null,
    },
  };
  const hash = eventHash(body);
  const signature = signEntry(seed, hash);
  const hb: HeadBody = { v: 1, tenant: body.tenant, gateway: body.gateway, seq: 1, hash, key_id: KEY_ID };
  return { entry: { body, hash, key_id: KEY_ID, signature }, head: { body: hb, signature: signHead(seed, hb) } };
}

async function opAuditGenesis(input: Record<string, unknown>): Promise<unknown> {
  const { entry } = genesisEntry(input);
  return { hash: entry.hash, signature: entry.signature };
}

async function opAuditVerify(input: Record<string, unknown>): Promise<unknown> {
  const keys = [{ key_id: KEY_ID, public_key: AUDIT_PUB, first_seq: 1, last_seq: null }];
  if (input.fixture === "genesis_from_TV-L--37") {
    const { entry, head } = genesisEntry({
      tenant: TENANT, gateway: GATEWAY, actor: ADMIN, event_id: "lte_000000000000000000001",
      time_ms: 1000000, policy: "P",
    });
    if (input.mutate) {
      const m = input.mutate as Record<string, unknown>;
      for (const [path, val] of Object.entries(m)) {
        if (path === "body.time_ms") entry.body.time_ms = val as number;
      }
    }
    const res = verifyChain({ entries: [entry], head, keys, tenant: TENANT, gateway: GATEWAY });
    return res.valid ? { valid: true, code: "OK" } : { valid: false, code: res.code };
  }
  if (input.fixture === "valid_entries_2_through_3") {
    const ctx = newCtx();
    await fixtureFresh(ctx);
    const entries = auditEntries(ctx, 1, 3);
    const head = headAt(ctx, 3);
    const anchorHash = input.anchor_hash === null ? null : { seq: 1, hash: input.anchor_hash as string };
    const res = verifyChain({
      entries, head, keys, tenant: TENANT, gateway: GATEWAY,
      anchor: anchorHash,
    });
    return res.valid ? { valid: true, code: "OK" } : { valid: false, code: res.code };
  }
  throw new Error(`audit_verify fixture ${input.fixture as string}`);
}

async function opStats(input: Record<string, unknown>): Promise<unknown> {
  const runs = input.runs as { count: number; verdict: string; latency_ms: number }[];
  const decisions: DecisionPoint[] = [];
  let t = 1000000, seq = 0;
  for (const r of runs) {
    for (let i = 0; i < r.count; i++) {
      seq += 1;
      decisions.push({ reviewer: H, received_ms: t, seq, approved: r.verdict === "approve", latency_ms: r.latency_ms });
      t += 10000;
    }
  }
  const rows = computeReviewerStats({ from_ms: 0, to_ms: 100000000, decisions, roster: [H] });
  const r0 = rows.find((r) => r.reviewer === H)!;
  return {
    decisions: r0.decisions, approved: r0.approved, rejected: r0.rejected,
    approval_bps: r0.approval_bps, median_latency_ms: r0.median_latency_ms,
    subsecond_bps: r0.subsecond_bps,
    prior_approval_bps: r0.prior_approval_bps,
    prior_median_latency_ms: r0.prior_median_latency_ms,
    flag: r0.flag,
  };
}

async function opEffects(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  const a = await buildFixture(ctx, input.fixture as string);
  // compute the named flag over a synthetic projection — must not touch state
  const synthetic: DecisionPoint[] = [];
  for (let i = 0; i < 20; i++) synthetic.push({ reviewer: H, received_ms: 1000000 + i * 10000, seq: i + 1, approved: true, latency_ms: 500 });
  const stats = computeReviewerStats({ from_ms: 0, to_ms: 2000000, decisions: synthetic, roster: [H] });
  if (stats[0]!.flag !== input.compute_flag) throw new Error(`flag computed ${stats[0]!.flag}, wanted ${input.compute_flag as string}`);
  const polRev = ctx.store.read((q) => ctx.store.metaGetInt(q, "active_policy_revision"));
  return { action_state: stateOf(ctx, a.id), dispatch_count: ctx.tools.dispatchCount, policy_revision: polRev };
}

async function opGetAction(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  const a = await buildFixture(ctx, input.fixture as string);
  void a;
  const auth = { ...authFor(ctx, ADMIN), tenant: input.auth_tenant as string };
  try {
    const body = await ctx.gw.getAction(auth, input.action_id as string);
    return { status: 200, body };
  } catch (e) {
    const { status, body } = toErrorBody(e);
    return { status, body };
  }
}

async function opReaudit(input: Record<string, unknown>): Promise<unknown> {
  const ctx = newCtx();
  const a = await buildFixture(ctx, "SUCCEEDED_FROM_READY");
  // policy revision 2 adds H2 to the reviewer roster
  const p2 = structuredClone(P) as Policy;
  p2.revision = 2;
  p2.reviewers = [...p2.reviewers, H2];
  await ctx.gw.putPolicy(authFor(ctx, ADMIN), { expected_revision: 1, policy: p2 as unknown as Json });
  const ra = await ctx.gw.reauditOpen(authFor(ctx, ADMIN), { action_id: a.id, reviewer: H2, reason: "manual_sample" });
  const raId = (ra as unknown as { reaudit_id: string }).reaudit_id;
  await ctx.gw.reauditVerdict(authFor(ctx, H2), raId, { verdict: input.reaudit_verdict as "question" });
  const raFinal = await ctx.gw.reauditGet(authFor(ctx, ADMIN), raId) as unknown as { state: string };
  const polRev = ctx.store.read((q) => ctx.store.metaGetInt(q, "active_policy_revision"));
  return {
    action_state: stateOf(ctx, a.id), dispatch_count: ctx.tools.dispatchCount,
    policy_revision: polRev, reaudit_state: raFinal.state,
  };
}

// ---------------- runner ----------------

export async function runAll(): Promise<{ passed: number; failed: number; failures: { id: string; actual: unknown; expected: unknown; error?: string }[] }> {
  const here = dirname(fileURLToPath(import.meta.url));
  const vectors = JSON.parse(readFileSync(join(here, "..", "conformance", "vectors.json"), "utf8")) as V[];
  const failures: { id: string; actual: unknown; expected: unknown; error?: string }[] = [];
  let passed = 0;
  for (const v of vectors) {
    const r = await runVector(v);
    if (r.pass) passed++;
    else failures.push(r.error === undefined
      ? { id: v.id, actual: r.actual, expected: v.expected }
      : { id: v.id, actual: r.actual, expected: v.expected, error: r.error });
  }
  return { passed, failed: failures.length, failures };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { passed, failed, failures } = await runAll();
  for (const f of failures) {
    console.log(`FAIL ${f.id}`);
    if (f.error) console.log(`  error: ${f.error.split("\n")[0]}`);
    console.log(`  expected: ${JSON.stringify(f.expected)}`);
    console.log(`  actual:   ${JSON.stringify(f.actual)}`);
  }
  console.log(`${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}
