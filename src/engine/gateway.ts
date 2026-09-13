/**
 * TenantGateway: the single-writer per-tenant engine implementing the
 * lextier/1 admission/decision/dispatch pipelines (spec §6), the signed audit
 * chain (§7), the outbox machine (§6.3), retention (§11.2), and recovery.
 *
 * Two-phase commit discipline: phase 1 runs inside a rolled-back transaction
 * (reads + event planning only — all writes are deferred via `apply`), event
 * bodies are built against the current head and signed via AUDIT_SIGNER,
 * then phase 2 revalidates the head CAS and applies domain writes plus the
 * signed audit inserts atomically. Network I/O never happens inside a
 * transaction, and nothing irreversible is sent from an uncommitted plan.
 */

import { canonicalBytes, type Json } from "../core/canonical.ts";
import { err, LexError } from "../core/errors.ts";
import { hashJson, sha256Hex, hashDomainJson, DOMAIN, ZERO_HASH, RE } from "../core/hash.ts";
import { isId, type IdGen } from "../core/ids.ts";
import {
  BUILTIN_DENIED, isRegisteredTool, validateCallShape, validateCallArgs,
  type ToolCall, type Tier, REGISTRY_DESCRIPTOR, REGISTRY_HASH,
} from "../core/registry.ts";
import { compilePolicy, evaluate, policyHash, type Policy } from "../core/policy.ts";
import {
  eventHash, signMessage, verifyRotationSig,
  type AuditBody, type AuditEntry, type AuditFacts, type EventType, type HeadBody,
  type SignedHead, type KeyRotation, TERMINAL_STATES,
} from "../core/audit.ts";
import {
  type ActionCommit, type ActionHandle, type BlastCard, type Card,
  type Decision, type DecisionInput, type Target, type ToolResult,
  type AuthResult, type ScopeSnapshot, type InspectResult,
} from "../core/schemas.ts";
import { computeReviewerStats, type DecisionPoint } from "../core/stats.ts";
import { Store, type Tx } from "./store.ts";
import { sealJson, openJson, type Envelope } from "./box.ts";
import {
  BindingError, scopeHash,
  type AuthBinding, type ShieldBinding, type ToolsBinding, type InboxBinding, type SignerBinding,
} from "./bindings.ts";
import type { GatewayConfig } from "../core/config.ts";

export interface GatewayDeps {
  config: GatewayConfig;
  store: Store;
  wall: () => number;
  ids: IdGen;
  auth: AuthBinding;
  shield: ShieldBinding;
  tools: ToolsBinding;
  inbox: InboxBinding;
  signer: SignerBinding;
  encKey: Uint8Array;
  buildHash: string;
}

export type ActionState =
  | "PENDING" | "STOPPED" | "READY" | "DISPATCHING" | "SUCCEEDED"
  | "FAILED" | "UNKNOWN" | "DENIED" | "REJECTED" | "EXPIRED" | "STALE" | "CANCELED";

const MAX_NONTERMINAL = 1000;
const MAX_OUTBOX_PENDING = 5000;
const DISPATCH_RETRY_MS = [250, 500, 1000];
const CARD_BACKOFF_MS = [1000, 2000, 4000, 8000, 16000, 30000];
const CARD_CLOSE_BUDGET_MS = 24 * 3600 * 1000;
const OUTBOX_LEASE_MS = 10000;
const OBS_MAX_AGE_MS = 1000;
const CLOCK_REGRESSION_MS = 1000;

const UNKNOWN_BLAST_INSTRUCTION = "No verified undo path.";

const REASON_BY_TIER: Record<Tier, string> = {
  allow: "ALLOWED", async_review: "REVIEW_REQUIRED", hard_stop: "STOP_REQUIRED",
};

export interface ActionRow {
  id: string; hash: string; state: ActionState; revision: number; actor: string;
  policy_revision: number; expires_ms: number; dispatch_deadline_ms: number | null;
  encrypted_commit: Envelope | null; payload_gone: boolean;
  handle: { tier: Tier | null; reason: string; card_id: string | null; decision_id: string | null };
}

interface PendingEvent {
  type: EventType; actor: string | null; action_id: string | null;
  facts: AuditFacts;
  evidence: { kind: string; body: Json }[];
}

type Emit = (e: PendingEvent) => void;

export interface CommitPlan<T> {
  result: T;
  /** deferred domain writes, executed inside the phase-2 commit */
  apply?: (q: Tx) => void;
  /** extra phase-2 assertions; throwing aborts the commit */
  recheck?: (q: Tx) => void;
  /** thrown to the caller after the commit succeeds (terminalize-then-409) */
  postThrow?: LexError;
}

export interface IdemCtx {
  method: string; path: string; key: string; bodyHash: string; status: number;
}

export class TenantGateway {
  private chain: Promise<unknown> = Promise.resolve();
  private rateBuckets = new Map<string, { tokens: number; refill_ms: number }>();
  private clearingLatch = false;
  readonly deps: GatewayDeps;

  constructor(deps: GatewayDeps) { this.deps = deps; }

  get config(): GatewayConfig { return this.deps.config; }

  serial<T>(op: () => Promise<T>): Promise<T> {
    const run = this.chain.then(op);
    this.chain = run.then(() => undefined, () => undefined);
    return run;
  }

  // ---------------- clock / pause ----------------

  private tick(q: Tx): number {
    const s = this.deps.store;
    const stored = s.metaGetInt(q, "logical_now_ms") ?? 0;
    const wall = this.deps.wall();
    if (wall + CLOCK_REGRESSION_MS < stored) throw err("CLOCK_UNSAFE");
    return Math.max(stored, wall);
  }

  private wallNow(): number { return this.deps.wall(); }

  private pausedReason(q: Tx): string | null {
    return this.deps.store.metaGet(q, "paused_reason");
  }

  /** Latch blocks ops unless this commit is the resume that clears it. */
  private pausedBlocked(q: Tx): string | null {
    const p = this.pausedReason(q);
    return p !== null && !this.clearingLatch ? p : null;
  }

  // ---------------- encryption helpers ----------------

  private seal(table: string, pk: string, value: Json): Envelope {
    return sealJson(this.deps.encKey, { tenant: this.config.tenant, gateway: this.config.gateway, table, primary_key: pk }, value);
  }
  private open<T>(table: string, pk: string, env: Envelope): T {
    return openJson(this.deps.encKey, { tenant: this.config.tenant, gateway: this.config.gateway, table, primary_key: pk }, env) as T;
  }

  // ---------------- audit chain commit ----------------

  private headRow(q: Tx): { seq: number; hash: string } {
    const s = this.deps.store;
    return { seq: s.metaGetInt(q, "head_seq") ?? 0, hash: s.metaGet(q, "head_hash") ?? ZERO_HASH };
  }

  private facts(partial: Partial<AuditFacts> & Pick<AuditFacts, "reason">, policyRev: number): AuditFacts {
    return {
      action_hash: partial.action_hash ?? null,
      policy_revision: policyRev,
      previous_state: partial.previous_state ?? null,
      state: partial.state ?? null,
      reason: partial.reason,
      detail_hash: partial.detail_hash ?? null,
      latency_ms: partial.latency_ms ?? null,
      verdict: partial.verdict ?? null,
    };
  }

  private async commit<T>(fn: (q: Tx, emit: Emit, now: number) => CommitPlan<T>): Promise<T> {
    // ---- phase 1: plan (tx always rolled back; writes only via apply) ----
    let plan: CommitPlan<T>;
    let now = 0, headSeq = 0, headHash = ZERO_HASH, keyId = "";
    const events: PendingEvent[] = [];
    const db = this.deps.store.db;
    db.exec("BEGIN IMMEDIATE");
    try {
      now = this.tick(db);
      const h = this.headRow(db);
      headSeq = h.seq; headHash = h.hash;
      keyId = this.deps.store.metaGet(db, "active_key_id") ?? this.config.audit_key_id;
      const emit: Emit = (e) => events.push(e);

      // pause/resume bookkeeping: if a pause latch is set and its invariant is
      // now healthy, record PAUSED+RESUMED ahead of this commit's own events.
      const latch = this.pausedReason(db);
      if (latch !== null) {
        const healthy = latch === "CLOCK_UNSAFE" ? this.deps.wall() >= (this.deps.store.metaGetInt(db, "logical_now_ms") ?? 0) : true;
        if (healthy) {
          emit({
            type: "GATEWAY_PAUSED", actor: null, action_id: null,
            facts: this.facts({ reason: latch === "CLOCK_UNSAFE" ? "CLOCK_UNSAFE" : latch === "AUDIT_UNAVAILABLE" ? "AUDIT_UNAVAILABLE" : latch === "DEPENDENCY_UNAVAILABLE" ? "DEPENDENCY_UNAVAILABLE" : "INVARIANT_BREACH", detail_hash: hashJson({ reason: latch, build_hash: this.deps.buildHash }) }, this.activePolicy(db)?.revision ?? 0),
            evidence: [{ kind: "lifecycle", body: { reason: latch, build_hash: this.deps.buildHash } }],
          });
          emit({
            type: "GATEWAY_RESUMED", actor: null, action_id: null,
            facts: this.facts({ reason: "INVARIANT_RESTORED", detail_hash: hashJson({ reason: "INVARIANT_RESTORED", build_hash: this.deps.buildHash }) }, this.activePolicy(db)?.revision ?? 0),
            evidence: [{ kind: "lifecycle", body: { reason: "INVARIANT_RESTORED", build_hash: this.deps.buildHash } }],
          });
          events.push({ type: "__CLEAR_LATCH__" as EventType, actor: null, action_id: null, facts: this.facts({ reason: "X" }, 0), evidence: [] });
        }
      }

      this.clearingLatch = events.some((e) => (e.type as string) === "__CLEAR_LATCH__");
      try {
        plan = fn(db, emit, now);
      } finally {
        this.clearingLatch = false;
      }
    } catch (e) {
      db.exec("ROLLBACK");
      if (e instanceof LexError && e.code === "CLOCK_UNSAFE") {
        // persist the fail-closed latch even though the plan tx rolled back
        this.deps.store.tx((q2) => this.deps.store.metaSet(q2, "paused_reason", "CLOCK_UNSAFE"));
      }
      throw e;
    }
    db.exec("ROLLBACK");
    // strip the internal latch marker from the event stream (not a real event)
    const clearLatch = events.some((e) => (e.type as string) === "__CLEAR_LATCH__");
    const realEvents = events.filter((e) => (e.type as string) !== "__CLEAR_LATCH__");

    // ---- sign (outside any transaction) ----
    const signed: { entry: AuditEntry; head: SignedHead; evidence: PendingEvent["evidence"] }[] = [];
    let seq = headSeq, prev = headHash;
    try {
      for (const e of realEvents) {
        seq += 1;
        const body: AuditBody = {
          v: 1, tenant: this.config.tenant, gateway: this.config.gateway, seq,
          event_id: this.deps.ids("event"), time_ms: now, type: e.type,
          actor: e.actor, action_id: e.action_id, prev_hash: prev, facts: e.facts,
        };
        const hash = eventHash(body);
        const m = signMessage(hash);
        const r1 = await this.deps.signer.sign({ key_id: keyId, purpose: "entry", message_hex: Buffer.from(m).toString("hex") });
        const hb: HeadBody = { v: 1, tenant: this.config.tenant, gateway: this.config.gateway, seq, hash, key_id: keyId };
        const hm = new Uint8Array([...new TextEncoder().encode(DOMAIN.HEAD), 0, ...canonicalBytes(hb as unknown as Json)]);
        const r2 = await this.deps.signer.sign({ key_id: keyId, purpose: "head", message_hex: Buffer.from(hm).toString("hex") });
        if (!RE.signature.test(r1.signature) || !RE.signature.test(r2.signature)) throw err("ADAPTER_PROTOCOL");
        signed.push({
          entry: { body, hash, key_id: keyId, signature: r1.signature },
          head: { body: hb, signature: r2.signature },
          evidence: e.evidence,
        });
        prev = hash;
      }
    } catch (se) {
      if (se instanceof LexError && se.code === "ADAPTER_PROTOCOL") throw se;
      this.deps.store.tx((q2) => {
        if (this.pausedReason(q2) === null) this.deps.store.metaSet(q2, "paused_reason", "AUDIT_UNAVAILABLE");
      });
      throw err("AUDIT_UNAVAILABLE");
    }

    // ---- phase 2: CAS + domain writes + signed audit inserts ----
    const committed = this.deps.store.tx((q) => {
      const h = this.headRow(q);
      if (h.seq !== headSeq) throw err("STATE_CONFLICT");
      plan.recheck?.(q);
      this.deps.store.metaSetInt(q, "logical_now_ms", now);
      if (clearLatch) q.prepare("DELETE FROM meta WHERE key='paused_reason'").run();
      plan.apply?.(q);
      for (const s of signed) {
        q.prepare("INSERT INTO audit (seq, event_id, hash, type, action_id, entry) VALUES (?, ?, ?, ?, ?, ?)")
          .run(s.entry.body.seq, s.entry.body.event_id, s.entry.hash, s.entry.body.type, s.entry.body.action_id, Buffer.from(canonicalBytes(s.entry as unknown as Json)));
        q.prepare("INSERT INTO heads (seq, body) VALUES (?, ?)")
          .run(s.head.body.seq, Buffer.from(canonicalBytes(s.head as unknown as Json)));
        for (const ev of s.evidence) {
          const eh = hashJson(ev.body);
          const enc = this.seal("evidence", eh, ev.body);
          q.prepare("INSERT INTO evidence (hash, kind, encrypted_body, delete_after_ms) VALUES (?, ?, ?, NULL) ON CONFLICT(hash) DO NOTHING")
            .run(eh, ev.kind, Buffer.from(JSON.stringify(enc)));
        }
      }
      if (signed.length > 0) {
        const last = signed[signed.length - 1]!;
        this.deps.store.metaSetInt(q, "head_seq", last.head.body.seq);
        this.deps.store.metaSet(q, "head_hash", last.entry.hash);
      }
      return plan.result;
    });
    if (plan.postThrow) throw plan.postThrow;
    return committed;
  }

  // ---------------- normalization ----------------

  /**
   * Plan deadline normalization (read-only in phase 1): emits EXPIRED events
   * and returns the post-normalization row copies plus a deferred apply.
   * Callers must consult `rows` (not fresh SELECTs) for normalized state.
   */
  private planExpiry(q: Tx, now: number, emit: Emit): { rows: ActionRow[]; apply: (q: Tx) => void } {
    const due = q.prepare(
      `SELECT * FROM actions WHERE (state IN ('PENDING','STOPPED') AND expires_ms <= ?)
         OR (state = 'READY' AND dispatch_deadline_ms IS NOT NULL AND dispatch_deadline_ms <= ?)`,
    ).all(now, now) as Record<string, unknown>[];
    const rows: ActionRow[] = [];
    const steps: ((q: Tx) => void)[] = [];
    for (const raw of due) {
      const row = this.rowToAction(raw);
      const prev = row.state;
      const deadline = row.state === "READY" ? row.dispatch_deadline_ms! : row.expires_ms;
      row.state = "EXPIRED";
      row.revision += 1;
      row.dispatch_deadline_ms = null;
      row.handle.reason = "EXPIRED";
      rows.push(row);
      const detail = { action_id: row.id, deadline_ms: deadline, reason: "EXPIRED" };
      emit({
        type: "ACTION_EXPIRED", actor: null, action_id: row.id,
        facts: this.facts({ action_hash: row.hash, previous_state: prev, state: "EXPIRED", reason: "EXPIRED", detail_hash: hashJson(detail) }, row.policy_revision),
        evidence: [{ kind: "control", body: detail as unknown as Json }],
      });
      steps.push((q2) => {
        this.writeAction(q2, row);
        this.enqueueClosingCard(q2, row, now);
        this.cancelJobs(q2, row.id);
        this.writeTerminalResult(q2, row, "EXPIRED");
      });
    }
    return { rows, apply: (q2) => { for (const s of steps) s(q2); } };
  }

  /** Load an action consulting planned expiry first. */
  private loadNorm(q: Tx, id: string, expired: ActionRow[]): ActionRow | null {
    const e = expired.find((r) => r.id === id);
    return e ?? this.loadAction(q, id);
  }

  // ---------------- row helpers ----------------

  private loadAction(q: Tx, id: string): ActionRow | null {
    const r = q.prepare("SELECT * FROM actions WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    return r ? this.rowToAction(r) : null;
  }

  private rowToAction(r: Record<string, unknown>): ActionRow {
    const enc = r.encrypted_commit === null ? null : (JSON.parse(Buffer.from(r.encrypted_commit as Uint8Array).toString("utf8")) as Envelope);
    const handle = JSON.parse(Buffer.from(r.handle as Uint8Array).toString("utf8")) as ActionRow["handle"];
    return {
      id: r.id as string, hash: r.hash as string, state: r.state as ActionState,
      revision: r.revision as number, actor: r.actor as string,
      policy_revision: r.policy_revision as number, expires_ms: r.expires_ms as number,
      dispatch_deadline_ms: r.dispatch_deadline_ms === null ? null : (r.dispatch_deadline_ms as number),
      encrypted_commit: enc, payload_gone: (r.payload_gone as number) === 1, handle,
    };
  }

  private commitOf(row: ActionRow): ActionCommit | null {
    if (!row.encrypted_commit) return null;
    return this.open<ActionCommit>("actions", row.id, row.encrypted_commit);
  }

  private handle(row: ActionRow): ActionHandle {
    return {
      action_id: row.id, action_hash: row.hash, state: row.state, revision: row.revision,
      tier: row.handle.tier, reason: row.handle.reason, expires_ms: row.expires_ms,
      dispatch_deadline_ms: row.state === "READY" ? row.dispatch_deadline_ms : null,
      card_id: row.handle.card_id,
    };
  }

  private writeAction(q: Tx, row: ActionRow): void {
    q.prepare(`INSERT INTO actions (id, hash, state, revision, actor, policy_revision, expires_ms, dispatch_deadline_ms, encrypted_commit, payload_gone, handle)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET state=excluded.state, revision=excluded.revision,
        dispatch_deadline_ms=excluded.dispatch_deadline_ms, encrypted_commit=excluded.encrypted_commit,
        payload_gone=excluded.payload_gone, handle=excluded.handle`)
      .run(row.id, row.hash, row.state, row.revision, row.actor, row.policy_revision, row.expires_ms,
        row.dispatch_deadline_ms,
        row.encrypted_commit ? Buffer.from(JSON.stringify(row.encrypted_commit)) : null,
        row.payload_gone ? 1 : 0,
        Buffer.from(JSON.stringify(row.handle)));
  }

  private activePolicy(q: Tx): { revision: number; policy: Policy; hash: string } | null {
    const rev = this.deps.store.metaGetInt(q, "active_policy_revision");
    if (rev === null) return null;
    const r = q.prepare("SELECT hash, body FROM policies WHERE revision = ?").get(rev) as { hash: string; body: Uint8Array } | undefined;
    if (!r) return null;
    return { revision: rev, policy: JSON.parse(Buffer.from(r.body).toString("utf8")) as Policy, hash: r.hash };
  }

  private evidenceGet(q: Tx, hash: string): Json | null {
    const r = q.prepare("SELECT kind, encrypted_body FROM evidence WHERE hash = ?").get(hash) as { kind: string; encrypted_body: Uint8Array } | undefined;
    if (!r) return null;
    const env = JSON.parse(Buffer.from(r.encrypted_body).toString("utf8")) as Envelope;
    return this.open<Json>("evidence", hash, env);
  }

  private writeTerminalResult(q: Tx, row: ActionRow, code: string): void {
    const res: ToolResult = { status: "not_executed", code, output: null, provider_ref: null };
    const enc = this.seal("results", row.id, res as unknown as Json);
    const del = this.wallNow() + this.config.terminal_retention_ms;
    q.prepare("INSERT INTO results (action_id, encrypted_body, delete_after_ms) VALUES (?,?,?) ON CONFLICT(action_id) DO UPDATE SET encrypted_body=excluded.encrypted_body, delete_after_ms=excluded.delete_after_ms")
      .run(row.id, Buffer.from(JSON.stringify(enc)), del);
  }

  private cancelJobs(q: Tx, actionId: string): void {
    q.prepare("UPDATE outbox SET state = 'CANCELED', revision = revision + 1 WHERE action_id = ? AND state IN ('QUEUED','CLAIMED')").run(actionId);
  }

  private cardFor(q: Tx, row: ActionRow): Card {
    const commit = this.commitOf(row);
    const pol = this.activePolicy(q);
    const actions: ("approve" | "reject" | "release")[] =
      row.state === "PENDING" ? ["approve", "reject"]
        : row.state === "STOPPED" ? ["release", "reject"]
          : [];
    let blast: BlastCard | null = null;
    if (commit?.blast_hash) {
      const ev = this.evidenceGet(q, commit.blast_hash);
      blast = ev ? (ev as unknown as BlastCard) : null;
    }
    return {
      card_id: row.handle.card_id ?? "",
      action: this.handle(row),
      principal: row.actor,
      call: commit?.call ?? { tool: "", args: {} },
      policy_revision: pol?.revision ?? row.policy_revision,
      mode: pol?.policy.mode ?? "ENFORCE",
      blast,
      actions,
    };
  }

  private enqueueCard(q: Tx, row: ActionRow, now: number): void {
    if (!row.handle.card_id) return;
    const card = this.cardFor(q, row);
    const enc = this.seal("outbox", card.card_id, card as unknown as Json);
    q.prepare(`INSERT INTO outbox (id, action_id, kind, state, revision, due_ms, claim_until_ms, body)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(this.deps.ids("outbox"), row.id, "CARD_UPSERT", "QUEUED", 1, now, null, Buffer.from(JSON.stringify(enc)));
  }

  private enqueueClosingCard(q: Tx, row: ActionRow, now: number): void {
    this.enqueueCard(q, row, now);
  }

  private enqueueDispatch(q: Tx, row: ActionRow, now: number): string {
    const existing = q.prepare("SELECT id FROM outbox WHERE action_id = ? AND kind = 'DISPATCH'").get(row.id) as { id: string } | undefined;
    if (existing) return existing.id;
    const commit = this.commitOf(row)!;
    const body: Json = {
      action_hash: row.hash, action_id: row.id, call: commit.call as unknown as Json,
      not_after_ms: row.dispatch_deadline_ms ?? row.expires_ms, target: commit.target as unknown as Json,
    };
    const enc = this.seal("outbox", row.id, body);
    const id = this.deps.ids("outbox");
    q.prepare(`INSERT INTO outbox (id, action_id, kind, state, revision, due_ms, claim_until_ms, body)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(id, row.id, "DISPATCH", "QUEUED", 1, now, null, Buffer.from(JSON.stringify(enc)));
    return id;
  }

  // ---------------- bootstrap / readiness ----------------

  async bootstrap(adminActor: string, policyRaw: unknown): Promise<{ revision: number; policy_hash: string }> {
    return this.serial(async () => {
      const existing = this.deps.store.read((q) => this.activePolicy(q));
      if (existing) return { revision: existing.revision, policy_hash: existing.hash };
      const policy = compilePolicy(policyRaw);
      if (policy.revision !== 1) throw err("POLICY_INVALID");
      const ph = policyHash(policy);
      return this.commit((q, emit, _now) => {
        emit({
          type: "POLICY_ACTIVATED", actor: adminActor, action_id: null,
          facts: this.facts({ reason: "POLICY_ACTIVATED", detail_hash: ph }, 1),
          evidence: [
            { kind: "policy", body: policy as unknown as Json },
            { kind: "registry", body: REGISTRY_DESCRIPTOR as unknown as Json },
          ],
        });
        return {
          result: { revision: 1, policy_hash: ph },
          apply: (q2) => {
            this.deps.store.metaSetInt(q2, "storage_version", 1);
            this.deps.store.metaSet(q2, "registry_hash", REGISTRY_HASH);
            this.deps.store.metaSet(q2, "build_hash", this.deps.buildHash);
            this.deps.store.metaSet(q2, "active_key_id", this.config.audit_key_id);
            q2.prepare("INSERT INTO policies (revision, hash, body) VALUES (?,?,?)")
              .run(1, ph, Buffer.from(canonicalBytes(policy as unknown as Json)));
            this.deps.store.metaSetInt(q2, "active_policy_revision", 1);
          },
        };
      });
    });
  }

  async installKeyRegistry(): Promise<void> {
    this.deps.store.tx((q) => {
      const kr = q.prepare("SELECT key_id FROM key_registry WHERE key_id = ?").get(this.config.audit_key_id);
      if (!kr) {
        q.prepare("INSERT INTO key_registry (key_id, public_key, first_seq, last_seq) VALUES (?,?,1,NULL)")
          .run(this.config.audit_key_id, this.config.audit_public_key);
      }
    });
  }

  async status(): Promise<Json> {
    return this.serial(async () => this.deps.store.read((q) => {
      const pol = this.activePolicy(q);
      let clock: "safe" | "unsafe" = "safe";
      const stored = this.deps.store.metaGetInt(q, "logical_now_ms") ?? 0;
      if (this.deps.wall() + CLOCK_REGRESSION_MS < stored) clock = "unsafe";
      const paused = this.pausedReason(q);
      const ready = pol !== null && paused === null && clock === "safe";
      return { protocol: "lextier/1", ready, policy_revision: pol?.revision ?? 0, mode: pol?.policy.mode ?? "ENFORCE", clock } as unknown as Json;
    }));
  }

  // ---------------- rate limiting / idempotency ----------------

  private rateLimit(bucketKey: string, perSec: number): boolean {
    const now = this.wallNow();
    const b = this.rateBuckets.get(bucketKey) ?? { tokens: perSec, refill_ms: now };
    const elapsed = now - b.refill_ms;
    if (elapsed > 0) {
      b.tokens = Math.min(perSec, b.tokens + (elapsed * perSec) / 1000);
      b.refill_ms = now;
    }
    if (b.tokens < 1) { this.rateBuckets.set(bucketKey, b); return false; }
    b.tokens -= 1;
    this.rateBuckets.set(bucketKey, b);
    return true;
  }

  idemLookup(q: Tx, principal: string, method: string, path: string, key: string, bodyHash: string): { status: number; body: Json } | "conflict" | null {
    const r = q.prepare("SELECT body_hash, status, encrypted_response FROM idempotency WHERE principal=? AND method=? AND path=? AND key=?")
      .get(principal, method, path, key) as { body_hash: string; status: number; encrypted_response: Uint8Array } | undefined;
    if (!r) return null;
    if (r.body_hash !== bodyHash) return "conflict";
    const env = JSON.parse(Buffer.from(r.encrypted_response).toString("utf8")) as Envelope;
    const body = this.open<Json>("idempotency", `${principal}:${method}:${path}:${key}`, env);
    return { status: r.status, body };
  }

  idemStore(q: Tx, principal: string, method: string, path: string, key: string, bodyHash: string, status: number, body: Json): void {
    const enc = this.seal("idempotency", `${principal}:${method}:${path}:${key}`, body);
    q.prepare("INSERT INTO idempotency (principal, method, path, key, body_hash, status, encrypted_response) VALUES (?,?,?,?,?,?,?)")
      .run(principal, method, path, key, bodyHash, status, Buffer.from(JSON.stringify(enc)));
  }

  // ---------------- admission ----------------

  async submit(auth: AuthResult, callRaw: unknown, idemKey: string | null): Promise<{ status: number; body: Json; replayed: boolean }> {
    return this.serial(async () => {
      const method = "POST", path = "/v1/actions";
      const validated = validateCallShape(callRaw);
      const bodyHash = hashJson(callRaw as Json);
      if (idemKey !== null) {
        const hit = this.deps.store.read((q) => this.idemLookup(q, auth.principal, method, path, idemKey, bodyHash));
        if (hit === "conflict") throw err("IDEMPOTENCY_CONFLICT");
        if (hit) return { status: hit.status, body: hit.body, replayed: true };
      }
      const res = await this.admit(auth, validated, idemKey === null ? undefined : { method, path, key: idemKey, bodyHash, status: 0 });
      return { ...res, replayed: false };
    });
  }

  private async admit(auth: AuthResult, call: ToolCall, idem?: IdemCtx): Promise<{ status: number; body: Json }> {
    const { config, deps } = this;
    const counts = this.deps.store.read((q) => ({
      nonterm: (q.prepare("SELECT COUNT(*) n FROM actions WHERE state NOT IN ('SUCCEEDED','FAILED','DENIED','REJECTED','EXPIRED','STALE','CANCELED')").get() as { n: number }).n,
      outbox: (q.prepare("SELECT COUNT(*) n FROM outbox WHERE state IN ('QUEUED','CLAIMED')").get() as { n: number }).n,
    }));
    if (counts.nonterm >= MAX_NONTERMINAL || counts.outbox >= MAX_OUTBOX_PENDING) throw err("CAPACITY");
    if (!this.rateLimit(`create:${auth.principal}`, 20)) throw err("RATE_LIMIT");
    if (!this.rateLimit(`tenant:${config.tenant}`, 100)) throw err("RATE_LIMIT");

    const tool = call.tool;
    const policyCut = this.deps.store.read((q) => this.activePolicy(q));
    if (!policyCut) throw err("DEPENDENCY_UNAVAILABLE");

    const planDenied = async (reason: string, shield: ScopeSnapshot | null, target: Target | null): Promise<{ status: number; body: Json }> => {
      return this.commit((q, emit, now) => {
        { const pb = this.pausedBlocked(q); if (pb !== null) throw err(pb); }
        const expiryPlan = this.planExpiry(q, now, emit); const expiry = expiryPlan.apply; const expired = expiryPlan.rows;
        const pol = this.activePolicy(q)!;
        const commit: ActionCommit = {
          v: 1, tenant: config.tenant, gateway: config.gateway,
          action_id: deps.ids("action"), actor: auth.principal, auth_epoch: auth.epoch,
          call, registry_hash: REGISTRY_HASH, policy_hash: pol.hash,
          shield_hash: shield ? scopeHash(shield) : null,
          blast_hash: null, target,
          created_ms: now, expires_ms: now,
        };
        const ah = hashDomainJson(DOMAIN.ACTION, commit as unknown as Json);
        const row: ActionRow = {
          id: commit.action_id, hash: ah, state: "DENIED", revision: 1, actor: auth.principal,
          policy_revision: pol.revision, expires_ms: now, dispatch_deadline_ms: null,
          encrypted_commit: null, payload_gone: false,
          handle: { tier: null, reason, card_id: null, decision_id: null },
        };
        emit({
          type: "ACTION_DENIED", actor: auth.principal, action_id: commit.action_id,
          facts: this.facts({ action_hash: ah, previous_state: null, state: "DENIED", reason, detail_hash: hashJson(commit as unknown as Json) }, pol.revision),
          evidence: [
            { kind: "commit", body: commit as unknown as Json },
            ...(shield ? [{ kind: "scope", body: scope as unknown as Json }] : []),
          ],
        });
        const h = this.handle(row);
        const plan: CommitPlan<{ status: number; body: Json }> = {
          result: { status: 201, body: h as unknown as Json },
        };
        plan.apply = (q2) => {
          expiry(q2);
          row.encrypted_commit = this.seal("actions", row.id, commit as unknown as Json);
          this.writeAction(q2, row);
          this.writeTerminalResult(q2, row, reason);
          if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, 201, h as unknown as Json);
        };
        return plan;
      });
    };

    // rejection order (§3.3): built-in deny, registry name, call schema,
    // hard-deny, enabled-tools, ordinary evaluation, scope, target
    if (BUILTIN_DENIED.has(tool)) return planDenied("HARD_DENY", null, null);
    if (!isRegisteredTool(tool)) return planDenied("UNKNOWN_TOOL", null, null);
    validateCallArgs(tool, call.args);
    const eval0 = evaluate(policyCut.policy, call);
    if (eval0.tier === null) return planDenied("HARD_DENY", null, null);
    if (!config.enabled_tools.includes(tool)) throw err("UNSUPPORTED_ADAPTER");

    let scope: ScopeSnapshot;
    try {
      scope = await deps.shield.check({ tenant: config.tenant, principal: auth.principal, call });
    } catch {
      throw err("DEPENDENCY_UNAVAILABLE");
    }
    if (typeof scope !== "object" || scope === null || !RE.reason.test(scope.reason ?? "") || (scope.verdict !== "allow" && scope.verdict !== "deny") || !Number.isInteger(scope.revision)) {
      throw err("ADAPTER_PROTOCOL");
    }
    if (scope.verdict === "deny") return planDenied("SCOPE_DENY", scope, null);

    const wantBlast = eval0.tier === "hard_stop";
    let insp: InspectResult;
    try {
      insp = await withTimeout(deps.tools.inspect({ call, include_blast: wantBlast }), 5000);
    } catch {
      throw err("DEPENDENCY_UNAVAILABLE");
    }
    if (!insp || typeof insp !== "object" || !RE.reason.test(insp.reason ?? "")) throw err("ADAPTER_PROTOCOL");
    if (!wantBlast && insp.blast !== null && insp.blast !== undefined) throw err("ADAPTER_PROTOCOL");
    if (!insp.permitted) return planDenied(insp.reason, scope, insp.target);

    let blast: BlastCard | null = null;
    if (wantBlast) {
      blast = insp.blast ?? this.unknownBlast(insp.target, this.wallNow());
    }

    return this.commit((q, emit, now) => {
      { const pb = this.pausedBlocked(q); if (pb !== null) throw err(pb); }
      const expiryPlan = this.planExpiry(q, now, emit); const expiry = expiryPlan.apply; const expired = expiryPlan.rows;
      const pol = this.activePolicy(q)!;
      if (pol.revision !== policyCut.revision) throw err("DEPENDENCY_UNAVAILABLE");
      const expires = now + (eval0.tier === "allow" ? pol.policy.dispatch_ttl_ms : pol.policy.review_ttl_ms);
      const commit: ActionCommit = {
        v: 1, tenant: config.tenant, gateway: config.gateway,
        action_id: deps.ids("action"), actor: auth.principal, auth_epoch: auth.epoch,
        call, registry_hash: REGISTRY_HASH, policy_hash: pol.hash,
        shield_hash: scopeHash(scope), blast_hash: blast ? hashJson(blast as unknown as Json) : null,
        target: insp.target, created_ms: now, expires_ms: expires,
      };
      const ah = hashDomainJson(DOMAIN.ACTION, commit as unknown as Json);
      const state: ActionState = eval0.tier === "allow" ? "READY" : eval0.tier === "async_review" ? "PENDING" : "STOPPED";
      const cardId = state === "READY" ? null : deps.ids("card");
      const row: ActionRow = {
        id: commit.action_id, hash: ah, state, revision: 1, actor: auth.principal,
        policy_revision: pol.revision, expires_ms: expires,
        dispatch_deadline_ms: state === "READY" ? expires : null,
        encrypted_commit: null, payload_gone: false,
        handle: { tier: eval0.tier, reason: REASON_BY_TIER[eval0.tier!], card_id: cardId, decision_id: null },
      };
      emit({
        type: "ACTION_CREATED", actor: auth.principal, action_id: commit.action_id,
        facts: this.facts({ action_hash: ah, previous_state: null, state, reason: REASON_BY_TIER[eval0.tier!], detail_hash: hashJson(commit as unknown as Json) }, pol.revision),
        evidence: [
          { kind: "commit", body: commit as unknown as Json },
          { kind: "scope", body: scope as unknown as Json },
          { kind: "registry", body: REGISTRY_DESCRIPTOR as unknown as Json },
          ...(blast ? [
            { kind: "blast", body: blast as unknown as Json },
            { kind: "blast-source", body: blastSource(blast) as unknown as Json },
          ] : []),
        ],
      });
      const h = this.handle(row);
      return {
        result: { status: 202, body: h as unknown as Json },
        apply: (q2) => {
          expiry(q2);
          row.encrypted_commit = this.seal("actions", row.id, commit as unknown as Json);
          this.writeAction(q2, row);
          if (state === "READY") this.enqueueDispatch(q2, row, now);
          else this.enqueueCard(q2, row, now);
          if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, 202, h as unknown as Json);
        },
      };
    });
  }

  private unknownBlast(target: Target, observedMs: number): BlastCard {
    const ev = {
      status: "unknown" as const, target, files: null, rows: null, money: null,
      undo: { kind: "none" as const, instruction: UNKNOWN_BLAST_INSTRUCTION },
      observed_ms: observedMs,
    };
    const eh = hashJson(ev as unknown as Json);
    return { ...ev, evidence_hash: eh };
  }

  // ---------------- reads ----------------

  private authorizeRead(q: Tx, auth: AuthResult, row: ActionRow): boolean {
    if (auth.tenant !== this.config.tenant) return false;
    if (auth.roles.includes("audit") || auth.roles.includes("admin")) return true;
    if (auth.principal === row.actor) return true;
    const pol = this.activePolicy(q);
    if (auth.roles.includes("review") && pol && pol.policy.reviewers.includes(auth.principal)) return true;
    return false;
  }

  async getAction(auth: AuthResult, actionId: string): Promise<Json> {
    return this.serial(async () => {
      if (!isId("action", actionId)) throw err("NOT_FOUND");
      if (auth.tenant !== this.config.tenant) throw err("NOT_FOUND");
      const out = await this.commit((q, emit, now) => {
        const expiryPlan = this.planExpiry(q, now, emit); const expiry = expiryPlan.apply; const expired = expiryPlan.rows;
        const row = this.loadNorm(q, actionId, expired);
        if (!row || !this.authorizeRead(q, auth, row)) {
          return { result: "notfound" as const, apply: (q2: Tx) => expiry(q2) };
        }
        return { result: this.actionView(q, row), apply: (q2: Tx) => expiry(q2) };
      });
      if (out === "notfound") throw err("NOT_FOUND");
      return out as unknown as Json;
    });
  }

  private actionView(q: Tx, row: ActionRow): Json {
    if (row.payload_gone) throw err("PAYLOAD_GONE", row.id);
    const commit = this.commitOf(row);
    const dec = q.prepare("SELECT body FROM decisions WHERE action_id = ?").get(row.id) as { body: Uint8Array } | undefined;
    const res = q.prepare("SELECT encrypted_body FROM results WHERE action_id = ?").get(row.id) as { encrypted_body: Uint8Array } | undefined;
    let blast: BlastCard | null = null;
    if (commit?.blast_hash) {
      const b = this.evidenceGet(q, commit.blast_hash);
      if (b) blast = b as unknown as BlastCard;
    }
    return {
      action: this.handle(row),
      commit,
      decision: dec ? (JSON.parse(Buffer.from(dec.body).toString("utf8")) as Decision) : null,
      result: res ? this.open<ToolResult>("results", row.id, JSON.parse(Buffer.from(res.encrypted_body).toString("utf8")) as Envelope) : null,
      blast,
    } as unknown as Json;
  }

  // ---------------- view ----------------

  async view(auth: AuthResult, actionId: string, input: { action_hash: string; card_id: string }): Promise<Json> {
    return this.serial(async () => {
      if (!isId("action", actionId)) throw err("NOT_FOUND");
      if (auth.kind !== "human") throw err("HUMAN_REQUIRED");
      const pol0 = this.deps.store.read((q) => this.activePolicy(q));
      if (!auth.roles.includes("review") || !pol0 || !pol0.policy.reviewers.includes(auth.principal)) throw err("FORBIDDEN");
      const out = await this.commit((q, emit, now) => {
        const expiryPlan = this.planExpiry(q, now, emit); const expiry = expiryPlan.apply; const expired = expiryPlan.rows;
        const row = this.loadNorm(q, actionId, expired);
        const applyExpiry = (q2: Tx) => expiry(q2);
        if (!row) return { result: null, apply: applyExpiry, postThrow: err("NOT_FOUND") } as CommitPlan<Json | null>;
        if (row.hash !== input.action_hash || row.handle.card_id !== input.card_id) {
          return { result: null, apply: applyExpiry, postThrow: err("HASH_MISMATCH") } as CommitPlan<Json | null>;
        }
        if (row.state !== "PENDING" && row.state !== "STOPPED") {
          return { result: null, apply: applyExpiry, postThrow: err("STATE_CONFLICT", row.id) } as CommitPlan<Json | null>;
        }
        const existing = q.prepare("SELECT first_view_ms FROM views WHERE action_id=? AND reviewer=? AND card_id=?")
          .get(row.id, auth.principal, input.card_id) as { first_view_ms: number } | undefined;
        if (existing) {
          return { result: { first_view_ms: existing.first_view_ms, expires_ms: row.expires_ms } as unknown as Json, apply: applyExpiry };
        }
        const detail = { action_id: row.id, card_id: input.card_id, reviewer: auth.principal, first_view_ms: now };
        emit({
          type: "REVIEW_VIEWED", actor: auth.principal, action_id: row.id,
          facts: this.facts({ action_hash: row.hash, previous_state: row.state, state: row.state, reason: "REVIEW_VIEWED", detail_hash: hashJson(detail) }, row.policy_revision),
          evidence: [{ kind: "view", body: detail as unknown as Json }],
        });
        return {
          result: { first_view_ms: now, expires_ms: row.expires_ms } as unknown as Json,
          apply: (q2) => {
            expiry(q2);
            q2.prepare("INSERT INTO views (action_id, reviewer, card_id, first_view_ms) VALUES (?,?,?,?)")
              .run(row.id, auth.principal, input.card_id, now);
          },
        };
      });
      return out!;
    });
  }

  // ---------------- decision ----------------

  async decide(auth: AuthResult, actionId: string, input: DecisionInput, idem?: IdemCtx): Promise<Json> {
    return this.serial(async () => {
      if (idem) {
        const hit = this.deps.store.read((q) => this.idemLookup(q, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash));
        if (hit === "conflict") throw err("IDEMPOTENCY_CONFLICT");
        if (hit) return hit.body;
      }
      if (!isId("action", actionId)) throw err("NOT_FOUND");
      // precedence: human-kind, self-review, roster/role, binding, state/rev
      if (auth.kind !== "human") throw err("HUMAN_REQUIRED");
      const row0 = this.deps.store.read((q) => this.loadAction(q, actionId));
      if (!row0) throw err("NOT_FOUND");
      if (auth.principal === row0.actor) throw err("SELF_REVIEW");
      const polNow = this.deps.store.read((q) => this.activePolicy(q));
      if (!polNow) throw err("DEPENDENCY_UNAVAILABLE");
      if (!auth.roles.includes("review") || !polNow.policy.reviewers.includes(auth.principal)) throw err("FORBIDDEN");
      if (row0.hash !== input.action_hash || row0.handle.card_id !== input.card_id) throw err("HASH_MISMATCH");
      if (row0.state !== "PENDING" && row0.state !== "STOPPED") throw err("STATE_CONFLICT", row0.id);
      if (input.expected_revision !== row0.revision) throw err("REVISION_CONFLICT", row0.id);
      const commit = this.commitOf(row0);
      if (!commit) throw err("PAYLOAD_GONE", row0.id);

      // verdict/confirmation shape
      if (input.verdict === "approve" && row0.state === "STOPPED") throw err("CONFIRM_REQUIRED", row0.id);
      if (input.verdict === "release" && row0.state !== "STOPPED") throw err("STATE_CONFLICT", row0.id);
      if (input.verdict === "release") {
        if (input.confirm_hash === null) throw err("CONFIRM_REQUIRED", row0.id);
        if (input.confirm_hash !== row0.hash) throw err("HASH_MISMATCH", row0.id);
      }
      if ((input.verdict === "approve" || input.verdict === "reject") && input.confirm_hash !== null) throw err("SCHEMA_INVALID");
      if ((input.verdict === "approve" || input.verdict === "release") && input.reason !== "reviewed") throw err("SCHEMA_INVALID");
      if (input.verdict === "reject" && input.reason === "reviewed") throw err("SCHEMA_INVALID");

      // expiry normalization happens inside commit; an expired-at-now action
      // terminalizes and the caller gets EXPIRED.
      const wantPositive = input.verdict !== "reject";

      // ---- fresh dependency observations (outside tx) ----
      const now0 = this.wallNow();
      let requester: AuthResult | null = null, requesterRevoked = false, requesterUnavailable = false;
      try { requester = await this.deps.auth.current({ tenant: this.config.tenant, principal: row0.actor }); }
      catch (e) { if (e instanceof LexError && e.code === "AUTH_REVOKED") requesterRevoked = true; else requesterUnavailable = true; }
      let reviewerCurrent: AuthResult;
      try { reviewerCurrent = await this.deps.auth.current({ tenant: this.config.tenant, principal: auth.principal }); }
      catch (e) {
        if (e instanceof LexError && e.code === "AUTH_REVOKED") throw err("AUTH_REVOKED");
        throw err("DEPENDENCY_UNAVAILABLE");
      }
      if (reviewerCurrent.kind !== "human") throw err("HUMAN_REQUIRED");
      const identityFresh = now0 - reviewerCurrent.verified_ms <= this.config.human_identity_max_age_ms;

      const policyDrift = polNow.hash !== commit.policy_hash;
      const registryNow = this.deps.store.read((q) => this.deps.store.metaGet(q, "registry_hash")) ?? REGISTRY_HASH;
      const registryDrift = registryNow !== commit.registry_hash;

      let scopeNow: ScopeSnapshot | null = null, scopeUnavailable = false;
      try { scopeNow = await this.deps.shield.check({ tenant: this.config.tenant, principal: row0.actor, call: commit.call }); }
      catch { scopeUnavailable = true; }

      let inspNow: InspectResult | null = null, targetUnavailable = false;
      try { inspNow = await this.deps.tools.inspect({ call: commit.call, include_blast: false }); }
      catch { targetUnavailable = true; }

      const targetDrift = inspNow !== null && (!inspNow.permitted || !targetEq(inspNow.target, commit.target));

      let outcome: "proceed" | "deny" | "stale" | "blocked" = "proceed";
      let denyReason = "";
      if (requesterRevoked) { outcome = "deny"; denyReason = "AUTH_REVOKED"; }
      else if (scopeNow && scopeNow.verdict === "deny") { outcome = "deny"; denyReason = "SCOPE_DENY"; }
      else if (policyDrift || registryDrift) {
        const ne = evaluate(polNow.policy, commit.call);
        if (ne.tier === null && ne.reason === "HARD_DENY") { outcome = "deny"; denyReason = "HARD_DENY"; }
        else outcome = "stale";
      }
      else if (requester && requester.epoch !== commit.auth_epoch) outcome = "stale";
      else if (targetDrift) outcome = "stale";

      if (outcome === "proceed" && wantPositive) {
        if (requesterUnavailable || !identityFresh || scopeUnavailable || targetUnavailable) {
          outcome = "blocked";
        }
      }

      const driftEvidence = {
        old_commit: commit, new_policy_hash: polNow.hash, new_registry_hash: registryNow,
        new_shield_hash: scopeNow ? scopeHash(scopeNow) : null,
        new_target: inspNow ? inspNow.target : null,
        requester_epoch: requesterRevoked ? null : requester ? requester.epoch : null,
        reviewer_epoch: reviewerCurrent ? reviewerCurrent.epoch : null,
        evaluation: evaluate(polNow.policy, commit.call),
      };
      if (outcome === "blocked") throw err("DEPENDENCY_UNAVAILABLE", row0.id);

      const out = await this.commit((q, emit, now) => {
        { const pb = this.pausedBlocked(q); if (pb !== null) throw err(pb); }
        const expiryPlan = this.planExpiry(q, now, emit); const expiry = expiryPlan.apply; const expired = expiryPlan.rows;
        const row = this.loadNorm(q, actionId, expired)!;
        const applyExpiry = (q2: Tx) => expiry(q2);
        if (row.state !== "PENDING" && row.state !== "STOPPED") {
          const pe = row.state === "EXPIRED" ? err("EXPIRED", row.id) : err("STATE_CONFLICT", row.id);
          return { result: null, apply: applyExpiry, postThrow: pe } as CommitPlan<Json | null>;
        }
        const pol = this.activePolicy(q)!;

        if (outcome === "deny" || outcome === "stale") {
          const toState = outcome === "deny" ? "DENIED" : "STALE";
          const code = outcome === "deny" ? denyReason : "DRIFT";
          const prev = row.state;
          row.state = toState; row.revision += 1; row.dispatch_deadline_ms = null;
          row.handle.reason = code;
          emit({
            type: toState === "DENIED" ? "ACTION_DENIED" : "DRIFT_DETECTED",
            actor: auth.principal, action_id: row.id,
            facts: this.facts({
              action_hash: row.hash, previous_state: prev, state: toState, reason: code,
              detail_hash: hashJson(driftEvidence as unknown as Json),
            }, pol.revision),
            evidence: [{ kind: "drift", body: driftEvidence as unknown as Json }],
          });
          return {
            // denial at a decision recheck maps to 409 (§8.1), not 403
            result: null, postThrow: new LexError(outcome === "deny" ? denyReason : "DRIFT", 409, false, row.id),
            apply: (q2) => {
              expiry(q2);
              this.writeAction(q2, row);
              this.enqueueClosingCard(q2, row, now);
              this.cancelJobs(q2, row.id);
              this.writeTerminalResult(q2, row, code);
            },
          } as CommitPlan<Json | null>;
        }

        const vw = q.prepare("SELECT first_view_ms FROM views WHERE action_id=? AND reviewer=? AND card_id=?")
          .get(row.id, auth.principal, input.card_id) as { first_view_ms: number } | undefined;
        if (!vw) {
          return { result: null, apply: applyExpiry, postThrow: err("VIEW_REQUIRED", row.id) } as CommitPlan<Json | null>;
        }

        const decisionId = this.deps.ids("decision");
        const received = now;
        const decision: Decision = {
          decision_id: decisionId, action_id: row.id, action_hash: row.hash, card_id: input.card_id,
          reviewer: auth.principal, auth_epoch: reviewerCurrent.epoch, verdict: input.verdict,
          reason: input.reason, received_ms: received, first_view_ms: vw.first_view_ms,
          latency_ms: received - vw.first_view_ms, queue_latency_ms: received - commit.created_ms,
        };
        const prev = row.state;
        if (input.verdict === "reject") {
          row.state = "REJECTED"; row.revision += 1; row.dispatch_deadline_ms = null;
          row.handle.reason = "HUMAN_REJECTED"; row.handle.decision_id = decisionId;
          emit({
            type: "DECISION_RECORDED", actor: auth.principal, action_id: row.id,
            facts: this.facts({
              action_hash: row.hash, previous_state: prev, state: "REJECTED", reason: "HUMAN_REJECTED",
              detail_hash: hashJson(decision as unknown as Json), latency_ms: decision.latency_ms, verdict: "reject",
            }, pol.revision),
            evidence: [{ kind: "decision", body: decision as unknown as Json }],
          });
          const h = this.handle(row);
          return {
            result: h as unknown as Json,
            apply: (q2) => {
              expiry(q2);
              this.writeAction(q2, row);
              q2.prepare("INSERT INTO decisions (id, action_id, body) VALUES (?,?,?)")
                .run(decisionId, row.id, Buffer.from(JSON.stringify(decision)));
              this.enqueueClosingCard(q2, row, now);
              this.cancelJobs(q2, row.id);
              this.writeTerminalResult(q2, row, "HUMAN_REJECTED");
              this.projectDecision(q2, auth.principal, received, false, decision.latency_ms);
              if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, idem.status, h as unknown as Json);
            },
          };
        }
        row.state = "READY"; row.revision += 1;
        row.dispatch_deadline_ms = Math.min(row.expires_ms, received + pol.policy.dispatch_ttl_ms);
        row.handle.reason = input.verdict === "approve" ? "HUMAN_APPROVED" : "HUMAN_RELEASED";
        row.handle.decision_id = decisionId;
        emit({
          type: "DECISION_RECORDED", actor: auth.principal, action_id: row.id,
          facts: this.facts({
            action_hash: row.hash, previous_state: prev, state: "READY",
            reason: input.verdict === "approve" ? "HUMAN_APPROVED" : "HUMAN_RELEASED",
            detail_hash: hashJson(decision as unknown as Json), latency_ms: decision.latency_ms, verdict: input.verdict,
          }, pol.revision),
          evidence: [{ kind: "decision", body: decision as unknown as Json }],
        });
        const h = this.handle(row);
        return {
          result: h as unknown as Json,
          apply: (q2) => {
            expiry(q2);
            this.writeAction(q2, row);
            q2.prepare("INSERT INTO decisions (id, action_id, body) VALUES (?,?,?)")
              .run(decisionId, row.id, Buffer.from(JSON.stringify(decision)));
            this.enqueueDispatch(q2, row, now);
            this.enqueueCard(q2, row, now);
            this.projectDecision(q2, auth.principal, received, true, decision.latency_ms);
            if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, idem.status, h as unknown as Json);
          },
        };
      });
      return out!;
    });
  }

  private projectDecision(q: Tx, reviewer: string, receivedMs: number, approved: boolean, latencyMs: number): void {
    const headSeq = this.deps.store.metaGetInt(q, "head_seq") ?? 0;
    q.prepare("INSERT INTO reviewer_projection (reviewer, decision_seq, received_ms, approved, latency_ms) VALUES (?,?,?,?,?)")
      .run(reviewer, headSeq + 1, receivedMs, approved ? 1 : 0, latencyMs);
  }

  // ---------------- cancel ----------------

  async cancel(auth: AuthResult, actionId: string, input: { expected_revision: number; reason: "requester_cancel" | "operator_cancel" }, idem?: IdemCtx): Promise<Json> {
    return this.serial(async () => {
      if (idem) {
        const hit = this.deps.store.read((q) => this.idemLookup(q, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash));
        if (hit === "conflict") throw err("IDEMPOTENCY_CONFLICT");
        if (hit) return hit.body;
      }
      if (!isId("action", actionId)) throw err("NOT_FOUND");
      const row0 = this.deps.store.read((q) => this.loadAction(q, actionId));
      if (!row0) throw err("NOT_FOUND");
      const isOwner = auth.principal === row0.actor;
      const isAdmin = auth.roles.includes("admin");
      if (input.reason === "requester_cancel" && !isOwner) throw err("FORBIDDEN");
      if (input.reason === "operator_cancel" && !isAdmin) throw err("FORBIDDEN");
      if (!isOwner && !isAdmin) throw err("FORBIDDEN");

      const out = await this.commit((q, emit, now) => {
        { const pb = this.pausedBlocked(q); if (pb !== null) throw err(pb); }
        const expiryPlan = this.planExpiry(q, now, emit); const expiry = expiryPlan.apply; const expired = expiryPlan.rows;
        const row = this.loadNorm(q, actionId, expired)!;
        const applyExpiry = (q2: Tx) => expiry(q2);
        if (row.state !== "PENDING" && row.state !== "STOPPED" && row.state !== "READY") {
          return { result: null, apply: applyExpiry, postThrow: err("STATE_CONFLICT", row.id) } as CommitPlan<Json | null>;
        }
        if (input.expected_revision !== row.revision) {
          return { result: null, apply: applyExpiry, postThrow: err("REVISION_CONFLICT", row.id) } as CommitPlan<Json | null>;
        }
        const prev = row.state;
        const deadline = prev === "READY" ? row.dispatch_deadline_ms : row.expires_ms;
        row.state = "CANCELED"; row.revision += 1; row.dispatch_deadline_ms = null;
        row.handle.reason = input.reason === "requester_cancel" ? "REQUESTER_CANCEL" : "OPERATOR_CANCEL";
        const detail = { action_id: row.id, deadline_ms: deadline, reason: row.handle.reason };
        emit({
          type: "ACTION_CANCELED", actor: auth.principal, action_id: row.id,
          facts: this.facts({ action_hash: row.hash, previous_state: prev, state: "CANCELED", reason: row.handle.reason, detail_hash: hashJson(detail) }, row.policy_revision),
          evidence: [{ kind: "control", body: detail as unknown as Json }],
        });
        const h = this.handle(row);
        return {
          result: h as unknown as Json,
          apply: (q2) => {
            expiry(q2);
            this.writeAction(q2, row);
            this.enqueueClosingCard(q2, row, now);
            this.cancelJobs(q2, row.id);
            this.writeTerminalResult(q2, row, row.handle.reason);
            if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, idem.status, h as unknown as Json);
          },
        };
      });
      return out!;
    });
  }

  // ---------------- reconcile ----------------

  async reconcile(auth: AuthResult, actionId: string): Promise<Json> {
    return this.serial(async () => {
      if (!auth.roles.includes("admin")) throw err("FORBIDDEN");
      if (!isId("action", actionId)) throw err("NOT_FOUND");
      const row0 = this.deps.store.read((q) => this.loadAction(q, actionId));
      if (!row0) throw err("NOT_FOUND");
      if (row0.state !== "UNKNOWN") throw err("STATE_CONFLICT", row0.id);
      let lr: ToolResult;
      try {
        lr = await withTimeout(this.deps.tools.lookup({ action_id: row0.id, action_hash: row0.hash }), 5000);
      } catch {
        lr = { status: "unknown", code: "PROVIDER_UNKNOWN", output: null, provider_ref: null };
      }
      if (!lr || typeof lr !== "object" || !RE.reason.test(lr.code ?? "")) {
        lr = { status: "unknown", code: "PROVIDER_UNKNOWN", output: null, provider_ref: null };
      }
      const definitive = lr.status === "succeeded" || lr.status === "failed";
      const out = await this.commit((q, emit, _now) => {
        const row = this.loadAction(q, actionId)!;
        if (row.state !== "UNKNOWN") return { result: null, postThrow: err("STATE_CONFLICT", row.id) } as CommitPlan<Json | null>;
        const pol = this.activePolicy(q)!;
        if (definitive) {
          const prev = row.state;
          row.state = lr.status === "succeeded" ? "SUCCEEDED" : "FAILED";
          row.revision += 1;
          row.handle.reason = lr.code;
          emit({
            type: "DISPATCH_RECONCILED", actor: auth.principal, action_id: row.id,
            facts: this.facts({ action_hash: row.hash, previous_state: prev, state: row.state, reason: lr.code, detail_hash: hashJson(lr as unknown as Json) }, pol.revision),
            evidence: [{ kind: "result", body: lr as unknown as Json }],
          });
          const h = this.handle(row);
          return {
            result: h as unknown as Json,
            apply: (q2) => {
              this.writeAction(q2, row);
              const enc = this.seal("results", row.id, lr as unknown as Json);
              q2.prepare("INSERT INTO results (action_id, encrypted_body, delete_after_ms) VALUES (?,?,?) ON CONFLICT(action_id) DO UPDATE SET encrypted_body=excluded.encrypted_body, delete_after_ms=excluded.delete_after_ms")
                .run(row.id, Buffer.from(JSON.stringify(enc)), this.wallNow() + this.config.terminal_retention_ms);
              this.enqueueClosingCard(q2, row, this.wallNow());
            },
          };
        }
        emit({
          type: "RECONCILE_OBSERVED", actor: auth.principal, action_id: row.id,
          facts: this.facts({ action_hash: row.hash, previous_state: row.state, state: row.state, reason: lr.code, detail_hash: hashJson(lr as unknown as Json) }, pol.revision),
          evidence: [{ kind: "result", body: lr as unknown as Json }],
        });
        return { result: this.handle(row) as unknown as Json, apply: () => undefined };
      });
      return out!;
    });
  }

  // ---------------- outbox drain ----------------

  async drainOutbox(kind?: "CARD_UPSERT" | "DISPATCH"): Promise<{ job: string; kind: string; code: string }[]> {
    return this.serial(async () => {
      const outcomes: { job: string; kind: string; code: string }[] = [];
      for (let guard = 0; guard < 512; guard++) {
        let job: Record<string, unknown> | null;
        try {
          job = this.deps.store.tx((q) => {
            const now = this.tick(q);
            this.deps.store.metaSetInt(q, "logical_now_ms", now);
            const sql = `SELECT * FROM outbox WHERE due_ms <= ? AND (state='QUEUED' OR (state='CLAIMED' AND claim_until_ms <= ?))${kind ? " AND kind = ?" : ""} ORDER BY due_ms LIMIT 1`;
            const rows = (kind
              ? q.prepare(sql).all(now, now, kind)
              : q.prepare(sql).all(now, now)) as Record<string, unknown>[];
            if (rows.length === 0) return null;
            const j = rows[0]!;
            q.prepare("UPDATE outbox SET state='CLAIMED', revision=revision+1, claim_until_ms=? WHERE id=?")
              .run(now + OUTBOX_LEASE_MS, j.id as string);
            return j;
          });
        } catch (e) {
          if (e instanceof LexError && e.code === "CLOCK_UNSAFE") {
            this.deps.store.tx((q2) => this.deps.store.metaSet(q2, "paused_reason", "CLOCK_UNSAFE"));
          }
          throw e;
        }
        if (!job) break;
        const code = await this.processOutboxJob(job);
        outcomes.push({ job: job.id as string, kind: job.kind as string, code });
        if (outcomes.length > 400) break;
      }
      return outcomes;
    });
  }

  private outboxBody<T>(j: Record<string, unknown>, pk: string): T {
    const env = JSON.parse(Buffer.from(j.body as Uint8Array).toString("utf8")) as Envelope;
    return this.open<T>("outbox", pk, env);
  }

  private async processOutboxJob(j: Record<string, unknown>): Promise<string> {
    const kind = j.kind as string;
    if (kind === "CARD_UPSERT") return this.processCardJob(j);
    if (kind === "DISPATCH") return this.processDispatchJob(j);
    return "ADAPTER_PROTOCOL";
  }

  private requeue(q: Tx, id: string, delayMs: number, now: number): void {
    q.prepare("UPDATE outbox SET state='QUEUED', due_ms=?, claim_until_ms=NULL, revision=revision+1 WHERE id=?")
      .run(now + delayMs, id);
  }

  private async processCardJob(j: Record<string, unknown>): Promise<string> {
    const jobId = j.id as string;
    const actionId = j.action_id as string;
    const attempt = (j.revision as number) - 1;
    const row = this.deps.store.read((q) => this.loadAction(q, actionId));
    if (!row || !row.handle.card_id) {
      this.deps.store.tx((q) => q.prepare("UPDATE outbox SET state='CANCELED', revision=revision+1 WHERE id=?").run(jobId));
      return "CANCELED";
    }
    const now = this.wallNow();
    const terminal = TERMINAL_STATES.has(row.state);
    if (!terminal && now >= row.expires_ms) {
      this.deps.store.tx((q) => q.prepare("UPDATE outbox SET state='CANCELED', revision=revision+1 WHERE id=?").run(jobId));
      return "EXPIRED";
    }
    if (terminal && now - (j.due_ms as number) > CARD_CLOSE_BUDGET_MS) {
      this.deps.store.tx((q) => q.prepare("UPDATE outbox SET state='CANCELED', revision=revision+1 WHERE id=?").run(jobId));
      return "CANCELED";
    }
    const card = this.deps.store.read((q) => this.cardFor(q, row));
    try {
      await this.deps.inbox.upsert(card);
      this.deps.store.tx((q) => q.prepare("UPDATE outbox SET state='DONE', revision=revision+1 WHERE id=?").run(jobId));
      return "OK";
    } catch {
      const delay = CARD_BACKOFF_MS[Math.min(attempt, CARD_BACKOFF_MS.length - 1)]!;
      this.deps.store.tx((q) => this.requeue(q, jobId, delay, now));
      return "DEPENDENCY_UNAVAILABLE";
    }
  }

  private async processDispatchJob(j: Record<string, unknown>): Promise<string> {
    const jobId = j.id as string;
    const actionId = j.action_id as string;
    const attempt = (j.revision as number) - 1;
    const pre = this.deps.store.read((q) => this.loadAction(q, actionId));
    if (!pre || pre.state !== "READY") {
      this.deps.store.tx((q) => q.prepare("UPDATE outbox SET state='CANCELED', revision=revision+1 WHERE id=?").run(jobId));
      return "STATE_CONFLICT";
    }
    const commit = this.commitOf(pre);
    if (!commit) return "PAYLOAD_GONE";

    // ---- fresh dependency reads (outside transactions) ----
    const now0 = this.wallNow();
    let requester: AuthResult | null = null, requesterRevoked = false, depsDown = false;
    try { requester = await this.deps.auth.current({ tenant: this.config.tenant, principal: pre.actor }); }
    catch (e) { if (e instanceof LexError && e.code === "AUTH_REVOKED") requesterRevoked = true; else depsDown = true; }

    let scope: ScopeSnapshot | null = null;
    try { scope = await this.deps.shield.check({ tenant: this.config.tenant, principal: pre.actor, call: commit.call }); }
    catch { depsDown = true; }

    let insp: InspectResult | null = null;
    try { insp = await this.deps.tools.inspect({ call: commit.call, include_blast: false }); }
    catch { depsDown = true; }

    const pol = this.deps.store.read((q) => this.activePolicy(q))!;
    const registryNow = this.deps.store.read((q) => this.deps.store.metaGet(q, "registry_hash")) ?? REGISTRY_HASH;

    const policyDrift = pol.hash !== commit.policy_hash;
    const registryDrift = registryNow !== commit.registry_hash;
    const targetDrift = insp !== null && (!insp.permitted || !targetEq(insp.target, commit.target));

    let outcome: "proceed" | "deny" | "stale" | "retry" = "proceed";
    let denyReason = "";
    if (requesterRevoked) { outcome = "deny"; denyReason = "AUTH_REVOKED"; }
    else if (scope && scope.verdict === "deny") { outcome = "deny"; denyReason = "SCOPE_DENY"; }
    else if (policyDrift || registryDrift) {
      const ne = evaluate(pol.policy, commit.call);
      if (ne.tier === null && ne.reason === "HARD_DENY") { outcome = "deny"; denyReason = "HARD_DENY"; }
      else outcome = "stale";
    }
    else if (requester && requester.epoch !== commit.auth_epoch) outcome = "stale";
    else if (targetDrift) outcome = "stale";
    else if (depsDown) outcome = "retry";
    if (outcome === "proceed" && this.wallNow() - now0 > OBS_MAX_AGE_MS) outcome = "retry";

    const driftEvidence = {
      old_commit: commit, new_policy_hash: pol.hash, new_registry_hash: registryNow,
      new_shield_hash: scope ? scopeHash(scope) : null,
      new_target: insp ? insp.target : null,
      requester_epoch: requesterRevoked ? null : requester ? requester.epoch : null,
      reviewer_epoch: null,
      evaluation: (() => { try { return evaluate(pol.policy, commit.call); } catch { return null; } })(),
    };

    if (outcome === "retry") {
      const delay = DISPATCH_RETRY_MS[Math.min(attempt, DISPATCH_RETRY_MS.length - 1)]!;
      this.deps.store.tx((q) => this.requeue(q, jobId, delay, this.wallNow()));
      return "DEPENDENCY_UNAVAILABLE";
    }

    if (outcome === "deny" || outcome === "stale") {
      const toState = outcome === "deny" ? "DENIED" : "STALE";
      const code = outcome === "deny" ? denyReason : "DRIFT";
      await this.commit((q, emit, now) => {
        const expiryPlan = this.planExpiry(q, now, emit); const expiry = expiryPlan.apply; const expired = expiryPlan.rows;
        const row = this.loadNorm(q, actionId, expired)!;
        if (row.state !== "READY") {
          return { result: null, apply: (q2: Tx) => { expiry(q2); q2.prepare("UPDATE outbox SET state='CANCELED', revision=revision+1 WHERE id=?").run(jobId); } };
        }
        const prev = row.state;
        row.state = toState; row.revision += 1; row.dispatch_deadline_ms = null;
        row.handle.reason = code;
        emit({
          type: toState === "DENIED" ? "ACTION_DENIED" : "DRIFT_DETECTED",
          actor: null, action_id: row.id,
          facts: this.facts({ action_hash: row.hash, previous_state: prev, state: toState, reason: code, detail_hash: hashJson(driftEvidence as unknown as Json) }, pol.revision),
          evidence: [{ kind: "drift", body: driftEvidence as unknown as Json }],
        });
        return {
          result: null,
          apply: (q2) => {
            expiry(q2);
            this.writeAction(q2, row);
            this.enqueueClosingCard(q2, row, now);
            q2.prepare("UPDATE outbox SET state='CANCELED', revision=revision+1 WHERE id=?").run(jobId);
            this.writeTerminalResult(q2, row, code);
          },
        };
      });
      return code;
    }

    // ---- commit DISPATCH_STARTED, then exactly one execute_once ----
    let phase: string;
    try {
      phase = await this.commit((q, emit, now) => {
        { const pb = this.pausedBlocked(q); if (pb !== null) throw err(pb); }
        const expiryPlan = this.planExpiry(q, now, emit); const expiry = expiryPlan.apply; const expired = expiryPlan.rows;
        const row = this.loadNorm(q, actionId, expired)!;
        if (row.state !== "READY") {
          return { result: row.state === "EXPIRED" ? "expired" : "gone", apply: (q2: Tx) => expiry(q2) };
        }
        const deadline = row.dispatch_deadline_ms!;
        const detail = { attempt_id: jobId, not_after_ms: deadline };
        const pol2 = this.activePolicy(q)!;
        row.state = "DISPATCHING"; row.revision += 1;
        row.handle.reason = "DISPATCH_STARTED";
        emit({
          type: "DISPATCH_STARTED", actor: null, action_id: row.id,
          facts: this.facts({ action_hash: row.hash, previous_state: "READY", state: "DISPATCHING", reason: "DISPATCH_STARTED", detail_hash: hashJson(detail) }, pol2.revision),
          evidence: [{ kind: "dispatch", body: detail as unknown as Json }],
        });
        return {
          result: "started",
          apply: (q2) => { expiry(q2); this.writeAction(q2, row); },
        };
      });
    } catch (e) {
      if (e instanceof LexError && (e.code === "AUDIT_UNAVAILABLE" || e.code === "CLOCK_UNSAFE" || e.code === "DEPENDENCY_UNAVAILABLE")) {
        const delay = DISPATCH_RETRY_MS[Math.min(attempt, DISPATCH_RETRY_MS.length - 1)]!;
        this.deps.store.tx((q) => this.requeue(q, jobId, delay, this.wallNow()));
        return e.code;
      }
      throw e;
    }
    if (phase !== "started") {
      this.deps.store.tx((q) => q.prepare("UPDATE outbox SET state='CANCELED', revision=revision+1 WHERE id=?").run(jobId));
      return phase === "expired" ? "EXPIRED" : "STATE_CONFLICT";
    }

    const input = this.outboxBody<{ action_id: string; action_hash: string; call: ToolCall; target: Target; not_after_ms: number }>(j, actionId);
    let result: ToolResult;
    try {
      result = await this.deps.tools.execute_once(input);
    } catch {
      result = { status: "unknown", code: "PROVIDER_UNKNOWN", output: null, provider_ref: null };
    }
    if (!result || typeof result !== "object" || !RE.reason.test(result.code ?? "") || !["succeeded", "failed", "unknown"].includes(result.status)) {
      result = { status: "unknown", code: "ADAPTER_PROTOCOL", output: null, provider_ref: null };
    }
    const finalCode = await this.commit((q, emit, now) => {
      const row = this.loadAction(q, actionId)!;
      const pol2 = this.activePolicy(q)!;
      const prev = row.state;
      const toState: ActionState = result.status === "succeeded" ? "SUCCEEDED" : result.status === "failed" ? "FAILED" : "UNKNOWN";
      row.state = toState; row.revision += 1; row.dispatch_deadline_ms = null;
      row.handle.reason = result.code;
      const type: EventType = toState === "SUCCEEDED" ? "DISPATCH_SUCCEEDED" : toState === "FAILED" ? "DISPATCH_FAILED" : "DISPATCH_UNKNOWN";
      emit({
        type, actor: null, action_id: row.id,
        facts: this.facts({ action_hash: row.hash, previous_state: prev, state: toState, reason: result.code, detail_hash: hashJson(result as unknown as Json) }, pol2.revision),
        evidence: [{ kind: "result", body: result as unknown as Json }],
      });
      return {
        result: result.code,
        apply: (q2) => {
          this.writeAction(q2, row);
          const enc = this.seal("results", row.id, result as unknown as Json);
          q2.prepare("INSERT INTO results (action_id, encrypted_body, delete_after_ms) VALUES (?,?,?) ON CONFLICT(action_id) DO UPDATE SET encrypted_body=excluded.encrypted_body, delete_after_ms=excluded.delete_after_ms")
            .run(row.id, Buffer.from(JSON.stringify(enc)), this.wallNow() + this.config.terminal_retention_ms);
          q2.prepare("UPDATE outbox SET state='DONE', revision=revision+1 WHERE id=?").run(jobId);
          this.enqueueClosingCard(q2, row, now);
        },
      };
    });
    return finalCode;
  }

  // ---------------- policy ----------------

  async getPolicy(): Promise<Json> {
    return this.serial(async () => {
      const pol = this.deps.store.read((q) => this.activePolicy(q));
      if (!pol) throw err("NOT_FOUND");
      return { policy: pol.policy, policy_hash: pol.hash } as unknown as Json;
    });
  }

  async putPolicy(auth: AuthResult, input: { expected_revision: number; policy: Json }, idem?: IdemCtx): Promise<Json> {
    return this.serial(async () => {
      if (idem) {
        const hit = this.deps.store.read((q) => this.idemLookup(q, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash));
        if (hit === "conflict") throw err("IDEMPOTENCY_CONFLICT");
        if (hit) return hit.body;
      }
      if (!auth.roles.includes("admin")) throw err("FORBIDDEN");
      const policy = compilePolicy(input.policy);
      const cur = this.deps.store.read((q) => this.activePolicy(q));
      const curRev = cur?.revision ?? 0;
      if (input.expected_revision !== curRev) throw err("REVISION_CONFLICT");
      if (policy.revision !== curRev + 1) throw err("REVISION_CONFLICT");
      for (const r of policy.reviewers) {
        let a: AuthResult;
        try { a = await this.deps.auth.current({ tenant: this.config.tenant, principal: r }); }
        catch { throw err("POLICY_INVALID"); }
        if (a.kind !== "human") throw err("POLICY_INVALID");
      }
      const ph = policyHash(policy);
      return this.commit((q, emit, now) => {
        const cur2 = this.activePolicy(q);
        if ((cur2?.revision ?? 0) !== curRev) throw err("REVISION_CONFLICT");
        emit({
          type: "POLICY_ACTIVATED", actor: auth.principal, action_id: null,
          facts: this.facts({ reason: "POLICY_ACTIVATED", detail_hash: ph }, policy.revision),
          evidence: [{ kind: "policy", body: policy as unknown as Json }],
        });
        const open = q.prepare("SELECT * FROM reaudits WHERE state='OPEN'").all() as Record<string, unknown>[];
        const toCancel: { id: string; body: Record<string, unknown>; action_id: string; action_hash: string | null }[] = [];
        for (const rr of open) {
          const body = JSON.parse(Buffer.from(rr.body as Uint8Array).toString("utf8")) as Record<string, unknown> & { reviewer: string };
          if (!policy.reviewers.includes(body.reviewer)) {
            const act = this.loadAction(q, rr.action_id as string);
            toCancel.push({ id: rr.id as string, body, action_id: rr.action_id as string, action_hash: act?.hash ?? null });
          }
        }
        for (const c of toCancel) {
          const closed = { ...c.body, state: "CANCELED", closed_ms: now };
          emit({
            type: "REAUDIT_CANCELED", actor: null, action_id: c.action_id,
            facts: this.facts({ action_hash: c.action_hash, reason: "ASSIGNEE_REMOVED", detail_hash: hashJson(closed as Json) }, policy.revision),
            evidence: [{ kind: "reaudit", body: closed as unknown as Json }],
          });
        }
        return {
          result: { revision: policy.revision, policy_hash: ph } as unknown as Json,
          apply: (q2) => {
            q2.prepare("INSERT INTO policies (revision, hash, body) VALUES (?,?,?)")
              .run(policy.revision, ph, Buffer.from(canonicalBytes(policy as unknown as Json)));
            this.deps.store.metaSetInt(q2, "active_policy_revision", policy.revision);
            for (const c of toCancel) {
              const closed = { ...c.body, state: "CANCELED", closed_ms: now };
              q2.prepare("UPDATE reaudits SET state='CANCELED', body=? WHERE id=?")
                .run(Buffer.from(JSON.stringify(closed)), c.id);
            }
            if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, idem.status, { revision: policy.revision, policy_hash: ph } as unknown as Json);
          },
        };
      });
    });
  }

  evaluateCall(callRaw: unknown): Json {
    const call = validateCallShape(callRaw);
    const pol = this.deps.store.read((q) => this.activePolicy(q));
    if (!pol) throw err("DEPENDENCY_UNAVAILABLE");
    return evaluate(pol.policy, call) as unknown as Json;
  }

  // ---------------- audit reads ----------------

  async auditPage(after: number, through: number | null, limit: number): Promise<Json> {
    return this.serial(async () => this.deps.store.read((q) => {
      const head = this.headRow(q);
      const thr = through ?? head.seq;
      if (!Number.isInteger(after) || !Number.isInteger(thr) || after < 0 || thr < after || thr > head.seq) throw err("SCHEMA_INVALID");
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw err("SCHEMA_INVALID");
      const rows = q.prepare("SELECT entry FROM audit WHERE seq > ? AND seq <= ? ORDER BY seq LIMIT ?")
        .all(after, thr, limit) as { entry: Uint8Array }[];
      const entries = rows.map((r) => JSON.parse(Buffer.from(r.entry).toString("utf8")) as AuditEntry);
      const headRowQ = q.prepare("SELECT body FROM heads WHERE seq = ?").get(thr) as { body: Uint8Array } | undefined;
      const headObj = headRowQ ? JSON.parse(Buffer.from(headRowQ.body).toString("utf8")) as SignedHead : null;
      const more = entries.length > 0 && entries[entries.length - 1]!.body.seq < thr ? entries[entries.length - 1]!.body.seq : null;
      return { after, through: thr, entries, head: headObj, next_after: more } as unknown as Json;
    }));
  }

  // ---------------- stats ----------------

  async stats(fromMs: number, toMs: number, throughSeq: number | null): Promise<Json> {
    return this.serial(async () => this.deps.store.read((q) => {
      const head = this.headRow(q);
      const cut = throughSeq ?? head.seq;
      if (!Number.isInteger(cut) || cut > head.seq || !Number.isInteger(fromMs) || !Number.isInteger(toMs) || toMs <= fromMs || toMs - fromMs > 2592000000) throw err("SCHEMA_INVALID");
      const rows = q.prepare("SELECT reviewer, decision_seq, received_ms, approved, latency_ms FROM reviewer_projection WHERE decision_seq <= ?")
        .all(cut) as { reviewer: string; decision_seq: number; received_ms: number; approved: number; latency_ms: number }[];
      const points: DecisionPoint[] = rows.map((r) => ({
        reviewer: r.reviewer, received_ms: r.received_ms, seq: r.decision_seq,
        approved: r.approved === 1, latency_ms: r.latency_ms,
      }));
      const act = q.prepare("SELECT entry FROM audit WHERE type='POLICY_ACTIVATED' AND seq <= ? ORDER BY seq DESC LIMIT 1")
        .get(cut) as { entry: Uint8Array } | undefined;
      let roster: string[] = [];
      if (act) {
        const entry = JSON.parse(Buffer.from(act.entry).toString("utf8")) as AuditEntry;
        const detail = entry.body.facts.detail_hash;
        if (detail) {
          const ev = this.evidenceGet(q, detail);
          if (ev) roster = ((ev as unknown as Policy).reviewers ?? []) as string[];
        }
      }
      const reviewers = computeReviewerStats({ from_ms: fromMs, to_ms: toMs, decisions: points, roster });
      return { from_ms: fromMs, to_ms: toMs, through_seq: cut, reviewers } as unknown as Json;
    }));
  }

  // ---------------- re-audits ----------------

  async reauditOpen(auth: AuthResult, input: { action_id: string; reviewer: string; reason: "manual_sample" | "manual_rotation" }, idem?: IdemCtx): Promise<Json> {
    return this.serial(async () => {
      if (idem) {
        const hit = this.deps.store.read((q) => this.idemLookup(q, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash));
        if (hit === "conflict") throw err("IDEMPOTENCY_CONFLICT");
        if (hit) return hit.body;
      }
      if (!auth.roles.includes("admin")) throw err("FORBIDDEN");
      if (!isId("action", input.action_id)) throw err("NOT_FOUND");
      const row = this.deps.store.read((q) => this.loadAction(q, input.action_id));
      if (!row) throw err("NOT_FOUND");
      if (!TERMINAL_STATES.has(row.state)) throw err("STATE_CONFLICT", row.id);
      const dec = this.deps.store.read((q) => q.prepare("SELECT body FROM decisions WHERE action_id=?").get(row.id) as { body: Uint8Array } | undefined);
      if (!dec) throw err("STATE_CONFLICT", row.id);
      const decision = JSON.parse(Buffer.from(dec.body).toString("utf8")) as Decision;
      const pol = this.deps.store.read((q) => this.activePolicy(q))!;
      if (!pol.policy.reviewers.includes(input.reviewer)) throw err("POLICY_INVALID");
      if (input.reviewer === row.actor || input.reviewer === decision.reviewer || input.reviewer === auth.principal) throw err("FORBIDDEN");
      let assignee: AuthResult;
      try { assignee = await this.deps.auth.current({ tenant: this.config.tenant, principal: input.reviewer }); }
      catch { throw err("POLICY_INVALID"); }
      if (assignee.kind !== "human") throw err("POLICY_INVALID");
      const dup = this.deps.store.read((q) => q.prepare("SELECT id FROM reaudits WHERE action_id=? AND state='OPEN'").get(row.id));
      if (dup) throw err("STATE_CONFLICT", row.id);
      const out = await this.commit((q, emit, now) => {
        const ra = {
          reaudit_id: this.deps.ids("reaudit"), action_id: row.id, reviewer: input.reviewer,
          created_ms: now, state: "OPEN", verdict: null, reason: input.reason, closed_ms: null,
        };
        emit({
          type: "REAUDIT_OPENED", actor: auth.principal, action_id: row.id,
          facts: this.facts({ action_hash: row.hash, reason: input.reason === "manual_sample" ? "MANUAL_SAMPLE" : "MANUAL_ROTATION", detail_hash: hashJson(ra as unknown as Json) }, pol.revision),
          evidence: [{ kind: "reaudit", body: ra as unknown as Json }],
        });
        return {
          result: ra as unknown as Json,
          apply: (q2) => {
            q2.prepare("INSERT INTO reaudits (id, action_id, reviewer, state, body) VALUES (?,?,?,?,?)")
              .run(ra.reaudit_id, row.id, input.reviewer, "OPEN", Buffer.from(JSON.stringify(ra)));
            if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, idem.status, ra as unknown as Json);
          },
        };
      });
      return out;
    });
  }

  async reauditGet(auth: AuthResult, id: string): Promise<Json> {
    return this.serial(async () => {
      if (!isId("reaudit", id)) throw err("NOT_FOUND");
      const r = this.deps.store.read((q) => q.prepare("SELECT * FROM reaudits WHERE id=?").get(id) as { body: Uint8Array; reviewer: string } | undefined);
      if (!r) throw err("NOT_FOUND");
      const isAssignee = r.reviewer === auth.principal;
      if (!isAssignee && !auth.roles.includes("audit") && !auth.roles.includes("admin")) throw err("NOT_FOUND");
      return JSON.parse(Buffer.from(r.body).toString("utf8")) as Json;
    });
  }

  async reauditVerdict(auth: AuthResult, id: string, input: { verdict: "uphold" | "question" }, idem?: IdemCtx): Promise<Json> {
    return this.serial(async () => {
      if (idem) {
        const hit = this.deps.store.read((q) => this.idemLookup(q, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash));
        if (hit === "conflict") throw err("IDEMPOTENCY_CONFLICT");
        if (hit) return hit.body;
      }
      if (!isId("reaudit", id)) throw err("NOT_FOUND");
      if (auth.kind !== "human") throw err("HUMAN_REQUIRED");
      const r = this.deps.store.read((q) => q.prepare("SELECT * FROM reaudits WHERE id=?").get(id) as { body: Uint8Array; reviewer: string; state: string } | undefined);
      if (!r) throw err("NOT_FOUND");
      if (r.reviewer !== auth.principal) throw err("FORBIDDEN");
      if (r.state !== "OPEN") throw err("STATE_CONFLICT");
      const body = JSON.parse(Buffer.from(r.body).toString("utf8")) as Record<string, unknown> & { action_id: string };
      const out = await this.commit((q, emit, now) => {
        const act = this.loadAction(q, body.action_id);
        const pol = this.activePolicy(q)!;
        const closed = { ...body, state: "CLOSED", verdict: input.verdict, closed_ms: now };
        emit({
          type: "REAUDIT_CLOSED", actor: auth.principal, action_id: body.action_id,
          facts: this.facts({ action_hash: act?.hash ?? null, reason: input.verdict === "uphold" ? "UPHOLD" : "QUESTION", detail_hash: hashJson(closed as Json) }, pol.revision),
          evidence: [{ kind: "reaudit", body: closed as unknown as Json }],
        });
        return {
          result: closed as unknown as Json,
          apply: (q2) => {
            q2.prepare("UPDATE reaudits SET state='CLOSED', body=? WHERE id=?")
              .run(Buffer.from(JSON.stringify(closed)), id);
            if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, idem.status, closed as unknown as Json);
          },
        };
      });
      return out;
    });
  }

  // ---------------- evidence ----------------

  async evidenceFetch(auth: AuthResult, hash: string): Promise<Json> {
    return this.serial(async () => {
      if (!auth.roles.includes("audit") && !auth.roles.includes("admin")) throw err("FORBIDDEN");
      if (!RE.hash.test(hash)) throw err("NOT_FOUND");
      const r = this.deps.store.read((q) => q.prepare("SELECT kind, encrypted_body, delete_after_ms FROM evidence WHERE hash=?").get(hash) as { kind: string; encrypted_body: Uint8Array; delete_after_ms: number | null } | undefined);
      if (!r) throw err("NOT_FOUND");
      const env = JSON.parse(Buffer.from(r.encrypted_body).toString("utf8")) as Envelope;
      const body = this.open<Json>("evidence", hash, env);
      return { hash, data: { kind: r.kind, body } } as unknown as Json;
    });
  }

  // ---------------- key rotation ----------------

  async rotateKey(auth: AuthResult, input: { expected_head_seq: number; new_key_id: string; new_public_key: string }, idem?: IdemCtx): Promise<Json> {
    return this.serial(async () => {
      if (idem) {
        const hit = this.deps.store.read((q) => this.idemLookup(q, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash));
        if (hit === "conflict") throw err("IDEMPOTENCY_CONFLICT");
        if (hit) return hit.body;
      }
      if (!auth.roles.includes("admin")) throw err("FORBIDDEN");
      const head = this.deps.store.read((q) => this.headRow(q));
      if (input.expected_head_seq !== head.seq) throw err("REVISION_CONFLICT");
      const firstSeq = head.seq + 2;
      const oldKeyId = this.deps.store.read((q) => this.deps.store.metaGet(q, "active_key_id")) ?? this.config.audit_key_id;
      const rotBody = { first_seq: firstSeq, new_key_id: input.new_key_id, new_public_key: input.new_public_key, old_key_id: oldKeyId };
      const rm = new Uint8Array([...new TextEncoder().encode(DOMAIN.ROTATE), 0, ...canonicalBytes(rotBody as unknown as Json)]);
      let proof: string;
      try {
        const r = await this.deps.signer.sign({ key_id: input.new_key_id, purpose: "rotation", message_hex: Buffer.from(rm).toString("hex") });
        proof = r.signature;
      } catch { throw err("ROTATION_INVALID"); }
      if (!verifyRotationSig(rotBody, proof, input.new_public_key)) throw err("ROTATION_INVALID");
      const rot: KeyRotation = { ...rotBody, new_key_proof: proof };
      return this.commit((q, emit, _now) => {
        const pol = this.activePolicy(q)!;
        emit({
          type: "KEY_ROTATED", actor: auth.principal, action_id: null,
          facts: this.facts({ reason: "KEY_ROTATED", detail_hash: hashJson(rot as unknown as Json) }, pol.revision),
          evidence: [{ kind: "rotation", body: rot as unknown as Json }],
        });
        return {
          result: { rotated_seq: head.seq + 1, first_seq: firstSeq, new_key_id: input.new_key_id } as unknown as Json,
          apply: (q2) => {
            q2.prepare("UPDATE key_registry SET last_seq=? WHERE key_id=?").run(head.seq + 1, oldKeyId);
            q2.prepare("INSERT INTO key_registry (key_id, public_key, first_seq, last_seq) VALUES (?,?,?,NULL) ON CONFLICT(key_id) DO UPDATE SET public_key=excluded.public_key, first_seq=excluded.first_seq, last_seq=NULL")
              .run(input.new_key_id, input.new_public_key, firstSeq);
            this.deps.store.metaSet(q2, "active_key_id", input.new_key_id);
            if (idem) this.idemStore(q2, auth.principal, idem.method, idem.path, idem.key, idem.bodyHash, idem.status, { rotated_seq: head.seq + 1, first_seq: firstSeq, new_key_id: input.new_key_id } as unknown as Json);
          },
        };
      });
    });
  }

  // ---------------- retention + recovery ----------------

  async sweep(now_ms: number): Promise<void> {
    return this.serial(async () => {
      this.deps.store.tx((q) => {
        const payloadCut = now_ms - this.config.payload_retention_ms;
        const rows = q.prepare(
          `SELECT id FROM actions WHERE payload_gone = 0 AND state IN ('SUCCEEDED','FAILED','DENIED','REJECTED','EXPIRED','STALE','CANCELED') AND expires_ms <= ?`,
        ).all(payloadCut) as { id: string }[];
        for (const { id } of rows) {
          q.prepare("UPDATE actions SET encrypted_commit=NULL, payload_gone=1 WHERE id=?").run(id);
          // delete argument-bearing evidence reachable from this action's events
          const evs = q.prepare("SELECT entry FROM audit WHERE action_id = ?").all(id) as { entry: Uint8Array }[];
          const hashes = new Set<string>();
          for (const { entry } of evs) {
            const e = JSON.parse(Buffer.from(entry).toString("utf8")) as AuditEntry;
            if (e.body.facts.detail_hash) hashes.add(e.body.facts.detail_hash);
          }
          for (const h of hashes) {
            q.prepare("DELETE FROM evidence WHERE hash=? AND kind IN ('commit','blast','blast-source')").run(h);
          }
        }
        const resRows = q.prepare("SELECT action_id FROM results WHERE delete_after_ms IS NOT NULL AND delete_after_ms <= ?").all(now_ms) as { action_id: string }[];
        for (const { action_id } of resRows) q.prepare("DELETE FROM results WHERE action_id=?").run(action_id);
      });
    });
  }

  async recover(): Promise<void> {
    await this.serial(async () => {
      const stuck = this.deps.store.read((q) =>
        q.prepare("SELECT id FROM actions WHERE state='DISPATCHING'").all() as { id: string }[]);
      for (const { id } of stuck) {
        const res: ToolResult = { status: "unknown", code: "PROVIDER_UNKNOWN", output: null, provider_ref: null };
        await this.commit((q, emit, _now) => {
          const row = this.loadAction(q, id)!;
          const pol = this.activePolicy(q)!;
          const prev = row.state;
          row.state = "UNKNOWN"; row.revision += 1; row.dispatch_deadline_ms = null;
          row.handle.reason = "PROVIDER_UNKNOWN";
          emit({
            type: "DISPATCH_UNKNOWN", actor: null, action_id: id,
            facts: this.facts({ action_hash: row.hash, previous_state: prev, state: "UNKNOWN", reason: "PROVIDER_UNKNOWN", detail_hash: hashJson(res as unknown as Json) }, pol.revision),
            evidence: [{ kind: "result", body: res as unknown as Json }],
          });
          return {
            result: null,
            apply: (q2) => {
              this.writeAction(q2, row);
              const enc = this.seal("results", row.id, res as unknown as Json);
              q2.prepare("INSERT INTO results (action_id, encrypted_body, delete_after_ms) VALUES (?,?,?) ON CONFLICT(action_id) DO UPDATE SET encrypted_body=excluded.encrypted_body")
                .run(row.id, Buffer.from(JSON.stringify(enc)));
            },
          };
        });
      }
    });
  }
}

// ---------------- helpers ----------------

function targetEq(a: Target, b: Target | null): boolean {
  if (!b) return false;
  return a.resource === b.resource && a.version === b.version && a.digest === b.digest;
}

function blastSource(b: BlastCard): Json {
  const { evidence_hash: _e, ...rest } = b;
  return rest as unknown as Json;
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: ReturnType<typeof setTimeout>;
  const to = new Promise<never>((_r, rej) => { t = setTimeout(() => rej(new BindingError("DEPENDENCY_UNAVAILABLE", "timeout")), ms); });
  try { return await Promise.race([p, to]); } finally { clearTimeout(t!); }
}
