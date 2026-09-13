/**
 * Crash-injection tests (spec §15): failures at every persistence and network
 * boundary leave no partial authority — failed speculative signatures are not
 * committed, rolled-back transactions leave no state, provider crashes never
 * auto-resend an effect.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { newCtx, boot, authFor, fixtureFresh, fixtureReady, R_CALL, U, H, P } from "./harness.ts";
import { LexError } from "../src/core/errors.ts";
import type { Json } from "../src/core/canonical.ts";

async function stateOf(ctx: ReturnType<typeof newCtx>, id: string): Promise<string | null> {
  return ctx.store.read((q) => {
    const r = q.prepare("SELECT state FROM actions WHERE id=?").get(id) as { state: string } | undefined;
    return r?.state ?? null;
  });
}
function auditCount(ctx: ReturnType<typeof newCtx>): number {
  return ctx.store.read((q) => (q.prepare("SELECT COUNT(*) n FROM audit").get() as { n: number }).n);
}
function actionCount(ctx: ReturnType<typeof newCtx>): number {
  return ctx.store.read((q) => (q.prepare("SELECT COUNT(*) n FROM actions").get() as { n: number }).n);
}

test("crash: signer unavailable during submit commits nothing", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  const before = auditCount(ctx);
  ctx.signer.unavailable = true;
  await assert.rejects(() => ctx.gw.submit(authFor(ctx, U), R_CALL as unknown as Json, "k-crashsigner001"), (e: LexError) => e.code === "AUDIT_UNAVAILABLE");
  assert.equal(actionCount(ctx), 0);
  assert.equal(auditCount(ctx), before); // no speculative signed event persisted
  ctx.signer.unavailable = false;
  const r = await ctx.gw.submit(authFor(ctx, U), R_CALL as unknown as Json, "k-crashsigner002");
  assert.equal(r.status, 202);
  assert.equal(actionCount(ctx), 1);
});

test("crash: COMMIT failure rolls back the entire mutation", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  const before = auditCount(ctx);
  // fail exactly one COMMIT
  const origExec = ctx.store.db.exec.bind(ctx.store.db);
  let armed = true;
  (ctx.store.db as { exec: typeof origExec }).exec = (sql: string) => {
    if (armed && sql === "COMMIT") { armed = false; throw new Error("injected commit crash"); }
    return origExec(sql);
  };
  await assert.rejects(() => ctx.gw.submit(authFor(ctx, U), R_CALL as unknown as Json, "k-commitfail0001"));
  (ctx.store.db as { exec: typeof origExec }).exec = origExec;
  assert.equal(actionCount(ctx), 0);
  assert.equal(auditCount(ctx), before);
  // engine still works after the crash
  const r = await ctx.gw.submit(authFor(ctx, U), R_CALL as unknown as Json, "k-commitfail0002");
  assert.equal(r.status, 202);
});

test("crash: shield outage at admission fails closed without action or audit", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  const before = auditCount(ctx);
  ctx.shield.unavailable = true;
  await assert.rejects(() => ctx.gw.submit(authFor(ctx, U), R_CALL as unknown as Json, "k-shielddown0001"), (e: LexError) => e.code === "DEPENDENCY_UNAVAILABLE");
  assert.equal(actionCount(ctx), 0);
  assert.equal(auditCount(ctx), before);
});

test("crash: inbox outage never increments dispatch_count and keeps card retryable", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  ctx.inbox.unavailable = true;
  const a = await fixtureFresh(ctx); // submit still succeeds; card delivery retries
  assert.equal(ctx.inbox.delivered("ltc_000000000000000000001"), false);
  assert.equal(ctx.tools.dispatchCount, 0);
  ctx.inbox.unavailable = false;
  await ctx.gw.drainOutbox("CARD_UPSERT");
  assert.ok(ctx.inbox.delivered("ltc_000000000000000000001"));
  assert.equal(await stateOf(ctx, a.id), "PENDING");
});

test("crash: provider throw between send and commit does not resend the effect", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  const a = await fixtureReady(ctx);
  // simulate provider crash after accepting: the fixture marks a result but
  // the boundary never reports it — engine must go UNKNOWN, never retry
  ctx.tools.provider = "timeout_after_accept";
  ctx.now = 1002000;
  const outs = await ctx.gw.drainOutbox("DISPATCH");
  assert.equal(outs.filter((o) => o.kind === "DISPATCH").length, 1);
  assert.equal(await stateOf(ctx, a.id), "UNKNOWN");
  assert.equal(ctx.tools.dispatchCount, 1); // exactly one send
  assert.equal(ctx.tools.effectCount, 0);   // effect never applied
  // repeated alarm runs must not resend
  await ctx.gw.drainOutbox("DISPATCH");
  await ctx.gw.drainOutbox("DISPATCH");
  assert.equal(ctx.tools.dispatchCount, 1);
});

test("crash: decide throws after signer outage leaves action reviewable", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  const a = await fixtureFresh(ctx);
  ctx.now = 1001000;
  const before = auditCount(ctx);
  ctx.signer.unavailable = true;
  await assert.rejects(() => ctx.gw.decide(authFor(ctx, H), a.id, {
    expected_revision: 1, action_hash: a.hash, card_id: a.card_id!,
    verdict: "approve", confirm_hash: null, reason: "reviewed",
  }, undefined), (e: LexError) => e.code === "AUDIT_UNAVAILABLE");
  ctx.signer.unavailable = false;
  assert.equal(await stateOf(ctx, a.id), "PENDING");
  assert.equal(auditCount(ctx), before);
  const h = await ctx.gw.decide(authFor(ctx, H), a.id, {
    expected_revision: 1, action_hash: a.hash, card_id: a.card_id!,
    verdict: "approve", confirm_hash: null, reason: "reviewed",
  }, undefined);
  assert.equal((h as { state: string }).state, "READY");
});
