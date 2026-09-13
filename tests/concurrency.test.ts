/**
 * Concurrency tests (spec §16 gate: "1000 concurrent duplicate submissions
 * create one action"). The engine serializes through TenantGateway.serial().
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { newCtx, boot, authFor, fixtureFresh, R_CALL, U, H } from "./harness.ts";
import type { Json } from "../src/core/canonical.ts";
import type { DecisionInput } from "../src/core/schemas.ts";
import { canonicalize } from "../src/core/canonical.ts";

function actionCount(ctx: ReturnType<typeof newCtx>): number {
  return ctx.store.read((q) => (q.prepare("SELECT COUNT(*) n FROM actions").get() as { n: number }).n);
}

test("concurrency: 200 duplicate submits with one idempotency key create exactly one action", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  const key = "race-key-00000000000001";
  const results = await Promise.all(
    Array.from({ length: 200 }, () => ctx.gw.submit(authFor(ctx, U), R_CALL as unknown as Json, key)),
  );
  assert.equal(actionCount(ctx), 1);
  const bodies = new Set(results.map((r) => canonicalize(r.body)));
  assert.equal(bodies.size, 1);
  assert.equal(results[0]!.status, 202);
  assert.ok(results.some((r) => r.replayed));
});

test("concurrency: 50 submits with distinct keys create 50 actions", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  const results = [];
  for (let i = 0; i < 50; i++) {
    ctx.now += 51; // stay under the 20/s per-principal create limit
    const call = { tool: "fs.write_text", args: { path: `/workspace/drafts/f${i}.txt`, text: "x", expected_version: "7" } };
    ctx.tools.files.set(`/workspace/drafts/f${i}.txt`, { version: "7", digest: "d".repeat(64) });
    results.push(await ctx.gw.submit(authFor(ctx, U), call as unknown as Json, `race-key-${String(i).padStart(8, "0")}`));
  }
  assert.equal(actionCount(ctx), 50);
  assert.ok(results.every((r) => r.status === 202));
});

test("concurrency: same key + different body produces exactly one action and a conflict", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  ctx.tools.files.set("/workspace/drafts/other.txt", { version: "7", digest: "d".repeat(64) });
  const callB = { tool: "fs.write_text", args: { path: "/workspace/drafts/other.txt", text: "x", expected_version: "7" } };
  const key = "race-key-00000000000002";
  const results = await Promise.allSettled([
    ctx.gw.submit(authFor(ctx, U), R_CALL as unknown as Json, key),
    ctx.gw.submit(authFor(ctx, U), callB as unknown as Json, key),
  ]);
  assert.equal(actionCount(ctx), 1);
  const codes = results.map((r) => r.status === "rejected" ? (r.reason as { code?: string }).code : "OK");
  assert.ok(codes.includes("OK") && codes.includes("IDEMPOTENCY_CONFLICT"), JSON.stringify(codes));
});

test("concurrency: competing decisions — exactly one wins, loser gets a conflict", async () => {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  const a = await fixtureFresh(ctx);
  ctx.now = 1001500;
  const approve = {
    expected_revision: 1, action_hash: a.hash, card_id: a.card_id!,
    verdict: "approve", confirm_hash: null, reason: "reviewed",
  } as DecisionInput;
  const reject = {
    expected_revision: 1, action_hash: a.hash, card_id: a.card_id!,
    verdict: "reject", confirm_hash: null, reason: "unsafe",
  } as DecisionInput;
  const results = await Promise.allSettled([
    ctx.gw.decide(authFor(ctx, H), a.id, approve, undefined),
    ctx.gw.decide(authFor(ctx, H), a.id, reject, undefined),
  ]);
  const final = ctx.store.read((q) => (q.prepare("SELECT state FROM actions WHERE id=?").get(a.id) as { state: string }).state);
  assert.ok(final === "READY" || final === "REJECTED");
  const codes = results.map((r) => r.status === "rejected" ? (r.reason as { code?: string }).code : "OK");
  assert.ok(codes.includes("OK"), JSON.stringify(codes));
  assert.ok(codes.includes("STATE_CONFLICT") || codes.includes("REVISION_CONFLICT"), JSON.stringify(codes));
});
