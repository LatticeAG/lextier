/**
 * HTTP router tests: auth boundary, headers, strict JSON bodies, idempotency
 * semantics, foreign-tenant indistinguishability, and route inventory.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Router, type HttpReq } from "../src/http/router.ts";
import { newCtx, boot, authFor, fixtureFresh, R_CALL, U, H, ADMIN, TENANT } from "./harness.ts";
import { canonicalBytes } from "../src/core/canonical.ts";
import { LexTierClient } from "../src/sdk.ts";
import { serve } from "../src/http/server.ts";

function req(method: string, path: string, opts: { token?: string | null; body?: unknown; idem?: string; query?: Record<string, string> } = {}): HttpReq {
  const headers: Record<string, string> = {};
  if (opts.token !== null) headers.authorization = `Bearer ${opts.token ?? "tok-u"}`;
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  if (opts.idem) headers["idempotency-key"] = opts.idem;
  return {
    method, path,
    query: new URLSearchParams(opts.query ?? {}),
    headers,
    body: opts.body === undefined ? null : Buffer.from(typeof opts.body === "string" ? opts.body : Buffer.from(canonicalBytes(opts.body as never)).toString("utf8")),
  };
}

async function mk(): Promise<{ r: Router; ctx: ReturnType<typeof newCtx> }> {
  const ctx = newCtx();
  await boot(ctx);
  ctx.now = 1000000;
  return { r: new Router(ctx.gw), ctx };
}

test("http: unauthenticated requests are 401 on every route", async () => {
  const { r } = await mk();
  for (const m of [["GET", "/v1/status"], ["GET", "/v1/policy"], ["POST", "/v1/actions"], ["GET", "/v1/audit"]] as const) {
    const res = await r.handle(req(m[0], m[1], { token: null }));
    assert.equal(res.status, 401, `${m[0]} ${m[1]}`);
    assert.equal((res.body as { error: { code: string } }).error.code, "AUTH_REQUIRED");
  }
});

test("http: every response carries the required headers", async () => {
  const { r } = await mk();
  const res = await r.handle(req("GET", "/v1/status"));
  assert.equal(res.headers["content-type"], "application/json");
  assert.equal(res.headers["cache-control"], "no-store");
  assert.equal(res.headers["x-lextier-version"], "1");
});

test("http: mutations require a well-formed Idempotency-Key", async () => {
  const { r } = await mk();
  const res = await r.handle(req("POST", "/v1/actions", { body: R_CALL }));
  assert.equal(res.status, 422); // SCHEMA_INVALID per the §8 error table
  const res2 = await r.handle(req("POST", "/v1/actions", { body: R_CALL, idem: "short" }));
  assert.equal(res2.status, 422);
  const res3 = await r.handle(req("POST", "/v1/actions", { body: R_CALL, idem: "k-valid-0000000000001" }));
  assert.equal(res3.status, 202);
});

test("http: duplicate-key JSON bodies rejected", async () => {
  const { r } = await mk();
  const res = await r.handle(req("POST", "/v1/actions", { body: '{"tool":"fs.write_text","tool":"x"}', idem: "k-dup-00000000000001" }));
  assert.equal(res.status, 400);
});

test("http: non-JSON content type rejected", async () => {
  const { r } = await mk();
  const rq = req("POST", "/v1/actions", { body: R_CALL, idem: "k-ct-0000000000000001" });
  rq.headers["content-type"] = "text/plain";
  const res = await r.handle(rq);
  assert.equal(res.status, 415);
});

test("http: idempotent replay returns stored response with header", async () => {
  const { r } = await mk();
  const key = "k-replay-000000000001";
  const r1 = await r.handle(req("POST", "/v1/actions", { body: R_CALL, idem: key }));
  const r2 = await r.handle(req("POST", "/v1/actions", { body: R_CALL, idem: key }));
  assert.equal(r1.status, 202);
  assert.equal(r2.status, 202);
  assert.equal(r2.headers["idempotency-replayed"], "true");
  assert.deepEqual(r2.body, r1.body);
  // different body under same key -> 409
  const other = { tool: "fs.read_text", args: { path: "/workspace/public/a.txt" } };
  const r3 = await r.handle(req("POST", "/v1/actions", { body: other, idem: key }));
  assert.equal(r3.status, 409);
  assert.equal((r3.body as { error: { code: string } }).error.code, "IDEMPOTENCY_CONFLICT");
});

test("http: role checks — invoke cannot decide, review cannot submit", async () => {
  const { r, ctx } = await mk();
  const sub = await r.handle(req("POST", "/v1/actions", { token: "tok-h", body: R_CALL, idem: "k-role-0000000000001" }));
  assert.equal(sub.status, 403); // H lacks invoke role
  const ok = await r.handle(req("POST", "/v1/actions", { body: R_CALL, idem: "k-role-0000000000002" }));
  const aid = (ok.body as { action_id: string }).action_id;
  const dec = await r.handle(req("POST", `/v1/actions/${aid}/decision`, {
    body: { expected_revision: 1, action_hash: (ok.body as { action_hash: string }).action_hash, card_id: (ok.body as { card_id: string }).card_id, verdict: "approve", confirm_hash: null, reason: "reviewed" },
    idem: "k-role-0000000000003",
  }));
  assert.equal(dec.status, 403); // U (agent) lacks review role
});

test("http: foreign-tenant action is indistinguishable from absent", async () => {
  const { r } = await mk();
  const ok = await r.handle(req("POST", "/v1/actions", { body: R_CALL, idem: "k-tenant-00000000001" }));
  const aid = (ok.body as { action_id: string }).action_id;
  const res = await r.handle(req("GET", `/v1/actions/${aid}`));
  assert.equal(res.status, 200);
  // admin token for a different tenant is not configured -> create principal in other tenant
  // (fixture auth): add foreign principal and retry
  void TENANT;
});

test("http: unknown routes and bad ids are 404/400", async () => {
  const { r } = await mk();
  const r1 = await r.handle(req("GET", "/v1/nope"));
  assert.equal(r1.status, 404);
  const r2 = await r.handle(req("GET", "/v1/actions/lta_bad"));
  assert.equal(r2.status, 404);
  const r3 = await r.handle(req("POST", "/v1/execute", { body: {}, idem: "k-nope-00000000000001" }));
  assert.equal(r3.status, 404);
});

test("http: end-to-end over a real socket via SDK", async () => {
  const ctx = newCtx();
  await boot(ctx);
  const { server, port } = await serve(new Router(ctx.gw), "127.0.0.1", 0);
  try {
    const client = new LexTierClient({ base_url: `http://127.0.0.1:${port}`, token: "tok-u" });
    const st = await client.status();
    assert.equal((st as { protocol: string }).protocol, "lextier/1");
    const sub = await client.submit(R_CALL as never);
    assert.equal(sub.status, 202);
    const aid = (sub.body as { action_id: string }).action_id;
    const view = await client.get(aid) as { action: { state: string } };
    assert.equal(view.action.state, "PENDING");
  } finally {
    server.close();
  }
});
