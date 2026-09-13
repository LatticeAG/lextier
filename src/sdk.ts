/**
 * LexTier TypeScript SDK (spec §9). Each method maps one-to-one to a §8 route.
 * The SDK never caches approvals, never dispatches tools directly, never
 * auto-retries effects, and never supplies tenant identity.
 */

import { canonicalBytes, type Json } from "./core/canonical.ts";
import { parseJsonStrict } from "./core/strict_json.ts";
import { randomBytes } from "node:crypto";

export interface SdkConfig {
  base_url: string;
  /** bearer token value (the secret itself, not an env name) */
  token: string;
  timeout_ms?: number;
}

export class LexTierError extends Error {
  readonly code: string;
  readonly status: number;
  readonly retryable: boolean;
  readonly action_id: string | null;
  constructor(code: string, status: number, retryable: boolean, actionId: string | null, message?: string) {
    super(message ?? code);
    this.code = code; this.status = status; this.retryable = retryable; this.action_id = actionId;
  }
}

export interface SubmitResult { status: number; body: Json; replayed: boolean }

function idemKey(): string { return randomBytes(24).toString("base64url"); }

export class LexTierClient {
  private base: string;
  private token: string;
  private timeout: number;

  constructor(cfg: SdkConfig) {
    if (!/^https?:\/\/[A-Za-z0-9._:-]+$/.test(cfg.base_url)) throw new LexTierError("SCHEMA_INVALID", 0, false, null, "bad base_url");
    if (typeof cfg.token !== "string" || cfg.token.length === 0) throw new LexTierError("UNAUTHENTICATED", 0, false, null, "empty token");
    this.base = cfg.base_url;
    this.token = cfg.token;
    this.timeout = cfg.timeout_ms ?? 10000;
  }

  private async req(method: string, path: string, body: Json | undefined, idem: boolean, query?: Record<string, string>): Promise<{ status: number; body: Json; replayed: boolean }> {
    const q = query ? "?" + new URLSearchParams(query).toString() : "";
    const headers: Record<string, string> = { authorization: `Bearer ${this.token}` };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (idem) headers["idempotency-key"] = idemKey();
    let res: Response;
    try {
      res = await fetch(this.base + path + q, {
        method, headers,
        body: body !== undefined ? Buffer.from(canonicalBytes(body)).toString("utf8") : null,
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (e) {
      throw new LexTierError("DEPENDENCY_UNAVAILABLE", 0, true, null, (e as Error).message);
    }
    const text = await res.text();
    const parsed = text.length > 0 ? (parseJsonStrict(text) as Json) : null;
    const replayed = res.headers.get("idempotency-replayed") === "true";
    if (res.status >= 400) {
      const e = (parsed as { error?: { code?: string; retryable?: boolean; action_id?: string | null } } | null)?.error;
      throw new LexTierError(e?.code ?? "INTERNAL", res.status, e?.retryable === true, e?.action_id ?? null);
    }
    return { status: res.status, body: parsed, replayed };
  }

  status(): Promise<Json> { return this.req("GET", "/v1/status", undefined, false).then((r) => r.body); }

  async submit(call: Json): Promise<SubmitResult> {
    const r = await this.req("POST", "/v1/actions", call, true);
    return { status: r.status, body: r.body, replayed: r.replayed };
  }

  get(actionId: string): Promise<Json> { return this.req("GET", `/v1/actions/${actionId}`, undefined, false).then((r) => r.body); }

  view(actionId: string, input: { action_hash: string; card_id: string }): Promise<Json> {
    return this.req("POST", `/v1/actions/${actionId}/view`, input as unknown as Json, false).then((r) => r.body);
  }

  decide(actionId: string, input: Json): Promise<Json> {
    return this.req("POST", `/v1/actions/${actionId}/decision`, input, true).then((r) => r.body);
  }

  cancel(actionId: string, input: { expected_revision: number; reason: string }): Promise<Json> {
    return this.req("POST", `/v1/actions/${actionId}/cancel`, input as unknown as Json, true).then((r) => r.body);
  }

  reconcile(actionId: string): Promise<Json> {
    return this.req("POST", `/v1/actions/${actionId}/reconcile`, {} as Json, true).then((r) => r.body);
  }

  policyGet(): Promise<Json> { return this.req("GET", "/v1/policy", undefined, false).then((r) => r.body); }

  policyPut(input: { expected_revision: number; policy: Json }): Promise<Json> {
    return this.req("PUT", "/v1/policy", input as unknown as Json, true).then((r) => r.body);
  }

  evaluate(call: Json): Promise<Json> {
    return this.req("POST", "/v1/policy/evaluate", call, false).then((r) => r.body);
  }

  auditPage(after: number, through?: number | null, limit?: number): Promise<Json> {
    const query: Record<string, string> = { after: String(after) };
    if (through != null) query.through = String(through);
    if (limit != null) query.limit = String(limit);
    return this.req("GET", "/v1/audit", undefined, false, query).then((r) => r.body);
  }

  evidenceGet(hash: string): Promise<Json> {
    return this.req("GET", `/v1/evidence/${hash}`, undefined, false).then((r) => r.body);
  }

  stats(fromMs: number, toMs: number, throughSeq?: number | null): Promise<Json> {
    const query: Record<string, string> = { from_ms: String(fromMs), to_ms: String(toMs) };
    if (throughSeq != null) query.through_seq = String(throughSeq);
    return this.req("GET", "/v1/reviewers/stats", undefined, false, query).then((r) => r.body);
  }

  reauditOpen(input: { action_id: string; reviewer: string; reason: "manual_sample" | "manual_rotation" }): Promise<Json> {
    return this.req("POST", "/v1/re-audits", input as unknown as Json, true).then((r) => r.body);
  }

  reauditGet(reauditId: string): Promise<Json> {
    return this.req("GET", `/v1/re-audits/${reauditId}`, undefined, false).then((r) => r.body);
  }

  reauditClose(reauditId: string, input: { verdict: "uphold" | "question" }): Promise<Json> {
    return this.req("POST", `/v1/re-audits/${reauditId}/verdict`, input as unknown as Json, true).then((r) => r.body);
  }

  rotateKey(input: { expected_head_seq: number; new_key_id: string; new_public_key: string }): Promise<Json> {
    return this.req("POST", "/v1/audit/rotate-key", input as unknown as Json, true).then((r) => r.body);
  }
}
