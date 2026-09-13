/**
 * HTTP surface for /v1 (spec §8): routing, auth binding, strict JSON bodies,
 * idempotency, error mapping, and response headers.
 */

import { err, LexError, toErrorBody, type ApiErrorBody } from "../core/errors.ts";
import { parseJsonBytes } from "../core/strict_json.ts";
import { hashJson, RE } from "../core/hash.ts";
import { canonicalBytes, type Json } from "../core/canonical.ts";
import { isId } from "../core/ids.ts";
import {
  viewInputF, decisionInputF, cancelInputF, policyPutF, reauditOpenF,
  reauditCloseF, rotateKeyF,
} from "../core/schemas.ts";
import type { AuthResult } from "../core/schemas.ts";
import type { TenantGateway } from "../engine/gateway.ts";

const MAX_BODY = 64 * 1024;
const IDEM_RE = /^[A-Za-z0-9_-]{16,64}$/;

export interface HttpReq {
  method: string;
  path: string;          // path portion only
  query: URLSearchParams;
  headers: Record<string, string>;
  body: Uint8Array | null;
  remote?: string;
}

export interface HttpRes {
  status: number;
  body: Json | ApiErrorBody;
  headers: Record<string, string>;
}

function baseHeaders(): Record<string, string> {
  return {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-lextier-version": "1",
  };
}

export class Router {
  private gw: TenantGateway;
  constructor(gw: TenantGateway) { this.gw = gw; }

  async handle(req: HttpReq): Promise<HttpRes> {
    const headers = baseHeaders();
    try {
      const res = await this.dispatch(req, headers);
      res.headers = { ...headers, ...res.headers };
      return res;
    } catch (e) {
      const { status, body } = toErrorBody(e);
      if (e instanceof LexError && (e.code === "CAPACITY" || e.code === "RATE_LIMIT")) {
        headers["retry-after"] = "1";
      }
      if (e instanceof LexError && e.status === 503) headers["retry-after"] = "1";
      return { status, body, headers };
    }
  }

  private async auth(req: HttpReq): Promise<AuthResult> {
    const h = req.headers["authorization"] ?? "";
    if (!h.startsWith("Bearer ")) throw err("AUTH_REQUIRED");
    const token = h.slice(7);
    if (token.length === 0 || token.length > 512) throw err("AUTH_REQUIRED");
    try {
      return await this.gw.deps.auth.verify({
        credential_binding: token, request_method: req.method, request_path: req.path,
      });
    } catch (e) {
      if (e instanceof LexError) throw e;
      throw err("DEPENDENCY_UNAVAILABLE");
    }
  }

  private bodyJson(req: HttpReq): unknown {
    if (req.body === null || req.body.length === 0) return null;
    if (req.body.length > MAX_BODY) throw err("BODY_TOO_LARGE");
    const ct = (req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
    if (ct !== "application/json") throw err("CONTENT_TYPE");
    return parseJsonBytes(req.body); // strict: duplicate keys -> DUPLICATE_KEY
  }

  private idemKey(req: HttpReq): string {
    const k = req.headers["idempotency-key"];
    if (!k || !IDEM_RE.test(k)) throw err("SCHEMA_INVALID");
    return k;
  }

  private async dispatch(req: HttpReq, headers: Record<string, string>): Promise<HttpRes> {
    const { method, path, query } = req;
    const segs = path.split("/").filter((s) => s.length > 0);
    if (segs.length < 1 || segs[0] !== "v1") throw err("NOT_FOUND");

    // every route requires a valid bearer
    const auth = await this.auth(req);

    if (method === "GET" && path === "/v1/status") {
      return { status: 200, body: await this.gw.status(), headers };
    }

    if (method === "POST" && path === "/v1/actions") {
      if (!auth.roles.includes("invoke")) throw err("FORBIDDEN");
      const key = this.idemKey(req);
      const body = this.bodyJson(req);
      const r = await this.gw.submit(auth, body, key);
      if (r.replayed) headers["idempotency-replayed"] = "true";
      return { status: r.status, body: r.body, headers };
    }

    if (method === "GET" && segs[1] === "actions" && segs.length === 3) {
      const id = segs[2]!;
      const body = await this.gw.getAction(auth, id);
      return { status: 200, body, headers };
    }

    if (method === "POST" && segs[1] === "actions" && segs.length === 4 && segs[3] === "view") {
      const id = segs[2]!;
      const body = viewInputF(this.bodyJson(req));
      // view marking is idempotent: no Idempotency-Key required
      const out = await this.gw.view(auth, id, body);
      return { status: 200, body: out, headers };
    }

    if (method === "POST" && segs[1] === "actions" && segs.length === 4 && segs[3] === "decision") {
      const id = segs[2]!;
      const key = this.idemKey(req);
      const body = decisionInputF(this.bodyJson(req));
      return this.idempotent(req, auth, key, "POST", `/v1/actions/${id}/decision`, this.bodyJson(req), 200,
        (idem) => this.gw.decide(auth, id, body, idem));
    }

    if (method === "POST" && segs[1] === "actions" && segs.length === 4 && segs[3] === "cancel") {
      const id = segs[2]!;
      const key = this.idemKey(req);
      const body = cancelInputF(this.bodyJson(req));
      return this.idempotent(req, auth, key, "POST", `/v1/actions/${id}/cancel`, this.bodyJson(req), 200,
        (idem) => this.gw.cancel(auth, id, body, idem));
    }

    if (method === "POST" && segs[1] === "actions" && segs.length === 4 && segs[3] === "reconcile") {
      const id = segs[2]!;
      this.bodyJson(req); // empty body allowed; if present must be JSON
      const out = await this.gw.reconcile(auth, id);
      return { status: 200, body: out, headers };
    }

    if (method === "GET" && path === "/v1/policy") {
      if (!auth.roles.includes("admin")) throw err("FORBIDDEN");
      return { status: 200, body: await this.gw.getPolicy(), headers };
    }

    if (method === "PUT" && path === "/v1/policy") {
      const key = this.idemKey(req);
      const body = policyPutF(this.bodyJson(req));
      return this.idempotent(req, auth, key, "PUT", "/v1/policy", this.bodyJson(req), 200,
        (idem) => this.gw.putPolicy(auth, body, idem));
    }

    if (method === "POST" && path === "/v1/policy/evaluate") {
      if (!auth.roles.includes("invoke") && !auth.roles.includes("review") && !auth.roles.includes("admin")) throw err("FORBIDDEN");
      const body = this.bodyJson(req);
      const out = this.gw.evaluateCall(body);
      return { status: 200, body: out, headers };
    }

    if (method === "GET" && path === "/v1/audit") {
      if (!auth.roles.includes("audit") && !auth.roles.includes("admin")) throw err("FORBIDDEN");
      const after = intQ(query.get("after"), 0);
      const through = query.get("through") === null ? null : intQ(query.get("through"), null);
      const limit = intQ(query.get("limit"), 1000);
      const out = await this.gw.auditPage(after, through, limit);
      return { status: 200, body: out, headers };
    }

    if (method === "GET" && path === "/v1/reviewers/stats") {
      if (!auth.roles.includes("audit") && !auth.roles.includes("admin")) throw err("FORBIDDEN");
      const fromMs = intQ(query.get("from_ms"), null);
      const toMs = intQ(query.get("to_ms"), null);
      const throughSeq = query.get("through_seq") === null ? null : intQ(query.get("through_seq"), null);
      const out = await this.gw.stats(fromMs, toMs, throughSeq);
      return { status: 200, body: out, headers };
    }

    if (method === "POST" && path === "/v1/re-audits") {
      const key = this.idemKey(req);
      const body = reauditOpenF(this.bodyJson(req));
      return this.idempotent(req, auth, key, "POST", "/v1/re-audits", this.bodyJson(req), 201,
        (idem) => this.gw.reauditOpen(auth, body, idem));
    }

    if (method === "GET" && segs[1] === "re-audits" && segs.length === 3) {
      const out = await this.gw.reauditGet(auth, segs[2]!);
      return { status: 200, body: out, headers };
    }

    if (method === "POST" && segs[1] === "re-audits" && segs.length === 4 && segs[3] === "verdict") {
      const key = this.idemKey(req);
      const body = reauditCloseF(this.bodyJson(req));
      const id = segs[2]!;
      return this.idempotent(req, auth, key, "POST", `/v1/re-audits/${id}/verdict`, this.bodyJson(req), 200,
        (idem) => this.gw.reauditVerdict(auth, id, body, idem));
    }

    if (method === "GET" && segs[1] === "evidence" && segs.length === 3) {
      const out = await this.gw.evidenceFetch(auth, segs[2]!);
      return { status: 200, body: out, headers };
    }

    if (method === "POST" && path === "/v1/audit/rotate-key") {
      const key = this.idemKey(req);
      const body = rotateKeyF(this.bodyJson(req));
      return this.idempotent(req, auth, key, "POST", "/v1/audit/rotate-key", this.bodyJson(req), 200,
        (idem) => this.gw.rotateKey(auth, body, idem));
    }

    // known path but wrong method -> 405
    if (this.knownPath(segs, path)) throw new LexError("METHOD_NOT_ALLOWED", 405, false, null);
    throw err("NOT_FOUND");
  }

  private knownPath(segs: string[], path: string): boolean {
    if (path === "/v1/status" || path === "/v1/actions" || path === "/v1/policy"
      || path === "/v1/policy/evaluate" || path === "/v1/audit"
      || path === "/v1/reviewers/stats" || path === "/v1/re-audits"
      || path === "/v1/audit/rotate-key") return true;
    if (segs[1] === "actions" && (segs.length === 3 || segs.length === 4) && isId("action", segs[2]!)) return true;
    if (segs[1] === "re-audits" && (segs.length === 3 || segs.length === 4) && isId("reaudit", segs[2]!)) return true;
    if (segs[1] === "evidence" && segs.length === 3 && RE.hash.test(segs[2]!)) return true;
    return false;
  }

  private async idempotent(
    req: HttpReq, auth: AuthResult, key: string, method: string, path: string,
    rawBody: unknown, status: number,
    fn: (idem: { method: string; path: string; key: string; bodyHash: string; status: number }) => Promise<Json>,
  ): Promise<HttpRes> {
    const bodyHash = hashJson(rawBody as Json);
    const gw = this.gw;
    const hit = gw.deps.store.read((q) => gw.idemLookup(q, auth.principal, method, path, key, bodyHash));
    if (hit === "conflict") throw err("IDEMPOTENCY_CONFLICT");
    if (hit) {
      // revoked principals cannot retrieve a cached success body
      try {
        await gw.deps.auth.current({ tenant: gw.config.tenant, principal: auth.principal });
      } catch { throw err("AUTH_REVOKED"); }
      return { status: hit.status, body: hit.body, headers: { "idempotency-replayed": "true" } };
    }
    // the engine stores the response atomically with the mutation commit
    const body = await fn({ method, path, key, bodyHash, status });
    return { status, body, headers: {} };
  }
}

function intQ(v: string | null, dflt: number | null): number {
  if (v === null) {
    if (dflt === null) throw err("SCHEMA_INVALID");
    return dflt;
  }
  if (!/^[0-9]+$/.test(v)) throw err("SCHEMA_INVALID");
  return Number(v);
}
