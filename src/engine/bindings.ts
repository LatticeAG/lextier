/**
 * Service-binding contracts (spec §9.1–9.2) and fixture implementations used
 * by the conformance harness and the local development runner. Bindings are
 * trusted internal dependencies: they never accept caller-supplied URLs.
 */

import { err } from "../core/errors.ts";
import { hashJson, sha256Hex, RE } from "../core/hash.ts";
import { canonicalBytes, type Json } from "../core/canonical.ts";
import { edSign, edPublicKeyFromSeed, hexToBytes, bytesToHex } from "../core/ed25519.ts";
import type { ToolCall } from "../core/registry.ts";
import type {
  AuthResult, ScopeSnapshot, InspectResult, ExecuteInput, LookupInput,
  ToolResult, Card, Target, BlastCard,
} from "../core/schemas.ts";

export class BindingError extends Error {
  readonly code: string;
  constructor(code: string, msg?: string) { super(msg ?? code); this.code = code; }
}

export interface AuthBinding {
  verify(req: { credential_binding: string; request_method: string; request_path: string }): Promise<AuthResult>;
  current(req: { tenant: string; principal: string }): Promise<AuthResult>;
}

export interface ShieldBinding {
  check(req: { tenant: string; principal: string; call: ToolCall }): Promise<ScopeSnapshot>;
}

export interface ToolsBinding {
  inspect(req: { call: ToolCall; include_blast: boolean }): Promise<InspectResult>;
  execute_once(req: ExecuteInput): Promise<ToolResult>;
  lookup(req: LookupInput): Promise<ToolResult>;
}

export interface InboxBinding {
  upsert(card: Card): Promise<{ card_id: string; revision: number; stored: boolean }>;
}

export interface SignerBinding {
  sign(req: { key_id: string; purpose: "entry" | "head" | "rotation"; message_hex: string }): Promise<{ signature: string }>;
  /** Public key for a provisioned key id, if known. */
  publicKey?(keyId: string): string | null;
}

// ---------------- fixture implementations ----------------

export interface FixturePrincipal {
  kind: "human" | "agent" | "service";
  roles: ("invoke" | "review" | "audit" | "admin")[];
  epoch: number;
  verified_ms: number;
  disabled?: boolean;
}

/**
 * Deterministic AUTH fixture. Tokens map to principals via `tokens`
 * (token value -> principal id); current() resolves live state.
 */
export class FixtureAuth implements AuthBinding {
  tokens: Map<string, { tenant: string; principal: string }> = new Map();
  principals: Map<string, FixturePrincipal & { tenant: string }> = new Map();
  failCurrent = false;

  addPrincipal(tenant: string, principal: string, p: FixturePrincipal, token?: string): void {
    this.principals.set(principal, { ...p, tenant });
    if (token) this.tokens.set(token, { tenant, principal });
  }
  setKind(principal: string, kind: FixturePrincipal["kind"]): void {
    const p = this.principals.get(principal); if (p) p.kind = kind;
  }
  setEpoch(principal: string, epoch: number): void {
    const p = this.principals.get(principal); if (p) p.epoch = epoch;
  }
  disable(principal: string): void {
    const p = this.principals.get(principal); if (p) p.disabled = true;
  }

  async verify(req: { credential_binding: string; request_method: string; request_path: string }): Promise<AuthResult> {
    const hit = this.tokens.get(req.credential_binding);
    if (!hit) throw err("AUTH_REQUIRED");
    const p = this.principals.get(hit.principal);
    if (!p || p.disabled || p.tenant !== hit.tenant) throw err("AUTH_REVOKED");
    return { tenant: hit.tenant, principal: hit.principal, kind: p.kind, roles: [...p.roles], epoch: p.epoch, verified_ms: p.verified_ms };
  }

  async current(req: { tenant: string; principal: string }): Promise<AuthResult> {
    if (this.failCurrent) throw new BindingError("DEPENDENCY_UNAVAILABLE");
    const p = this.principals.get(req.principal);
    if (!p || p.disabled || p.tenant !== req.tenant) throw err("AUTH_REVOKED");
    return { tenant: req.tenant, principal: req.principal, kind: p.kind, roles: [...p.roles], epoch: p.epoch, verified_ms: p.verified_ms };
  }
}

export class FixtureShield implements ShieldBinding {
  snapshot: ScopeSnapshot = { revision: 1, verdict: "allow", reason: "SCOPE_OK" };
  unavailable = false;
  calls = 0;
  async check(_req: { tenant: string; principal: string; call: ToolCall }): Promise<ScopeSnapshot> {
    this.calls++;
    if (this.unavailable) throw new BindingError("DEPENDENCY_UNAVAILABLE");
    return { ...this.snapshot };
  }
}

export interface FixtureFile { version: string; digest: string }

/**
 * Deterministic TOOLS fixture. Files map pins target versions/digests;
 * provider behavior is selectable per call.
 */
export class FixtureTools implements ToolsBinding {
  files: Map<string, FixtureFile> = new Map();
  /** provider mode: healthy | timeout_after_accept | atomic_version_mismatch | symlink_at_effect_boundary */
  provider = "healthy";
  inspectUnavailable = false;
  enrichTimeout = false;
  dispatchCount = 0;
  effectCount = 0;
  results: Map<string, ToolResult> = new Map();

  constructor() {
    // canonical fixture file backing R
    this.files.set("/workspace/drafts/a.txt", {
      version: "7",
      digest: "cba06b5736faf67e54b07b561eae94395e774c517a7d910a54369e1263ccfbd4",
    });
    this.files.set("/workspace/public/a.txt", {
      version: "3",
      digest: sha256Hex("fixture:public:a.txt"),
    });
  }

  setVersion(path: string, version: string): void {
    const f = this.files.get(path) ?? { version, digest: "" };
    f.version = version;
    f.digest = sha256Hex(`fixture:${path}:${version}`);
    this.files.set(path, f);
  }

  async inspect(req: { call: ToolCall; include_blast: boolean }): Promise<InspectResult> {
    if (this.inspectUnavailable) throw new BindingError("DEPENDENCY_UNAVAILABLE");
    const { call } = req;
    const path = call.args.path as string | undefined;
    let target: Target;
    let blast: BlastCard | null = null;
    if (call.tool.startsWith("fs.")) {
      const f = this.files.get(path!);
      if (!f) return { target: { resource: `file:${path}`, version: "0", digest: sha256Hex("missing") }, permitted: false, reason: "TARGET_DENIED", blast: null };
      if ((call.tool === "fs.write_text" || call.tool === "fs.remove_file") && !path!.startsWith("/workspace/drafts/")) {
        return { target: { resource: `file:${path}`, version: f.version, digest: f.digest }, permitted: false, reason: "TARGET_DENIED", blast: null };
      }
      target = { resource: `file:${path}`, version: f.version, digest: f.digest };
      const ev = call.args.expected_version as string | undefined;
      if (ev !== undefined && ev !== f.version) {
        return { target, permitted: false, reason: "VERSION_MISMATCH", blast: null };
      }
      if (req.include_blast && call.tool === "fs.remove_file") {
        blast = this.enrich(target);
      }
    } else if (call.tool === "db.select_rows" || call.tool === "db.delete_rows") {
      const ids = (call.args.ids as string[]) ?? [];
      target = {
        resource: `db:${call.args.table}`,
        version: sha256Hex(`db:${call.args.table}:${ids.join(",")}`).slice(0, 32),
        digest: sha256Hex(`digest:${call.args.table}:${ids.join(",")}`),
      };
      const ev = call.args.expected_version as string | undefined;
      if (ev !== undefined && ev !== target.version) {
        return { target, permitted: false, reason: "VERSION_MISMATCH", blast: null };
      }
      if (req.include_blast && call.tool === "db.delete_rows") blast = this.enrich(target);
    } else if (call.tool === "payments.send") {
      const rid = call.args.recipient_id as string;
      const amt = call.args.amount_minor as number;
      if (amt < 1 || amt > 1000000 || !/^recipient_[a-z0-9_-]{1,48}$/.test(rid)) {
        target = { resource: `payments:recipient:${rid}`, version: "1", digest: sha256Hex(`pay:${rid}`) };
        return { target, permitted: false, reason: "TARGET_DENIED", blast: null };
      }
      target = { resource: `payments:recipient:${rid}`, version: "1", digest: sha256Hex(`pay:${rid}`) };
      const ev = call.args.expected_version as string | undefined;
      if (ev !== undefined && ev !== "1") {
        return { target, permitted: false, reason: "VERSION_MISMATCH", blast: null };
      }
      if (req.include_blast) blast = this.enrich(target);
    } else {
      throw new BindingError("UNSUPPORTED_ADAPTER");
    }
    if (req.include_blast && blast === null) blast = this.enrich(target);
    return { target, permitted: true, reason: "TARGET_OK", blast };
  }

  private enrich(target: Target): BlastCard | null {
    if (this.enrichTimeout) return null; // caller applies the 200 ms fallback
    return null; // fixture supplies no verified counts; fallback used
  }

  async execute_once(req: ExecuteInput): Promise<ToolResult> {
    this.dispatchCount++;
    const key = req.action_id;
    const prior = this.results.get(key);
    if (prior) {
      if (prior.provider_ref !== null) return prior; // dedup same action
    }
    let r: ToolResult;
    switch (this.provider) {
      case "timeout_after_accept":
        r = { status: "unknown", code: "PROVIDER_UNKNOWN", output: null, provider_ref: null };
        break;
      case "atomic_version_mismatch":
        r = { status: "failed", code: "PRECONDITION_CHANGED", output: null, provider_ref: null };
        break;
      case "symlink_at_effect_boundary":
        r = { status: "failed", code: "TARGET_UNSAFE", output: null, provider_ref: null };
        break;
      default:
        this.effectCount++;
        r = { status: "succeeded", code: "OK", output: { version: "8" }, provider_ref: "write-1" };
    }
    this.results.set(key, r);
    return r;
  }

  async lookup(req: LookupInput): Promise<ToolResult> {
    return this.results.get(req.action_id) ?? { status: "unknown", code: "PROVIDER_UNKNOWN", output: null, provider_ref: null };
  }
}

export class FixtureInbox implements InboxBinding {
  cards: Map<string, { card: Card; revision: number }> = new Map();
  unavailable = false;
  upserts = 0;
  async upsert(card: Card): Promise<{ card_id: string; revision: number; stored: boolean }> {
    this.upserts++;
    if (this.unavailable) throw new BindingError("DEPENDENCY_UNAVAILABLE");
    const prior = this.cards.get(card.card_id);
    const rev = card.action.revision;
    if (prior && prior.revision > rev) return { card_id: card.card_id, revision: prior.revision, stored: false };
    this.cards.set(card.card_id, { card: structuredClone(card), revision: rev });
    return { card_id: card.card_id, revision: rev, stored: true };
  }
  delivered(cardId: string): boolean { return this.cards.has(cardId); }
}

/**
 * Local audit signer: holds raw seeds (dev/test only — production binds a
 * platform KMS). Validates purpose and message bounds per §9.2.
 */
export class LocalSigner implements SignerBinding {
  seeds: Map<string, Uint8Array> = new Map();
  unavailable = false;
  calls = 0;

  addKey(keyId: string, seedHex: string): void {
    this.seeds.set(keyId, hexToBytes(seedHex));
  }
  publicKey(keyId: string): string | null {
    const s = this.seeds.get(keyId);
    return s ? bytesToHex(edPublicKeyFromSeed(s)) : null;
  }
  async sign(req: { key_id: string; purpose: "entry" | "head" | "rotation"; message_hex: string }): Promise<{ signature: string }> {
    this.calls++;
    if (this.unavailable) throw new BindingError("AUDIT_UNAVAILABLE");
    if (!/^[0-9a-f]*$/.test(req.message_hex) || req.message_hex.length % 2 !== 0) throw err("ADAPTER_PROTOCOL");
    if (req.message_hex.length / 2 > 4096) throw err("ADAPTER_PROTOCOL");
    const seed = this.seeds.get(req.key_id);
    if (!seed) throw new BindingError("DEPENDENCY_UNAVAILABLE");
    return { signature: bytesToHex(edSign(seed, hexToBytes(req.message_hex))) };
  }
}

/** Scope snapshot hashing per §6.1: hash {revision,verdict,reason} only. */
export function scopeHash(s: ScopeSnapshot): string {
  return hashJson({ reason: s.reason, revision: s.revision, verdict: s.verdict } as Json);
}

export function canonicalJsonOf(v: Json): Uint8Array {
  return canonicalBytes(v);
}
