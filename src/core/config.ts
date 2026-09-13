/**
 * Deployment and CLI configuration schemas (spec §4.4). Unknown fields or
 * absent bindings fail readiness; secret values are never accepted here.
 */

import { err } from "./errors.ts";
import type { Json } from "./canonical.ts";
import { isSafeInt } from "./canonical.ts";
import { RE } from "./hash.ts";
import { isId } from "./ids.ts";
import { closed, uInt, str, bool, enumF, pubKeyF, idF } from "./schemas.ts";
import { isRegisteredTool } from "./registry.ts";

export interface GatewayConfig {
  v: 1; tenant: string; gateway: string; policy_file: string;
  auth_binding: "AUTH"; shield_binding: "LEXSHIELD"; inbox_binding: "VEKINBOX";
  tools_binding: "TOOLS"; audit_signer_binding: "AUDIT_SIGNER";
  audit_key_id: string; audit_public_key: string;
  encryption_key_binding: "ACTION_ENCRYPTION_KEY";
  registry_profile: "known-tools-1"; registry_version: 1; enabled_tools: string[];
  payload_retention_ms: number; terminal_retention_ms: number;
  human_identity_max_age_ms: number; production: boolean;
}

export function gatewayConfigF(v: unknown): GatewayConfig {
  const o = closed(v, [
    "audit_key_id", "audit_public_key", "audit_signer_binding", "auth_binding",
    "enabled_tools", "encryption_key_binding", "gateway", "human_identity_max_age_ms",
    "inbox_binding", "payload_retention_ms", "policy_file", "production",
    "registry_profile", "registry_version", "shield_binding", "tenant",
    "terminal_retention_ms", "tools_binding", "v",
  ]);
  if (o.v !== 1) throw err("UNSUPPORTED_VERSION");
  const tenant = idF("tenant")(o.tenant);
  const gateway = idF("gateway")(o.gateway);
  if (o.auth_binding !== "AUTH" || o.shield_binding !== "LEXSHIELD" || o.inbox_binding !== "VEKINBOX"
    || o.tools_binding !== "TOOLS" || o.audit_signer_binding !== "AUDIT_SIGNER"
    || o.encryption_key_binding !== "ACTION_ENCRYPTION_KEY") throw err("POLICY_INVALID", null, "absent binding");
  if (o.registry_profile !== "known-tools-1" || o.registry_version !== 1) throw err("UNSUPPORTED_VERSION");
  const enabled = o.enabled_tools;
  if (!Array.isArray(enabled) || enabled.length < 1) throw err("POLICY_INVALID");
  const seen = new Set<string>();
  for (const t of enabled) {
    if (typeof t !== "string" || !isRegisteredTool(t) || seen.has(t)) throw err("POLICY_INVALID");
    seen.add(t);
  }
  const sorted = [...seen].sort();
  if ([...seen].join(",") !== sorted.join(",")) throw err("POLICY_INVALID"); // ascending unique
  const hima = uInt(o.human_identity_max_age_ms);
  if (hima > 300000) throw err("POLICY_INVALID");
  const pr = uInt(o.payload_retention_ms);
  const tr = uInt(o.terminal_retention_ms);
  if (pr < 86400000 || pr > 604800000) throw err("POLICY_INVALID");
  if (tr < 7776000000 || tr > 31536000000) throw err("POLICY_INVALID");
  return {
    v: 1, tenant, gateway,
    policy_file: str(o.policy_file, 512),
    auth_binding: "AUTH", shield_binding: "LEXSHIELD", inbox_binding: "VEKINBOX",
    tools_binding: "TOOLS", audit_signer_binding: "AUDIT_SIGNER",
    audit_key_id: idF("key")(o.audit_key_id),
    audit_public_key: pubKeyF(o.audit_public_key),
    encryption_key_binding: "ACTION_ENCRYPTION_KEY",
    registry_profile: "known-tools-1", registry_version: 1,
    enabled_tools: sorted,
    payload_retention_ms: pr, terminal_retention_ms: tr,
    human_identity_max_age_ms: hima,
    production: bool(o.production),
  };
}

export interface CliConfig { v: 1; base_url: string; credential_env: string; timeout_ms: number; trust_file: string }
export function cliConfigF(v: unknown): CliConfig {
  const o = closed(v, ["base_url", "credential_env", "timeout_ms", "trust_file", "v"]);
  if (o.v !== 1) throw err("UNSUPPORTED_VERSION");
  return {
    v: 1,
    base_url: str(o.base_url, 512),
    credential_env: str(o.credential_env, 128),
    timeout_ms: uInt(o.timeout_ms),
    trust_file: str(o.trust_file, 512),
  };
}

export interface TrustKey { key_id: string; public_key: string; first_seq: number; last_seq: number | null }
export interface TrustFile { v: 1; tenant: string; gateway: string; keys: TrustKey[] }
export function trustFileF(v: unknown): TrustFile {
  const o = closed(v, ["gateway", "keys", "tenant", "v"]);
  if (o.v !== 1) throw err("UNSUPPORTED_VERSION");
  const keys = o.keys;
  if (!Array.isArray(keys) || keys.length < 1) throw err("SCHEMA_INVALID");
  const parsed: TrustKey[] = keys.map((k) => {
    const kk = closed(k, ["first_seq", "key_id", "last_seq", "public_key"]);
    return {
      key_id: idF("key")(kk.key_id), public_key: pubKeyF(kk.public_key),
      first_seq: uInt(kk.first_seq), last_seq: kk.last_seq === null ? null : uInt(kk.last_seq),
    };
  });
  // intervals must not overlap
  const sorted = [...parsed].sort((a, b) => a.first_seq - b.first_seq);
  for (let i = 0; i < sorted.length; i++) {
    const k = sorted[i]!;
    if (k.first_seq < 1) throw err("SCHEMA_INVALID");
    if (i > 0) {
      const prev = sorted[i - 1]!;
      if (prev.last_seq === null || k.first_seq <= prev.last_seq) throw err("SCHEMA_INVALID");
    }
  }
  if (sorted.length > 0 && sorted[0]!.first_seq !== 1) throw err("SCHEMA_INVALID");
  return { v: 1, tenant: idF("tenant")(o.tenant), gateway: idF("gateway")(o.gateway), keys: parsed };
}
