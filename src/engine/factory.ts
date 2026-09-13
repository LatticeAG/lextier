/**
 * Gateway construction: load deployment config, seed policy, fixture or
 * real bindings, key registry, and recovery.
 */

import { readFileSync } from "node:fs";
import { randomBytes, createHash } from "node:crypto";
import { gatewayConfigF, type GatewayConfig } from "../core/config.ts";
import { parseYaml } from "../core/yaml.ts";
import { parseJsonBytes } from "../core/strict_json.ts";
import { fixtureIdGen, csprngIdGen, type IdGen } from "../core/ids.ts";
import { edPublicKeyFromSeed, hexToBytes, bytesToHex } from "../core/ed25519.ts";
import { err } from "../core/errors.ts";
import { compilePolicy } from "../core/policy.ts";
import { Store } from "./store.ts";
import {
  FixtureAuth, FixtureShield, FixtureTools, FixtureInbox, LocalSigner,
  type AuthBinding, type ShieldBinding, type ToolsBinding, type InboxBinding, type SignerBinding,
} from "./bindings.ts";
import { TenantGateway, type GatewayDeps } from "./gateway.ts";

export interface BuildOptions {
  dbPath?: string;
  wall?: () => number;
  ids?: IdGen;
  encKey?: Uint8Array;
  auth?: AuthBinding;
  shield?: ShieldBinding;
  tools?: ToolsBinding;
  inbox?: InboxBinding;
  signer?: SignerBinding;
}

export interface Built {
  gw: TenantGateway;
  store: Store;
  config: GatewayConfig;
  auth: AuthBinding; shield: ShieldBinding; tools: ToolsBinding;
  inbox: InboxBinding; signer: SignerBinding;
}

export function loadConfigFile(path: string): GatewayConfig {
  const raw = readFileSync(path);
  const parsed = path.endsWith(".yaml") || path.endsWith(".yml") ? parseYaml(raw.toString("utf8")) : parseJsonBytes(new Uint8Array(raw));
  return gatewayConfigF(parsed);
}

export function loadPolicyFile(path: string): unknown {
  const raw = readFileSync(path).toString("utf8");
  const parsed = path.endsWith(".yaml") || path.endsWith(".yml") ? parseYaml(raw) : parseJsonBytes(new TextEncoder().encode(raw));
  return parsed;
}

/**
 * Build a TenantGateway. Without explicit bindings, in-process fixture
 * bindings are used (development/test); production deployment wires platform
 * bindings through the same interfaces.
 */
export async function buildGateway(config: GatewayConfig, opts: BuildOptions = {}): Promise<Built> {
  const store = new Store(opts.dbPath ?? ":memory:");
  const wall = opts.wall ?? (() => Date.now());
  const ids = opts.ids ?? csprngIdGen();
  const auth = opts.auth ?? new FixtureAuth();
  const shield = opts.shield ?? new FixtureShield();
  const tools = opts.tools ?? new FixtureTools();
  const inbox = opts.inbox ?? new FixtureInbox();
  const signer = opts.signer ?? new LocalSigner();
  const encKey = opts.encKey ?? randomBytes(32);
  const buildHash = createHash("sha256").update(`lextier-dev-build`).digest("hex");

  const gw = new TenantGateway({
    config, store, wall, ids, auth, shield, tools, inbox, signer,
    encKey, buildHash,
  });
  return { gw, store, config, auth, shield, tools, inbox, signer };
}

/** Boot sequence: install key registry, recover, bootstrap policy, readiness. */
export async function boot(built: Built, opts: { policyRaw: unknown; adminActor: string; signerSeedHex?: string }): Promise<void> {
  const { gw, signer } = built;
  if (signer instanceof LocalSigner && opts.signerSeedHex) {
    signer.addKey(built.config.audit_key_id, opts.signerSeedHex);
  }
  // key registry check: the configured public key must match the signer's key
  if (signer instanceof LocalSigner && opts.signerSeedHex) {
    const pub = bytesToHex(edPublicKeyFromSeed(hexToBytes(opts.signerSeedHex)));
    if (pub !== built.config.audit_public_key) {
      throw err("POLICY_INVALID", null, `audit_public_key mismatch: signer has ${pub}`);
    }
  }
  await gw.installKeyRegistry();
  await gw.recover();
  await gw.bootstrap(opts.adminActor, opts.policyRaw);
  const ready = await gw.status();
  void ready;
}
