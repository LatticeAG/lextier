/**
 * AES-256-GCM envelope encryption (spec §11.2). Independent random 96-bit
 * nonces; associated data is J({tenant,gateway,table,primary_key,
 * schema_version:1}); envelope layout exactly
 * {v:1,key_version,nonce_hex,ciphertext_hex,tag_hex}.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { canonicalBytes, type Json } from "../core/canonical.ts";
import { err } from "../core/errors.ts";

export interface AadContext {
  tenant: string; gateway: string; table: string; primary_key: string;
}

export interface Envelope {
  v: 1; key_version: number; nonce_hex: string; ciphertext_hex: string; tag_hex: string;
}

function aad(ctx: AadContext): Uint8Array {
  return canonicalBytes({
    gateway: ctx.gateway, primary_key: ctx.primary_key, schema_version: 1,
    table: ctx.table, tenant: ctx.tenant,
  }) as Uint8Array;
}

export function seal(key: Uint8Array, ctx: AadContext, plaintext: Uint8Array, keyVersion = 1): Envelope {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
  c.setAAD(Buffer.from(aad(ctx)));
  const ct = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  const tag = c.getAuthTag();
  return {
    v: 1, key_version: keyVersion,
    nonce_hex: nonce.toString("hex"), ciphertext_hex: ct.toString("hex"), tag_hex: tag.toString("hex"),
  };
}

export function sealJson(key: Uint8Array, ctx: AadContext, value: Json, keyVersion = 1): Envelope {
  return seal(key, ctx, canonicalBytes(value), keyVersion);
}

export function open(key: Uint8Array, ctx: AadContext, env: Envelope): Uint8Array {
  if (env.v !== 1 || typeof env.nonce_hex !== "string" || env.nonce_hex.length !== 24) throw err("SCHEMA_INVALID");
  if (typeof env.tag_hex !== "string" || env.tag_hex.length !== 32) throw err("SCHEMA_INVALID");
  const d = createDecipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(env.nonce_hex, "hex"));
  d.setAAD(Buffer.from(aad(ctx)));
  d.setAuthTag(Buffer.from(env.tag_hex, "hex"));
  const pt = Buffer.concat([d.update(Buffer.from(env.ciphertext_hex, "hex")), d.final()]);
  return new Uint8Array(pt);
}

export function openJson(key: Uint8Array, ctx: AadContext, env: Envelope): Json {
  return JSON.parse(Buffer.from(open(key, ctx, env)).toString("utf8")) as Json;
}
