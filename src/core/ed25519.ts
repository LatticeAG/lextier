/**
 * Ed25519 per RFC 8032, implemented over BigInt for exact cross-runtime
 * parity. Deterministic signing; strict verification (spec §7): rejects
 * malformed lengths, noncanonical scalars (S >= l), noncanonical/invalid
 * point encodings, and small-order public keys.
 */

import { createHash } from "node:crypto";

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const D = mod(-121665n * inv(121666n));
const I = pow2((P - 1n) / 4n); // sqrt(-1) mod p

type Pt = { X: bigint; Y: bigint; Z: bigint; T: bigint }; // extended coords

const IDENTITY: Pt = { X: 0n, Y: 1n, Z: 1n, T: 0n };
const B: Pt = (() => {
  const y = mod(4n * inv(5n));
  const x = recoverX(y, 0);
  return { X: x, Y: y, Z: 1n, T: mod(x * y) };
})();

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}
function inv(a: bigint): bigint {
  return pow(mod(a), P - 2n);
}
function pow(a: bigint, e: bigint): bigint {
  let base = mod(a), exp = e, r = 1n;
  while (exp > 0n) {
    if (exp & 1n) r = mod(r * base);
    base = mod(base * base);
    exp >>= 1n;
  }
  return r;
}
function pow2(e: bigint): bigint { return pow(2n, e); }

function recoverX(y: bigint, sign: number): bigint {
  const y2 = mod(y * y);
  const xx = mod((y2 - 1n) * inv(mod(D * y2 + 1n)));
  let x = pow(xx, (P + 3n) / 8n);
  if (mod(x * x - xx) !== 0n) x = mod(x * I);
  if (mod(x * x - xx) !== 0n) throw new Error("ed25519: point not on curve");
  if (Number(x & 1n) !== sign) x = mod(-x);
  return x;
}

function add(p: Pt, q: Pt): Pt {
  const A = mod((p.Y - p.X) * (q.Y - q.X));
  const Bv = mod((p.Y + p.X) * (q.Y + q.X));
  const C = mod(2n * D * p.T * q.T);
  const Dv = mod(2n * p.Z * q.Z);
  const E = mod(Bv - A), F = mod(Dv - C), G = mod(Dv + C), H = mod(Bv + A);
  return { X: mod(E * F), Y: mod(G * H), T: mod(E * H), Z: mod(F * G) };
}

function dbl(p: Pt): Pt { return add(p, p); }

function scalarmult(p: Pt, e: bigint): Pt {
  let r = IDENTITY, b = p, s = e;
  while (s > 0n) {
    if (s & 1n) r = add(r, b);
    b = dbl(b);
    s >>= 1n;
  }
  return r;
}

function isIdentity(p: Pt): boolean {
  return mod(p.X) === 0n && mod(p.Y - p.Z) === 0n;
}

function encodePoint(p: Pt): Uint8Array {
  const zi = inv(p.Z);
  const x = mod(p.X * zi), y = mod(p.Y * zi);
  const out = new Uint8Array(32);
  let v = y | (BigInt(Number(x & 1n)) << 255n);
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

/** Strict decode: y must be < p (canonical) and x must recover. */
function decodePointStrict(s: Uint8Array): Pt | null {
  if (s.length !== 32) return null;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(s[i]!);
  const sign = Number(y >> 255n);
  y &= (1n << 255n) - 1n;
  if (y >= P) return null; // noncanonical encoding
  let x: bigint;
  try { x = recoverX(y, sign); } catch { return null; }
  const pt = { X: x, Y: y, Z: 1n, T: mod(x * y) };
  // verify on-curve equation -x^2 + y^2 = 1 + d x^2 y^2
  const x2 = mod(x * x), y2 = mod(y * y);
  if (mod(-x2 + y2 - 1n - mod(D * x2 * y2)) !== 0n) return null;
  return pt;
}

/** Small-order check: points with order dividing the cofactor are rejected. */
function isSmallOrder(p: Pt): boolean {
  return isIdentity(scalarmult(p, 8n));
}

function sha512(b: Uint8Array): Uint8Array {
  return createHash("sha512").update(b).digest();
}

function leInt(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return v;
}
function leBytes(v: bigint, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

export function edPublicKeyFromSeed(seed: Uint8Array): Uint8Array {
  const h = sha512(seed);
  const a = clampScalar(h.slice(0, 32));
  return encodePoint(scalarmult(B, a));
}

function clampScalar(h: Uint8Array): bigint {
  const a = h.slice();
  a[0] = a[0]! & 248; a[31] = (a[31]! & 127) | 64;
  return leInt(a);
}

/** Deterministic RFC 8032 signature. seed is 32 bytes. */
export function edSign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  const h = sha512(seed);
  const a = clampScalar(h.slice(0, 32));
  const A = encodePoint(scalarmult(B, a));
  const r = leInt(sha512(concat(h.slice(32, 64), message))) % L;
  const R = encodePoint(scalarmult(B, r));
  const k = leInt(sha512(concat(R, A, message))) % L;
  const S = (r + k * a) % L;
  return concat(R, leBytes(S, 32));
}

export function edPublicKeyValid(publicKey: Uint8Array): boolean {
  const A = decodePointStrict(publicKey);
  if (A === null) return false;
  if (isSmallOrder(A)) return false;
  return true;
}

/** Strict verification. Returns false on any malformed input. */
export function edVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const R = signature.slice(0, 32);
  const sBytes = signature.slice(32, 64);
  const S = leInt(sBytes);
  if (S >= L) return false; // noncanonical scalar
  const A = decodePointStrict(publicKey);
  if (A === null || isSmallOrder(A)) return false;
  const Rp = decodePointStrict(R);
  if (Rp === null) return false;
  const k = leInt(sha512(concat(R, publicKey, message))) % L;
  const lhs = scalarmult(B, S);
  const rhs = add(Rp, scalarmult(A, k));
  const zi1 = inv(lhs.Z), zi2 = inv(rhs.Z);
  return mod(lhs.X * zi1 - rhs.X * zi2) === 0n && mod(lhs.Y * zi1 - rhs.Y * zi2) === 0n;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}
export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
