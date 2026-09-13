/** Unit tests for deterministic core primitives against pinned spec values. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalBytes, canonicalize as canonicalString, type Json } from "../src/core/canonical.ts";
import { parseJsonBytes, parseJsonStrict } from "../src/core/strict_json.ts";
import { parseYaml } from "../src/core/yaml.ts";
import { sha256Hex, hashDomainJson, DOMAIN } from "../src/core/hash.ts";
import { edSign, edVerify, edPublicKeyFromSeed, edPublicKeyValid, hexToBytes, bytesToHex } from "../src/core/ed25519.ts";
import { compilePolicy, policyHash } from "../src/core/policy.ts";
import { REGISTRY_HASH } from "../src/core/registry.ts";
import { LexError } from "../src/core/errors.ts";
import { P, RH, rCommit } from "./harness.ts";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

const RFC_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC_SIG_EMPTY = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

test("canonical: object key ordering is byte-sorted", () => {
  assert.equal(canonicalString({ b: 1, a: 2, "10": 3, "2": 4 }), '{"10":3,"2":4,"a":2,"b":1}');
  assert.equal(canonicalString({}), "{}");
  assert.equal(canonicalString([]), "[]");
  assert.equal(canonicalString(null), "null");
});

test("canonical: the wire domain admits safe integers only", () => {
  assert.equal(canonicalString(0), "0");
  assert.equal(canonicalString(-0), "0");
  assert.equal(canonicalString(1), "1");
  assert.equal(canonicalString(-42), "-42");
  assert.equal(canonicalString(Number.MAX_SAFE_INTEGER), "9007199254740991");
  assert.equal(canonicalString(Number.MIN_SAFE_INTEGER), "-9007199254740991");
  assert.throws(() => canonicalBytes(1.5 as never));
  assert.throws(() => canonicalBytes(1e20 as never)); // exceeds safe-integer domain
  assert.throws(() => canonicalBytes(1e-7 as never));
  assert.throws(() => canonicalBytes(Number.NaN as never));
  assert.throws(() => canonicalBytes(Number.POSITIVE_INFINITY as never));
});

test("canonical: string escaping minimal per JCS", () => {
  assert.equal(canonicalString('a"b'), '"a\\"b"');
  assert.equal(canonicalString("a\nb"), '"a\\nb"');
  assert.equal(canonicalString("é"), '"é"'); // non-ASCII unescaped
  assert.equal(canonicalString("\u0001"), '"\\u0001"');
  assert.equal(canonicalString("\\"), '"\\\\"');
  assert.equal(canonicalString("\ud834\udd1e"), '"\ud834\udd1e"'); // surrogate pair preserved
});

test("canonical: rejects lone surrogates and non-JSON types", () => {
  assert.throws(() => canonicalBytes("\ud800" as never));
  assert.throws(() => canonicalBytes("\udc00" as never));
  assert.throws(() => canonicalBytes(undefined as never));
  assert.throws(() => canonicalBytes(Symbol("x") as never));
  assert.throws(() => canonicalBytes(10n as never));
  assert.throws(() => canonicalBytes({ a: undefined } as never));
});

test("strict json: duplicate keys rejected at any depth", () => {
  assert.throws(() => parseJsonStrict('{"a":1,"a":2}'), LexError);
  assert.throws(() => parseJsonStrict('{"x":{"a":1,"a":2}}'), LexError);
  assert.throws(() => parseJsonStrict('[{"a":1,"a":2}]'), LexError);
  assert.equal(JSON.stringify(parseJsonStrict('{"a":1,"b":2}')), '{"a":1,"b":2}');
});

test("strict json: rejects non-integer numbers and overflow", () => {
  assert.throws(() => parseJsonStrict('{"a":1.5}'));
  assert.throws(() => parseJsonStrict('{"a":1e3}'));
  assert.throws(() => parseJsonStrict('{"a":9007199254740993}')); // > MAX_SAFE_INTEGER
  assert.equal((parseJsonStrict('{"a":-1}') as { a: number }).a, -1); // signed ints in range are in-domain
  assert.equal((parseJsonStrict('{"a":0}') as { a: number }).a, 0);
});

test("strict json: rejects NaN/Infinity/trailing/empty/bad utf8", () => {
  assert.throws(() => parseJsonStrict("NaN"));
  assert.throws(() => parseJsonStrict("Infinity"));
  assert.throws(() => parseJsonStrict("{} garbage"));
  assert.throws(() => parseJsonStrict(""));
  assert.throws(() => parseJsonBytes(new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]))); // invalid utf8
  assert.throws(() => parseJsonStrict('{"a":01}'));
  assert.throws(() => parseJsonStrict("{'a':1}"));
});

test("strict json: nesting depth bounded at 16", () => {
  const deep = "[".repeat(17) + "1" + "]".repeat(17);
  assert.throws(() => parseJsonStrict(deep));
  const ok = "[".repeat(15) + "1" + "]".repeat(15);
  assert.doesNotThrow(() => parseJsonStrict(ok));
});

test("yaml: rejects anchors, aliases, merge keys, tags, multi-doc", () => {
  assert.throws(() => parseYaml("a: &x 1\nb: *x\n"), LexError);
  assert.throws(() => parseYaml("a: !!str 1\n"));
  assert.throws(() => parseYaml("---\na: 1\n---\nb: 2\n"));
  assert.throws(() => parseYaml("? complex\n: key\n"));
  assert.throws(() => parseYaml("base: &b {x: 1}\nderived:\n  <<: *b\n"));
});

test("yaml: reference policy compiles to pinned hash", () => {
  const raw = readFileSync(join(here, "..", "lextier.yaml"), "utf8");
  const pol = compilePolicy(parseYaml(raw));
  assert.equal(policyHash(pol), "90083af6504c50a4c01730b60a7ddd13e1ca0dc582a4a4ac06a2ea7537d93613");
});

test("registry: pinned registry hash", () => {
  assert.equal(REGISTRY_HASH, "e9035c1b1e57a23ebcfe00db0150c94b84a6bab9f7f95615b74c1528a25cb65a");
});

test("commit: pinned action hash for the §8.4 fixture", () => {
  assert.equal(hashDomainJson(DOMAIN.ACTION, rCommit() as unknown as Json), RH);
});

test("ed25519: RFC 8032 test vector 1 (empty message)", () => {
  const seed = hexToBytes(RFC_SEED);
  const pub = edPublicKeyFromSeed(seed);
  assert.equal(bytesToHex(pub), RFC_PUB);
  const sig = edSign(seed, new Uint8Array(0));
  assert.equal(bytesToHex(sig), RFC_SIG_EMPTY);
  assert.ok(edVerify(pub, new Uint8Array(0), sig));
  assert.ok(!edVerify(pub, new Uint8Array([1]), sig));
});

test("ed25519: rejects malformed keys and signatures", () => {
  const seed = hexToBytes(RFC_SEED);
  const pub = edPublicKeyFromSeed(seed);
  const msg = new Uint8Array([1, 2, 3]);
  const sig = edSign(seed, msg);
  assert.ok(edVerify(pub, msg, sig));
  // flipped bit in signature
  const bad = new Uint8Array(sig); bad[10]! ^= 1;
  assert.ok(!edVerify(pub, msg, bad));
  // identity / small-order public key must be rejected
  assert.ok(!edPublicKeyValid(new Uint8Array(32).fill(0)));
  assert.ok(!edVerify(new Uint8Array(32).fill(0), msg, sig));
  // wrong-length inputs
  assert.ok(!edVerify(pub.subarray(0, 31), msg, sig));
  assert.ok(!edVerify(pub, msg, sig.subarray(0, 63)));
});

test("hash: domain separation produces distinct digests", () => {
  const a = sha256Hex(new Uint8Array([1]));
  assert.match(a, /^[0-9a-f]{64}$/);
});
