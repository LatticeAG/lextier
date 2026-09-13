/**
 * Seeded fuzzing of the strict parsers and canonicalizer (spec §15).
 * Reproducible: fixed LCG seeds; failures print the seed for replay.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseJsonStrict, parseJsonBytes } from "../src/core/strict_json.ts";
import { canonicalBytes, canonicalize, type Json } from "../src/core/canonical.ts";
import { parseYaml } from "../src/core/yaml.ts";

/** Deterministic LCG (numerical recipes). */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 0x100000000; };
}

const UNICODE_POOL = [
  "a", "Z", "0", " ", "\n", "\t", '"', "\\", "é", "中", "🙂", "\u0001", "\u001f",
  "\u007f", "ﬀ", " ", " ", "﻿", "/", "-", "_", "~", "\ud834\udd1e",
];

function randJson(r: () => number, depth: number): Json {
  const t = r();
  if (depth >= 8 || t < 0.3) {
    const k = r();
    if (k < 0.2) return null;
    if (k < 0.4) return r() < 0.5;
    if (k < 0.6) return Math.floor(r() * 9007199254740991) * (r() < 0.5 ? -1 : 1);
    const len = Math.floor(r() * 12);
    let s = "";
    for (let i = 0; i < len; i++) s += UNICODE_POOL[Math.floor(r() * UNICODE_POOL.length)]!;
    return s;
  }
  if (t < 0.65) {
    const n = Math.floor(r() * 6);
    return Array.from({ length: n }, () => randJson(r, depth + 1));
  }
  const n = Math.floor(r() * 6);
  const o: Record<string, Json> = {};
  const keys = new Set<string>();
  for (let i = 0; i < n; i++) {
    const k = UNICODE_POOL[Math.floor(r() * UNICODE_POOL.length)]! + String(Math.floor(r() * 100));
    if (keys.has(k)) continue; // unique keys only — duplicates tested separately
    keys.add(k);
    o[k] = randJson(r, depth + 1);
  }
  return o;
}

test("fuzz: canonical(parse(canonical(v))) round-trips for 2000 seeded values", () => {
  const r = rng(0xC0FFEE);
  for (let i = 0; i < 2000; i++) {
    const v = randJson(r, 0);
    const c1 = canonicalize(v);
    const back = parseJsonStrict(c1);
    const c2 = canonicalize(back);
    assert.equal(c2, c1, `seed 0xC0FFEE case ${i}: ${JSON.stringify(v).slice(0, 120)}`);
  }
});

test("fuzz: canonical bytes are valid UTF-8 and reparsable", () => {
  const r = rng(12345);
  for (let i = 0; i < 1000; i++) {
    const v = randJson(r, 0);
    const b = canonicalBytes(v);
    const back = parseJsonBytes(b);
    assert.deepEqual(back, JSON.parse(new TextDecoder().decode(b)));
  }
});

test("fuzz: duplicate keys always rejected regardless of position", () => {
  const r = rng(777);
  for (let i = 0; i < 500; i++) {
    const key = "k" + Math.floor(r() * 10);
    const doc = `{"${key}":${i},"other":[1,{"${key}":2,"${key}":3}]}`;
    assert.throws(() => parseJsonStrict(doc), undefined);
  }
});

test("fuzz: random bytes never crash the strict parser", () => {
  const r = rng(0xBEEF);
  for (let i = 0; i < 1000; i++) {
    const n = Math.floor(r() * 64);
    const buf = new Uint8Array(n).map(() => Math.floor(r() * 256));
    try { parseJsonBytes(buf); } catch (e) {
      assert.ok(e instanceof Error, `case ${i} threw non-error`);
    }
  }
});

test("fuzz: forbidden YAML features rejected in generated docs", () => {
  const r = rng(4242);
  // forbidden constructs in the positions where they are actually syntax
  const docs = [
    (n: number) => `a: &anchor ${n}\nb: *anchor\n`,      // anchor+alias
    (n: number) => `a: !!str ${n}\n`,                      // explicit tag
    () => `%YAML 1.2\na: 1\n`,                            // directive
    () => `a: 1\n---\nb: 2\n`,                           // second document
    () => `a: 1\n...\n`,                                  // doc terminator
    () => `base:\n  x: 1\nderived:\n  <<: *base\n`,     // merge key
    () => `? complex\n: key\n`,                           // explicit key
    () => `a: *ref\n`,                                     // bare alias value
    () => `a: &n 1\nb: 2\n`,                              // bare anchor
  ];
  for (let i = 0; i < 500; i++) {
    const gen = docs[Math.floor(r() * docs.length)]!;
    const doc = gen(Math.floor(r() * 100));
    assert.throws(() => parseYaml(doc), undefined);
  }
});

test("fuzz: generate-and-compare canonical strings against JSON.stringify for objects", () => {
  // JSON.stringify of a plain object does NOT sort keys; canonical must.
  const r = rng(99);
  for (let i = 0; i < 500; i++) {
    const v = randJson(r, 0) as Record<string, Json>;
    const c = canonicalize(v);
    if (typeof v !== "object" || v === null || Array.isArray(v)) continue;
    const keys = Object.keys(v).sort();
    if (keys.length > 1) {
      assert.ok(c.indexOf(JSON.stringify(keys[0]!)) <= c.indexOf(JSON.stringify(keys[keys.length - 1]!)));
    }
  }
});
