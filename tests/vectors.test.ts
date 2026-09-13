/**
 * Conformance vectors TV-*-01..52 — each vector runs through the real
 * production code path via the harness; no production special-casing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runVector } from "./harness.ts";

interface V { id: string; name: string; input: Record<string, unknown>; expected: Record<string, unknown> }

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "..", "conformance", "vectors.json"), "utf8")) as V[];

for (const v of vectors) {
  test(`${v.id} ${v.name}`, async () => {
    const r = await runVector(v);
    assert.ok(r.pass, `expected ${JSON.stringify(v.expected)} got ${JSON.stringify(r.actual)}${r.error ? " err: " + r.error.split("\n")[0] : ""}`);
  });
}
