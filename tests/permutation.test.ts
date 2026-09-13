/**
 * Policy rule-order permutation tests (spec §15): evaluation results are
 * order-independent even though the canonical policy hash is not.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { compilePolicy, evaluate, policyHash, type Policy, type Rule } from "../src/core/policy.ts";
import { P, R_CALL } from "./harness.ts";

function permutations<T>(xs: T[]): T[][] {
  if (xs.length <= 1) return [xs];
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i++) {
    for (const rest of permutations([...xs.slice(0, i), ...xs.slice(i + 1)])) {
      out.push([xs[i]!, ...rest]);
    }
  }
  return out;
}

test("rule order does not change evaluation outcome", () => {
  const baseline = evaluate(P, R_CALL);
  const seen = new Set<string>();
  for (const perm of permutations(P.rules)) {
    const pol: Policy = { ...P, rules: perm };
    const ev = evaluate(pol, R_CALL);
    assert.deepEqual(ev, baseline);
    seen.add(policyHash(pol));
  }
  assert.equal(seen.size, permutations(P.rules).length > 1 ? permutations(P.rules).length : 1);
});

test("hard_deny order does not change evaluation outcome", () => {
  const denies = [
    { id: "d1", tool: "fs.read_text", when: [{ path: "/path", op: "path_under", value: "/workspace/private" }] },
    { id: "d2", tool: "fs.read_text", when: [{ path: "/path", op: "path_under", value: "/workspace/private/keys" }] },
  ] as Policy["hard_denies"];
  const call = { tool: "fs.read_text", args: { path: "/workspace/private/keys/k.pem" } };
  const a = evaluate({ ...P, hard_denies: denies }, call);
  const b = evaluate({ ...P, hard_denies: [...denies].reverse() }, call);
  assert.deepEqual(a, b);
  assert.deepEqual(a.matched_rules, ["d1", "d2"].sort());
});

test("predicate order inside a rule does not change matching", () => {
  const r: Rule = {
    id: "multi", tool: "fs.write_text",
    when: [
      { path: "/path", op: "path_under", value: "/workspace/drafts" },
      { path: "/expected_version", op: "eq", value: "7" },
    ],
    tier: "allow",
  };
  const a = evaluate({ ...P, rules: [r] }, R_CALL);
  const b = evaluate({ ...P, rules: [{ ...r, when: [...r.when].reverse() }] }, R_CALL);
  assert.deepEqual(a, b);
  assert.equal(a.tier, "async_review"); // allow rule meets the async_review tool floor
});

test("compiled policy from permuted YAML rule order evaluates identically", () => {
  const rawP = {
    v: 1, revision: 1, mode: "ENFORCE", review_ttl_ms: 120000, dispatch_ttl_ms: 5000,
    reviewers: ["ltp_000000000000000000002"],
    rules: [
      { id: "aa", tool: "fs.read_text", when: [], tier: "allow" },
      { id: "bb", tool: "fs.read_text", when: [{ path: "/path", op: "path_under", value: "/workspace/private" }], tier: "hard_stop" },
      { id: "cc", tool: "fs.read_text", when: [{ path: "/path", op: "path_under", value: "/workspace/private" }], tier: "async_review" },
    ],
    hard_denies: [],
  };
  const p1 = compilePolicy(structuredClone(rawP));
  rawP.rules.reverse();
  const p2 = compilePolicy(rawP);
  const call = { tool: "fs.read_text", args: { path: "/workspace/private/x" } };
  const e1 = evaluate(p1, call);
  const e2 = evaluate(p2, call);
  assert.equal(e1.tier, e2.tier); // strongest tier wins regardless of order
  assert.equal(e1.tier, "hard_stop");
  assert.deepEqual(e1.matched_rules, e2.matched_rules);
});
