/** Offline smoke test of the shipped CLI entrypoint and example policy. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const cli = fileURLToPath(new URL("../bin/lextier.mjs", import.meta.url));
const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], {
  cwd: root, encoding: "utf8",
});

const help = run("--help");
assert.equal(help.status, 0, help.stderr);
assert.match(help.stdout, /policy lint/);

const lint = run("policy", "lint", "--file", "lextier.yaml");
assert.equal(lint.status, 0, lint.stderr);
const result = JSON.parse(lint.stdout);
assert.equal(result.valid, true);
assert.equal(typeof result.revision, "number");
assert.match(result.policy_hash, /^[0-9a-f]{64}$/);

const missing = run("policy", "lint", "--file", "missing-policy.yaml");
assert.notEqual(missing.status, 0, "lint must reject a missing policy");
console.log("CLI smoke passed: help, policy lint, and missing policy rejection");
