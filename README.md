# LatticeAG LexTier

<p align="center">
  <a href="https://github.com/LatticeAG/lextier/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/LatticeAG/lextier?style=for-the-badge" alt="License" />
  </a>
  <a href="https://github.com/LatticeAG/lextier/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/LatticeAG/lextier/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI" />
  </a>
  <a href="https://github.com/LatticeAG/lextier/stargazers">
    <img src="https://img.shields.io/github/stars/LatticeAG/lextier?style=for-the-badge" alt="GitHub stars" />
  </a>
  <a href="https://github.com/LatticeAG/lextier/issues">
    <img src="https://img.shields.io/github/issues/LatticeAG/lextier?style=for-the-badge&label=Issues" alt="GitHub issues" />
  </a>
  <a href="https://github.com/LatticeAG/lextier">
    <img src="https://img.shields.io/github/languages/top/LatticeAG/lextier?style=for-the-badge" alt="Top language" />
  </a>
  <a href="https://github.com/LatticeAG/lextier">
    <img src="https://img.shields.io/badge/TypeScript-5.9-blue?style=for-the-badge&logo=typescript" alt="TypeScript" />
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  </a>
</p>

Deterministic per-tool authorization tiers and a signed, verifiable audit chain
for agent tool calls. Protocol `lextier/1`, specification edition A-N1 rev 2.

LexTier is the enforcement core: an agent never holds provider credentials and
can never dispatch a protected tool directly. Every protected call passes
through admission → review → release → dispatch with an append-only,
hash-chained, Ed25519-signed audit trail that verifies fully offline.

## The six-tool wedge

LexTier is deliberately not a general safety classifier. It enforces
structured, deterministic tiers over exactly six registered tools:

| Tool | Floor | Effect |
| --- | --- | --- |
| `fs.read_text` | `allow` | read a workspace file |
| `fs.write_text` | `async_review` | versioned file write |
| `fs.remove_file` | `hard_stop` | versioned file delete |
| `db.select_rows` | `allow` | row read by primary IDs |
| `db.delete_rows` | `hard_stop` | row delete by primary IDs |
| `payments.send` | `hard_stop` | bounded payment |

`shell.exec`, `fs.remove_tree`, `db.drop_table`, and every unknown tool or
alias are denied unconditionally. There is no arbitrary shell, SQL, HTTP,
nested call, stored procedure, or fallback tool.

## Tiers

- **allow** — static policy match; dispatches without human review.
- **async_review** — queued for a human reviewer; approves release it.
- **hard_stop** — requires a reviewer release with an explicit `confirm_hash`
  re-binding; never auto-executes.

Policy is a versioned, hash-pinned document (restricted YAML or strict JSON).
Every decision binds the exact `action_hash` over the canonical
`ActionCommit` — tool, args, target resource, version pin, tenant, policy and
registry hashes — so a stale or drifted approval cannot execute.

## Audit chain

Every state transition appends a signed event (`LEXTIER-AUDIT/1`) whose hash
chains to its predecessor; exports are JSONL entry lines plus a signed head.
`lextier audit verify` replays sequence, hashes, signatures, monotone time,
key intervals, and legal transitions entirely offline. Key rotation is
old-key-signed plus new-key possession proof; trust extends through
`KEY_ROTATED` events when rotation evidence is replayed.

## Layout

```
src/core/      pure protocol: JCS, strict JSON, YAML subset, ids, SHA-256,
               Ed25519, registry, policy, stats, audit chain
src/engine/    SQLite store, AES-256-GCM envelope, bindings, TenantGateway
src/http/      /v1 router + local server
src/cli/       lextier CLI (offline + network commands)
src/sdk.ts     TypeScript SDK (16 methods, one-to-one with §8 routes)
python/        Python parity core + SDK + vector subset
conformance/   vectors.json — the 52 numbered TV-* fixtures
tests/         vector harness + unit/permutation/fuzz/crash/concurrency/HTTP
```

## Quick start (development)

```sh
npm install
npm test            # 97 tests incl. all 52 conformance vectors
npm run typecheck

# dev gateway (fixture bindings, loopback only)
LEXTIER_AUDIT_SEED=<32-byte-hex> \
  node bin/lextier.mjs serve --gateway-config lextier-gateway.json --port 8787

# CLI happy path
export LEXTIER_TOKEN=tok-u            # dev fixture identity (agent U)
node bin/lextier.mjs submit --file call.json --json
node bin/lextier.mjs status --json
```

Python:

```sh
cd python && python3 -m pytest tests/ -q   # 31 tests, 23-vector subset
```

## What this repo is not

Hosted control planes, multi-tenant mesh, real payment/provider adapters,
platform secret stores, and the LexShield/LexInbox implementations are paid or
platform surfaces. The OSS core exposes their contracts as bindings; the
fixture adapters in `src/engine/bindings.ts` are deterministic development
implementations only — `serve` refuses `production=true` because fixtures
cannot satisfy it (spec §6.4).

## License

MIT — see [LICENSE](LICENSE).
