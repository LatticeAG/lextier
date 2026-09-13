/**
 * Authoritative tenant store (spec §11.1): the SQLite schema is the DO
 * layout; one store per tenant, single writer.
 */

import { DatabaseSync } from "node:sqlite";

export const STORAGE_VERSION = 1;

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS policies (revision INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, actor TEXT NOT NULL, policy_revision INTEGER NOT NULL, expires_ms INTEGER NOT NULL, dispatch_deadline_ms INTEGER, encrypted_commit BLOB, payload_gone INTEGER NOT NULL DEFAULT 0, handle BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (id TEXT PRIMARY KEY, action_id TEXT UNIQUE NOT NULL, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS views (action_id TEXT NOT NULL, reviewer TEXT NOT NULL, card_id TEXT NOT NULL, first_view_ms INTEGER NOT NULL, PRIMARY KEY(action_id,reviewer,card_id));
CREATE TABLE IF NOT EXISTS results (action_id TEXT PRIMARY KEY, encrypted_body BLOB NOT NULL, delete_after_ms INTEGER);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, hash TEXT UNIQUE NOT NULL, type TEXT NOT NULL, action_id TEXT, entry BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS heads (seq INTEGER PRIMARY KEY, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS evidence (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, encrypted_body BLOB NOT NULL, delete_after_ms INTEGER);
CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, action_id TEXT, kind TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, due_ms INTEGER NOT NULL, claim_until_ms INTEGER, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS idempotency (principal TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, key TEXT NOT NULL, body_hash TEXT NOT NULL, status INTEGER NOT NULL, encrypted_response BLOB NOT NULL, PRIMARY KEY(principal,method,path,key));
CREATE TABLE IF NOT EXISTS reaudits (id TEXT PRIMARY KEY, action_id TEXT NOT NULL, reviewer TEXT NOT NULL, state TEXT NOT NULL, body BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS reviewer_projection (reviewer TEXT NOT NULL, decision_seq INTEGER NOT NULL, received_ms INTEGER NOT NULL, approved INTEGER NOT NULL, latency_ms INTEGER NOT NULL, PRIMARY KEY(reviewer,decision_seq));
CREATE TABLE IF NOT EXISTS key_registry (key_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, first_seq INTEGER NOT NULL, last_seq INTEGER);
CREATE INDEX IF NOT EXISTS actions_due ON actions(state,expires_ms);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state,due_ms);
CREATE INDEX IF NOT EXISTS projection_time ON reviewer_projection(received_ms,reviewer);
`;

export type Tx = DatabaseSync;

export class Store {
  readonly db: DatabaseSync;
  constructor(path: string | ":memory:") {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA_SQL);
  }

  /** Run fn inside an IMMEDIATE transaction; roll back on throw. */
  tx<T>(fn: (tx: Tx) => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn(this.db);
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try { this.db.exec("ROLLBACK"); } catch { /* already rolled back */ }
      throw e;
    }
  }

  /** Read-only transaction. */
  read<T>(fn: (tx: Tx) => T): T {
    this.db.exec("BEGIN");
    try {
      const r = fn(this.db);
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try { this.db.exec("ROLLBACK"); } catch { }
      throw e;
    }
  }

  metaGet(tx: Tx, key: string): string | null {
    const r = tx.prepare("SELECT value FROM meta WHERE key = ?").get(key) as { value: Uint8Array } | undefined;
    return r ? Buffer.from(r.value).toString("utf8") : null;
  }
  metaSet(tx: Tx, key: string, value: string): void {
    tx.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(key, Buffer.from(value, "utf8"));
  }
  metaGetInt(tx: Tx, key: string): number | null {
    const v = this.metaGet(tx, key);
    return v === null ? null : Number(v);
  }
  metaSetInt(tx: Tx, key: string, value: number): void {
    this.metaSet(tx, key, String(value));
  }

  close(): void { this.db.close(); }
}
