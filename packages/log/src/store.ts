// packages/log/src/store.ts
import { DatabaseSync } from "node:sqlite";
import { validateEvent, verifyApproval, verifyBytes, type ApprovalContext, type ApprovalVerdict, type EventEnvelope, type PublicKeyRegistry } from "@auora/contracts";
import { GENESIS, hashOfEvent } from "./chain.js";

export class ChainConflictError extends Error {
  constructor(public readonly run_id: string, public readonly expected_seq: number, public readonly expected_prev: string) {
    super(`chain conflict for ${run_id}: expected seq ${expected_seq} after ${expected_prev}`);
    this.name = "ChainConflictError";
  }
}
export class ForgedEventError extends Error {
  constructor(public readonly reason: "HASH_MISMATCH" | "UNKNOWN_KEY" | "SIGNATURE_INVALID") {
    super(`forged event: ${reason}`);
    this.name = "ForgedEventError";
  }
}
export interface Head { seq: number; hash: string }
export type LedgerContext = Omit<ApprovalContext, "seenNonces" | "now"> & { clock: () => string };

function sleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export class EventStore {
  constructor(private readonly db: DatabaseSync, private readonly registry: PublicKeyRegistry) {
    db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, head_seq INTEGER NOT NULL, head_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events (run_id TEXT NOT NULL, seq INTEGER NOT NULL, event_hash TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY (run_id, seq));
      CREATE TABLE IF NOT EXISTS checkpoints (run_id TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (run_id, seq));
      CREATE TABLE IF NOT EXISTS approvals (nonce TEXT PRIMARY KEY, approval_id TEXT NOT NULL, action_id TEXT NOT NULL, consumed_at TEXT NOT NULL);
    `);
  }
  static open(path: string, registry: PublicKeyRegistry): EventStore { return new EventStore(new DatabaseSync(path), registry); }
  static memory(registry: PublicKeyRegistry): EventStore { return new EventStore(new DatabaseSync(":memory:"), registry); }

  // Cross-process writers wait here; in one process the sync section that holds the lock always runs to completion first.
  private beginImmediate(): void {
    for (let attempt = 0; ; attempt++) {
      try { this.db.exec("BEGIN IMMEDIATE"); return; }
      catch (error) {
        if (attempt >= 50 || !/SQLITE_BUSY|database is locked/.test(String(error))) throw error;
        sleep(5);
      }
    }
  }

  head(runId: string): Head | null {
    const row = this.db.prepare("SELECT head_seq, head_hash FROM runs WHERE run_id = ?").get(runId) as { head_seq: number; head_hash: string } | undefined;
    return row ? { seq: row.head_seq, hash: row.head_hash } : null;
  }

  async append(event: EventEnvelope): Promise<void> {
    const validated = validateEvent(event);
    if (!validated.ok) throw new Error("invalid event: " + validated.errors.join("; "));
    if (hashOfEvent(event) !== event.event_hash) throw new ForgedEventError("HASH_MISMATCH");
    const key = this.registry.get(event.key_id);
    if (!key) throw new ForgedEventError("UNKNOWN_KEY");
    if (!(await verifyBytes("auora.event/1", key, new TextEncoder().encode(event.event_hash), event.signature))) throw new ForgedEventError("SIGNATURE_INVALID");
    this.beginImmediate();
    try {
      const head = this.head(event.run_id);
      const expectedSeq = head ? head.seq + 1 : 0;
      const expectedPrev = head ? head.hash : GENESIS;
      if (event.seq !== expectedSeq || event.prev_hash !== expectedPrev) throw new ChainConflictError(event.run_id, expectedSeq, expectedPrev);
      this.db.prepare("INSERT INTO events (run_id, seq, event_hash, body) VALUES (?, ?, ?, ?)").run(event.run_id, event.seq, event.event_hash, JSON.stringify(event));
      this.db.prepare("INSERT INTO runs (run_id, head_seq, head_hash) VALUES (?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET head_seq = excluded.head_seq, head_hash = excluded.head_hash").run(event.run_id, event.seq, event.event_hash);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  list(runId: string, fromSeq = 0): EventEnvelope[] {
    const rows = this.db.prepare("SELECT body FROM events WHERE run_id = ? AND seq >= ? ORDER BY seq").all(runId, fromSeq) as { body: string }[];
    return rows.map((r) => JSON.parse(r.body) as EventEnvelope);
  }
  runs(): string[] {
    return (this.db.prepare("SELECT run_id FROM runs ORDER BY run_id").all() as { run_id: string }[]).map((r) => r.run_id);
  }
  saveCheckpoint(runId: string, seq: number, body: string): void {
    this.db.prepare("INSERT OR REPLACE INTO checkpoints (run_id, seq, body) VALUES (?, ?, ?)").run(runId, seq, body);
  }
  loadCheckpoints(runId: string): string[] {
    return (this.db.prepare("SELECT body FROM checkpoints WHERE run_id = ? ORDER BY seq").all(runId) as { body: string }[]).map((r) => r.body);
  }

  // The signature and binding checks are pure and run before the lock; the time-sensitive facts (expiry, signer still registered)
  // are checked again synchronously inside the write transaction, so nothing consumed can have gone stale while waiting.
  async verifyAndConsumeApproval(record: unknown, ctx: LedgerContext): Promise<ApprovalVerdict> {
    const verdict = await verifyApproval(record, { ...ctx, now: ctx.clock(), seenNonces: new Set<string>() });
    if (!verdict.ok) return verdict;
    this.beginImmediate();
    try {
      const now = ctx.clock();
      if (Date.parse(now) > Date.parse(verdict.record.expires_at)) { this.db.exec("ROLLBACK"); return { ok: false, code: "EXPIRED" }; }
      if (!ctx.registry.has(verdict.record.signer_key_id)) { this.db.exec("ROLLBACK"); return { ok: false, code: "UNKNOWN_SIGNER" }; }
      const existing = this.db.prepare("SELECT nonce FROM approvals WHERE nonce = ?").get(verdict.record.nonce);
      if (existing) { this.db.exec("ROLLBACK"); return { ok: false, code: "NONCE_REUSED" }; }
      this.db.prepare("INSERT INTO approvals (nonce, approval_id, action_id, consumed_at) VALUES (?, ?, ?, ?)").run(verdict.record.nonce, verdict.record.approval_id, verdict.record.action_id, now);
      this.db.exec("COMMIT");
      return verdict;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  close(): void { this.db.close(); }
}
