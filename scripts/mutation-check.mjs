// scripts/mutation-check.mjs
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const POLICY_EVAL = "packages/policy/src/evaluate.ts";
const POLICY_GUARD = "packages/policy/src/guard.ts";
const POLICY_COMPILE = "packages/policy/src/compile.ts";
const LOG_VERIFY = "packages/log/src/verify.ts";
const LOG_STORE = "packages/log/src/store.ts";
const LOG_CHECKPOINT = "packages/log/src/checkpoint.ts";
const APPROVAL = "packages/contracts/src/approval.ts";
const CANONICAL = "packages/contracts/src/canonical.ts";
const GOLDEN = "packages/policy/test/golden.test.ts";
const GUARD_TEST = "packages/policy/test/guard.test.ts";
const COMPILE_TEST = "packages/policy/test/compile.test.ts";
const CHAIN_TEST = "packages/log/test/chain.test.ts";
const STORE_TEST = "packages/log/test/store.test.ts";
const CHECKPOINT_TEST = "packages/log/test/checkpoint.test.ts";
const APPROVAL_TEST = "packages/contracts/test/approval.test.ts";
const CANONICAL_TEST = "packages/contracts/test/canonical.test.ts";

const MUTATIONS = [
  { name: "guard tier disabled", file: POLICY_EVAL, find: "const guard = guardTier(d);", replace: "const guard = null;", test: GOLDEN },
  { name: "conflict detection removed", file: POLICY_EVAL, find: 'if (outcomes.size > 1) { outcome = "deny"; reasons.push("POLICY_CONFLICT"); }', replace: "if (false) {}", test: GOLDEN },
  { name: "secret exfiltration guard removed", file: POLICY_GUARD, find: 'if (leaves && labels.has("secret")) return deny("GUARD_SECRET_EXFILTRATION", "guard:secret-exfiltration");', replace: "", test: GUARD_TEST },
  { name: "protected config guard removed", file: POLICY_GUARD, find: 'if ((d.effect_class === "write" || d.effect_class === "delete") && d.target.kind === "path" && isProtectedPath(d.target.value)) return deny("GUARD_PROTECTED_CONFIG", "guard:protected-config");', replace: "", test: GUARD_TEST },
  { name: "privilege change guard removed", file: POLICY_GUARD, find: 'if (d.effect_class === "privilege_change") return deny("GUARD_PRIVILEGE_CHANGE", "guard:privilege-change");', replace: "", test: GUARD_TEST },
  { name: "file payload guard removed", file: POLICY_GUARD, find: 'if (d.target.attributes?.includes("file_payload_reference")) return deny("GUARD_FILE_PAYLOAD_REFERENCE", "guard:file-payload-reference");', replace: "", test: GUARD_TEST },
  { name: "allow without effect accepted", file: POLICY_COMPILE, find: 'if (!c.effect) throw new PolicyCompileError("ALLOW_WITHOUT_EFFECT", rule.id);', replace: "if (!c.effect) c.effect = new Set(EFFECT_CLASSES);", test: COMPILE_TEST },
  { name: "allow of privilege change accepted", file: POLICY_COMPILE, find: 'if (c.effect.has("privilege_change")) throw new PolicyCompileError("ALLOW_GUARDED_EFFECT", rule.id);', replace: "", test: COMPILE_TEST },
  { name: "allow with labels accepted", file: POLICY_COMPILE, find: 'if (c.labels_any || c.labels_read_any) throw new PolicyCompileError("ALLOW_LABEL_MATCHER", rule.id);', replace: "", test: COMPILE_TEST },
  { name: "allow with signals accepted", file: POLICY_COMPILE, find: 'if (c.signals_any) throw new PolicyCompileError("SIGNAL_RULE_ALLOWS", rule.id);', replace: "", test: COMPILE_TEST },
  { name: "run binding removed", file: LOG_VERIFY, find: 'if (ev.run_id !== runId) errors.push({ seq: ev.seq, code: "RUN_MISMATCH" });', replace: "", test: CHAIN_TEST },
  { name: "duplicate check removed", file: LOG_VERIFY, find: 'if (seen.has(ev.seq)) errors.push({ seq: ev.seq, code: "DUPLICATE_SEQ" });', replace: "", test: CHAIN_TEST },
  { name: "order check removed", file: LOG_VERIFY, find: 'if (!seen.has(ev.seq) && ev.seq < expectedSeq) errors.push({ seq: ev.seq, code: "OUT_OF_ORDER" });', replace: "", test: CHAIN_TEST },
  { name: "gap check removed", file: LOG_VERIFY, find: 'if (!seen.has(ev.seq) && ev.seq > expectedSeq) errors.push({ seq: ev.seq, code: "SEQ_GAP" });', replace: "", test: CHAIN_TEST },
  { name: "genesis at zero check removed", file: LOG_VERIFY, find: 'if (ev.seq === 0 && ev.prev_hash !== GENESIS) errors.push({ seq: ev.seq, code: "GENESIS_MISPLACED" });', replace: "", test: CHAIN_TEST },
  { name: "genesis later check removed", file: LOG_VERIFY, find: 'if (ev.seq !== 0 && ev.prev_hash === GENESIS) errors.push({ seq: ev.seq, code: "GENESIS_MISPLACED" });', replace: "", test: CHAIN_TEST },
  { name: "prev hash check removed", file: LOG_VERIFY, find: 'if (ev.prev_hash !== GENESIS && ev.prev_hash !== prev) errors.push({ seq: ev.seq, code: "PREV_HASH_MISMATCH" });', replace: "", test: CHAIN_TEST },
  { name: "hash check removed", file: LOG_VERIFY, find: 'if (hashOfEvent(ev) !== ev.event_hash) errors.push({ seq: ev.seq, code: "HASH_MISMATCH" });', replace: "", test: CHAIN_TEST },
  { name: "unknown key check removed", file: LOG_VERIFY, find: 'if (!key) errors.push({ seq: ev.seq, code: "UNKNOWN_KEY" });', replace: "", test: CHAIN_TEST },
  { name: "event signature check removed", file: LOG_VERIFY, find: 'if (key && !(await verifyBytes("auora.event/1", key, new TextEncoder().encode(ev.event_hash), ev.signature))) errors.push({ seq: ev.seq, code: "SIGNATURE_INVALID" });', replace: "", test: CHAIN_TEST },
  { name: "approval run binding removed", file: APPROVAL, find: 'if (record.run_id !== ctx.run_id) return { ok: false, code: "RUN_MISMATCH" };', replace: "", test: APPROVAL_TEST },
  { name: "approval action binding removed", file: APPROVAL, find: 'if (record.action_id !== ctx.action_id) return { ok: false, code: "ACTION_MISMATCH" };', replace: "", test: APPROVAL_TEST },
  { name: "approval digest binding removed", file: APPROVAL, find: 'if (record.descriptor_digest !== ctx.descriptor_digest) return { ok: false, code: "DIGEST_MISMATCH" };', replace: "", test: APPROVAL_TEST },
  { name: "approval policy binding removed", file: APPROVAL, find: 'if (record.policy_digest !== ctx.policy_digest) return { ok: false, code: "POLICY_MISMATCH" };', replace: "", test: APPROVAL_TEST },
  { name: "approval not-yet-valid check removed", file: APPROVAL, find: 'if (now < Date.parse(record.issued_at) - ISSUED_AT_SKEW_MS) return { ok: false, code: "NOT_YET_VALID" };', replace: "", test: APPROVAL_TEST },
  { name: "approval expiry removed", file: APPROVAL, find: 'if (now > Date.parse(record.expires_at)) return { ok: false, code: "EXPIRED" };', replace: "", test: APPROVAL_TEST },
  { name: "approval nonce check removed", file: APPROVAL, find: 'if (ctx.seenNonces.has(record.nonce)) return { ok: false, code: "NONCE_REUSED" };', replace: "", test: APPROVAL_TEST },
  { name: "approval signer registry removed", file: APPROVAL, find: 'if (!key) return { ok: false, code: "UNKNOWN_SIGNER" };', replace: "if (!key) return { ok: true, record };", test: APPROVAL_TEST },
  { name: "approval signature check removed", file: APPROVAL, find: 'if (!valid) return { ok: false, code: "BAD_SIGNATURE" };', replace: "", test: APPROVAL_TEST },
  { name: "append hash verification removed", file: LOG_STORE, find: 'if (hashOfEvent(event) !== event.event_hash) throw new ForgedEventError("HASH_MISMATCH");', replace: "", test: STORE_TEST },
  { name: "append signature verification removed", file: LOG_STORE, find: 'if (!(await verifyBytes("auora.event/1", key, new TextEncoder().encode(event.event_hash), event.signature))) throw new ForgedEventError("SIGNATURE_INVALID");', replace: "", test: STORE_TEST },
  { name: "compare-and-swap removed", file: LOG_STORE, find: "if (event.seq !== expectedSeq || event.prev_hash !== expectedPrev) throw new ChainConflictError(event.run_id, expectedSeq, expectedPrev);", replace: "", test: STORE_TEST },
  { name: "ledger expiry recheck removed", file: LOG_STORE, find: 'if (Date.parse(now) > Date.parse(verdict.record.expires_at)) { this.db.exec("ROLLBACK"); return { ok: false, code: "EXPIRED" }; }', replace: "", test: STORE_TEST },
  { name: "ledger signer recheck removed", file: LOG_STORE, find: 'if (!ctx.registry.has(verdict.record.signer_key_id)) { this.db.exec("ROLLBACK"); return { ok: false, code: "UNKNOWN_SIGNER" }; }', replace: "", test: STORE_TEST },
  // Anchored on the INSERT itself (the consumption), not the "if (existing)" guard above it: both are killed by
  // the race test below, but the insert failing on a duplicate primary key is the mechanism the schema guarantees.
  { name: "ledger nonce consumption removed", file: LOG_STORE, find: 'this.db.prepare("INSERT INTO approvals (nonce, approval_id, action_id, consumed_at) VALUES (?, ?, ?, ?)").run(verdict.record.nonce, verdict.record.approval_id, verdict.record.action_id, now);', replace: "", test: STORE_TEST },
  { name: "checkpoint truncation check removed", file: LOG_CHECKPOINT, find: 'if (!at) return { ok: false, code: "TRUNCATED" };', replace: "if (!at) return { ok: true };", test: CHECKPOINT_TEST },
  { name: "float rejection removed", file: CANONICAL, find: 'if (!Number.isInteger(value)) throw new CanonicalError("NON_INTEGER_NUMBER", path);', replace: "", test: CANONICAL_TEST },
];

let failed = 0;
for (const m of MUTATIONS) {
  const original = readFileSync(m.file, "utf8");
  if (!original.includes(m.find)) { console.error(`[${m.name}] anchor not found in ${m.file}`); failed++; continue; }
  writeFileSync(m.file, original.replace(m.find, m.replace));
  try {
    const result = spawnSync("pnpm", ["exec", "vitest", "run", m.test], { stdio: "pipe", shell: true, encoding: "utf8" });
    if (result.status === 0) { console.error(`[${m.name}] MUTANT SURVIVED: ${m.test} still passes`); failed++; }
    else console.log(`[${m.name}] killed`);
  } finally {
    writeFileSync(m.file, original);
  }
}
if (failed > 0) { console.error(`${failed} mutation check(s) failed`); process.exit(1); }
console.log(`all ${MUTATIONS.length} mutants killed`);
