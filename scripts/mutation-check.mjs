// scripts/mutation-check.mjs
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

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
  // The replacement set deliberately excludes "privilege_change": using EFFECT_CLASSES here would immediately
  // trip the very next guard (ALLOW_GUARDED_EFFECT), so the test would only be proving it can tell error codes
  // apart, not that a broad effect-less allow rule actually compiles once this throw is gone.
  { name: "allow without effect accepted", file: POLICY_COMPILE, find: 'if (!c.effect) throw new PolicyCompileError("ALLOW_WITHOUT_EFFECT", rule.id);', replace: 'if (!c.effect) c.effect = new Set(["read"]);', test: COMPILE_TEST },
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
  { name: "append unknown key check removed", file: LOG_STORE, find: 'if (!key) throw new ForgedEventError("UNKNOWN_KEY");', replace: "", test: STORE_TEST },
  { name: "append signature verification removed", file: LOG_STORE, find: 'if (!(await verifyBytes("auora.event/1", key, new TextEncoder().encode(event.event_hash), event.signature))) throw new ForgedEventError("SIGNATURE_INVALID");', replace: "", test: STORE_TEST },
  { name: "compare-and-swap removed", file: LOG_STORE, find: "if (event.seq !== expectedSeq || event.prev_hash !== expectedPrev) throw new ChainConflictError(event.run_id, expectedSeq, expectedPrev);", replace: "", test: STORE_TEST },
  { name: "ledger expiry recheck removed", file: LOG_STORE, find: 'if (Date.parse(now) > Date.parse(verdict.record.expires_at)) { this.db.exec("ROLLBACK"); return { ok: false, code: "EXPIRED" }; }', replace: "", test: STORE_TEST },
  { name: "ledger signer recheck removed", file: LOG_STORE, find: 'if (!ctx.registry.has(verdict.record.signer_key_id)) { this.db.exec("ROLLBACK"); return { ok: false, code: "UNKNOWN_SIGNER" }; }', replace: "", test: STORE_TEST },
  // Both the guard below and the insert after it are killed by the race test: the guard is the intended
  // fast-path rejection, and the insert failing on a duplicate primary key is the schema's independent backstop.
  { name: "ledger nonce reuse check removed", file: LOG_STORE, find: 'if (existing) { this.db.exec("ROLLBACK"); return { ok: false, code: "NONCE_REUSED" }; }', replace: "", test: STORE_TEST },
  { name: "ledger nonce consumption removed", file: LOG_STORE, find: 'this.db.prepare("INSERT INTO approvals (nonce, approval_id, action_id, consumed_at) VALUES (?, ?, ?, ?)").run(verdict.record.nonce, verdict.record.approval_id, verdict.record.action_id, now);', replace: "", test: STORE_TEST },
  { name: "checkpoint truncation check removed", file: LOG_CHECKPOINT, find: 'if (!at) return { ok: false, code: "TRUNCATED" };', replace: "if (!at) return { ok: true };", test: CHECKPOINT_TEST },
  { name: "float rejection removed", file: CANONICAL, find: 'if (!Number.isInteger(value)) throw new CanonicalError("NON_INTEGER_NUMBER", path);', replace: "", test: CANONICAL_TEST },
];

// A single command string (not an args array) avoids Node's DEP0190 shell-argument-joining warning;
// the shell option is still needed on Windows because pnpm is a .cmd shim, not a directly executable binary.
function runVitest(testPath) {
  return spawnSync(`pnpm exec vitest run "${testPath}"`, { stdio: "pipe", shell: true, encoding: "utf8" });
}

// Whatever mutation is currently written to disk, so a signal handler can put the file back. Cleared as soon
// as the mutation is reverted. Read by restoreInFlight(), which is also registered below so a Ctrl+C (or a
// kill) during a vitest run cannot leave a mutated security predicate sitting on disk for `git add -A` to pick up.
let inFlight = null;
function restoreInFlight() {
  if (inFlight) {
    writeFileSync(inFlight.file, inFlight.original);
    inFlight = null;
  }
}
process.on("SIGINT", () => { restoreInFlight(); process.exit(130); });
process.on("SIGTERM", () => { restoreInFlight(); process.exit(143); });
process.on("exit", restoreInFlight);

const DISTINCT_TESTS = [...new Set(MUTATIONS.map((m) => m.test))];

// Pre-flight: a test path that matches no file makes `vitest run` exit 1 having run nothing, which would
// otherwise be indistinguishable from every mutant anchored on it being killed. Fail loudly before mutating.
const missingTests = DISTINCT_TESTS.filter((t) => !existsSync(t));
let ready = missingTests.length === 0;
if (!ready) {
  console.error("missing test file(s), cannot run mutation-check:");
  for (const t of missingTests) console.error(`  ${t}`);
}

// One unmutated baseline per distinct test file: a pre-broken suite would make every kill anchored on it
// meaningless, so every baseline must pass before any source file is mutated.
if (ready) {
  console.log(`running ${DISTINCT_TESTS.length} baseline run(s) (unmutated)...`);
  for (const t of DISTINCT_TESTS) {
    const result = runVitest(t);
    if (result.status === 0) {
      console.log(`[baseline] ${t} OK`);
    } else {
      console.error(`[baseline] ${t} FAILED before any mutation was applied, stopping`);
      console.error(result.stdout ?? "");
      if (result.stderr) console.error(result.stderr);
      ready = false;
      break;
    }
  }
}

let anchorFailures = 0;
let survivors = 0;
if (ready) {
  for (const m of MUTATIONS) {
    const original = readFileSync(m.file, "utf8");
    const occurrences = original.split(m.find).length - 1;
    if (occurrences !== 1) {
      console.error(`[${m.name}] anchor ${occurrences === 0 ? "not found" : `matched ${occurrences} times, expected exactly 1`} in ${m.file}`);
      anchorFailures++;
      continue;
    }
    inFlight = { file: m.file, original };
    try {
      writeFileSync(m.file, original.replace(m.find, m.replace));
      const result = runVitest(m.test);
      if (result.status === 0) {
        console.error(`[${m.name}] MUTANT SURVIVED: ${m.test} still passes`);
        console.error(result.stdout ?? "");
        if (result.stderr) console.error(result.stderr);
        survivors++;
      } else {
        console.log(`[${m.name}] killed`);
      }
    } finally {
      restoreInFlight();
    }
  }
  if (anchorFailures > 0) console.error(`${anchorFailures} anchor problem(s): nothing was tested for these entries`);
  if (survivors > 0) console.error(`${survivors} surviving mutant(s): the predicate is not covered`);
  if (anchorFailures > 0 || survivors > 0) process.exitCode = 1;
  else console.log(`all ${MUTATIONS.length} mutants killed`);
} else {
  process.exitCode = 1;
}
