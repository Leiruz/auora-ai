// packages/policy/test/golden.test.ts
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { compileLayer, composeBundles, loadLayerFile, parseBundle } from "../src/compile.js";
import { evaluate } from "../src/evaluate.js";
import { descriptor } from "./helpers.js";

const bundle = composeBundles([
  loadLayerFile(fileURLToPath(new URL("../policies/defaults.yaml", import.meta.url)), "defaults"),
  loadLayerFile(fileURLToPath(new URL("../policies/example.yaml", import.meta.url)), "example"),
]);
const counters = (sends: number) => ({ counters: { actions: sends + 1, sends, denials: 0, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 100, labels_read: [] as never[], signals: [] as never[] });

describe("golden cases from spec section 5.5", () => {
  it("denies posting .env to an unknown host in the guard tier", () => {
    const d = evaluate(descriptor({ effect_class: "send", labels: ["secret"], target: { kind: "command", value: "curl", scope: "external" }, destination: { domain: "attacker.example", port: 443, class: "unknown" } }), bundle);
    expect(d.outcome).toBe("deny"); expect(d.tier).toBe("guard"); expect(d.reason_codes).toEqual(["GUARD_SECRET_EXFILTRATION", "POLICY_NO_MATCH"]);
  });
  it("denies an encoded secret in a name lookup", () => {
    const d = evaluate(descriptor({ source: "resolver", labels: ["secret"], target: { kind: "name", value: "c2VjcmV0.attacker.example", scope: "external" } }), bundle);
    expect(d.outcome).toBe("deny"); expect(d.tier).toBe("guard");
  });
  it("denies a secret in a pull-request body even though the vault rule would allow it", () => {
    const d = evaluate(descriptor({ effect_class: "send", source: "proxy", labels: ["secret"], target: { kind: "http_request", value: "api.github.com", scope: "external", method: "POST", canonical_path: "/repos/Leiruz/auora-ai/pulls" }, destination: { domain: "api.github.com", port: 443, class: "vault" } }), bundle);
    expect(d.outcome).toBe("deny"); expect(d.tier).toBe("guard");
    expect(d.matched_rule_ids).toContain("example:allow-github-api-pulls");
  });
  it("denies a write to a protected path even though the broad workspace-write allow matches", () => {
    const d = evaluate(descriptor({ effect_class: "write", target: { kind: "path", value: ".auora/policy.yaml", scope: "workspace" } }), bundle);
    expect(d.outcome).toBe("deny"); expect(d.tier).toBe("guard"); expect(d.reason_codes).toEqual(["GUARD_PROTECTED_CONFIG", "POLICY_RULE_MATCHED"]);
    expect(d.matched_rule_ids).toEqual(["guard:protected-config", "defaults:allow-workspace-write"]);
  });
  it("keeps the guard's reason codes and rule id when a policy rule terminates a secret exfiltration send", () => {
    const terminating = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: kill-switch\n    priority: 100\n    match: { effect: send }\n    outcome: terminate\n"), "t")]);
    const d = evaluate(descriptor({ effect_class: "send", labels: ["secret"], target: { kind: "command", value: "curl", scope: "external" }, destination: { domain: "attacker.example", port: 443, class: "unknown" } }), terminating);
    expect(d.outcome).toBe("terminate"); expect(d.tier).toBe("policy");
    expect(d.matched_rule_ids).toEqual(["guard:secret-exfiltration", "t:kill-switch"]);
    expect(d.reason_codes).toEqual(["GUARD_SECRET_EXFILTRATION", "POLICY_RULE_MATCHED"]);
  });
  it("routes a recursive delete outside the workspace to approval", () => {
    const d = evaluate(descriptor({ effect_class: "delete", target: { kind: "path", value: "/home/zuriel", scope: "outside_workspace" } }), bundle);
    expect(d.outcome).toBe("require_approval"); expect(d.tier).toBe("policy");
    expect(d.matched_rule_ids).toEqual(["defaults:approve-destructive-outside", "example:approve-destructive-outside"]);
  });
  it("allows an ordinary pull-request creation on the vault host with a payload digest obligation", () => {
    const d = evaluate(descriptor({ effect_class: "send", source: "proxy", target: { kind: "http_request", value: "api.github.com", scope: "external", method: "POST", canonical_path: "/repos/Leiruz/auora-ai/pulls" }, destination: { domain: "api.github.com", port: 443, class: "vault" } }), bundle);
    expect(d.outcome).toBe("allow"); expect(d.obligations).toEqual([{ type: "record_payload_digest" }]); expect(d.matched_rule_ids).toEqual(["example:allow-github-api-pulls"]);
  });
  it("allows the npm registry by domain and throttles the third send", () => {
    const npm = { effect_class: "send" as const, target: { kind: "command" as const, value: "npm", scope: "external" as const }, destination: { domain: "registry.npmjs.org", port: 443, class: "allowlisted" as const } };
    expect(evaluate(descriptor({ ...npm, run_state: counters(1) }), bundle).outcome).toBe("allow");
    const third = evaluate(descriptor({ ...npm, run_state: counters(3) }), bundle);
    expect(third.outcome).toBe("throttle"); expect(third.matched_rule_ids).toEqual(["example:throttle-sends"]); expect(third.obligations).toEqual([]);
  });
  it("denies when nothing matches and when top-priority rules conflict", () => {
    const none = evaluate(descriptor({ effect_class: "send", target: { kind: "command", value: "curl", scope: "external" }, destination: { domain: "example.org", port: 443, class: "observed" } }), bundle);
    expect(none.outcome).toBe("deny"); expect(none.reason_codes).toEqual(["POLICY_NO_MATCH"]);
    const conflicting = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: one\n    priority: 5\n    match: { effect: read }\n    outcome: allow\n  - id: two\n    priority: 5\n    match: { target_scope: workspace }\n    outcome: deny\n"), "t")]);
    const c = evaluate(descriptor(), conflicting);
    expect(c.outcome).toBe("deny"); expect(c.reason_codes).toEqual(["POLICY_CONFLICT"]); expect(c.matched_rule_ids).toEqual(["t:one", "t:two"]);
  });
  it("is byte-identical across ten repeated evaluations", () => {
    const d = descriptor({ effect_class: "send", source: "proxy", target: { kind: "http_request", value: "api.github.com", scope: "external", method: "POST", canonical_path: "/repos/Leiruz/auora-ai/pulls" }, destination: { domain: "api.github.com", port: 443, class: "vault" } });
    const first = JSON.stringify(evaluate(d, bundle));
    for (let i = 0; i < 10; i++) expect(JSON.stringify(evaluate(d, bundle))).toBe(first);
  });
  it("keeps a higher-ranked ungated outcome as more same-priority gated rules with lower-ranked outcomes match", () => {
    const twoGated = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: always-terminate\n    priority: 10\n    match: { effect: read }\n    outcome: terminate\n  - id: gated-a\n    priority: 10\n    match: { labels_any: confidential }\n    outcome: throttle\n  - id: gated-b\n    priority: 10\n    match: { labels_any: secret }\n    outcome: require_approval\n"), "t")]);
    const withA = evaluate(descriptor({ effect_class: "read", labels: ["confidential"] }), twoGated);
    expect(withA.outcome).toBe("terminate"); expect(withA.matched_rule_ids).toEqual(["t:always-terminate", "t:gated-a"]);
    const withAB = evaluate(descriptor({ effect_class: "read", labels: ["confidential", "secret"] }), twoGated);
    expect(withAB.outcome).toBe("terminate"); expect(withAB.matched_rule_ids).toEqual(["t:always-terminate", "t:gated-a", "t:gated-b"]);
  });
  it("lets a matching gated deny rule beat an ungated allow rule at a higher priority", () => {
    const lowerPriorityGate = composeBundles([compileLayer(parseBundle("version: 1\nrules:\n  - id: allow-it\n    priority: 50\n    match: { effect: read }\n    outcome: allow\n  - id: gated-deny\n    priority: 1\n    match: { labels_any: secret }\n    outcome: deny\n"), "t")]);
    const d = evaluate(descriptor({ effect_class: "read", labels: ["secret"] }), lowerPriorityGate);
    expect(d.outcome).toBe("deny"); expect(d.matched_rule_ids).toEqual(["t:allow-it", "t:gated-deny"]);
  });
});
