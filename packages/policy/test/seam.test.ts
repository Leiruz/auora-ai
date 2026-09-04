// packages/policy/test/seam.test.ts
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { validateAction, validateDecision, type ActionDescriptor } from "@auora/contracts";
// Through the "./pure" subpath, not a relative import, so this test also exercises that the exports
// map actually resolves it (a typo there would otherwise go unnoticed, since nothing else imports it).
import { composeBundles, evaluate, MissingApprovalRequestIdError, promoteDecision } from "@auora/policy/pure";
import { loadLayerFile } from "../src/load.js";
import { descriptor } from "./helpers.js";

const bundle = composeBundles([
  loadLayerFile(fileURLToPath(new URL("../policies/defaults.yaml", import.meta.url)), "defaults"),
  loadLayerFile(fileURLToPath(new URL("../policies/example.yaml", import.meta.url)), "example"),
]);

// Golden descriptors from spec 5.5, covering all three shapes promoteDecision must handle: a guard-tier
// deny, an ordinary policy-tier allow, and the one outcome that needs a caller-supplied identifier.
const GOLDEN_APPROVAL = descriptor({ effect_class: "delete", target: { kind: "path", value: "/home/zuriel", scope: "outside_workspace" } });
const GOLDEN_ALLOW = descriptor({ effect_class: "send", source: "proxy", target: { kind: "http_request", value: "api.github.com", scope: "external", method: "POST", canonical_path: "/repos/Leiruz/auora-ai/pulls" }, destination: { domain: "api.github.com", port: 443, class: "vault" } });
const GOLDEN_DENY = descriptor({ effect_class: "write", target: { kind: "path", value: ".auora/policy.yaml", scope: "workspace" } });

const DECISION_IDS = ["dec_01ARZ3NDEKTSV4RRFFQ69G5FAX", "dec_01ARZ3NDEKTSV4RRFFQ69G5FAY", "dec_01ARZ3NDEKTSV4RRFFQ69G5FAZ"];

describe("policy/contracts seam", () => {
  it("accepts every golden descriptor through validateAction", () => {
    for (const d of [GOLDEN_APPROVAL, GOLDEN_ALLOW, GOLDEN_DENY]) expect(validateAction(d).ok).toBe(true);
  });

  it("promotes each golden decision draft to a Decision that satisfies validateDecision", () => {
    const cases: { d: ActionDescriptor; approval_request_id?: string }[] = [
      { d: GOLDEN_APPROVAL, approval_request_id: "apr_01ARZ3NDEKTSV4RRFFQ69G5FAY" },
      { d: GOLDEN_ALLOW },
      { d: GOLDEN_DENY },
    ];
    cases.forEach((c, i) => {
      const draft = evaluate(c.d, bundle);
      const decision = promoteDecision(draft, {
        decision_id: DECISION_IDS[i]!,
        action_id: c.d.action_id,
        run_id: c.d.run_id,
        ...(c.approval_request_id !== undefined ? { approval_request_id: c.approval_request_id } : {}),
      });
      expect(validateDecision(decision).ok).toBe(true);
    });
  });

  it("throws MissingApprovalRequestIdError, carrying a code like the branch's other error types, when a require_approval draft is promoted without an approval request id", () => {
    const draft = evaluate(GOLDEN_APPROVAL, bundle);
    expect(draft.outcome).toBe("require_approval");
    let thrown: unknown;
    try {
      promoteDecision(draft, { decision_id: "dec_01ARZ3NDEKTSV4RRFFQ69G5FAX", action_id: GOLDEN_APPROVAL.action_id, run_id: GOLDEN_APPROVAL.run_id });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(MissingApprovalRequestIdError);
    expect((thrown as MissingApprovalRequestIdError).code).toBe("MISSING_APPROVAL_REQUEST_ID");
  });
});
