// packages/policy/src/decision.ts
import type { Decision } from "@auora/contracts";
import type { DecisionDraft } from "./evaluate.js";

/**
 * Identifiers the caller owns, not the policy engine: `@auora/policy` mints no identifiers, since the
 * evaluation path uses no randomness (spec 5.1). `approval_request_id` is required only when the
 * draft's outcome is `require_approval`, matching the contracts decision schema's conditional.
 */
export interface DecisionIdentifiers { decision_id: string; action_id: string; run_id: string; approval_request_id?: string }

export class MissingApprovalRequestIdError extends Error {
  constructor() {
    super("a require_approval draft cannot be promoted to a Decision without an approval_request_id");
    this.name = "MissingApprovalRequestIdError";
  }
}

/** Promotes a DecisionDraft (the engine's pure output) to a full Decision by attaching caller-owned identifiers. */
export function promoteDecision(draft: DecisionDraft, ids: DecisionIdentifiers): Decision {
  if (draft.outcome === "require_approval" && ids.approval_request_id === undefined) throw new MissingApprovalRequestIdError();
  return {
    schema_version: "auora.decision/1",
    decision_id: ids.decision_id,
    action_id: ids.action_id,
    run_id: ids.run_id,
    outcome: draft.outcome,
    tier: draft.tier,
    reason_codes: draft.reason_codes,
    matched_rule_ids: draft.matched_rule_ids,
    policy_digest: draft.policy_digest,
    obligations: draft.obligations,
    ttl_ms: draft.ttl_ms,
    ...(ids.approval_request_id !== undefined ? { approval_request_id: ids.approval_request_id } : {}),
  };
}
