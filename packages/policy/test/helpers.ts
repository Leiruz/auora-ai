import type { ActionDescriptor } from "@auora/contracts";

const D = ("sha256:" + "a".repeat(64)) as ActionDescriptor["descriptor_digest"];

export function descriptor(overrides: Partial<ActionDescriptor> = {}): ActionDescriptor {
  return {
    schema_version: "auora.action/1", action_id: "act_01ARZ3NDEKTSV4RRFFQ69G5FAW", run_id: "run_01ARZ3NDEKTSV4RRFFQ69G5FAV", seq: 1,
    agent: { kind: "claude-code", version: "2.1.84" }, source: "hook", effect_class: "read", risk_class: "low",
    target: { kind: "path", value: "src/index.ts", scope: "workspace" }, labels: ["internal"],
    command_digest: D, argument_digest: D,
    run_state: { counters: { actions: 1, sends: 0, denials: 0, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 10, labels_read: [], signals: [] },
    descriptor_digest: D,
    ...overrides,
  };
}
