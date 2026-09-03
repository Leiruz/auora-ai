// packages/contracts/src/types.ts
import type { Digest } from "./canonical.js";

export const OUTCOMES = ["allow", "throttle", "require_approval", "deny", "terminate"] as const;
export type Outcome = (typeof OUTCOMES)[number];
export const OUTCOME_RANK: Readonly<Record<Outcome, number>> = { allow: 0, throttle: 1, require_approval: 2, deny: 3, terminate: 4 };

export const EFFECT_CLASSES = ["read", "write", "delete", "send", "execute", "privilege_change"] as const;
export type EffectClass = (typeof EFFECT_CLASSES)[number];
export const RISK_CLASSES = ["low", "medium", "high", "critical"] as const;
export type RiskClass = (typeof RISK_CLASSES)[number];
export const SOURCES = ["hook", "resolver", "proxy", "isolate"] as const;
export type Source = (typeof SOURCES)[number];
export const TARGET_KINDS = ["path", "domain", "command", "tool", "http_request", "name"] as const;
export type TargetKind = (typeof TARGET_KINDS)[number];
export const TARGET_SCOPES = ["workspace", "outside_workspace", "system", "external", "unknown"] as const;
export type TargetScope = (typeof TARGET_SCOPES)[number];
export const DESTINATION_CLASSES = ["allowlisted", "vault", "observed", "unknown"] as const;
export type DestinationClass = (typeof DESTINATION_CLASSES)[number];
export const LABELS = ["public", "internal", "confidential", "secret"] as const;
export type Label = (typeof LABELS)[number];
export const LABEL_RANK: Readonly<Record<Label, number>> = { public: 0, internal: 1, confidential: 2, secret: 3 };
export const SIGNAL_CODES = ["new_destination", "sensitive_read_then_send", "denied_action_velocity", "action_acceleration", "scope_drift", "post_approval_mutation"] as const;
export type SignalCode = (typeof SIGNAL_CODES)[number];
export const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];
export const AGENT_KINDS = ["claude-code", "codex", "generic"] as const;
export type AgentKind = (typeof AGENT_KINDS)[number];
export const TARGET_ATTRIBUTES = ["file_payload_reference"] as const;
export type TargetAttribute = (typeof TARGET_ATTRIBUTES)[number];
export const OBLIGATION_TYPES = ["redact_fields", "max_response_bytes", "record_payload_digest", "notify"] as const;
export type ObligationType = (typeof OBLIGATION_TYPES)[number];
export const EVENT_TYPES = ["run.started", "action.requested", "policy.decided", "approval.requested", "approval.resolved", "approval.expired", "effect.observed", "coverage.changed", "run.terminated", "run.ended"] as const;
export type EventType = (typeof EVENT_TYPES)[number];
export const COVERAGE = ["protected", "observed", "unprotected"] as const;
export type Coverage = (typeof COVERAGE)[number];

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export interface Signal { code: SignalCode; basis_points: number; reason: string }
export interface Counters { actions: number; sends: number; denials: number; approvals: number; retries: number }
export interface RunState { counters: Counters; spend_minor: number; elapsed_ms: number; labels_read: Label[]; signals: Signal[] }
export interface Target {
  kind: TargetKind; value: string; scope: TargetScope;
  method?: HttpMethod; canonical_path?: string; body_digest?: Digest; attributes?: TargetAttribute[];
}
export interface Destination { domain: string; port: number; class: DestinationClass }
export interface ActionDescriptor {
  schema_version: "auora.action/1"; action_id: string; run_id: string; seq: number;
  agent: { kind: AgentKind; version: string }; source: Source; effect_class: EffectClass; risk_class: RiskClass;
  target: Target; destination?: Destination; labels: Label[]; tool_name?: string;
  command_digest: Digest; argument_digest: Digest; run_state: RunState; descriptor_digest: Digest;
}
export interface Obligation { type: ObligationType; fields?: string[]; max_bytes?: number; channel?: string }
export interface Decision {
  schema_version: "auora.decision/1"; decision_id: string; action_id: string; run_id: string;
  outcome: Outcome; tier: "guard" | "policy"; reason_codes: string[]; matched_rule_ids: string[];
  policy_digest: Digest; obligations: Obligation[]; approval_request_id?: string; ttl_ms: number;
}
export interface HookEvent {
  schema_version: "auora.hook/1"; kind: "event"; agent: AgentKind;
  event: "pre_tool" | "post_tool" | "permission_request" | "session_start" | "session_end";
  session_id: string; cwd: string; tool_name?: string; tool_input?: { [key: string]: JsonValue }; tool_use_id?: string; raw_digest: Digest;
}
export interface HookResponse { schema_version: "auora.hook/1"; kind: "response"; decision: "allow" | "deny" | "ask"; reason: string; action_id?: string }
export interface CapabilityCall { schema_version: "auora.capability/1"; kind: "call"; run_id: string; capability: string; method: string; args: { [key: string]: JsonValue }; seq: number; isolate_execution_id: string }
export interface CapabilityResult { schema_version: "auora.capability/1"; kind: "result"; ok: boolean; data?: { [key: string]: JsonValue }; error?: { code: string; message: string }; labels: Label[]; size_bytes: number }
export interface EventEnvelope {
  schema_version: "auora.event/1"; event_id: string; run_id: string; seq: number; type: EventType;
  occurred_at: string; coverage: Coverage; prev_hash: Digest | "GENESIS"; payload: { [key: string]: JsonValue };
  event_hash: Digest; key_id: string; signature: string;
}
export interface ApprovalRecord {
  schema_version: "auora.approval/1"; approval_id: string; action_id: string; descriptor_digest: Digest; run_id: string;
  policy_digest: Digest; surface: "desktop" | "device"; signer_key_id: string; issued_at: string; expires_at: string; nonce: string; signature: string;
}
