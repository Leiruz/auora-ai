// packages/policy/src/types.ts
import type { AgentKind, DestinationClass, Digest, EffectClass, HttpMethod, Label, Obligation, Outcome, RiskClass, SignalCode, Source, TargetKind, TargetScope } from "@auora/contracts";

export interface CounterThresholds { actions_gte?: number; sends_gte?: number; denials_gte?: number; approvals_gte?: number; retries_gte?: number }
export type StrOrList = string | string[];
export interface MatcherSpec {
  effect?: StrOrList; source?: StrOrList; agent?: StrOrList; target_kind?: StrOrList; target_scope?: StrOrList;
  destination?: StrOrList; destination_class?: StrOrList; method?: StrOrList; path_pattern?: StrOrList;
  labels_any?: StrOrList; labels_read_any?: StrOrList; risk?: StrOrList; tool_name?: StrOrList; signals_any?: StrOrList;
  counters?: CounterThresholds;
}
export type ObligationSpec = string | Obligation;
export interface RuleSpec { id: string; priority: number; description?: string; match: MatcherSpec; outcome: Outcome; obligations?: ObligationSpec[] }
export interface BundleSpec { version: 1; ttl_ms?: number; rules: RuleSpec[] }

export interface CompiledMatcher {
  effect?: ReadonlySet<EffectClass>; source?: ReadonlySet<Source>; agent?: ReadonlySet<AgentKind>;
  target_kind?: ReadonlySet<TargetKind>; target_scope?: ReadonlySet<TargetScope>;
  destination?: ReadonlySet<string>; destination_class?: ReadonlySet<DestinationClass>;
  method?: ReadonlySet<HttpMethod>; path_pattern?: readonly RegExp[];
  labels_any?: ReadonlySet<Label>; labels_read_any?: ReadonlySet<Label>; risk?: ReadonlySet<RiskClass>;
  tool_name?: ReadonlySet<string>; signals_any?: ReadonlySet<SignalCode>; counters?: CounterThresholds;
}
export interface CompiledRule { id: string; layer: string; qualified_id: string; priority: number; outcome: Outcome; obligations: Obligation[]; match: CompiledMatcher }
export interface CompiledLayer { name: string; digest: Digest; ttl_ms: number | null; rules: CompiledRule[] }
export interface CompiledBundle { digest: Digest; layers: { name: string; digest: Digest }[]; ttl_ms: number; rules: CompiledRule[] }

export const POLICY_ERROR_CODES = ["SCHEMA", "INVALID_VALUE", "DUPLICATE_RULE_ID", "INVALID_PATTERN", "INVALID_DOMAIN", "ALLOW_GUARDED_EFFECT", "ALLOW_LABEL_MATCHER", "SIGNAL_RULE_ALLOWS", "ALLOW_WITHOUT_EFFECT", "UNMATCHABLE_PATH_PATTERN"] as const;
export type PolicyErrorCode = (typeof POLICY_ERROR_CODES)[number];
export class PolicyCompileError extends Error {
  constructor(public readonly code: PolicyErrorCode, public readonly detail: string) {
    super(`${code}: ${detail}`);
    this.name = "PolicyCompileError";
  }
}
