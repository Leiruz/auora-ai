// packages/policy/src/evaluate.ts
import { OBLIGATION_TYPES, OUTCOME_RANK, type ActionDescriptor, type Digest, type Obligation, type ObligationType, type Outcome } from "@auora/contracts";
import { guardTier } from "./guard.js";
import type { CompiledBundle, CompiledMatcher, CompiledRule, CounterThresholds } from "./types.js";

export interface DecisionDraft {
  outcome: Outcome; tier: "guard" | "policy"; reason_codes: string[]; matched_rule_ids: string[];
  obligations: Obligation[]; policy_digest: Digest; ttl_ms: number;
}

function countersMatch(t: CounterThresholds, d: ActionDescriptor): boolean {
  const c = d.run_state.counters;
  return (t.actions_gte === undefined || c.actions >= t.actions_gte)
    && (t.sends_gte === undefined || c.sends >= t.sends_gte)
    && (t.denials_gte === undefined || c.denials >= t.denials_gte)
    && (t.approvals_gte === undefined || c.approvals >= t.approvals_gte)
    && (t.retries_gte === undefined || c.retries >= t.retries_gte);
}

export function matches(m: CompiledMatcher, d: ActionDescriptor): boolean {
  if (m.effect && !m.effect.has(d.effect_class)) return false;
  if (m.source && !m.source.has(d.source)) return false;
  if (m.agent && !m.agent.has(d.agent.kind)) return false;
  if (m.target_kind && !m.target_kind.has(d.target.kind)) return false;
  if (m.target_scope && !m.target_scope.has(d.target.scope)) return false;
  if (m.destination && (!d.destination || !m.destination.has(d.destination.domain))) return false;
  if (m.destination_class && (!d.destination || !m.destination_class.has(d.destination.class))) return false;
  if (m.method && (!d.target.method || !m.method.has(d.target.method))) return false;
  if (m.path_pattern) {
    const path = d.target.canonical_path;
    if (!path || !m.path_pattern.some((p) => p.test(path))) return false;
  }
  if (m.labels_any && !d.labels.some((l) => m.labels_any!.has(l))) return false;
  if (m.labels_read_any && !d.run_state.labels_read.some((l) => m.labels_read_any!.has(l))) return false;
  if (m.risk && !m.risk.has(d.risk_class)) return false;
  if (m.tool_name && (!d.tool_name || !m.tool_name.has(d.tool_name))) return false;
  if (m.signals_any && !d.run_state.signals.some((s) => m.signals_any!.has(s.code))) return false;
  if (m.counters && !countersMatch(m.counters, d)) return false;
  return true;
}

function mergedObligation(type: ObligationType, group: readonly Obligation[]): Obligation {
  switch (type) {
    case "redact_fields":
      return { type, fields: [...new Set(group.flatMap((o) => o.fields ?? []))].sort() };
    case "max_response_bytes": {
      const bytes = group.map((o) => o.max_bytes).filter((b): b is number => b !== undefined);
      return bytes.length > 0 ? { type, max_bytes: Math.min(...bytes) } : { type };
    }
    case "notify": {
      const channels = group.map((o) => o.channel).filter((c): c is string => c !== undefined).sort();
      return channels.length > 0 ? { type, channel: channels[0]! } : { type };
    }
    case "record_payload_digest":
      return { type };
  }
}

export function mergeObligations(rules: readonly CompiledRule[]): Obligation[] {
  const byType = new Map<ObligationType, Obligation[]>();
  for (const rule of rules) for (const o of rule.obligations) {
    const group = byType.get(o.type);
    if (group) group.push(o); else byType.set(o.type, [o]);
  }
  return OBLIGATION_TYPES.filter((t) => byType.has(t)).map((t) => mergedObligation(t, byType.get(t)!));
}

interface PolicyTierResult { outcome: Outcome; reasons: string[]; top: CompiledRule[] }

function policyTier(d: ActionDescriptor, rules: readonly CompiledRule[]): PolicyTierResult {
  const matched = rules.filter((rule) => matches(rule.match, d));
  if (matched.length === 0) return { outcome: "deny", reasons: ["POLICY_NO_MATCH"], top: [] };
  const max = Math.max(...matched.map((r) => r.priority));
  const top = matched.filter((r) => r.priority === max);
  const outcomes = new Set(top.map((r) => r.outcome));
  const reasons: string[] = [];
  let outcome: Outcome;
  if (outcomes.size > 1) { outcome = "deny"; reasons.push("POLICY_CONFLICT"); }
  else { outcome = top[0]!.outcome; reasons.push("POLICY_RULE_MATCHED"); }
  return { outcome, reasons, top };
}

export function evaluate(d: ActionDescriptor, bundle: CompiledBundle): DecisionDraft {
  const guard = guardTier(d);
  const neutral: ActionDescriptor = { ...d, labels: [], run_state: { ...d.run_state, labels_read: [], signals: [] } };
  const baseline = policyTier(neutral, bundle.rules);
  const asGiven = policyTier(d, bundle.rules);
  const policy = OUTCOME_RANK[asGiven.outcome] >= OUTCOME_RANK[baseline.outcome] ? asGiven : baseline;
  let outcome = policy.outcome;
  const reasons = policy.reasons;
  let ids = policy.top.map((r) => r.qualified_id).sort();
  let tier: "guard" | "policy" = "policy";
  if (guard) {
    reasons.unshift(...guard.reason_codes);
    ids = [...guard.rule_ids, ...ids];
    if (OUTCOME_RANK[guard.outcome] >= OUTCOME_RANK[outcome]) {
      outcome = guard.outcome;
      tier = "guard";
    }
  }
  const obligations = outcome === "allow" ? mergeObligations(policy.top) : [];
  return { outcome, tier, reason_codes: reasons, matched_rule_ids: ids, obligations, policy_digest: bundle.digest, ttl_ms: bundle.ttl_ms };
}
