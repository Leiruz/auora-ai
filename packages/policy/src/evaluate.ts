// packages/policy/src/evaluate.ts
import { OBLIGATION_TYPES, OUTCOME_RANK, type ActionDescriptor, type Digest, type Obligation, type Outcome } from "@auora/contracts";
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

export function mergeObligations(rules: readonly CompiledRule[]): Obligation[] {
  const byType = new Map<string, Obligation>();
  for (const rule of rules) for (const o of rule.obligations) if (!byType.has(o.type)) byType.set(o.type, o);
  return OBLIGATION_TYPES.filter((t) => byType.has(t)).map((t) => byType.get(t)!);
}

export function evaluate(d: ActionDescriptor, bundle: CompiledBundle): DecisionDraft {
  const guard = guardTier(d);
  const matched = bundle.rules.filter((rule) => matches(rule.match, d));
  let outcome: Outcome;
  const reasons: string[] = [];
  let top: CompiledRule[] = [];
  if (matched.length === 0) {
    outcome = "deny";
    reasons.push("POLICY_NO_MATCH");
  } else {
    const max = Math.max(...matched.map((r) => r.priority));
    top = matched.filter((r) => r.priority === max);
    const outcomes = new Set(top.map((r) => r.outcome));
    if (outcomes.size > 1) { outcome = "deny"; reasons.push("POLICY_CONFLICT"); }
    else { outcome = top[0]!.outcome; reasons.push("POLICY_RULE_MATCHED"); }
  }
  let ids = top.map((r) => r.qualified_id).sort();
  let tier: "guard" | "policy" = "policy";
  if (guard && OUTCOME_RANK[guard.outcome] >= OUTCOME_RANK[outcome]) {
    outcome = guard.outcome;
    tier = "guard";
    reasons.unshift(...guard.reason_codes);
    ids = [...guard.rule_ids, ...ids];
  }
  const obligations = outcome === "allow" ? mergeObligations(top) : [];
  return { outcome, tier, reason_codes: reasons, matched_rule_ids: ids, obligations, policy_digest: bundle.digest, ttl_ms: bundle.ttl_ms };
}
