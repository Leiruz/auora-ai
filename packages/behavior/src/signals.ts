// packages/behavior/src/signals.ts
import type { Digest, EffectClass, Label, Outcome, Signal, TargetScope } from "@auora/contracts";

export interface HistoryEntry {
  seq: number; elapsed_ms: number; effect_class: EffectClass; target_scope: TargetScope; destination?: string;
  outcome: Outcome; descriptor_digest: Digest; action_id: string;
}
export interface CurrentAction { effect_class: EffectClass; target_scope: TargetScope; destination?: string; is_lookup: boolean; labels_read: Label[]; descriptor_digest: Digest; approved_digest?: Digest }
export interface RunProfile { allowed_domains: readonly string[]; allowed_scopes: readonly TargetScope[] }

export const WINDOW = 20;

function spanMs(entries: readonly HistoryEntry[]): number {
  const first = entries[0]; const last = entries[entries.length - 1];
  if (!first || !last) return 0;
  return last.elapsed_ms - first.elapsed_ms;
}

export function computeSignals(history: readonly HistoryEntry[], current: CurrentAction, profile: RunProfile): Signal[] {
  const signals: Signal[] = [];
  if (current.destination !== undefined) {
    const seen = new Set(history.map((h) => h.destination).filter((d): d is string => d !== undefined));
    if (!profile.allowed_domains.includes(current.destination) && !seen.has(current.destination)) {
      signals.push({ code: "new_destination", basis_points: 10000, reason: `NEW_DESTINATION:${current.destination}` });
    }
  }
  if ((current.effect_class === "send" || current.is_lookup) && current.labels_read.some((l) => l === "confidential" || l === "secret")) {
    signals.push({ code: "sensitive_read_then_send", basis_points: 10000, reason: "SENSITIVE_READ_THEN_SEND" });
  }
  const denials = history.slice(-WINDOW).filter((h) => h.outcome === "deny").length;
  if (denials >= 3) signals.push({ code: "denied_action_velocity", basis_points: Math.min(10000, denials * 2000), reason: `DENIALS_IN_WINDOW:${denials}` });
  if (history.length >= 20) {
    const recentSpan = spanMs(history.slice(-10));
    const earlierSpan = spanMs(history.slice(-20, -10));
    if (earlierSpan > 0 && recentSpan >= 0 && 2 * recentSpan < earlierSpan) {
      const score = recentSpan === 0 ? 10000 : Math.min(10000, Math.floor((earlierSpan * 2500) / recentSpan));
      signals.push({ code: "action_acceleration", basis_points: score, reason: `SPAN_MS:${recentSpan}:${earlierSpan}` });
    }
  }
  const scopes = [...history.map((h) => h.target_scope), current.target_scope];
  const outside = scopes.filter((s) => !profile.allowed_scopes.includes(s)).length;
  const driftBp = Math.floor((outside * 10000) / scopes.length);
  if (driftBp >= 2000) signals.push({ code: "scope_drift", basis_points: driftBp, reason: `OUTSIDE_SHARE_BP:${driftBp}` });
  if (current.approved_digest !== undefined && current.approved_digest !== current.descriptor_digest) {
    signals.push({ code: "post_approval_mutation", basis_points: 10000, reason: "POST_APPROVAL_MUTATION" });
  }
  return signals;
}
