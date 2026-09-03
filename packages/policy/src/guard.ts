import type { ActionDescriptor, Outcome } from "@auora/contracts";

export interface GuardResult { outcome: Outcome; reason_codes: string[]; rule_ids: string[] }

export const PROTECTED_PATH_PATTERNS: readonly RegExp[] = [
  /(^|[\\/])\.auora([\\/]|$)/,
  /(^|[\\/])\.claude[\\/]settings(\.local)?\.json$/,
  /(^|[\\/])\.codex([\\/]|$)/,
  /^auora:\/\//,
];

export function isProtectedPath(value: string): boolean {
  return PROTECTED_PATH_PATTERNS.some((pattern) => pattern.test(value));
}

function deny(code: string, ruleId: string): GuardResult {
  return { outcome: "deny", reason_codes: [code], rule_ids: [ruleId] };
}

export function guardTier(d: ActionDescriptor): GuardResult | null {
  const labels = new Set([...d.labels, ...d.run_state.labels_read]);
  const leaves = d.effect_class === "send" || d.source === "resolver" || d.target.kind === "name" || d.target.kind === "http_request";
  if (leaves && labels.has("secret")) return deny("GUARD_SECRET_EXFILTRATION", "guard:secret-exfiltration");
  if ((d.effect_class === "write" || d.effect_class === "delete") && d.target.kind === "path" && isProtectedPath(d.target.value)) return deny("GUARD_PROTECTED_CONFIG", "guard:protected-config");
  if (d.effect_class === "privilege_change") return deny("GUARD_PRIVILEGE_CHANGE", "guard:privilege-change");
  if (d.target.attributes?.includes("file_payload_reference")) return deny("GUARD_FILE_PAYLOAD_REFERENCE", "guard:file-payload-reference");
  return null;
}
