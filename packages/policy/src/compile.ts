// packages/policy/src/compile.ts
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import { parseDocument } from "yaml";
import { AGENT_KINDS, CanonicalError, DESTINATION_CLASSES, EFFECT_CLASSES, HTTP_METHODS, LABELS, OBLIGATION_TYPES, RISK_CLASSES, SIGNAL_CODES, SOURCES, TARGET_KINDS, TARGET_SCOPES, digestOf, type Digest, type Obligation } from "@auora/contracts";
import policySchema from "../schemas/policy.v1.json";
import { PolicyCompileError, type BundleSpec, type CompiledBundle, type CompiledLayer, type CompiledMatcher, type CompiledRule, type ObligationSpec, type RuleSpec, type StrOrList } from "./types.js";

export { PolicyCompileError } from "./types.js";

// This module performs no I/O: the schema above is a static import (bundled at build time, not read
// from disk at runtime), so a Worker can import evaluate and the rest of the pure surface without
// pulling node:fs into its bundle. The one filesystem-touching function, loadLayerFile, lives in
// ./load.js instead; the evaluation path (later modules) performs no I/O either.
type BundleValidator = { ajv: Ajv2020; validate: ValidateFunction };
let cachedValidator: BundleValidator | undefined;
function bundleValidator(): BundleValidator {
  if (!cachedValidator) {
    const ajv = new Ajv2020({ strict: true, allErrors: true });
    cachedValidator = { ajv, validate: ajv.compile(policySchema) };
  }
  return cachedValidator;
}

export const DEFAULT_TTL_MS = 5000;
const DOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const PATH_CHARS = /^\/[A-Za-z0-9._~*/-]*$/;

function list(value: StrOrList | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value : [value];
}

function setOf<T extends string>(ruleId: string, field: string, values: string[] | undefined, allowed: readonly T[]): ReadonlySet<T> | undefined {
  if (!values) return undefined;
  for (const v of values) {
    if (!(allowed as readonly string[]).includes(v)) throw new PolicyCompileError("INVALID_VALUE", `${ruleId}.match.${field}: ${v}`);
  }
  return new Set(values as T[]);
}

/**
 * Contract: `pattern`, and any path later tested against the compiled RegExp, must already be
 * percent-decoded and dot-segment normalized by the caller (the enforcement point) before it
 * reaches this function. Matching is case-sensitive and exact on trailing slashes: a pattern
 * without a trailing slash never matches a path that has one. A single `*` compiles to
 * `[^/]+`, so it never crosses a decoded `/`, but it still matches a percent-encoded
 * separator such as `%2F`, because that is three literal characters, not a `/`. This function
 * only compiles the pattern; it does not decode, normalize, or reject encoded input itself.
 */
export function compilePathPattern(pattern: string): RegExp {
  if (!PATH_CHARS.test(pattern) || pattern.includes("**")) throw new PolicyCompileError("INVALID_PATTERN", pattern);
  const source = pattern.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^/]+");
  return new RegExp("^" + source + "$");
}

function normalizeObligations(ruleId: string, specs: ObligationSpec[] | undefined): Obligation[] {
  const byType = new Map<string, Obligation>();
  for (const spec of specs ?? []) {
    const obligation: Obligation = typeof spec === "string" ? { type: spec as Obligation["type"] } : spec;
    if (!(OBLIGATION_TYPES as readonly string[]).includes(obligation.type)) throw new PolicyCompileError("INVALID_VALUE", `${ruleId}.obligations: ${obligation.type}`);
    byType.set(obligation.type, obligation);
  }
  return OBLIGATION_TYPES.filter((t) => byType.has(t)).map((t) => byType.get(t)!);
}

function byId(a: RuleSpec, b: RuleSpec): number {
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export function parseBundle(text: string): BundleSpec {
  try {
    const doc = parseDocument(text, { logLevel: "error" });
    if (doc.errors.length > 0) throw new PolicyCompileError("SCHEMA", doc.errors[0]!.message);
    if (doc.warnings.length > 0) throw new PolicyCompileError("SCHEMA", doc.warnings[0]!.message);
    if (doc.directives.yaml.version !== "1.2") throw new PolicyCompileError("SCHEMA", "unsupported YAML version");
    const value: unknown = doc.toJS();
    const { ajv, validate } = bundleValidator();
    if (!validate(value)) throw new PolicyCompileError("SCHEMA", ajv.errorsText(validate.errors));
    return value as BundleSpec;
  } catch (e) {
    if (e instanceof PolicyCompileError) throw e;
    throw new PolicyCompileError("SCHEMA", String(e));
  }
}

export function compileLayer(spec: BundleSpec, name: string): CompiledLayer {
  const { ajv, validate } = bundleValidator();
  if (!validate(spec)) throw new PolicyCompileError("SCHEMA", ajv.errorsText(validate.errors));
  let digest: Digest;
  try {
    digest = digestOf({ version: spec.version, ttl_ms: spec.ttl_ms ?? null, rules: [...spec.rules].sort(byId) });
  } catch (e) {
    if (e instanceof CanonicalError) throw new PolicyCompileError("SCHEMA", e.message);
    throw e;
  }
  const ids = new Set<string>();
  const rules: CompiledRule[] = [];
  for (const rule of spec.rules) {
    if (ids.has(rule.id)) throw new PolicyCompileError("DUPLICATE_RULE_ID", `${name}:${rule.id}`);
    ids.add(rule.id);
    const m = rule.match;
    const c: CompiledMatcher = {};
    const effect = setOf(rule.id, "effect", list(m.effect), EFFECT_CLASSES); if (effect) c.effect = effect;
    const source = setOf(rule.id, "source", list(m.source), SOURCES); if (source) c.source = source;
    const agent = setOf(rule.id, "agent", list(m.agent), AGENT_KINDS); if (agent) c.agent = agent;
    const targetKind = setOf(rule.id, "target_kind", list(m.target_kind), TARGET_KINDS); if (targetKind) c.target_kind = targetKind;
    const targetScope = setOf(rule.id, "target_scope", list(m.target_scope), TARGET_SCOPES); if (targetScope) c.target_scope = targetScope;
    const destinationClass = setOf(rule.id, "destination_class", list(m.destination_class), DESTINATION_CLASSES); if (destinationClass) c.destination_class = destinationClass;
    const method = setOf(rule.id, "method", list(m.method), HTTP_METHODS); if (method) c.method = method;
    const labelsAny = setOf(rule.id, "labels_any", list(m.labels_any), LABELS); if (labelsAny) c.labels_any = labelsAny;
    const labelsReadAny = setOf(rule.id, "labels_read_any", list(m.labels_read_any), LABELS); if (labelsReadAny) c.labels_read_any = labelsReadAny;
    const risk = setOf(rule.id, "risk", list(m.risk), RISK_CLASSES); if (risk) c.risk = risk;
    const signalsAny = setOf(rule.id, "signals_any", list(m.signals_any), SIGNAL_CODES); if (signalsAny) c.signals_any = signalsAny;
    const destinations = list(m.destination);
    if (destinations) {
      for (const d of destinations) if (!DOMAIN.test(d)) throw new PolicyCompileError("INVALID_DOMAIN", `${rule.id}.match.destination: ${d}`);
      c.destination = new Set(destinations);
    }
    const patterns = list(m.path_pattern);
    if (patterns) c.path_pattern = patterns.map(compilePathPattern);
    // path_pattern is matched only against canonical_path (a vault-request field, spec 5.5). A rule that
    // also names target_kind: path can never match, since a path target never carries a canonical_path;
    // for a deny rule that is a policy-weakening primitive, so it is rejected at compile time.
    if (c.path_pattern && c.target_kind?.has("path")) throw new PolicyCompileError("UNMATCHABLE_PATH_PATTERN", rule.id);
    const tools = list(m.tool_name);
    if (tools) c.tool_name = new Set(tools);
    if (m.counters) c.counters = { ...m.counters };
    if (rule.outcome === "allow") {
      if (!c.effect) throw new PolicyCompileError("ALLOW_WITHOUT_EFFECT", rule.id);
      if (c.effect.has("privilege_change")) throw new PolicyCompileError("ALLOW_GUARDED_EFFECT", rule.id);
      if (c.labels_any || c.labels_read_any) throw new PolicyCompileError("ALLOW_LABEL_MATCHER", rule.id);
      if (c.signals_any) throw new PolicyCompileError("SIGNAL_RULE_ALLOWS", rule.id);
    }
    rules.push({ id: rule.id, layer: name, qualified_id: `${name}:${rule.id}`, priority: rule.priority, outcome: rule.outcome, obligations: normalizeObligations(rule.id, rule.obligations), match: c });
  }
  return { name, digest, ttl_ms: spec.ttl_ms ?? null, rules };
}

export function composeBundles(layers: CompiledLayer[]): CompiledBundle {
  let ttl = DEFAULT_TTL_MS;
  for (const layer of layers) if (layer.ttl_ms !== null) ttl = layer.ttl_ms;
  const summary = layers.map((l) => ({ name: l.name, digest: l.digest }));
  return { digest: digestOf({ layers: summary }), layers: summary, ttl_ms: ttl, rules: layers.flatMap((l) => l.rules) };
}
