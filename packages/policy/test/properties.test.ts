// packages/policy/test/properties.test.ts
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { AGENT_KINDS, DESTINATION_CLASSES, EFFECT_CLASSES, LABELS, OUTCOMES, OUTCOME_RANK, RISK_CLASSES, SIGNAL_CODES, SOURCES, TARGET_KINDS, TARGET_SCOPES, type ActionDescriptor, type EffectClass, type Obligation, type Outcome } from "@auora/contracts";
import { compileLayer, composeBundles, PolicyCompileError, type BundleSpec, type RuleSpec } from "../src/index.js";
import { evaluate } from "../src/evaluate.js";
import { guardTier } from "../src/guard.js";
import { descriptor } from "./helpers.js";

const el = <T extends readonly string[]>(xs: T) => fc.constantFrom(...xs) as fc.Arbitrary<T[number]>;
const subset = <T extends readonly string[]>(xs: T, min = 0) => fc.uniqueArray(el(xs), { minLength: min, maxLength: xs.length });
const nonAllow = OUTCOMES.filter((o): o is Exclude<Outcome, "allow"> => o !== "allow");
const allowableEffects = EFFECT_CLASSES.filter((e): e is Exclude<EffectClass, "privilege_change"> => e !== "privilege_change");

const arbDescriptor: fc.Arbitrary<ActionDescriptor> = fc.record({
  effect_class: el(EFFECT_CLASSES), source: el(SOURCES), risk_class: el(RISK_CLASSES),
  agent: fc.record({ kind: el(AGENT_KINDS), version: fc.constant("1") }),
  target: fc.record({ kind: el(TARGET_KINDS), value: fc.constantFrom("src/a.ts", "/etc/passwd", "curl", "api.github.com", "x.attacker.example", ".auora/policy.yaml"), scope: el(TARGET_SCOPES) }),
  destination: fc.option(fc.record({ domain: fc.constantFrom("registry.npmjs.org", "api.github.com", "example.org"), port: fc.constant(443), class: el(DESTINATION_CLASSES) }), { nil: undefined }),
  labels: subset(LABELS),
  sends: fc.nat({ max: 5 }), denials: fc.nat({ max: 5 }),
  labels_read: subset(LABELS), signals: subset(SIGNAL_CODES),
}).map((r) => descriptor({
  effect_class: r.effect_class, source: r.source, risk_class: r.risk_class, agent: r.agent, target: r.target,
  ...(r.destination ? { destination: r.destination } : {}), labels: r.labels,
  run_state: { counters: { actions: r.sends + r.denials + 1, sends: r.sends, denials: r.denials, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 5, labels_read: r.labels_read, signals: r.signals.map((code) => ({ code, basis_points: 5000, reason: "test" })) },
}));

const arbCommonMatch = fc.record({
  target_scope: fc.option(subset(TARGET_SCOPES, 1), { nil: undefined }),
  destination: fc.option(fc.constantFrom("registry.npmjs.org", "api.github.com"), { nil: undefined }),
  destination_class: fc.option(subset(DESTINATION_CLASSES, 1), { nil: undefined }),
  counters: fc.option(fc.record({ sends_gte: fc.nat({ max: 4 }) }), { nil: undefined }),
}).map((m) => Object.fromEntries(Object.entries(m).filter(([, v]) => v !== undefined)) as Record<string, unknown>);

const arbObligation: fc.Arbitrary<Obligation> = fc.oneof(
  fc.record({ type: fc.constant("redact_fields" as const), fields: fc.uniqueArray(fc.constantFrom("a", "b", "c"), { minLength: 1, maxLength: 3 }) }),
  fc.record({ type: fc.constant("max_response_bytes" as const), max_bytes: fc.integer({ min: 1, max: 65536 }) }),
  fc.record({ type: fc.constant("record_payload_digest" as const) }),
  fc.record({ type: fc.constant("notify" as const), channel: fc.constantFrom("email", "slack") }),
);

const arbAllowRule: fc.Arbitrary<RuleSpec> = fc.record({ priority: fc.nat({ max: 100 }), effect: subset(allowableEffects, 1), common: arbCommonMatch, obligations: fc.array(arbObligation, { maxLength: 4 }) })
  .map((r) => ({ id: "x", priority: r.priority, outcome: "allow" as const, match: { ...r.common, effect: r.effect } as RuleSpec["match"], obligations: r.obligations }));

const arbRestrictiveRule: fc.Arbitrary<RuleSpec> = fc.record({
  priority: fc.nat({ max: 100 }), outcome: el(nonAllow), effect: fc.option(subset(EFFECT_CLASSES, 1), { nil: undefined }), common: arbCommonMatch,
  labels_any: fc.option(subset(LABELS, 1), { nil: undefined }), labels_read_any: fc.option(subset(LABELS, 1), { nil: undefined }), signals_any: fc.option(subset(SIGNAL_CODES, 1), { nil: undefined }),
}).map((r) => {
  const match: Record<string, unknown> = { ...r.common };
  if (r.effect) match["effect"] = r.effect;
  if (r.labels_any) match["labels_any"] = r.labels_any;
  if (r.labels_read_any) match["labels_read_any"] = r.labels_read_any;
  if (r.signals_any) match["signals_any"] = r.signals_any;
  if (Object.keys(match).length === 0) match["effect"] = [...EFFECT_CLASSES];
  return { id: "x", priority: r.priority, outcome: r.outcome, match: match as RuleSpec["match"] };
});

const arbBundle: fc.Arbitrary<BundleSpec> = fc.array(fc.oneof(arbAllowRule, arbRestrictiveRule), { minLength: 1, maxLength: 6 })
  .map((rules) => ({ version: 1 as const, rules: rules.map((r, i) => ({ ...r, id: `rule-${i}` })) }));

function compiled(spec: BundleSpec) { return composeBundles([compileLayer(spec, "p")]); }
const rank = (o: Outcome) => OUTCOME_RANK[o];

describe("policy laws", () => {
  it("law 1: rule order never changes a decision, policy digest included", () => {
    fc.assert(fc.property(arbDescriptor, arbBundle.chain((spec) => fc.tuple(fc.constant(spec), fc.shuffledSubarray(spec.rules, { minLength: spec.rules.length, maxLength: spec.rules.length }))), (d, [spec, permuted]) => {
      expect(evaluate(d, compiled({ ...spec, rules: permuted }))).toEqual(evaluate(d, compiled(spec)));
    }));
  });
  it("law 2: adding a restrictive label never moves a decision towards allow", () => {
    fc.assert(fc.property(arbDescriptor, arbBundle, el(["confidential", "secret"] as const), (d, spec, label) => {
      const b = compiled(spec);
      const before = rank(evaluate(d, b).outcome);
      const after = rank(evaluate({ ...d, labels: [...new Set([...d.labels, label])] }, b).outcome);
      expect(after).toBeGreaterThanOrEqual(before);
    }), { numRuns: 500 });
    // Third, differently-shaped check: add a non-empty SUBSET of labels at once (not just one),
    // so several gated rules can become newly matching in the same step.
    fc.assert(fc.property(arbDescriptor, arbBundle, subset(["confidential", "secret"] as const, 1), (d, spec, labels) => {
      const b = compiled(spec);
      const before = rank(evaluate(d, b).outcome);
      const after = rank(evaluate({ ...d, labels: [...new Set([...d.labels, ...labels])] }, b).outcome);
      expect(after).toBeGreaterThanOrEqual(before);
    }), { numRuns: 500 });
    // Fourth check: adding a read label never moves a decision towards allow.
    fc.assert(fc.property(arbDescriptor, arbBundle, el(["confidential", "secret"] as const), (d, spec, label) => {
      const b = compiled(spec);
      const before = rank(evaluate(d, b).outcome);
      const after = rank(evaluate({ ...d, run_state: { ...d.run_state, labels_read: [...new Set([...d.run_state.labels_read, label])] } }, b).outcome);
      expect(after).toBeGreaterThanOrEqual(before);
    }), { numRuns: 500 });
  });
  it("law 3: adding a behavior signal never moves a decision towards allow", () => {
    fc.assert(fc.property(arbDescriptor, arbBundle, el(SIGNAL_CODES), (d, spec, code) => {
      const b = compiled(spec);
      const before = rank(evaluate(d, b).outcome);
      const signals = [...d.run_state.signals.filter((s) => s.code !== code), { code, basis_points: 10000, reason: "test" }];
      const after = rank(evaluate({ ...d, run_state: { ...d.run_state, signals } }, b).outcome);
      expect(after).toBeGreaterThanOrEqual(before);
    }), { numRuns: 500 });
  });
  it("law 4: no bundle lowers a guard-tier floor, and statically guarded allows are rejected at compile time", () => {
    fc.assert(fc.property(arbDescriptor, arbBundle, (d, spec) => {
      const g = guardTier(d);
      if (g) expect(rank(evaluate(d, compiled(spec)).outcome)).toBeGreaterThanOrEqual(rank(g.outcome));
    }));
    expect(() => compileLayer({ version: 1, rules: [{ id: "bad", priority: 999, match: { effect: "send", labels_any: "secret" }, outcome: "allow" }] }, "p")).toThrowError(PolicyCompileError);
    expect(() => compileLayer({ version: 1, rules: [{ id: "bad", priority: 999, match: { target_scope: "workspace" }, outcome: "allow" }] }, "p")).toThrowError(/ALLOW_WITHOUT_EFFECT/);
  });
  it("law 5: evaluation mutates neither the descriptor nor the bundle", () => {
    const stringify = (v: unknown) => JSON.stringify(v, (_k, x) => (x instanceof Set ? [...x] : x instanceof RegExp ? x.source : x));
    fc.assert(fc.property(arbDescriptor, arbBundle, (d, spec) => {
      const b = compiled(spec);
      const before = stringify(d); const bundleBefore = stringify(b);
      evaluate(Object.freeze(d), b);
      expect(stringify(d)).toBe(before);
      expect(stringify(b)).toBe(bundleBefore);
    }));
  });
});
