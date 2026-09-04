// packages/contracts/src/schemas.ts
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { ValidateFunction } from "ajv";
import { assertSignable } from "./canonical.js";
import type { ActionDescriptor, ApprovalRecord, CapabilityCall, CapabilityResult, Decision, EventEnvelope, EventType, HookEvent, HookResponse } from "./types.js";
// Static JSON imports (not readFileSync) so this module performs no I/O: the schemas are bundled at
// build time, not read from disk at runtime, so a Worker can import the pure policy surface (which
// carries these transitively via @auora/contracts) without pulling node:fs into its bundle.
import actionSchema from "../schemas/auora.action.v1.json" with { type: "json" };
import decisionSchema from "../schemas/auora.decision.v1.json" with { type: "json" };
import hookSchema from "../schemas/auora.hook.v1.json" with { type: "json" };
import capabilitySchema from "../schemas/auora.capability.v1.json" with { type: "json" };
import eventSchema from "../schemas/auora.event.v1.json" with { type: "json" };
import approvalSchema from "../schemas/auora.approval.v1.json" with { type: "json" };

const BASE = "https://auora.dev/schemas/";
const SCHEMAS = [actionSchema, decisionSchema, hookSchema, capabilitySchema, eventSchema, approvalSchema];

// strictRequired: false because auora.decision.v1.json's "then" requires "approval_request_id",
// a property declared in the schema's top-level "properties" rather than restated inside "then";
// that is valid 2020-12 (if/then apply to the same instance) but Ajv's strict linter flags it.
const ajv = new Ajv2020({ strict: true, allErrors: true, strictRequired: false });
addFormats(ajv);
for (const schema of SCHEMAS) ajv.addSchema(schema as object);

export type Validation<T> = { ok: true; value: T } | { ok: false; errors: string[] };

export const MAX_DEPTH = 32;

// Runs before Ajv: an iterative walk that bounds nesting depth and requires NFC on every string and key,
// so that anything a validator accepts is also accepted by canonicalJson (spec 7.2 and 7.3).
export function shapeErrors(root: unknown): string[] {
  const errors: string[] = [];
  const stack: { value: unknown; depth: number; path: string }[] = [{ value: root, depth: 0, path: "$" }];
  while (stack.length > 0) {
    const { value, depth, path } = stack.pop()!;
    if (depth > MAX_DEPTH) { errors.push(`${path} exceeds depth ${MAX_DEPTH}`); continue; }
    if (typeof value === "string") { if (value.normalize("NFC") !== value) errors.push(`${path} is not NFC`); continue; }
    if (Array.isArray(value)) { value.forEach((v, i) => stack.push({ value: v, depth: depth + 1, path: `${path}[${i}]` })); continue; }
    if (value !== null && typeof value === "object") {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (k.normalize("NFC") !== k) errors.push(`${path}.${k} key is not NFC`);
        stack.push({ value: v, depth: depth + 1, path: `${path}.${k}` });
      }
    }
  }
  return errors;
}

function compileRef<T>(ref: string): (input: unknown) => Validation<T> {
  const fn: ValidateFunction<T> = ajv.compile<T>({ $ref: BASE + ref });
  return (input: unknown) => {
    const shape = shapeErrors(input);
    if (shape.length > 0) return { ok: false, errors: shape };
    try { assertSignable(input); } catch (error) { return { ok: false, errors: [String(error)] }; }
    if (fn(input)) return { ok: true, value: input };
    return { ok: false, errors: (fn.errors ?? []).map((e) => `${e.instancePath || "$"} ${e.message ?? "invalid"}`) };
  };
}

export const validateAction = compileRef<ActionDescriptor>("auora.action.v1.json");
export const validateDecision = compileRef<Decision>("auora.decision.v1.json");
export const validateHookEvent = compileRef<HookEvent>("auora.hook.v1.json#/$defs/event");
export const validateHookResponse = compileRef<HookResponse>("auora.hook.v1.json#/$defs/response");
export const validateCapabilityCall = compileRef<CapabilityCall>("auora.capability.v1.json#/$defs/call");
export const validateCapabilityResult = compileRef<CapabilityResult>("auora.capability.v1.json#/$defs/result");
export const validateApproval = compileRef<ApprovalRecord>("auora.approval.v1.json");

const validateEnvelope = compileRef<EventEnvelope>("auora.event.v1.json");
const payloadValidators: Record<EventType, (input: unknown) => Validation<unknown>> = {
  "run.started": compileRef("auora.event.v1.json#/$defs/payload_run_started"),
  "action.requested": compileRef("auora.event.v1.json#/$defs/payload_action_requested"),
  "policy.decided": compileRef("auora.event.v1.json#/$defs/payload_policy_decided"),
  "approval.requested": compileRef("auora.event.v1.json#/$defs/payload_approval_requested"),
  "approval.resolved": compileRef("auora.event.v1.json#/$defs/payload_approval_resolved"),
  "approval.expired": compileRef("auora.event.v1.json#/$defs/payload_approval_expired"),
  "effect.observed": compileRef("auora.event.v1.json#/$defs/payload_effect_observed"),
  "coverage.changed": compileRef("auora.event.v1.json#/$defs/payload_coverage_changed"),
  "run.terminated": compileRef("auora.event.v1.json#/$defs/payload_run_terminated"),
  "run.ended": compileRef("auora.event.v1.json#/$defs/payload_run_ended"),
};

export function validateEvent(input: unknown): Validation<EventEnvelope> {
  const envelope = validateEnvelope(input);
  if (!envelope.ok) return envelope;
  const payload = payloadValidators[envelope.value.type](envelope.value.payload);
  if (!payload.ok) return { ok: false, errors: payload.errors.map((e) => `payload ${e}`) };
  return envelope;
}
