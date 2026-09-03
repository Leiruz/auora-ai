// packages/contracts/test/approval.test.ts
import { describe, expect, it } from "vitest";
import { signApproval, verifyApproval, type ApprovalContext } from "../src/approval.js";
import { validateApproval } from "../src/schemas.js";
import { generateKeyPair } from "../src/signing.js";
import { sampleApproval } from "./samples.js";

async function setup() {
  const device = await generateKeyPair();
  const transport = await generateKeyPair();
  const base = sampleApproval({ signer_key_id: device.keyId });
  const { signature: _drop, ...unsigned } = base;
  const record = await signApproval(unsigned, device);
  const ctx: ApprovalContext = {
    run_id: record.run_id, action_id: record.action_id, descriptor_digest: record.descriptor_digest, policy_digest: record.policy_digest,
    now: "2026-09-02T10:01:00Z", seenNonces: new Set<string>(), registry: new Map([[device.keyId, device.publicKey]]),
  };
  return { device, transport, record, ctx };
}

describe("approval verification", () => {
  it("accepts a valid device-signed record", async () => {
    const { record, ctx } = await setup();
    expect((await verifyApproval(record, ctx)).ok).toBe(true);
  });
  it("rejects each mutated field with its own code", async () => {
    const { record, ctx, transport } = await setup();
    const code = async (r: unknown, c: ApprovalContext = ctx) => { const v = await verifyApproval(r, c); return v.ok ? "OK" : v.code; };
    expect(await code({ ...record, extra: 1 })).toBe("SCHEMA_INVALID");
    expect(await code(record, { ...ctx, run_id: "run_01ARZ3NDEKTSV4RRFFQ69G5FA0" })).toBe("RUN_MISMATCH");
    expect(await code(record, { ...ctx, action_id: "act_01ARZ3NDEKTSV4RRFFQ69G5FA0" })).toBe("ACTION_MISMATCH");
    expect(await code(record, { ...ctx, descriptor_digest: ("sha256:" + "c".repeat(64)) as never })).toBe("DIGEST_MISMATCH");
    expect(await code(record, { ...ctx, policy_digest: ("sha256:" + "d".repeat(64)) as never })).toBe("POLICY_MISMATCH");
    expect(await code(record, { ...ctx, now: "2026-09-02T09:00:00Z" })).toBe("NOT_YET_VALID");
    expect(await code(record, { ...ctx, now: "2026-09-02T10:06:00Z" })).toBe("EXPIRED");
    expect(await code(record, { ...ctx, now: "2026-09-02T09:59:00Z" })).toBe("OK");
    expect(await code(record, { ...ctx, now: "2026-09-02T09:58:59.999Z" })).toBe("NOT_YET_VALID");
    expect(await code(record, { ...ctx, now: "2026-09-02T10:05:00Z" })).toBe("OK");
    expect(await code(record, { ...ctx, now: "2026-09-02T10:05:00.001Z" })).toBe("EXPIRED");
    expect(await code(record, { ...ctx, seenNonces: new Set([record.nonce]) })).toBe("NONCE_REUSED");
    expect(await code(record, { ...ctx, registry: new Map([[transport.keyId, transport.publicKey]]) })).toBe("UNKNOWN_SIGNER");
    expect(await code({ ...record, expires_at: "2026-09-02T10:09:00Z" })).toBe("BAD_SIGNATURE");
    expect(await code({ ...record, signature: "B".repeat(86) })).toBe("BAD_SIGNATURE");
  });
  it("rejects a record whose claimed signer key is not in the registry", async () => {
    const { record, ctx, transport } = await setup();
    const { signature: _drop, ...unsigned } = { ...record, signer_key_id: transport.keyId };
    const forged = await signApproval(unsigned, transport);
    const v = await verifyApproval(forged, ctx);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.code).toBe("UNKNOWN_SIGNER");
  });
  it("rejects a schema-valid record whose expires_at is an unparseable leap second", async () => {
    const device = await generateKeyPair();
    const base = sampleApproval({ signer_key_id: device.keyId, expires_at: "2026-09-02T23:59:60Z" });
    expect(validateApproval(base).ok).toBe(true);
    const { signature: _drop, ...unsigned } = base;
    const record = await signApproval(unsigned, device);
    const ctx: ApprovalContext = {
      run_id: record.run_id, action_id: record.action_id, descriptor_digest: record.descriptor_digest, policy_digest: record.policy_digest,
      now: "2026-09-02T10:01:00Z", seenNonces: new Set<string>(), registry: new Map([[device.keyId, device.publicKey]]),
    };
    const v = await verifyApproval(record, ctx);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.code).toBe("SCHEMA_INVALID");
  });
  it("rejects when ctx.now is unparseable", async () => {
    const { record, ctx } = await setup();
    const v = await verifyApproval(record, { ...ctx, now: "not a time" });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.code).toBe("SCHEMA_INVALID");
  });
});
