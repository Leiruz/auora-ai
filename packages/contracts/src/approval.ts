// packages/contracts/src/approval.ts
import { canonicalBytes, type Digest } from "./canonical.js";
import { validateApproval } from "./schemas.js";
import { signBytes, verifyBytes, type PublicKeyRegistry, type Signer } from "./signing.js";
import type { ApprovalRecord } from "./types.js";

export const APPROVAL_REJECTIONS = ["SCHEMA_INVALID", "RUN_MISMATCH", "ACTION_MISMATCH", "DIGEST_MISMATCH", "POLICY_MISMATCH", "NOT_YET_VALID", "EXPIRED", "NONCE_REUSED", "UNKNOWN_SIGNER", "BAD_SIGNATURE"] as const;
export type ApprovalRejection = (typeof APPROVAL_REJECTIONS)[number];

export interface ApprovalContext {
  run_id: string; action_id: string; descriptor_digest: Digest; policy_digest: Digest;
  now: string; seenNonces: ReadonlySet<string>; registry: PublicKeyRegistry;
}
export type ApprovalVerdict = { ok: true; record: ApprovalRecord } | { ok: false; code: ApprovalRejection; detail?: string };

const ISSUED_AT_SKEW_MS = 60_000;

export type UnsignedApproval = Omit<ApprovalRecord, "signature">;

export async function signApproval(unsigned: UnsignedApproval, signer: Signer): Promise<ApprovalRecord> {
  const signature = await signBytes("auora.approval/1", signer.privateKey, canonicalBytes(unsigned));
  return { ...unsigned, signature };
}

export async function verifyApproval(input: unknown, ctx: ApprovalContext): Promise<ApprovalVerdict> {
  const validated = validateApproval(input);
  if (!validated.ok) return { ok: false, code: "SCHEMA_INVALID", detail: validated.errors.join("; ") };
  const record = validated.value;
  const key = ctx.registry.get(record.signer_key_id);
  if (!key) return { ok: false, code: "UNKNOWN_SIGNER" };
  const { signature, ...unsigned } = record;
  const valid = await verifyBytes("auora.approval/1", key, canonicalBytes(unsigned), signature);
  if (!valid) return { ok: false, code: "BAD_SIGNATURE" };
  if (record.run_id !== ctx.run_id) return { ok: false, code: "RUN_MISMATCH" };
  if (record.action_id !== ctx.action_id) return { ok: false, code: "ACTION_MISMATCH" };
  if (record.descriptor_digest !== ctx.descriptor_digest) return { ok: false, code: "DIGEST_MISMATCH" };
  if (record.policy_digest !== ctx.policy_digest) return { ok: false, code: "POLICY_MISMATCH" };
  const now = Date.parse(ctx.now);
  if (!Number.isFinite(now) || !Number.isFinite(Date.parse(record.issued_at)) || !Number.isFinite(Date.parse(record.expires_at))) return { ok: false, code: "SCHEMA_INVALID", detail: "unparseable timestamp" };
  if (now < Date.parse(record.issued_at) - ISSUED_AT_SKEW_MS) return { ok: false, code: "NOT_YET_VALID" };
  if (now > Date.parse(record.expires_at)) return { ok: false, code: "EXPIRED" };
  if (ctx.seenNonces.has(record.nonce)) return { ok: false, code: "NONCE_REUSED" };
  return { ok: true, record };
}
