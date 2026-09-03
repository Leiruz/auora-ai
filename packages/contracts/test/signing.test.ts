import { describe, expect, it } from "vitest";
import { exportPrivateKeyPkcs8, exportPublicKey, generateKeyPair, importPrivateKeyPkcs8, importPublicKey, signBytes, verifyBytes } from "../src/signing.js";

const bytes = new TextEncoder().encode("sha256:" + "b".repeat(64));

describe("Ed25519 signing", () => {
  it("signs and verifies under the same domain", async () => {
    const pair = await generateKeyPair();
    const sig = await signBytes("auora.event/1", pair.privateKey, bytes);
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(await verifyBytes("auora.event/1", pair.publicKey, bytes, sig)).toBe(true);
  });
  it("rejects another domain, tampered bytes, another key and a malformed signature", async () => {
    const pair = await generateKeyPair();
    const other = await generateKeyPair();
    const sig = await signBytes("auora.event/1", pair.privateKey, bytes);
    expect(await verifyBytes("auora.approval/1", pair.publicKey, bytes, sig)).toBe(false);
    const tampered = new Uint8Array(bytes); tampered[0] = tampered[0]! ^ 1;
    expect(await verifyBytes("auora.event/1", pair.publicKey, tampered, sig)).toBe(false);
    expect(await verifyBytes("auora.event/1", other.publicKey, bytes, sig)).toBe(false);
    expect(await verifyBytes("auora.event/1", pair.publicKey, bytes, "not base64url!")).toBe(false);
    expect(await verifyBytes("auora.event/1", pair.publicKey, bytes, "AAAA")).toBe(false);
  });
  it("round-trips public and private keys and keeps the key id stable", async () => {
    const pair = await generateKeyPair();
    const imported = await importPublicKey(await exportPublicKey(pair.publicKey));
    expect(imported.keyId).toBe(pair.keyId);
    expect(pair.keyId).toMatch(/^key_[0-9a-f]{32}$/);
    const restored = await importPrivateKeyPkcs8(await exportPrivateKeyPkcs8(pair.privateKey));
    expect(restored.extractable).toBe(false);
    const sig = await signBytes("auora.checkpoint/1", restored, bytes);
    expect(await verifyBytes("auora.checkpoint/1", imported.publicKey, bytes, sig)).toBe(true);
  });
});
