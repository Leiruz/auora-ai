import { describe, expect, it } from "vitest";
import { exportPrivateKeyPkcs8, exportPublicKey, fromBase64Url, generateKeyPair, importPrivateKeyPkcs8, importPublicKey, SIGNATURE_DOMAINS, signBytes, toBase64Url, verifyBytes, type SignatureDomain } from "../src/signing.js";

const bytes = new TextEncoder().encode("sha256:" + "b".repeat(64));
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function differentBase64UrlChar(c: string): string {
  return BASE64URL_ALPHABET.charAt((BASE64URL_ALPHABET.indexOf(c) + 1) % 64);
}
function flipUnusedLowBit(c: string): string {
  return BASE64URL_ALPHABET.charAt(BASE64URL_ALPHABET.indexOf(c) ^ 1);
}

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
    for (const signDomain of SIGNATURE_DOMAINS) {
      const domainSig = await signBytes(signDomain, pair.privateKey, bytes);
      for (const checkDomain of SIGNATURE_DOMAINS) {
        if (checkDomain === signDomain) continue;
        expect(await verifyBytes(checkDomain, pair.publicKey, bytes, domainSig)).toBe(false);
      }
    }
    const tampered = new Uint8Array(bytes); tampered[0] = tampered[0]! ^ 1;
    expect(await verifyBytes("auora.event/1", pair.publicKey, tampered, sig)).toBe(false);
    expect(await verifyBytes("auora.event/1", other.publicKey, bytes, sig)).toBe(false);
    expect(await verifyBytes("auora.event/1", pair.publicKey, bytes, "not base64url!")).toBe(false);
    expect(await verifyBytes("auora.event/1", pair.publicKey, bytes, "AAAA")).toBe(false);
    expect(await verifyBytes("auora.event/1", pair.privateKey, bytes, sig)).toBe(false);

    const middle = Math.floor(sig.length / 2);
    const tamperedMiddleSig = sig.slice(0, middle) + differentBase64UrlChar(sig.charAt(middle)) + sig.slice(middle + 1);
    expect(await verifyBytes("auora.event/1", pair.publicKey, bytes, tamperedMiddleSig)).toBe(false);

    const lastIndex = sig.length - 1;
    const malleableSig = sig.slice(0, lastIndex) + flipUnusedLowBit(sig.charAt(lastIndex));
    expect(fromBase64Url(malleableSig)).toEqual(fromBase64Url(sig));
    expect(await verifyBytes("auora.event/1", pair.publicKey, bytes, sig)).toBe(true);
    expect(await verifyBytes("auora.event/1", pair.publicKey, bytes, malleableSig)).toBe(false);

    const forgedDomain = "auora.approval/1\nEXTRA" as SignatureDomain;
    await expect(signBytes(forgedDomain, pair.privateKey, bytes)).rejects.toThrow();
    expect(await verifyBytes(forgedDomain, pair.publicKey, bytes, sig)).toBe(false);
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

    const canonicalSpki = fromBase64Url(await exportPublicKey(pair.publicKey));
    const nonCanonicalSpki = new Uint8Array(canonicalSpki.length + 1);
    nonCanonicalSpki.set(canonicalSpki, 0);
    const nonCanonicalBase64Url = toBase64Url(nonCanonicalSpki);
    let nonCanonicalImportError: unknown;
    let importedNonCanonical: { keyId: string } | undefined;
    try {
      importedNonCanonical = await importPublicKey(nonCanonicalBase64Url);
    } catch (err) {
      nonCanonicalImportError = err;
    }
    if (importedNonCanonical) {
      expect(importedNonCanonical.keyId).toBe(pair.keyId);
    } else {
      expect(nonCanonicalImportError).toBeInstanceOf(Error);
    }
  });
});
