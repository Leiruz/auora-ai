import { webcrypto } from "node:crypto";
import { sha256Hex } from "./canonical.js";

const subtle = webcrypto.subtle;

export const SIGNATURE_DOMAINS = ["auora.event/1", "auora.approval/1", "auora.checkpoint/1", "auora.batch/1", "auora.signer/1"] as const;
export type SignatureDomain = (typeof SIGNATURE_DOMAINS)[number];
export interface KeyPair { keyId: string; publicKey: CryptoKey; privateKey: CryptoKey }
export interface Signer { keyId: string; privateKey: CryptoKey }
export type PublicKeyRegistry = ReadonlyMap<string, CryptoKey>;

const DOMAIN_PREFIXES = new Map<SignatureDomain, Uint8Array>();
for (const domain of SIGNATURE_DOMAINS) DOMAIN_PREFIXES.set(domain, new TextEncoder().encode(`${domain}\n`));

export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new Error("invalid base64url");
  const buf = Buffer.from(text, "base64url");
  const result = new Uint8Array(buf.length);
  result.set(buf);
  return result;
}

export function keyIdFromSpki(spki: Uint8Array): string {
  return "key_" + sha256Hex(spki).slice(0, 32);
}

const ED25519: webcrypto.AlgorithmIdentifier = { name: "Ed25519" };

export async function generateKeyPair(): Promise<KeyPair> {
  const pair = (await subtle.generateKey(ED25519, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const spki = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
  return { keyId: keyIdFromSpki(spki), publicKey: pair.publicKey, privateKey: pair.privateKey };
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  return toBase64Url(new Uint8Array(await subtle.exportKey("spki", key)));
}

export async function importPublicKey(spkiBase64Url: string): Promise<{ keyId: string; publicKey: CryptoKey }> {
  const spki = fromBase64Url(spkiBase64Url);
  const publicKey = await subtle.importKey("spki", spki, { name: "Ed25519" }, true, ["verify"]);
  const canonical = new Uint8Array(await subtle.exportKey("spki", publicKey));
  return { keyId: keyIdFromSpki(canonical), publicKey };
}

export async function exportPrivateKeyPkcs8(privateKey: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle.exportKey("pkcs8", privateKey));
}

export async function importPrivateKeyPkcs8(pkcs8: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

function withDomain(domain: SignatureDomain, bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const prefix = DOMAIN_PREFIXES.get(domain)!;
  const out = new Uint8Array(prefix.length + bytes.length);
  out.set(prefix, 0);
  out.set(bytes, prefix.length);
  return out;
}

export async function signBytes(domain: SignatureDomain, privateKey: CryptoKey, bytes: Uint8Array): Promise<string> {
  if (!SIGNATURE_DOMAINS.includes(domain)) throw new Error(`unsupported signature domain: ${domain}`);
  return toBase64Url(new Uint8Array(await subtle.sign("Ed25519", privateKey, withDomain(domain, bytes))));
}

export async function verifyBytes(domain: SignatureDomain, publicKey: CryptoKey, bytes: Uint8Array, signature: string): Promise<boolean> {
  if (!SIGNATURE_DOMAINS.includes(domain)) return false;
  try {
    const raw = fromBase64Url(signature);
    if (raw.length !== 64) return false;
    if (toBase64Url(raw) !== signature) return false;
    return await subtle.verify("Ed25519", publicKey, raw, withDomain(domain, bytes));
  } catch {
    return false;
  }
}
