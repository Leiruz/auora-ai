// packages/log/src/crypto.ts
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export function encryptText(key: Uint8Array, plaintext: string, aad?: Uint8Array): string {
  if (key.length !== 32) throw new Error("key must be 32 bytes");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]).toString("base64url");
}

export function decryptText(key: Uint8Array, token: string, aad?: Uint8Array): string {
  if (key.length !== 32) throw new Error("key must be 32 bytes");
  const buf = Buffer.from(token, "base64url");
  if (buf.length < 28) throw new Error("ciphertext too short");
  const iv = buf.subarray(0, 12); const tag = buf.subarray(buf.length - 16); const ciphertext = buf.subarray(12, buf.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
