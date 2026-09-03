// packages/log/src/signer.ts
import { readFileSync, writeFileSync } from "node:fs";
import { exportPrivateKeyPkcs8, exportPublicKey, generateKeyPair, importPrivateKeyPkcs8, importPublicKey, signBytes, verifyBytes, type Signer } from "@auora/contracts";
import { decryptText, encryptText } from "./crypto.js";
import type { KeyProvider } from "./keys.js";

interface SignerFile { version: 1; key_id: string; public_key_spki: string; private_key_pkcs8_ciphertext: string }
const CHALLENGE = new TextEncoder().encode("auora persisted signer correspondence check");

function metadataAad(keyId: string, spki: string): Uint8Array {
  return new TextEncoder().encode(`${keyId}\n${spki}`);
}

export class PersistedSigner implements Signer {
  private constructor(public readonly keyId: string, public readonly privateKey: CryptoKey, public readonly publicKey: CryptoKey) {}

  static async load(path: string, provider: KeyProvider): Promise<PersistedSigner> {
    const key = await provider.getKey();
    let text = PersistedSigner.readOrNull(path);
    if (text === null) {
      const pair = await generateKeyPair();
      const spki = await exportPublicKey(pair.publicKey);
      const file: SignerFile = {
        version: 1, key_id: pair.keyId, public_key_spki: spki,
        private_key_pkcs8_ciphertext: encryptText(key, Buffer.from(await exportPrivateKeyPkcs8(pair.privateKey)).toString("base64url"), metadataAad(pair.keyId, spki)),
      };
      try {
        writeFileSync(path, JSON.stringify(file), { flag: "wx", mode: 0o600 });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      text = PersistedSigner.readOrNull(path);
      if (text === null) throw new Error("signer file vanished after creation");
    }
    const file = JSON.parse(text) as SignerFile;
    const pkcs8 = new Uint8Array(Buffer.from(decryptText(key, file.private_key_pkcs8_ciphertext, metadataAad(file.key_id, file.public_key_spki)), "base64url"));
    const imported = await importPublicKey(file.public_key_spki);
    if (imported.keyId !== file.key_id) throw new Error("signer file key id mismatch");
    const privateKey = await importPrivateKeyPkcs8(pkcs8);
    const proof = await signBytes("auora.signer/1", privateKey, CHALLENGE);
    if (!(await verifyBytes("auora.signer/1", imported.publicKey, CHALLENGE, proof))) throw new Error("signer file key pair does not correspond");
    return new PersistedSigner(file.key_id, privateKey, imported.publicKey);
  }

  private static readOrNull(path: string): string | null {
    try { return readFileSync(path, "utf8"); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; throw error; }
  }
}
