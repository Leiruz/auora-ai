// packages/log/src/keys.ts
import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface KeyProvider { getKey(): Promise<Uint8Array> }

export class MemoryKeyProvider implements KeyProvider {
  constructor(private readonly key: Uint8Array) { if (key.length !== 32) throw new Error("key must be 32 bytes"); }
  async getKey(): Promise<Uint8Array> { return this.key; }
}

// File-backed provider for sub-project 1 only, never the production secret store: file modes are not
// enforced on Windows, and the operating-system keychain provider replaces this in sub-project 2 (spec 7.4).
export class FileKeyProvider implements KeyProvider {
  constructor(private readonly path: string) {}
  async getKey(): Promise<Uint8Array> {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    try {
      writeFileSync(this.path, randomBytes(32), { flag: "wx", mode: 0o600 });
      if (process.platform !== "win32") chmodSync(this.path, 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const key = new Uint8Array(readFileSync(this.path));
    if (key.length !== 32) throw new Error("key file is corrupt");
    return key;
  }
}
