// packages/contracts/src/canonical.ts
/// <reference lib="es2024.string" />
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

export type Digest = `sha256:${string}`;
export const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

export type CanonicalErrorCode = "NON_INTEGER_NUMBER" | "UNSAFE_INTEGER" | "NON_NFC_STRING" | "UNSUPPORTED_VALUE";

export class CanonicalError extends Error {
  constructor(public readonly code: CanonicalErrorCode, public readonly path: string) {
    super(`${code} at ${path}`);
    this.name = "CanonicalError";
  }
}

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === Object.prototype || proto === null;
}

function check(value: unknown, path: string): void {
  if (value === null) return;
  switch (typeof value) {
    case "boolean":
      return;
    case "number":
      if (!Number.isInteger(value)) throw new CanonicalError("NON_INTEGER_NUMBER", path);
      if (!Number.isSafeInteger(value)) throw new CanonicalError("UNSAFE_INTEGER", path);
      return;
    case "string":
      if (!value.isWellFormed()) throw new CanonicalError("UNSUPPORTED_VALUE", path);
      if (value.normalize("NFC") !== value) throw new CanonicalError("NON_NFC_STRING", path);
      return;
    case "object": {
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          if (!(i in value)) throw new CanonicalError("UNSUPPORTED_VALUE", `${path}[${i}]`);
          check(value[i], `${path}[${i}]`);
        }
        return;
      }
      if (!isPlainObject(value)) throw new CanonicalError("UNSUPPORTED_VALUE", path);
      for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
        if (v === undefined) throw new CanonicalError("UNSUPPORTED_VALUE", `${path}.${key}`);
        if (!key.isWellFormed()) throw new CanonicalError("UNSUPPORTED_VALUE", `${path}.${key}`);
        if (key.normalize("NFC") !== key) throw new CanonicalError("NON_NFC_STRING", `${path}.${key}`);
        check(v, `${path}.${key}`);
      }
      return;
    }
    default:
      throw new CanonicalError("UNSUPPORTED_VALUE", path);
  }
}

export function assertSignable(value: unknown): void {
  check(value, "$");
}

export function canonicalJson(value: unknown): string {
  assertSignable(value);
  const text = canonicalize(value);
  if (text === undefined) throw new CanonicalError("UNSUPPORTED_VALUE", "$");
  return text;
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function digestOf(value: unknown): Digest {
  return `sha256:${sha256Hex(canonicalBytes(value))}`;
}

export function digestWithout<T extends object>(value: T, omit: readonly (keyof T & string)[]): Digest {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  for (const key of omit) delete copy[key];
  return digestOf(copy);
}

export function isDigest(value: unknown): value is Digest {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}
