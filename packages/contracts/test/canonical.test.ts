// packages/contracts/test/canonical.test.ts
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import canonicalize from "canonicalize";
import { CanonicalError, assertSignable, canonicalJson, digestOf, digestWithout, isDigest } from "../src/canonical.js";

interface Fixture { name: string; input: unknown; canonical: string; digest?: string }
const fixtures = JSON.parse(readFileSync(new URL("./fixtures/canonical.json", import.meta.url), "utf8")) as Fixture[];

describe("canonical bytes", () => {
  for (const f of fixtures) {
    it(`matches the fixture and the reference library: ${f.name}`, () => {
      expect(canonicalJson(f.input)).toBe(f.canonical);
      expect(canonicalJson(f.input)).toBe(canonicalize(f.input));
      if (f.digest) expect(digestOf(f.input)).toBe(f.digest);
    });
  }
  it("gives identical digests for different key orders", () => {
    const a = { x: 1, y: { p: "q", r: [1, 2] } };
    const b = { y: { r: [1, 2], p: "q" }, x: 1 };
    expect(digestOf(a)).toBe(digestOf(b));
    expect(isDigest(digestOf(a))).toBe(true);
  });
  it("rejects floats, unsafe integers, non NFC strings, non-plain objects and unsupported values before canonicalization", () => {
    expect(() => assertSignable({ n: 1.5 })).toThrowError(CanonicalError);
    expect(() => canonicalJson({ n: 9007199254740992 })).toThrowError(/UNSAFE_INTEGER/);
    expect(() => canonicalJson({ s: "é" })).toThrowError(/NON_NFC_STRING/);
    expect(() => canonicalJson({ u: undefined })).toThrowError(/UNSUPPORTED_VALUE/);
    expect(() => canonicalJson({ f: () => 1 })).toThrowError(/UNSUPPORTED_VALUE/);
    expect(() => canonicalJson({ d: new Date(0) })).toThrowError(/UNSUPPORTED_VALUE/);
    expect(() => canonicalJson({ m: new Map() })).toThrowError(/UNSUPPORTED_VALUE/);
    expect(() => canonicalJson(Object.create({ inherited: 1 }))).toThrowError(/UNSUPPORTED_VALUE/);
    expect(() => assertSignable([1, , 3])).toThrowError(/UNSUPPORTED_VALUE/);
    expect(() => assertSignable(new Array(2))).toThrowError(/UNSUPPORTED_VALUE/);
    expect(() => assertSignable({ s: "\ud800" })).toThrowError(/UNSUPPORTED_VALUE/);
    expect(() => assertSignable({ "\ud800": 1 })).toThrowError(/UNSUPPORTED_VALUE/);
  });
  it("digests without the named keys", () => {
    const obj = { a: 1, b: 2, signature: "x" };
    expect(digestWithout(obj, ["signature"])).toBe(digestOf({ a: 1, b: 2 }));
  });
});
