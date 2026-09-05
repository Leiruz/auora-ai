// packages/policy/test/compile.test.ts
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { compileLayer, compilePathPattern, composeBundles, parseBundle, PolicyCompileError } from "../src/compile.js";
import { loadLayerFile } from "../src/load.js";

const EXAMPLE = fileURLToPath(new URL("../policies/example.yaml", import.meta.url));
const DEFAULTS = fileURLToPath(new URL("../policies/defaults.yaml", import.meta.url));

function code(fn: () => unknown): string {
  try { fn(); } catch (e) { if (e instanceof PolicyCompileError) return e.code; throw e; }
  return "OK";
}

describe("policy compiler", () => {
  it("compiles the example and the defaults and composes them with a stable digest", () => {
    const example = loadLayerFile(EXAMPLE, "example");
    const defaults = loadLayerFile(DEFAULTS, "defaults");
    expect(example.rules.map((r) => r.qualified_id)).toEqual(["example:approve-destructive-outside", "example:throttle-sends", "example:allow-github-api-pulls", "example:allow-npm-registry"]);
    const a = composeBundles([defaults, example]);
    const b = composeBundles([defaults, example]);
    expect(a.digest).toBe(b.digest);
    expect(a.ttl_ms).toBe(5000);
    expect(a.rules).toHaveLength(defaults.rules.length + example.rules.length);
    expect(a.rules.find((r) => r.id === "allow-github-api-pulls")?.obligations).toEqual([{ type: "record_payload_digest" }]);
  });
  it("gives the same layer digest whatever the rule order", () => {
    const spec = parseBundle("version: 1\nrules:\n  - id: first\n    priority: 1\n    match: { effect: read }\n    outcome: deny\n  - id: second\n    priority: 2\n    match: { effect: send }\n    outcome: throttle\n");
    const reversed = { ...spec, rules: [...spec.rules].reverse() };
    expect(compileLayer(spec, "t").digest).toBe(compileLayer(reversed, "t").digest);
    const different = parseBundle("version: 1\nrules:\n  - id: first\n    priority: 1\n    match: { effect: read }\n    outcome: deny\n");
    expect(compileLayer(different, "t").digest).not.toBe(compileLayer(spec, "t").digest);
  });
  it("compiles path patterns as closed single-segment wildcards", () => {
    const re = compilePathPattern("/repos/Leiruz/*/pulls");
    expect(re.test("/repos/Leiruz/auora-ai/pulls")).toBe(true);
    expect(re.test("/repos/Leiruz/a/b/pulls")).toBe(false);
    expect(re.test("/repos/Leiruz/auora-ai/pulls/1")).toBe(false);
    expect(code(() => compilePathPattern("/repos/**"))).toBe("INVALID_PATTERN");
    expect(code(() => compilePathPattern("repos/x"))).toBe("INVALID_PATTERN");
    const dot = compilePathPattern("/v1/user.json");
    expect(dot.test("/v1/userXjson")).toBe(false);
    expect(dot.test("/v1/user.json")).toBe(true);
  });
  it("assumes the caller already percent-decoded the path, so an encoded separator still matches inside a *", () => {
    const re = compilePathPattern("/repos/Leiruz/*/pulls");
    expect(re.test("/repos/Leiruz/a%2Fb/pulls")).toBe(true);
  });
  it("rejects bad bundles with distinct codes", () => {
    const base = parseBundle("version: 1\nrules:\n  - id: a-rule\n    priority: 1\n    match: { effect: send }\n    outcome: deny\n");
    expect(code(() => compileLayer({ ...base, rules: [base.rules[0]!, base.rules[0]!] }, "t"))).toBe("DUPLICATE_RULE_ID");
    expect(code(() => compileLayer({ version: 1, rules: [{ id: "a-rule", priority: 1, match: { effect: "launch" }, outcome: "deny" }] }, "t"))).toBe("INVALID_VALUE");
    expect(code(() => compileLayer({ version: 1, rules: [{ id: "a-rule", priority: 1, match: { destination: "API.GitHub.com" }, outcome: "deny" }] }, "t"))).toBe("INVALID_DOMAIN");
    expect(code(() => compileLayer({ version: 1, rules: [{ id: "a-rule", priority: 1, match: { effect: "send", labels_any: "secret" }, outcome: "allow" }] }, "t"))).toBe("ALLOW_LABEL_MATCHER");
    expect(code(() => compileLayer({ version: 1, rules: [{ id: "a-rule", priority: 1, match: { effect: "send", signals_any: "scope_drift" }, outcome: "allow" }] }, "t"))).toBe("SIGNAL_RULE_ALLOWS");
    expect(code(() => compileLayer({ version: 1, rules: [{ id: "a-rule", priority: 1, match: { effect: "privilege_change" }, outcome: "allow" }] }, "t"))).toBe("ALLOW_GUARDED_EFFECT");
    expect(code(() => compileLayer({ version: 1, rules: [{ id: "a-rule", priority: 1, match: { target_scope: "workspace" }, outcome: "allow" }] }, "t"))).toBe("ALLOW_WITHOUT_EFFECT");
    // path_pattern is tested only against the descriptor's canonical_path, a vault-request field that a
    // target_kind: path descriptor never carries, so this combination can never match (deny rules included).
    expect(code(() => compileLayer({ version: 1, rules: [{ id: "a-rule", priority: 1, match: { target_kind: "path", path_pattern: "/etc/*" }, outcome: "deny" }] }, "t"))).toBe("UNMATCHABLE_PATH_PATTERN");
    expect(code(() => compileLayer({ version: 1, rules: [{ id: "a-rule", priority: 1, match: { effect: [ "write", "delete" ], target_scope: "workspace" }, outcome: "allow" }] }, "t"))).toBe("OK");
    expect(code(() => parseBundle("version: 2\nrules: []\n"))).toBe("SCHEMA");
    expect(code(() => parseBundle("version: 1\nrules:\n  - id: a-rule\n    priority: 1.5\n    match: { effect: send }\n    outcome: deny\n"))).toBe("SCHEMA");
    expect(code(() => parseBundle("version: 1\nversion: 1\nrules: []\n"))).toBe("SCHEMA");
    expect(code(() => parseBundle("version: 1\nrules: !!js/function []\n"))).toBe("SCHEMA");
    expect(code(() => parseBundle("version: 1\nrules: []\n---\nversion: 1\nrules:\n  - id: sneaky\n    priority: 1\n    match: { effect: send }\n    outcome: allow\n"))).toBe("SCHEMA");
    const anchorBomb = "a: &a [1,1,1,1,1,1,1,1,1]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n";
    expect(code(() => parseBundle(anchorBomb))).toBe("SCHEMA");
    expect(code(() => parseBundle("%YAML 1.1\n---\nversion: 1\nrules: []\n"))).toBe("SCHEMA");
    expect(code(() => parseBundle("version: 1\nrules: []\n"))).toBe("OK");
  });
  it("has no import, transitively from pure.ts, of a Node built-in a Worker cannot provide", () => {
    // Walks the real static import graph (not a text grep) from the fs-free surface's entry point, so
    // a node:fs (or similar) import anywhere in the graph fails this test, not just a direct import in
    // compile.ts. node:crypto is excluded from the disallowed set because the Workers runtime provides
    // it (Web Crypto backed); node:fs, node:path and node:sqlite are not, and neither is anything else.
    const ALLOWED_BUILTINS = new Set(["node:crypto"]);
    const CONTRACTS_INDEX = resolve(fileURLToPath(new URL("../../contracts/src/index.ts", import.meta.url)));
    const CONTRACTS_SCHEMAS = resolve(fileURLToPath(new URL("../../contracts/src/schemas.ts", import.meta.url)));
    const PURE_ENTRY = resolve(fileURLToPath(new URL("../src/pure.ts", import.meta.url)));

    // Only import/export-from statements that survive TypeScript's erasure carry a real runtime edge:
    // a line starting "import type" or "export type" is fully erased under verbatimModuleSyntax, even
    // though a mixed `{ real, type Also }` specifier list still counts, since the statement is not
    // all-type there.
    function realImportSpecifiers(source: string): string[] {
      const specifiers: string[] = [];
      for (const line of source.split("\n")) {
        const trimmed = line.trim();
        if (/^(import|export)\s+type\s/.test(trimmed)) continue;
        const m = /^(?:import|export)\b.*\bfrom\s+["']([^"']+)["']/.exec(trimmed);
        if (m?.[1]) specifiers.push(m[1]);
      }
      return specifiers;
    }

    // A relative specifier resolves to sibling .ts source; @auora/contracts resolves to the contracts
    // package's own entry point (as the seam it actually is); any other bare specifier is a third-party
    // package this walk does not open, and a non-".js" relative specifier (the JSON schema imports) is
    // a data leaf, not a source module.
    function resolveWorkspaceFile(spec: string, fromFile: string): string | null {
      if (spec === "@auora/contracts") return CONTRACTS_INDEX;
      if (!spec.startsWith(".")) return null;
      const abs = resolve(dirname(fromFile), spec);
      return abs.endsWith(".js") ? abs.slice(0, -3) + ".ts" : null;
    }

    const visited = new Set<string>();
    const disallowed: string[] = [];
    const queue = [PURE_ENTRY];
    while (queue.length > 0) {
      const file = queue.pop()!;
      if (visited.has(file)) continue;
      visited.add(file);
      for (const spec of realImportSpecifiers(readFileSync(file, "utf8"))) {
        if (spec.startsWith("node:")) {
          if (!ALLOWED_BUILTINS.has(spec)) disallowed.push(`${spec} imported by ${file}`);
          continue;
        }
        const resolved = resolveWorkspaceFile(spec, file);
        if (resolved) queue.push(resolved);
      }
    }

    expect(disallowed).toEqual([]);
    // Sanity: the walk must actually have reached contracts' schema-loading module, the one that used
    // to carry node:fs, or an over-narrow resolver could vacuously pass by never looking anywhere real.
    expect(visited.has(CONTRACTS_SCHEMAS)).toBe(true);
  });
});
