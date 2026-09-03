// packages/policy/test/guard.test.ts
import { describe, expect, it } from "vitest";
import { guardTier, isProtectedPath } from "../src/guard.js";
import { descriptor } from "./helpers.js";

describe("guard tier", () => {
  it("denies any send, lookup or request carrying a secret label, vault hosts included", () => {
    const unknown = descriptor({ effect_class: "send", labels: ["secret"], target: { kind: "command", value: "curl", scope: "external" }, destination: { domain: "attacker.example", port: 443, class: "unknown" } });
    expect(guardTier(unknown)?.reason_codes).toEqual(["GUARD_SECRET_EXFILTRATION"]);
    const lookup = descriptor({ source: "resolver", effect_class: "read", labels: ["secret"], target: { kind: "name", value: "c2VjcmV0.attacker.example", scope: "external" } });
    expect(guardTier(lookup)?.outcome).toBe("deny");
    const vault = descriptor({ effect_class: "send", source: "proxy", labels: ["secret"], target: { kind: "http_request", value: "api.github.com", scope: "external", method: "POST", canonical_path: "/repos/Leiruz/auora-ai/pulls" }, destination: { domain: "api.github.com", port: 443, class: "vault" } });
    expect(guardTier(vault)?.outcome).toBe("deny");
    const readEarlier = descriptor({ effect_class: "send", labels: ["internal"], run_state: { counters: { actions: 2, sends: 0, denials: 0, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 10, labels_read: ["secret"], signals: [] }, destination: { domain: "registry.npmjs.org", port: 443, class: "allowlisted" } });
    expect(guardTier(readEarlier)?.outcome).toBe("deny");
  });
  it("denies writes to protected configuration and privilege changes", () => {
    expect(isProtectedPath(".auora/policy.yaml")).toBe(true);
    expect(isProtectedPath("sub/.claude/settings.local.json")).toBe(true);
    expect(isProtectedPath(".codex/hooks.json")).toBe(true);
    expect(isProtectedPath("auora://config/daemon.toml")).toBe(true);
    expect(isProtectedPath("src/.auora-like/file")).toBe(false);
    expect(guardTier(descriptor({ effect_class: "write", target: { kind: "path", value: ".auora/policy.yaml", scope: "workspace" } }))?.reason_codes).toEqual(["GUARD_PROTECTED_CONFIG"]);
    expect(guardTier(descriptor({ effect_class: "privilege_change", target: { kind: "command", value: "sudo", scope: "system" } }))?.reason_codes).toEqual(["GUARD_PRIVILEGE_CHANGE"]);
  });
  it("denies file-referenced shell payloads to every destination, vault hosts included", () => {
    const external = descriptor({ effect_class: "send", target: { kind: "command", value: "curl", scope: "external", attributes: ["file_payload_reference"] }, destination: { domain: "example.org", port: 443, class: "observed" } });
    expect(guardTier(external)?.reason_codes).toEqual(["GUARD_FILE_PAYLOAD_REFERENCE"]);
    const vault = descriptor({ effect_class: "send", target: { kind: "command", value: "curl", scope: "external", attributes: ["file_payload_reference"] }, destination: { domain: "api.github.com", port: 443, class: "vault" } });
    expect(guardTier(vault)?.reason_codes).toEqual(["GUARD_FILE_PAYLOAD_REFERENCE"]);
  });
  it("returns null for ordinary actions", () => {
    expect(guardTier(descriptor())).toBeNull();
    expect(guardTier(descriptor({ effect_class: "send", destination: { domain: "registry.npmjs.org", port: 443, class: "allowlisted" }, target: { kind: "command", value: "npm", scope: "external" } }))).toBeNull();
  });
  it("matches protected paths case-insensitively", () => {
    expect(isProtectedPath(".AUORA/policy.yaml")).toBe(true);
    expect(isProtectedPath("C:\\Users\\z\\.Auora\\policy.yaml")).toBe(true);
    expect(isProtectedPath(".Claude\\settings.json")).toBe(true);
    expect(isProtectedPath("AUORA://config/daemon.toml")).toBe(true);
  });
  it("protects shell and PowerShell profile startup files", () => {
    expect(isProtectedPath("home/z/.bashrc")).toBe(true);
    expect(isProtectedPath("Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1")).toBe(true);
    expect(isProtectedPath("src/bashrc.md")).toBe(false);
  });
  it("protects the .claude directory and the top-level .claude.json and .mcp.json files", () => {
    expect(isProtectedPath(".claude/hooks/pre.sh")).toBe(true);
    expect(isProtectedPath(".claude/agents/x.md")).toBe(true);
    expect(isProtectedPath(".mcp.json")).toBe(true);
    expect(isProtectedPath(".claude.json")).toBe(true);
    expect(isProtectedPath(".claude.json.bak")).toBe(false);
    expect(isProtectedPath("foo.claude/x")).toBe(false);
  });
  it("extends guard 1 to targets scoped external, without widening it for internal labels", () => {
    const external = descriptor({ effect_class: "execute", target: { kind: "command", value: "curl", scope: "external" }, run_state: { counters: { actions: 1, sends: 0, denials: 0, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 10, labels_read: ["secret"], signals: [] } });
    expect(guardTier(external)?.reason_codes).toEqual(["GUARD_SECRET_EXFILTRATION"]);
    const notSecret = descriptor({ effect_class: "execute", target: { kind: "command", value: "curl", scope: "external" }, run_state: { counters: { actions: 1, sends: 0, denials: 0, approvals: 0, retries: 0 }, spend_minor: 0, elapsed_ms: 10, labels_read: ["internal"], signals: [] } });
    expect(guardTier(notSecret)).toBeNull();
  });
  it("covers the protected-config delete branch, a guardTier-driven URI write, and guard 4 on a local workspace read", () => {
    expect(guardTier(descriptor({ effect_class: "delete", target: { kind: "path", value: ".auora/policy.yaml", scope: "workspace" } }))?.reason_codes).toEqual(["GUARD_PROTECTED_CONFIG"]);
    expect(guardTier(descriptor({ effect_class: "write", target: { kind: "path", value: "auora://config/daemon.toml", scope: "workspace" } }))?.reason_codes).toEqual(["GUARD_PROTECTED_CONFIG"]);
    expect(guardTier(descriptor({ effect_class: "read", target: { kind: "path", value: "notes.txt", scope: "workspace", attributes: ["file_payload_reference"] } }))?.reason_codes).toEqual(["GUARD_FILE_PAYLOAD_REFERENCE"]);
  });
});
