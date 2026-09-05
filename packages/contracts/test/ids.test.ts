import { describe, expect, it } from "vitest";
import { newId, parseId } from "../src/ids.js";

describe("prefixed identifiers", () => {
  it("creates ids with the prefix and a 26 character Crockford body", () => {
    const id = newId("run");
    expect(id).toMatch(/^run_[0-9A-HJKMNP-TV-Z]{26}$/);
  });
  it("creates distinct ids", () => {
    expect(newId("act")).not.toBe(newId("act"));
  });
  it("parses only the requested prefix and a valid body", () => {
    const id = newId("evt");
    expect(parseId("evt", id)).toBe(id);
    expect(parseId("run", id)).toBeNull();
    expect(parseId("evt", "evt_" + "0".repeat(25))).toBeNull();
    expect(parseId("evt", "evt_" + "I".repeat(26))).toBeNull();
    expect(parseId("evt", "evt_" + "0".repeat(26).toLowerCase())).toBe("evt_" + "0".repeat(26));
    expect(parseId("evt", 42)).toBeNull();
  });
});
