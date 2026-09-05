import { describe, expect, it } from "vitest";
import { CONTRACTS_PACKAGE } from "../src/index.js";

describe("workspace", () => {
  it("resolves the contracts package", () => {
    expect(CONTRACTS_PACKAGE).toBe("@auora/contracts");
  });
});
