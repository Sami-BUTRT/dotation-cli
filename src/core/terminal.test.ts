import { describe, expect, it } from "vitest";
import { safeLine, safeText } from "./terminal.js";

describe("safeLine", () => {
  it("rend visibles les contrôles C0/C1 et les surcharges bidi", () => {
    expect(safeLine("a\x1b[31m\u0085b")).toBe("a\\x1b[31m\\x85b");
    expect(safeLine("x‮y⁦z⁩")).toBe("x\\u202ey\\u2066z\\u2069");
    expect(safeText("l1\nl2‮")).toBe("l1\nl2\\u202e");
  });
});
