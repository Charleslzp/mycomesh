import { describe, expect, it } from "vitest";
import { canonicalInferenceInputBytes } from "./inputLimits";

describe("canonical inference input bytes", () => {
  it("counts the JSON-encoded UTF-8 bytes sent to the Provider", () => {
    expect(canonicalInferenceInputBytes("hello")).toBe(7);
    expect(canonicalInferenceInputBytes("  hello  ")).toBe(11);
    expect(canonicalInferenceInputBytes("hello  ")).toBe(9);
    expect(canonicalInferenceInputBytes("你好")).toBe(8);
    expect(canonicalInferenceInputBytes('a"b\\c')).toBe(9);
    expect(canonicalInferenceInputBytes("a\nb")).toBe(6);
  });
});
