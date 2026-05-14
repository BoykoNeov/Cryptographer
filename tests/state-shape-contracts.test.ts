/**
 * Tests that every step type registered in the default registry declares
 * a `shapeContract` in its documentation block. The contract is OPTIONAL
 * on `StepDocumentation`, so a step without one isn't a compile error —
 * but it silently disables (a) the palette's shape chip + tooltip,
 * (b) drop-anchor greying in the graph view, (c) the static
 * `state-shape-mismatch` warning. This test makes the omission load.
 *
 * If a future step ships without a contract, this test flags it on the
 * same PR — surface the rule rather than letting drift erode the UX.
 *
 * Companion to `tests/spec-shapes.test.ts`, which exercises that the
 * declared contracts pass `validateShapes` on every shipped CipherSpec
 * (i.e. the contracts are internally consistent with the spec topology).
 * Together: this test pins "every step has a contract"; the other pins
 * "the contracts cohere".
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { StateShape } from "@/core/types";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

const VALID_INPUT_VALUES: ReadonlySet<StateShape | "any"> = new Set([
  "bytes",
  "matrix4x4-bytes",
  "bitvec",
  "bigint",
  "any",
]);
const VALID_OUTPUT_VALUES: ReadonlySet<StateShape | "preserveInput"> = new Set([
  "bytes",
  "matrix4x4-bytes",
  "bitvec",
  "bigint",
  "preserveInput",
]);

describe("state-shape contracts — every registered step declares one", () => {
  it("default registry: 100% coverage", () => {
    const missing: string[] = [];
    for (const stepType of registry.types()) {
      const doc = registry.getDoc(stepType);
      if (!doc || !doc.shapeContract) missing.push(stepType);
    }
    expect(missing, `step types without shapeContract: ${missing.join(", ")}`).toEqual([]);
  });

  it("input + output values fall inside the union of valid shapes", () => {
    // Catches typos like `shapeContract: { input: "matrix-4x4", ... }`.
    // The TypeScript declaration would catch this at build time, but a
    // future refactor that loosens the type (e.g. adds a discriminator
    // wrapper) shouldn't let typos slip past.
    for (const stepType of registry.types()) {
      const contract = registry.getDoc(stepType)?.shapeContract;
      expect(contract, `${stepType} has no contract`).toBeDefined();
      if (!contract) continue;
      expect(
        VALID_INPUT_VALUES.has(contract.input),
        `${stepType}: invalid input '${contract.input}'`,
      ).toBe(true);
      expect(
        VALID_OUTPUT_VALUES.has(contract.output),
        `${stepType}: invalid output '${contract.output}'`,
      ).toBe(true);
    }
  });
});
