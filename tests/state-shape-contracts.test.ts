/**
 * Tests that every legacy-shaped step type registered in the default
 * registry declares a `shapeContract` in its documentation block. The
 * contract is OPTIONAL on `StepDocumentation`, so a step without one
 * isn't a compile error — but it silently disables (a) the palette's
 * shape chip + tooltip, (b) drop-anchor greying in the graph view,
 * (c) the static `state-shape-mismatch` warning. This test makes the
 * omission load.
 *
 * If a future legacy step ships without a contract, this test flags it
 * on the same PR — surface the rule rather than letting drift erode
 * the UX.
 *
 * **Slice 2.1a (universal-port plan, 2026-05-24) — port-native skip.**
 * Phase 2+ port-native registrations (`kind: "ported"` with no `legacy`
 * field) intentionally OMIT `shapeContract` because they describe their
 * surface via the richer `PortContract` instead. The single-thread state-
 * shape concept doesn't apply to them; the palette / drop-anchor / spec-
 * shape-mismatch UX surfaces are out of scope for port-native steps
 * until they earn first-class graph rendering in a later slice. Both
 * tests in this file now use `isPortNative()` to skip those entries.
 *
 * Companion to `tests/spec-shapes.test.ts`, which exercises that the
 * declared contracts pass `validateShapes` on every shipped CipherSpec
 * (i.e. the contracts are internally consistent with the spec topology).
 * Together: this test pins "every legacy step has a contract"; the
 * other pins "the contracts cohere".
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { StateShape } from "@/core/types";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

/**
 * A step type is "port-native" when its registration is `kind: "ported"`
 * AND it has no `legacy` fallback executor — i.e., authored against the
 * port-native contract directly rather than lifted from a legacy
 * executor during the Phase 1 migration. Phase 1's lifted entries still
 * carry both `legacy` and `meta` and so still have the legacy state-
 * shape contract; only Phase 2+ port-native entries (Slice 2.1a's
 * `rotate-bits-right@1` is the first) skip these checks.
 */
const isPortNative = (stepType: string): boolean => {
  const reg = registry.getRegistration(stepType);
  return reg?.kind === "ported" && reg.legacy === undefined;
};

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

describe("state-shape contracts — every legacy-shaped step declares one", () => {
  it("default registry: 100% coverage (port-native entries excluded)", () => {
    const missing: string[] = [];
    for (const stepType of registry.types()) {
      if (isPortNative(stepType)) continue;
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
      if (isPortNative(stepType)) continue;
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
