/**
 * Narration-registry contract test. Walks the core step registry and
 * asserts that every shipped step type whose input shape supports cell-
 * level rendering (matrix4x4-bytes or bytes) EITHER has a narration fn
 * registered OR sits on the explicit `NARRATION_NO_OP_ALLOWLIST`.
 *
 * Why: without this enforcement, a future cipher addition could land
 * step types with no per-frame value-prose and nothing would fail. The
 * test mirrors `tests/provenance-registry-contract.test.ts` literally —
 * turn "did I cover all the cases" from a manual audit into a CI gate.
 *
 * Failure mode is opinionated: a step type in the core registry but
 * neither registered nor allowlisted fails with a message that names
 * the offending stepType AND suggests both fixes. New cipher authors
 * either write a narration fn or make an explicit "we considered this
 * and the byte-level surface isn't worth it" decision via the allowlist.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { NARRATION_NO_OP_ALLOWLIST, hasNarrationFn } from "@/ui/narration/registry";
// Importing the index file eagerly initializes the narration registry
// via its module-load side-effect. Without this import the
// `hasNarrationFn` lookups all return false.
import "@/ui/narration/index";
import { describe, expect, it } from "vitest";

const isCellShape = (shape: string | undefined): boolean =>
  shape === "matrix4x4-bytes" || shape === "bytes";

describe("narration-registry coverage contract", () => {
  const registry = buildDefaultRegistry();

  // Inventory of step types whose input shape supports cell-level
  // narration (matrix or bytes). Read off the doc block's
  // `shapeContract` field; steps without a contract are skipped.
  const cellShapeStepTypes: string[] = [];
  for (const stepType of registry.types()) {
    const contract = registry.getDoc(stepType)?.shapeContract;
    if (!contract) continue;
    if (isCellShape(contract.input)) {
      cellShapeStepTypes.push(stepType);
    }
  }

  it("inventories a non-empty set of cell-shape step types (sanity check)", () => {
    expect(cellShapeStepTypes.length).toBeGreaterThan(0);
  });

  it("every cell-shape step type is either narration-registered or allowlisted", () => {
    const uncovered: string[] = [];
    for (const stepType of cellShapeStepTypes) {
      const registered = hasNarrationFn(stepType);
      const allowlisted = NARRATION_NO_OP_ALLOWLIST.has(stepType);
      if (!registered && !allowlisted) {
        uncovered.push(stepType);
      }
      // Inverse error: a step type accidentally on both lists would
      // mean "we said it's a no-op but also wrote a narrator" — wires
      // crossed. Fail loudly.
      if (registered && allowlisted) {
        throw new Error(
          `step type "${stepType}" is BOTH registered with a narration fn AND on the no-op allowlist; pick one`,
        );
      }
    }

    if (uncovered.length > 0) {
      const bullets = uncovered.map((t) => `  - ${t}`).join("\n");
      throw new Error(
        `Narration-coverage gap. The following step types have a cell-shape contract but no narration handling:\n${bullets}\n\nFor each, either:\n  - Register a NarrationFn in src/ui/narration/{aes,serpent,…}.ts and wire it in src/ui/narration/index.ts; OR\n  - Add the stepType to NARRATION_NO_OP_ALLOWLIST in src/ui/narration/registry.ts with a brief rationale.`,
      );
    }
    expect(uncovered).toEqual([]);
  });

  // The four matrix AES round-operation narrators (byte-substitution /
  // shift-rows / mix-columns / add-round-key) were retired in Phase 5
  // Slice 5.1 (2026-05-30) with their step types + the MatrixState shape.

  it("registers fns for Serpent byte-level + bit-permutation steps (Phase 2)", () => {
    expect(hasNarrationFn("serpent.sub-bytes@1")).toBe(true);
    expect(hasNarrationFn("serpent.add-round-key@1")).toBe(true);
    expect(hasNarrationFn("serpent.bit-permutation@1")).toBe(true);
  });

  it("registers fns for Speck round + round-inverse (Phase 2)", () => {
    expect(hasNarrationFn("speck.round@1")).toBe(true);
    expect(hasNarrationFn("speck.round-inverse@1")).toBe(true);
  });

  it("registers fns for the 6 padding step types (Phase 3)", () => {
    expect(hasNarrationFn("generic.pkcs7-pad@1")).toBe(true);
    expect(hasNarrationFn("generic.pkcs7-unpad@1")).toBe(true);
    expect(hasNarrationFn("generic.zero-pad@1")).toBe(true);
    expect(hasNarrationFn("generic.zero-unpad@1")).toBe(true);
    expect(hasNarrationFn("generic.iso7816-4-pad@1")).toBe(true);
    expect(hasNarrationFn("generic.iso7816-4-unpad@1")).toBe(true);
  });

  // The 5 matrix boundary narrators (load-block / store-block / split-blocks
  // / concat-blocks / compute-block-count) were retired in Phase 5 Slice 5.1
  // (2026-05-30) with their step types + the MatrixState shape.

  it("registers fns for the 3 aux primitive step types (Phase 3)", () => {
    // These declare `input: "any"` so they wouldn't be caught by the
    // cell-shape coverage walk above. Explicit per-step assertions are the
    // safety net — without them a silent omission could survive. (The matrix
    // chaining narrators iv-load / xor-aux-into-state / state-to-aux retired
    // in Phase 5 Slice 5.1 with their step types.)
    expect(hasNarrationFn("generic.aux-load@1")).toBe(true);
    expect(hasNarrationFn("generic.aux-xor@1")).toBe(true);
    expect(hasNarrationFn("generic.aux-copy@1")).toBe(true);
  });

  it("allowlists key-expansion step types (covered by KeyScheduleExplorer)", () => {
    expect(NARRATION_NO_OP_ALLOWLIST.has("aes.key-expansion@1")).toBe(true);
    expect(NARRATION_NO_OP_ALLOWLIST.has("aes.key-expansion@2")).toBe(true);
    expect(NARRATION_NO_OP_ALLOWLIST.has("serpent.key-expansion@1")).toBe(true);
    // `speck.key-schedule@1` was on this allowlist until the K2c follow-up
    // (2026-06-01) — the executor + its StepDocumentation were retired then,
    // so the allowlist entry was dropped (an allowlist entry for an
    // un-registered step type would be dead). The decomposed schedule's
    // publish tail (`speck.publish-round-keys@1`) carries the parity entry.
  });

  it("allowlists Serpent's bit-level LINEAR transforms (byte-approximation too muddled)", () => {
    // After Phase 2 only the GF(2) linear transforms remain on the
    // allowlist: their 6-7-bit fan-in defeats byte-level prose.
    // `serpent.bit-permutation@1` moved OFF the allowlist with a
    // dedicated narrator (single-bit-per-output drill is honest).
    expect(NARRATION_NO_OP_ALLOWLIST.has("serpent.linear-transform@1")).toBe(true);
    expect(NARRATION_NO_OP_ALLOWLIST.has("serpent.inv-linear-transform@1")).toBe(true);
    expect(NARRATION_NO_OP_ALLOWLIST.has("serpent.bit-permutation@1")).toBe(false);
  });

  it("allowlist contents are exactly the expected set (set-equality pin)", () => {
    // Switched from a numeric `.size` pin to a `toEqual(new Set([...]))` set-
    // equality assertion at the K2c follow-up (2026-06-01) per advisor pass:
    // the size pin churned on every cipher decomposition (8 → 9 for K2a's
    // publish tail, then 9 → 8 for K2c's monolith retire), each delta a
    // one-line bump that added nothing the positive `has(...)` assertions
    // didn't already cover. The set-equality assertion is one-time
    // refactoring effort that pins the entire shape; K3 (Serpent
    // decomposition) and K4 (DES decomposition) will touch the data array,
    // not the assertion arithmetic.
    //
    // Current contents (5 permanent + 3 cipher-specific):
    //   - 3 surviving key-expansion / key-schedule step types covered by
    //     `<KeyScheduleExplorer />` (`aes.key-expansion@{1,2}` — the AES
    //     branch is unreachable but the executors stay as FIPS oracle;
    //     `serpent.key-expansion@1` — actively used). The Speck entry was
    //     dropped at the K2c follow-up with its executor.
    //   - 2 bit-level Serpent linear transforms whose byte-level prose
    //     would mislead.
    //   - `des.key-schedule@1` — multi-round PC-1 → shifts → PC-2 walk;
    //     wrong surface for per-frame narration.
    //   - `aes.publish-round-keys@1` and `speck.publish-round-keys@1` —
    //     identity-passthrough aux-publish tails (decomposed-schedule K1a
    //     and K2a); the math is the recurrence leaves above them.
    const expected = new Set<string>([
      "aes.key-expansion@1",
      "aes.key-expansion@2",
      "serpent.key-expansion@1",
      "serpent.linear-transform@1",
      "serpent.inv-linear-transform@1",
      "des.key-schedule@1",
      "aes.publish-round-keys@1",
      "speck.publish-round-keys@1",
      // K3a (2026-06-02): the decomposed Serpent key schedule's publish tail.
      "serpent.publish-round-keys@1",
    ]);
    expect(NARRATION_NO_OP_ALLOWLIST).toEqual(expected);
    // Negative assertion: the 6 round-body DES step types must NOT be on
    // the allowlist after Phase 4 (would mean we forgot to register a
    // narrator and the contract test's coverage check would lie).
    for (const t of [
      "des.initial-permutation@1",
      "des.final-permutation@1",
      "des.expand-R@1",
      "des.xor-with-K@1",
      "des.s-boxes@1",
      "des.p-permutation@1",
    ]) {
      expect(
        NARRATION_NO_OP_ALLOWLIST.has(t),
        `${t} should NOT be on allowlist after Phase 4`,
      ).toBe(false);
    }
  });
});
