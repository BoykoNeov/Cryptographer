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

  it("registers fns for the four AES round operations (Phase 1)", () => {
    expect(hasNarrationFn("generic.byte-substitution@1")).toBe(true);
    expect(hasNarrationFn("generic.shift-rows@1")).toBe(true);
    expect(hasNarrationFn("generic.mix-columns@1")).toBe(true);
    expect(hasNarrationFn("generic.add-round-key@1")).toBe(true);
  });

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

  it("registers fns for the 5 boundary step types (Phase 3)", () => {
    expect(hasNarrationFn("generic.load-block@1")).toBe(true);
    expect(hasNarrationFn("generic.store-block@1")).toBe(true);
    expect(hasNarrationFn("generic.split-blocks@1")).toBe(true);
    expect(hasNarrationFn("generic.concat-blocks@1")).toBe(true);
    expect(hasNarrationFn("generic.compute-block-count@1")).toBe(true);
  });

  it("registers fns for the 6 aux primitive step types (Phase 3)", () => {
    // Note: 5 of these declare `input: "any"` so they wouldn't be caught
    // by the cell-shape coverage walk above. Explicit per-step assertions
    // are the safety net — without them a silent omission could survive.
    expect(hasNarrationFn("generic.aux-load@1")).toBe(true);
    expect(hasNarrationFn("generic.aux-xor@1")).toBe(true);
    expect(hasNarrationFn("generic.aux-copy@1")).toBe(true);
    expect(hasNarrationFn("generic.iv-load@1")).toBe(true);
    expect(hasNarrationFn("generic.xor-aux-into-state@1")).toBe(true);
    expect(hasNarrationFn("generic.state-to-aux@1")).toBe(true);
  });

  it("allowlists key-expansion step types (covered by KeyScheduleExplorer)", () => {
    expect(NARRATION_NO_OP_ALLOWLIST.has("aes.key-expansion@1")).toBe(true);
    expect(NARRATION_NO_OP_ALLOWLIST.has("aes.key-expansion@2")).toBe(true);
    expect(NARRATION_NO_OP_ALLOWLIST.has("serpent.key-expansion@1")).toBe(true);
    expect(NARRATION_NO_OP_ALLOWLIST.has("speck.key-schedule@1")).toBe(true);
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

  it("allowlist size: 6 irreducible + 1 toy-test entry (Phase 2 of DES + branching primitive plan)", () => {
    // Pins the final landing place: Phase 3 brings the no-op list down
    // to the entries that have a structural reason to opt out of byte-
    // level narration. Phase 2 of `docs/plans/des-feistel.md` adds the
    // toy F (`feistel.toy-add-k@1`) — never user-visible, removed when
    // the toy is decommissioned post-Phase 3. Any other regression that
    // re-adds a step type (instead of registering a narrator) trips this
    // assertion.
    expect(NARRATION_NO_OP_ALLOWLIST.size).toBe(7);
    expect(NARRATION_NO_OP_ALLOWLIST.has("feistel.toy-add-k@1")).toBe(true);
  });
});
