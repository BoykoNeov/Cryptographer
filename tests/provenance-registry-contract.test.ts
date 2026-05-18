/**
 * Provenance-registry contract test. Walks the core step registry and
 * asserts that every shipped step type EITHER has a provenance fn
 * registered OR sits on the explicit no-provenance allowlist.
 *
 * Why: without this enforcement, a future cipher addition could silently
 * land step types with no hover support and nothing would fail. The
 * test mirrors the pattern in `tests/cross-mode-mirror-coverage.test.tsx`
 * — turn "did I cover all the cases" from a manual audit into a CI gate.
 *
 * Failure mode is opinionated: when a step type is in the core registry
 * but neither registered nor allowlisted, the test fails with a message
 * that names the offending stepType AND suggests both fixes. So a new
 * cipher author either writes a provenance fn or makes an explicit
 * "we considered this and it's not worth a fn" decision via the
 * allowlist entry.
 *
 * Out-of-scope step types: anything whose `shapeContract.input` is not
 * `matrix4x4-bytes` or `bytes` — provenance is cell-level and only
 * those two shapes have cells today. BitVec / BigInt would need their
 * own provenance contract when those shapes get cell-level views.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { PROVENANCE_NO_OP_ALLOWLIST, hasProvenanceFn } from "@/ui/provenance/registry";
// Importing the index file eagerly initializes the provenance registry
// via its module-load side-effect. Without this import the `hasProvenanceFn`
// lookups all return false because nothing was registered.
import "@/ui/provenance/index";
import { describe, expect, it } from "vitest";

const isCellShape = (shape: string | undefined): boolean =>
  shape === "matrix4x4-bytes" || shape === "bytes";

describe("provenance-registry coverage contract", () => {
  const registry = buildDefaultRegistry();

  // Inventory of step types whose input shape supports cell-level
  // hover (matrix or bytes). Read off the doc block's `shapeContract`
  // field. Steps without a contract are skipped (legacy + future-types
  // that haven't declared one yet — the cell-level hover wouldn't know
  // how to render them anyway).
  const cellShapeStepTypes: string[] = [];
  for (const stepType of registry.types()) {
    const contract = registry.getDoc(stepType)?.shapeContract;
    if (!contract) continue;
    if (isCellShape(contract.input)) {
      cellShapeStepTypes.push(stepType);
    }
  }

  it("inventories a non-empty set of cell-shape step types (sanity check)", () => {
    // Guards against a refactor that accidentally strips all shape
    // contracts and leaves the registry hollow — would mask a wholesale
    // regression in this test's coverage.
    expect(cellShapeStepTypes.length).toBeGreaterThan(0);
  });

  it("every cell-shape step type is either provenance-registered or allowlisted", () => {
    const uncovered: string[] = [];
    for (const stepType of cellShapeStepTypes) {
      const registered = hasProvenanceFn(stepType);
      const allowlisted = PROVENANCE_NO_OP_ALLOWLIST.has(stepType);
      if (!registered && !allowlisted) {
        uncovered.push(stepType);
      }
      // Catch the inverse error too: a step type accidentally on the
      // allowlist AND registered would mean "we said it's a no-op but
      // also wrote a provenance fn" — wires crossed. Fail loudly.
      if (registered && allowlisted) {
        throw new Error(
          `step type "${stepType}" is BOTH registered with a provenance fn AND on the no-op allowlist; pick one`,
        );
      }
    }

    if (uncovered.length > 0) {
      // Multi-line failure message kept readable via a single template
      // literal — biome's no-unused-template-literal rule fires on the
      // pieces individually, so compose them here as one string.
      const bullets = uncovered.map((t) => `  - ${t}`).join("\n");
      throw new Error(
        `Provenance-coverage gap. The following step types have a cell-shape contract but no provenance handling:\n${bullets}\n\nFor each, either:\n  - Register a ProvenanceFn in src/ui/provenance/{aes,serpent,...}.ts and wire it in src/ui/provenance/index.ts; OR\n  - Add the stepType to PROVENANCE_NO_OP_ALLOWLIST in src/ui/provenance/registry.ts with a brief rationale.`,
      );
    }
    expect(uncovered).toEqual([]);
  });

  it("registers fns for the four AES round operations", () => {
    expect(hasProvenanceFn("generic.byte-substitution@1")).toBe(true);
    expect(hasProvenanceFn("generic.shift-rows@1")).toBe(true);
    expect(hasProvenanceFn("generic.mix-columns@1")).toBe(true);
    expect(hasProvenanceFn("generic.add-round-key@1")).toBe(true);
  });

  it("registers fns for the Serpent byte-level steps (AddRoundKey, SubBytes)", () => {
    expect(hasProvenanceFn("serpent.add-round-key@1")).toBe(true);
    expect(hasProvenanceFn("serpent.sub-bytes@1")).toBe(true);
  });

  it("allowlists Serpent's bit-level steps (byte-approximation too muddled)", () => {
    expect(PROVENANCE_NO_OP_ALLOWLIST.has("serpent.linear-transform@1")).toBe(true);
    expect(PROVENANCE_NO_OP_ALLOWLIST.has("serpent.inv-linear-transform@1")).toBe(true);
    expect(PROVENANCE_NO_OP_ALLOWLIST.has("serpent.bit-permutation@1")).toBe(true);
  });
});
