// @vitest-environment jsdom

/**
 * ParamEditor coverage for the ML-DSA layer (P2 of
 * `docs/plans/refactored-petting-tide.md`) and every `zq-` step.
 *
 * Same gap `tests/zq-param-editor-coverage.test.tsx` closes for ML-KEM: these
 * steps are palette-only, so `tests/param-editor-coverage.test.tsx` (which walks
 * SHIPPED specs) never sees them, while `StepPalette` lists them all.
 *
 * **Prefix-derived, not hand-listed.** The step types come from
 * `registry.types()` filtered on `ml-dsa.` and `zq-`, so a step registered
 * tomorrow is enrolled without anyone remembering to add it. A hand list passes
 * green when an entry goes missing — the vacuous-suite hazard MT19937 found.
 *
 * Two assertions per step, as in the ML-KEM file:
 *  1. No raw-JSON fallback.
 *  2. A leaf dropped from the palette (`params: {}`) still shows every
 *     editable row its type declares — rows keyed on the TYPE, not on whether
 *     the value is present.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { StepNode } from "@/core/types";
import { ML_DSA_BLOCK_ROWS, ParamEditor } from "@/ui/components/ParamEditor";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetSpecForTests, insertStepIntoSpec, setLattice, useSpec } from "@/ui/stores/spec";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const FALLBACK_RE = /no editor for step type/i;

const registry = buildDefaultRegistry();
const ML_DSA_TYPES = registry
  .types()
  .filter((t) => t.startsWith("ml-dsa."))
  .sort();
const ZQ_TYPES = registry
  .types()
  .filter((t) => t.startsWith("zq-"))
  .sort();

const firstLeafId = (nodes: readonly StepNode[]): string => {
  for (const node of nodes) {
    if (node.kind === "step") return node.id;
    const inner = firstLeafId(node.children);
    if (inner) return inner;
  }
  return "";
};

const dropAndRender = (stepType: string) => {
  const newId = insertStepIntoSpec(stepType, {
    kind: "after",
    stepId: firstLeafId(useSpec()().steps),
  });
  return render(() => <ParamEditor stepId={newId} />);
};

describe("ParamEditor covers every ML-DSA and Z_q step — from a palette drop", () => {
  beforeEach(() => {
    __resetCipherForTests();
    __resetSpecForTests();
    // The ML-DSA transform is the natural host for its own arithmetic.
    setLattice("ntt-8380417-256");
  });

  afterEach(() => {
    cleanup();
  });

  it("inventories the prefix walk (so the loops below cannot pass vacuously)", () => {
    expect(ML_DSA_TYPES).toContain("ml-dsa.decompose@1");
    expect(ZQ_TYPES).toContain("zq-vec-mul@1");
    expect(ZQ_TYPES).toContain("zq-inf-norm-below@1");
  });

  for (const stepType of [...ZQ_TYPES, ...ML_DSA_TYPES]) {
    it(`${stepType} renders a real editor, not the raw-JSON fallback`, () => {
      const { queryByText, unmount } = dropAndRender(stepType);
      expect(
        queryByText(FALLBACK_RE),
        `${stepType} renders the raw-JSON fallback — give it a row in ParamEditor.tsx`,
      ).toBeNull();
      unmount();
    });
  }

  for (const stepType of ML_DSA_TYPES) {
    const rows = ML_DSA_BLOCK_ROWS[stepType];
    if (rows === undefined) continue;
    it(`${stepType} shows every editable row and names its wired constants on a fresh drop`, () => {
      const { queryByText, unmount } = dropAndRender(stepType);
      for (const row of rows.ints) {
        expect(queryByText(row.label), `${stepType} hides its "${row.label}" row`).not.toBeNull();
      }
      if (rows.wired.length > 0) {
        expect(queryByText(/Wired constants/)).not.toBeNull();
        for (const w of rows.wired) expect(queryByText(w)).not.toBeNull();
      }
      unmount();
    });
  }

  it("every ML-DSA wired-constant row names a real input port of its step", () => {
    // The row is prose, so nothing else checks it against the contract. A port
    // renamed in an executor would leave the editor pointing at nothing.
    for (const [stepType, rows] of Object.entries(ML_DSA_BLOCK_ROWS)) {
      const shape = registry.getRegistration(stepType);
      if (shape === undefined) continue;
      const contract = shape.shape;
      const inputs = typeof contract.inputs === "function" ? contract.inputs({}) : contract.inputs;
      for (const w of rows.wired) {
        const portName = w.split(" ")[0] as string;
        expect(inputs.has(portName), `${stepType} names "${portName}", not one of its ports`).toBe(
          true,
        );
      }
    }
  });
});
