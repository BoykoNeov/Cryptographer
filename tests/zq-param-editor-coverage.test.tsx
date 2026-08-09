// @vitest-environment jsdom

/**
 * ParamEditor coverage for the Z_q / lattice step family (ML-KEM P1 + P2).
 *
 * `tests/param-editor-coverage.test.tsx` walks only step types that appear in a
 * SHIPPED spec, on the stated grounds that a registered-but-unused type is
 * unreachable from the UI. **That reasoning does not hold for this family.**
 * P2's own plan says its surface is "the test suite plus the palette", and
 * `StepPalette` lists every non-padding registered step type — so all five P2
 * steps are droppable onto any spec today while appearing in none, which is
 * precisely the gap between the two tests. This file closes it.
 *
 * Two things are asserted for each, and the second is the one that bites:
 *
 *  1. No raw-JSON fallback. The classic omission this whole test family exists
 *     to catch — `JSON.stringify(params, null, 2)` renders one line per value.
 *  2. **A leaf dropped from the palette can actually be configured.**
 *     `insertStepIntoSpec` gives a new leaf `params: {}`, so an editor that
 *     decides which rows to show by testing whether a value is present would
 *     hide the only control that could set it. The `d` and `η` rows are
 *     therefore keyed on the step TYPE, and this test drops each step through
 *     the real store path to prove it — rendering a hand-built leaf with
 *     populated params would pass while the actual user path stayed broken.
 */

import type { StepNode } from "@/core/types";
import { ParamEditor } from "@/ui/components/ParamEditor";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetSpecForTests, insertStepIntoSpec, setLattice, useSpec } from "@/ui/stores/spec";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const FALLBACK_RE = /no editor for step type/i;

/** Every Z_q step type, P1's three and P2's five. */
const ZQ_STEP_TYPES = [
  "zq-vec-add@1",
  "zq-vec-sub@1",
  "zq-vec-mul-scalar@1",
  "zq-compress@1",
  "zq-decompress@1",
  "zq-byte-encode@1",
  "zq-byte-decode@1",
  "zq-cbd@1",
  "zq-base-case-mul@1",
] as const;

/** Steps whose `d` is meant to be editable. */
const HAS_D = new Set(["zq-compress@1", "zq-decompress@1", "zq-byte-encode@1", "zq-byte-decode@1"]);

const firstLeafId = (nodes: readonly StepNode[]): string => {
  for (const node of nodes) {
    if (node.kind === "step") return node.id;
    const inner = firstLeafId(node.children);
    if (inner) return inner;
  }
  return "";
};

describe("ParamEditor covers every Z_q step type — including the palette-only ones", () => {
  beforeEach(() => {
    __resetCipherForTests();
    __resetSpecForTests();
    // The NTT is the family's natural host, and the only shipped lattice spec.
    setLattice("ntt-3329-256");
  });

  afterEach(() => {
    cleanup();
  });

  for (const stepType of ZQ_STEP_TYPES) {
    it(`${stepType} dropped from the palette renders a real editor`, () => {
      const anchorId = firstLeafId(useSpec()().steps);
      expect(anchorId).not.toBe("");
      const newId = insertStepIntoSpec(stepType, { kind: "after", stepId: anchorId });

      const { queryByText, unmount } = render(() => <ParamEditor stepId={newId} />);
      expect(
        queryByText(FALLBACK_RE),
        `${stepType} renders the raw-JSON fallback — add it to the Z_q <Match> in ParamEditor.tsx`,
      ).toBeNull();
      // The block itself rendered, not just "no step selected".
      expect(queryByText(/Modulus q/)).not.toBeNull();
      unmount();
    });
  }

  it("a freshly dropped compression step still offers its d control", () => {
    // The regression this file exists for: `insertStepIntoSpec` supplies
    // `params: {}`, so a row gated on `params().d !== undefined` would vanish
    // exactly when the user needs it. Asserted for every step that carries d.
    for (const stepType of HAS_D) {
      __resetSpecForTests();
      setLattice("ntt-3329-256");
      const newId = insertStepIntoSpec(stepType, {
        kind: "after",
        stepId: firstLeafId(useSpec()().steps),
      });
      const leaf = render(() => <ParamEditor stepId={newId} />);
      expect(
        leaf.queryByText(/\(d\)/),
        `${stepType} hides its d row on a fresh drop`,
      ).not.toBeNull();
      leaf.unmount();
    }
  });

  it("a freshly dropped noise sampler still offers its η control", () => {
    const newId = insertStepIntoSpec("zq-cbd@1", {
      kind: "after",
      stepId: firstLeafId(useSpec()().steps),
    });
    const { queryByText } = render(() => <ParamEditor stepId={newId} />);
    expect(queryByText(/Noise η/)).not.toBeNull();
  });

  it("does NOT offer a d control on the steps that have no d", () => {
    // The mirror assertion, so the type-keyed gate cannot degrade into
    // "always show everything".
    for (const stepType of ["zq-vec-add@1", "zq-base-case-mul@1", "zq-cbd@1"] as const) {
      __resetSpecForTests();
      setLattice("ntt-3329-256");
      const newId = insertStepIntoSpec(stepType, {
        kind: "after",
        stepId: firstLeafId(useSpec()().steps),
      });
      const leaf = render(() => <ParamEditor stepId={newId} />);
      expect(leaf.queryByText(/\(d\)/), `${stepType} shows a d row it has no use for`).toBeNull();
      leaf.unmount();
    }
  });

  it("keeps the whole family's params on ONE block — a new member costs one Match arm", () => {
    // Guard against the family drifting into nine near-identical blocks. If a
    // future step genuinely needs its own, this assertion is the place to say so.
    const seen = new Set<string>();
    for (const stepType of ZQ_STEP_TYPES) {
      __resetSpecForTests();
      setLattice("ntt-3329-256");
      const newId = insertStepIntoSpec(stepType, {
        kind: "after",
        stepId: firstLeafId(useSpec()().steps),
      });
      const leaf = render(() => <ParamEditor stepId={newId} />);
      const rows = leaf.container.querySelectorAll(".param-scalar-row dt");
      seen.add([...rows].map((r) => r.textContent).join("|"));
      leaf.unmount();
    }
    // FOUR shapes, and the fourth is deliberate rather than drift: the two
    // families that carry `d` label it differently, because the compression
    // pair DISCARDS down to d bits while the packing pair STORES in d bits
    // losing nothing. Reading "bits kept" on an encoder would imply a loss that
    // is not happening there. So: no extra param, "Bits kept (d)", "Bits per
    // coeff (d)", "Noise η".
    expect(seen.size).toBe(4);
    expect([...seen].filter((s) => s.includes("Bits kept (d)"))).toHaveLength(1);
    expect([...seen].filter((s) => s.includes("Bits per coeff (d)"))).toHaveLength(1);
  });
});
