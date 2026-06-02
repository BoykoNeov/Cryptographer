// @vitest-environment jsdom

/**
 * Speck round-body α/β/byteOrder editable in-place (Option 2 of the
 * compose-and-save parameterization discussion; plan
 * `~/.claude/plans/floofy-swimming-dream.md`).
 *
 * `SpeckRoundBlock` used to render all five Speck params as read-only `dl`
 * rows. The `speck.round@1` / `speck.round-inverse@1` executors read
 * `alpha`/`beta`/`byteOrder` at run time, so these are free parameters — making
 * them editable is the "what if Speck rotated by 3 instead of 7?" pedagogy.
 * `roundKeyAux` (per-round distinct wiring) and `wordBits` (structural) stay
 * read-only.
 *
 * The load-bearing assertion is the **scoped** apply-to-all: it broadcasts only
 * α/β/byteOrder and must PRESERVE each round's distinct `roundKeyAux`. A naive
 * reuse of the generic `ApplyAllRow` (which copies the whole params object)
 * would point every round at the same key — exactly what this test guards
 * against.
 */

import { findStep } from "@/core/spec-mutations";
import type { StepLeaf, StepNode } from "@/core/types";
import { ParamEditor } from "@/ui/components/ParamEditor";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

type SpeckParams = {
  roundKeyAux: string;
  alpha: number;
  beta: number;
  wordBits: number;
  byteOrder: string;
};

/** Every `speck.round@1` leaf in the active (encrypt) spec, in order. */
const speckRounds = (): StepLeaf[] =>
  useSpec()().steps.filter(
    (n: StepNode): n is StepLeaf => n.kind === "step" && n.type === "speck.round@1",
  );

const paramsOf = (id: string): SpeckParams =>
  (findStep(useSpec()(), id) as StepLeaf).params as SpeckParams;

describe("Speck round-body α/β/byteOrder editable in place", () => {
  beforeEach(() => {
    __resetCipherForTests();
    __resetSpecForTests();
    // be-paper Speck32/64: canonical α=7, β=2 on every round body.
    setCipher("speck-32-64-be");
  });

  afterEach(() => {
    cleanup();
  });

  it("editing α commits to ONLY that round's params (other rounds untouched)", () => {
    const rounds = speckRounds();
    expect(rounds.length, "Speck32/64 has 22 round-body leaves").toBeGreaterThan(1);
    const target = rounds[0] as StepLeaf;

    const { getByDisplayValue } = render(() => <ParamEditor stepId={target.id} />);
    // α is the only input showing "7" (β shows "2"; byteOrder is a <select>).
    const alphaInput = getByDisplayValue("7") as HTMLInputElement;
    fireEvent.input(alphaInput, { target: { value: "3" } });
    fireEvent.blur(alphaInput); // IntInput commits on blur

    expect(paramsOf(target.id).alpha, "edited round's α is now 3").toBe(3);
    for (const r of speckRounds()) {
      if (r.id !== target.id) {
        expect((r.params as SpeckParams).alpha, `round ${r.id} α stays 7`).toBe(7);
      }
    }
  });

  it("byteOrder <select> shows the current value and commits a change", () => {
    const target = speckRounds()[0] as StepLeaf;
    const { container } = render(() => <ParamEditor stepId={target.id} />);

    const select = container.querySelector<HTMLSelectElement>("select.speck-byteorder-select");
    expect(select, "byteOrder select is rendered").not.toBeNull();
    expect(select?.value, "select reflects the spec's current byteOrder").toBe("be-paper");

    fireEvent.change(select as HTMLSelectElement, { target: { value: "le-nsa" } });
    expect(paramsOf(target.id).byteOrder, "byteOrder committed to the spec").toBe("le-nsa");
  });

  it("apply-to-all broadcasts α/β/byteOrder to every round but PRESERVES each round's roundKeyAux", () => {
    const target = speckRounds()[0] as StepLeaf;

    // Snapshot every round's roundKeyAux before; assert they're genuinely
    // distinct (roundKey.0 … roundKey.21) so "preserved distinct wiring" is a
    // real property, not vacuously true.
    const beforeRk = new Map<string, string>();
    for (const r of speckRounds()) beforeRk.set(r.id, (r.params as SpeckParams).roundKeyAux);
    expect(new Set(beforeRk.values()).size, "rounds reference distinct round keys").toBeGreaterThan(
      1,
    );

    const { getByDisplayValue, container } = render(() => <ParamEditor stepId={target.id} />);
    // Diverge α on the viewed round, then broadcast.
    const alphaInput = getByDisplayValue("7") as HTMLInputElement;
    fireEvent.input(alphaInput, { target: { value: "3" } });
    fireEvent.blur(alphaInput);

    const applyBtn = container.querySelector<HTMLButtonElement>(".apply-all-row button");
    expect(applyBtn, "scoped apply-to-all button is present (matchingCount > 1)").not.toBeNull();
    fireEvent.click(applyBtn as HTMLButtonElement);

    for (const r of speckRounds()) {
      const p = r.params as SpeckParams;
      expect(p.alpha, `round ${r.id} got broadcast α`).toBe(3);
      expect(p.beta, `round ${r.id} got broadcast β`).toBe(2);
      expect(p.byteOrder, `round ${r.id} got broadcast byteOrder`).toBe("be-paper");
      expect(p.roundKeyAux, `round ${r.id} KEPT its own round key`).toBe(beforeRk.get(r.id));
    }
  });
});
