// @vitest-environment jsdom

/**
 * The MINSTD multiplier and modulus are editable FROM THE APP.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY THIS FILE EXISTS, AND WHAT `tests/lcg-kat.test.ts` CANNOT COVER.
 *
 * The KAT already proves the constants are live *in the runtime*: it rewrites a
 * `constant-load@1` leaf's `bytes` on a spec object and asserts the stream
 * changes to match. That is a real and necessary check, and it is **not** the
 * claim the project makes about this cipher.
 *
 * The claim — in the README, the CHANGELOG, the plan and the step's own
 * narration — is that a *learner* can set `a = 1` and watch the generator stop
 * generating. Between those two statements sits `ParamEditor`, and it very
 * nearly broke the claim: `ConstantLoadBlock` rendered every constant as a
 * read-only `<pre>` hex dump, locked on a rationale that named SHA-256's
 * 256-byte K table. Under that block the KAT stayed green, the runtime stayed
 * correct, and the advertised experiment was unreachable.
 *
 * Nothing type-checks a promise made in prose. This file is the guard: it drives
 * the real editor component and asserts the edit reaches the spec, so the lock
 * cannot be reinstated (or the block replaced) without a failure that names the
 * behaviour rather than the implementation.
 *
 * The width branch is asserted in BOTH directions, because the SHA-256
 * reasoning is still correct and must survive: small constants edit, large
 * published tables stay locked.
 */

import { MCG_ITERATE_ID, MCG_MODULUS_ID, MCG_MULTIPLIER_ID } from "@/ciphers/lcg";
import { findStep } from "@/core/spec-mutations";
import type { Json, StepLeaf, StepNode } from "@/core/types";
import { ParamEditor } from "@/ui/components/ParamEditor";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetSpecForTests, setCipher, setPrng, useSpec } from "@/ui/stores/spec";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

/** `params` is `Json`, so reaching a leaf's `bytes` array needs the same
 *  through-`unknown` cast the rest of the suite uses. */
const bytesOf = (params: Json | undefined): readonly number[] =>
  (params as unknown as { bytes: readonly number[] }).bytes;

/** The generator body's leaves live inside the iterate, so `findStep` (which
 *  walks the whole tree) is the way to reach them by id. */
const leafBytes = (id: string): readonly number[] =>
  bytesOf((findStep(useSpec()(), id) as StepLeaf).params);

describe("MINSTD — the published constants are editable from the app", () => {
  beforeEach(() => {
    __resetCipherForTests();
    __resetSpecForTests();
    setPrng("minstd-rand0");
  });

  afterEach(() => {
    cleanup();
    __resetCipherForTests();
    __resetSpecForTests();
  });

  it("the multiplier renders as editable byte cells, not a locked hex dump", () => {
    const { container } = render(() => <ParamEditor stepId={MCG_MULTIPLIER_ID} />);
    // The house pattern for a small editable array (KeyExpansionBlock's Rcon).
    const cells = container.querySelectorAll<HTMLInputElement>(".rcon-row input");
    expect(cells.length, "one byte cell per byte of the 4-byte multiplier").toBe(4);
    expect(
      container.querySelector(".param-hex-dump"),
      "a small constant must NOT fall back to the read-only hex dump",
    ).toBeNull();
  });

  it("editing a multiplier byte commits to the spec", () => {
    // 16807 = 0x000041a7. Rewrite the low byte to 0xa8 → 16808.
    expect(leafBytes(MCG_MULTIPLIER_ID)).toEqual([0x00, 0x00, 0x41, 0xa7]);

    const { container } = render(() => <ParamEditor stepId={MCG_MULTIPLIER_ID} />);
    const cells = container.querySelectorAll<HTMLInputElement>(".rcon-row input");
    const low = cells[3] as HTMLInputElement;
    fireEvent.input(low, { target: { value: "a8" } });
    fireEvent.blur(low); // ByteCellInput commits on blur

    expect(leafBytes(MCG_MULTIPLIER_ID), "the edit reached the spec").toEqual([
      0x00, 0x00, 0x41, 0xa8,
    ]);
  });

  it("the modulus is editable too — the other half of the recurrence", () => {
    // Both constants matter pedagogically: swapping the prime modulus for a
    // power of two is what makes the low-bit weakness appear.
    expect(leafBytes(MCG_MODULUS_ID)).toEqual([0x7f, 0xff, 0xff, 0xff]);

    const { container } = render(() => <ParamEditor stepId={MCG_MODULUS_ID} />);
    const cells = container.querySelectorAll<HTMLInputElement>(".rcon-row input");
    expect(cells.length, "one cell per byte of the modulus").toBe(4);

    const high = cells[0] as HTMLInputElement;
    fireEvent.input(high, { target: { value: "80" } });
    fireEvent.blur(high);

    expect(leafBytes(MCG_MODULUS_ID), "modulus is now 2^31, a power of two").toEqual([
      0x80, 0xff, 0xff, 0xff,
    ]);
  });

  it("the edit lands on the leaf inside the iterate, not a same-named sibling", () => {
    // Guards the addressing rather than the editing: these leaves are nested in
    // the generator's iterate, so a mutation helper that only walked top-level
    // steps would silently no-op and every assertion above would still pass on
    // a stale read. Assert the iterate's child is the object that changed.
    const { container } = render(() => <ParamEditor stepId={MCG_MULTIPLIER_ID} />);
    const cell = container.querySelectorAll<HTMLInputElement>(
      ".rcon-row input",
    )[3] as HTMLInputElement;
    fireEvent.input(cell, { target: { value: "03" } });
    fireEvent.blur(cell);

    const iterate = useSpec()().steps.find((n: StepNode) => n.id === MCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    const mult = iterate.children.find(
      (c: StepNode): c is StepLeaf => c.kind === "step" && c.id === MCG_MULTIPLIER_ID,
    );
    expect(bytesOf(mult?.params)).toEqual([0x00, 0x00, 0x41, 0x03]);
  });
});

describe("constant-load@1 — large published tables stay locked", () => {
  beforeEach(() => {
    __resetCipherForTests();
    __resetSpecForTests();
  });

  afterEach(() => {
    cleanup();
    __resetCipherForTests();
    __resetSpecForTests();
  });

  it("Blowfish's 72-byte π P-array seed renders read-only", () => {
    // The original lock's rationale, preserved — but aimed at the constant that
    // actually justifies it. The old comment named SHA-256's "256-byte K table";
    // Slice 2.4's one-constant-per-leaf granularity means no such leaf exists
    // (SHA-256 carries 64 four-byte K leaves). Blowfish's π seed is the single
    // large `constant-load@1` left in the app, and it must stay a hex dump.
    setCipher("blowfish");
    const spec = useSpec()();
    // Find any constant-load leaf wider than the editable threshold.
    const wide: StepLeaf[] = [];
    const walk = (nodes: readonly StepNode[]): void => {
      for (const n of nodes) {
        if (n.kind === "step") {
          if (n.type === "constant-load@1") {
            const b = (n.params as { bytes?: readonly number[] }).bytes ?? [];
            if (b.length > 8) wide.push(n);
          }
        } else if (n.kind === "group" || n.kind === "iterate") {
          walk(n.children);
        }
      }
    };
    walk(spec.steps);
    expect(wide.length, "Blowfish carries the 72-byte π constant-load leaf").toBeGreaterThan(0);

    const { container } = render(() => <ParamEditor stepId={(wide[0] as StepLeaf).id} />);
    expect(
      container.querySelector(".param-hex-dump"),
      "large table keeps the hex dump",
    ).not.toBeNull();
    expect(
      container.querySelectorAll(".rcon-row input").length,
      "large table exposes no byte cells",
    ).toBe(0);
  });
});
