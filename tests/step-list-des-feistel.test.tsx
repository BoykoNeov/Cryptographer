// @vitest-environment jsdom

/**
 * Regression test for the StepList crash on DES.
 *
 * Before Phase 5-pre of `docs/plans/des-feistel.md`, `StepList`'s `NodeRow`
 * dispatched only between `step` (LeafRow) and "everything else" (GroupRow).
 * A `feistel-round` node fell into the GroupRow branch and GroupRow accessed
 * `props.node.children.length` unconditionally. `FeistelRoundGroup` exposes
 * `.tracks`, not `.children`, so the render threw `TypeError: Cannot read
 * properties of undefined (reading 'length')` the moment the user picked
 * DES and scrubbed into a round body (which auto-expanded the "rounds"
 * group, causing each `feistel-round` child to render as a GroupRow).
 *
 * The fix adds a `FeistelRow` branch in NodeRow that walks `.tracks[]` and
 * renders each track as a labeled "L track" / "R track" sub-group. This
 * test pins:
 *   - StepList renders without throwing when the active frame is inside
 *     a round body (the broken-before scenario).
 *   - The round container row appears (label "Round 1").
 *   - The track sub-rows appear (labels "L track", "R track").
 *   - The R-track leaves (DES's F-function: expand-R, xor-K, s-boxes,
 *     p-permute) render as clickable buttons.
 *   - The empty L-track shows a "(passthrough — no steps)" hint.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { StepList } from "@/ui/components/StepList";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setFrame, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// FIPS 46-3 Appendix B test vector — same as `tests/des-vectors.test.ts`.
const DES_PT = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
const DES_KEY = new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]);

const seedDesTrace = () => {
  setCipher("des");
  const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: DES_PT },
    initialAux: new Map([["key", DES_KEY]]),
  });
  setTrace(trace);
  return trace;
};

const resetAll = (): void => {
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
};

describe("StepList — DES feistel-round rendering", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders without throwing when the active frame is inside a round R-track", () => {
    const trace = seedDesTrace();
    const rTrackFrameIdx = trace.frames.findIndex((f) => f.stepId.startsWith("round.1.expand-R"));
    expect(rTrackFrameIdx).toBeGreaterThan(-1);
    setFrame(rTrackFrameIdx);
    // The exact assertion: render does not throw. Before Phase 5-pre this
    // threw TypeError inside GroupRow on the first feistel-round child.
    expect(() => render(() => <StepList />)).not.toThrow();
  });

  it("renders the round container and its L / R track sub-rows when expanded", () => {
    const trace = seedDesTrace();
    // Scrub into round 1's R track so "rounds" + "round.1" + "R track"
    // all auto-expand on initial render.
    const rTrackFrameIdx = trace.frames.findIndex((f) => f.stepId.startsWith("round.1.expand-R"));
    setFrame(rTrackFrameIdx);
    const { container } = render(() => <StepList />);
    const text = container.textContent ?? "";
    expect(text).toContain("Round 1");
    expect(text).toContain("L track");
    expect(text).toContain("R track");
  });

  it("renders the R-track F-function leaves as clickable rows", () => {
    const trace = seedDesTrace();
    const rTrackFrameIdx = trace.frames.findIndex((f) => f.stepId.startsWith("round.1.expand-R"));
    setFrame(rTrackFrameIdx);
    const { container } = render(() => <StepList />);
    const buttons = Array.from(container.querySelectorAll("button"));
    // The four DES F-function leaves all live in round 1's R track.
    const titlesOfLeafButtons = buttons
      .filter((b) => b.classList.contains("step-row"))
      .map((b) => b.getAttribute("title") ?? "");
    expect(titlesOfLeafButtons.some((t) => t.startsWith("round.1.expand-R\n"))).toBe(true);
    expect(titlesOfLeafButtons.some((t) => t.startsWith("round.1.xor-K\n"))).toBe(true);
    expect(titlesOfLeafButtons.some((t) => t.startsWith("round.1.s-boxes\n"))).toBe(true);
    expect(titlesOfLeafButtons.some((t) => t.startsWith("round.1.p-permute\n"))).toBe(true);
  });

  it("renders the passthrough hint for the empty L track", () => {
    const trace = seedDesTrace();
    const rTrackFrameIdx = trace.frames.findIndex((f) => f.stepId.startsWith("round.1.expand-R"));
    setFrame(rTrackFrameIdx);
    const { container } = render(() => <StepList />);
    // L track has no children in DES — the FeistelTrackRow renders a
    // "passthrough" hint instead of an empty <For>.
    expect(container.querySelector(".step-row-passthrough")?.textContent ?? "").toContain(
      "passthrough",
    );
  });
});
