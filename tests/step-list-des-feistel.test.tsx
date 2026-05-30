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
import { __resetSpecForTests, __setSpecForTests, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setFrame, setTrace, useFrameIndex } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSyntheticFeistelSpec } from "./fixtures/synthetic-feistel-rounds";

// B4 (universal-port Phase 4d): the port-native DES no longer uses
// `feistel-round`, so StepList's FeistelRow sidebar branch is a surviving
// (Phase-5-doomed) render path with no shipped cipher to exercise it. The
// runnable synthetic Feistel fixture (16 rounds, "Round N" labels, 4-leaf R
// tracks with DES-style ids, runnable via feistel.toy-add-k) drives it.
const TOY_BLOCK = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

const seedDesTrace = () => {
  __setSpecForTests(buildSyntheticFeistelSpec(16));
  const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: TOY_BLOCK },
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

  // ─── 2026-05-20 sidebar UX: rejoin row + track auto-expand ──────────

  it("renders a clickable rejoin row inside each expanded round", () => {
    const trace = seedDesTrace();
    const rTrackFrameIdx = trace.frames.findIndex((f) => f.stepId.startsWith("round.1.expand-R"));
    setFrame(rTrackFrameIdx);
    const { container } = render(() => <StepList />);
    // The active-ancestor auto-expand opens round 1 only; only round 1
    // should have its rejoin row mounted in the DOM.
    const rejoinRows = container.querySelectorAll(".feistel-rejoin-row");
    expect(rejoinRows.length).toBe(1);
    const row = rejoinRows[0];
    expect(row?.getAttribute("title")).toContain("round.1:rejoin");
    expect(row?.textContent ?? "").toContain("rejoin");
    expect(row?.textContent ?? "").toContain("⇄");
    // Combine kind appears in the type slot (mirrors how leaf rows show
    // their step type).
    expect(row?.textContent ?? "").toContain("feistel-standard");
  });

  it("clicking the rejoin row scrubs the trace to the round's rejoin frame", () => {
    const trace = seedDesTrace();
    const rTrackFrameIdx = trace.frames.findIndex((f) => f.stepId.startsWith("round.1.expand-R"));
    setFrame(rTrackFrameIdx);
    const { container } = render(() => <StepList />);
    const rejoinRow = container.querySelector(".feistel-rejoin-row");
    if (!rejoinRow) throw new Error("rejoin row missing");
    fireEvent.click(rejoinRow);
    // Expect the scrubber to land on the round.1 rejoin frame.
    const expectedIdx = trace.frames.findIndex((f) => f.stepId === "round.1:rejoin");
    expect(expectedIdx).toBeGreaterThan(-1);
    expect(useFrameIndex()()).toBe(expectedIdx);
  });

  it("scrubbing to a rejoin frame marks the rejoin row active", () => {
    const trace = seedDesTrace();
    const rejoinIdx = trace.frames.findIndex((f) => f.stepId === "round.1:rejoin");
    expect(rejoinIdx).toBeGreaterThan(-1);
    setFrame(rejoinIdx);
    const { container } = render(() => <StepList />);
    const rejoinRow = container.querySelector(".feistel-rejoin-row");
    expect(rejoinRow?.classList.contains("active")).toBe(true);
  });

  it("expanding a round auto-expands its R track (no extra click required)", () => {
    // Active scrubber sits outside any round (on IP) so no round is
    // auto-expanded initially. The user clicks round 5's header to
    // expand it; the R track inside should render its F-stack leaves
    // without requiring a second click on the track header.
    const trace = seedDesTrace();
    const ipIdx = trace.frames.findIndex((f) => f.stepType === "des.initial-permutation@1");
    setFrame(ipIdx);
    const { container } = render(() => <StepList />);

    // No round.5 leaves should be in the DOM initially (rounds collapsed).
    expect(container.textContent ?? "").not.toContain("round.5.expand-R");

    // Expand the "rounds" group first (it's also collapsed since the
    // active step is IP, not inside any round).
    const groupRows = Array.from(container.querySelectorAll(".group-row"));
    const roundsGroup = groupRows.find(
      (r) => r.querySelector(".group-label")?.textContent === "Rounds",
    );
    if (!roundsGroup) throw new Error("rounds group missing");
    fireEvent.click(roundsGroup);

    // Now find the round 5 header and expand it.
    const round5Header = Array.from(container.querySelectorAll(".feistel-round-row")).find(
      (r) => r.querySelector(".group-label")?.textContent === "Round 5",
    );
    if (!round5Header) throw new Error("round 5 header missing");
    fireEvent.click(round5Header);

    // Without the auto-expand fix the R track would render collapsed
    // and round.5.expand-R wouldn't appear. With the fix, both the L
    // passthrough hint AND the R track's leaves should render.
    const titles = Array.from(container.querySelectorAll("button.step-row"))
      .map((b) => b.getAttribute("title") ?? "")
      .filter((t) => t.startsWith("round.5"));
    expect(titles.some((t) => t.startsWith("round.5.expand-R\n"))).toBe(true);
    expect(titles.some((t) => t.startsWith("round.5.xor-K\n"))).toBe(true);
    expect(titles.some((t) => t.startsWith("round.5.s-boxes\n"))).toBe(true);
    expect(titles.some((t) => t.startsWith("round.5.p-permute\n"))).toBe(true);
  });
});
