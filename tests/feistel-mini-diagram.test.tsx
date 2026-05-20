// @vitest-environment jsdom

/**
 * Phase 5b of `docs/plans/des-feistel.md` — `FeistelMiniDiagram` regression.
 *
 * The mini diagram is an abstract SVG showing the Feistel structure
 * (split / F-stack / combine / output) — distinct from the graph view
 * which shows spec topology. This file pins:
 *
 *   - Hidden when frame.branchPath is empty.
 *   - Renders the SVG when inside a Feistel round body.
 *   - The F-stack contains one leaf-rect per R-track leaf (4 for DES).
 *   - The active frame's leaf gets `.feistel-mini-diagram-leaf-active`.
 *   - Clicking a leaf in the F-stack moves the scrubber to that frame.
 *   - Output labels reflect the combine kind (feistel-standard → "R" + "L⊕F";
 *     feistel-no-swap → "L⊕F" + "R").
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { TraceFrame } from "@/core/types";
import { FeistelMiniDiagram } from "@/ui/components/FeistelMiniDiagram";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace, useFrameIndex } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const DES_PT = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
const DES_KEY = new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]);

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
};

type SeedResult = {
  ipFrame: TraceFrame;
  round1ExpandR: TraceFrame;
  round1SBoxes: TraceFrame;
  round16Frame: TraceFrame; // any frame inside round 16 (feistel-no-swap)
  traceFrames: readonly TraceFrame[];
};

const seed = (): SeedResult => {
  setCipher("des");
  const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: DES_PT },
    initialAux: new Map([["key", DES_KEY]]),
  });
  setTrace(trace);
  const ipFrame = trace.frames.find((f) => f.stepType === "des.initial-permutation@1");
  const round1ExpandR = trace.frames.find((f) => f.stepId.startsWith("round.1.expand-R"));
  const round1SBoxes = trace.frames.find((f) => f.stepId.startsWith("round.1.s-boxes"));
  const round16Frame = trace.frames.find((f) => f.stepId.startsWith("round.16.expand-R"));
  if (!ipFrame || !round1ExpandR || !round1SBoxes || !round16Frame) {
    throw new Error("expected frames missing from seed");
  }
  return { ipFrame, round1ExpandR, round1SBoxes, round16Frame, traceFrames: trace.frames };
};

describe("FeistelMiniDiagram — DES", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing on root-scope frames (no branchPath)", () => {
    const { ipFrame } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={ipFrame} />);
    expect(container.querySelector(".feistel-mini-diagram")).toBeNull();
  });

  it("renders the SVG and shows the combine kind in the header", () => {
    const { round1ExpandR } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round1ExpandR} />);
    const wrapper = container.querySelector(".feistel-mini-diagram");
    expect(wrapper).not.toBeNull();
    expect(container.querySelector("svg.feistel-mini-diagram-svg")).not.toBeNull();
    expect(wrapper?.textContent ?? "").toContain("feistel-standard");
  });

  it("F-stack has exactly 4 leaves for DES (expand-R, xor-K, s-boxes, p-permute)", () => {
    const { round1ExpandR } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round1ExpandR} />);
    const leafGroups = container.querySelectorAll(".feistel-mini-diagram-leaf-group");
    expect(leafGroups.length).toBe(4);
    // Verify the leaf labels (last dot-segment of each id).
    const labels = Array.from(container.querySelectorAll(".feistel-mini-diagram-leaf-label")).map(
      (el) => el.textContent ?? "",
    );
    expect(labels).toEqual(["expand-R", "xor-K", "s-boxes", "p-permute"]);
  });

  it("active frame's leaf has .feistel-mini-diagram-leaf-active", () => {
    const { round1SBoxes } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round1SBoxes} />);
    const activeGroups = container.querySelectorAll(".feistel-mini-diagram-leaf-active");
    expect(activeGroups.length).toBe(1);
    // The active group should contain the s-boxes label.
    const label = activeGroups[0]?.querySelector(".feistel-mini-diagram-leaf-label")?.textContent;
    expect(label).toBe("s-boxes");
  });

  it("clicking a non-active leaf scrubs the trace to its frame", () => {
    const { round1ExpandR, traceFrames } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round1ExpandR} />);
    // Click the s-boxes leaf (3rd in the F-stack). Frame index should
    // match the trace's first round.1.s-boxes:tR.
    const leafGroups = Array.from(container.querySelectorAll(".feistel-mini-diagram-leaf-group"));
    const sboxesLeaf = leafGroups[2];
    if (!sboxesLeaf) throw new Error("s-boxes leaf missing");
    fireEvent.click(sboxesLeaf);
    const expectedIdx = traceFrames.findIndex((f) => f.stepId.startsWith("round.1.s-boxes"));
    expect(useFrameIndex()()).toBe(expectedIdx);
  });

  it("round 16 (feistel-no-swap) renders different output labels", () => {
    const { round16Frame } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round16Frame} />);
    // The header reports the kind.
    expect(container.textContent).toContain("feistel-no-swap");
    // Output labels for feistel-no-swap: leftLabel = "L⊕F", rightLabel = "R".
    // Round 1 (feistel-standard) would have the reverse. Collect the two
    // bottom-most half-label texts.
    const halfLabels = Array.from(container.querySelectorAll(".feistel-mini-diagram-half-label"));
    // 4 halves: L, R (top inputs); then 2 outputs. Outputs are the last 2.
    expect(halfLabels.length).toBe(4);
    expect(halfLabels[2]?.textContent).toBe("L⊕F");
    expect(halfLabels[3]?.textContent).toBe("R");
  });
});
