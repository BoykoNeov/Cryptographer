// @vitest-environment jsdom

/**
 * `FeistelMiniDiagram` smoke — retargeted to the toy Feistel fixture in B4
 * (universal-port Phase 4d). After the DES rebuild no SHIPPED cipher uses
 * the `feistel-round` primitive, so this component is app-unreachable and
 * Phase-5-doomed (a port-native Feistel/swap diagram is the obligatory
 * rebuild follow-up). It remains in the tree until Phase 5, and the
 * cipher-agnostic component (it derives structure from R-track children +
 * the combine kind, not from DES specifics) is exercised here against
 * `FEISTEL_TOY_SPEC` — the only surviving `feistel-round` construct.
 *
 * Toy shape (see `src/ciphers/feistel-toy.ts`): 2 rounds, each R-track has
 * ONE leaf (`add-k`); round 1 = `feistel-standard`, round 2 =
 * `feistel-no-swap`. So this smoke keeps everything the toy supports
 * (render gate, SVG, leaf count = 1, active-leaf class, click-scrub, both
 * combine kinds) and DROPS the DES-only assertions (the 4 named F-leaves
 * and the K_i cross-reference labels — the toy F uses a param `k`, no
 * `roundKeyAux`).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { runSpec } from "@/core/runtime";
import type { TraceFrame } from "@/core/types";
import { FeistelMiniDiagram } from "@/ui/components/FeistelMiniDiagram";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, __setSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace, useFrameIndex } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const TOY_PT = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
};

type SeedResult = {
  round1AddK: TraceFrame; // R-track body frame, round 1 (feistel-standard)
  round2AddK: TraceFrame; // R-track body frame, round 2 (feistel-no-swap)
  rejoinFrame: TraceFrame; // round.1:rejoin — no branchPath (root-scope)
  traceFrames: readonly TraceFrame[];
};

const seed = (): SeedResult => {
  __setSpecForTests(FEISTEL_TOY_SPEC);
  const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: TOY_PT },
  });
  setTrace(trace);
  const round1AddK = trace.frames.find((f) => f.stepId.startsWith("round.1.add-k"));
  const round2AddK = trace.frames.find((f) => f.stepId.startsWith("round.2.add-k"));
  const rejoinFrame = trace.frames.find((f) => f.stepId === "round.1:rejoin");
  if (!round1AddK || !round2AddK || !rejoinFrame) {
    throw new Error("expected toy frames missing from seed");
  }
  return { round1AddK, round2AddK, rejoinFrame, traceFrames: trace.frames };
};

describe("FeistelMiniDiagram — toy Feistel", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing on root-scope frames (no branchPath)", () => {
    const { rejoinFrame } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={rejoinFrame} />);
    expect(container.querySelector(".feistel-mini-diagram")).toBeNull();
  });

  it("renders the SVG and shows the combine kind in the header", () => {
    const { round1AddK } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round1AddK} />);
    const wrapper = container.querySelector(".feistel-mini-diagram");
    expect(wrapper).not.toBeNull();
    expect(container.querySelector("svg.feistel-mini-diagram-svg")).not.toBeNull();
    expect(wrapper?.textContent ?? "").toContain("feistel-standard");
  });

  it("F-stack has exactly 1 leaf for the toy (add-k)", () => {
    const { round1AddK } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round1AddK} />);
    const leafGroups = container.querySelectorAll(".feistel-mini-diagram-leaf-group");
    expect(leafGroups.length).toBe(1);
    const labels = Array.from(container.querySelectorAll(".feistel-mini-diagram-leaf-label")).map(
      (el) => el.textContent ?? "",
    );
    expect(labels).toEqual(["add-k"]);
  });

  it("active frame's leaf has .feistel-mini-diagram-leaf-active", () => {
    const { round1AddK } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round1AddK} />);
    const activeGroups = container.querySelectorAll(".feistel-mini-diagram-leaf-active");
    expect(activeGroups.length).toBe(1);
    const label = activeGroups[0]?.querySelector(".feistel-mini-diagram-leaf-label")?.textContent;
    expect(label).toBe("add-k");
  });

  it("clicking a leaf scrubs the trace to its frame", () => {
    const { round1AddK, traceFrames } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round1AddK} />);
    const leaf = container.querySelector(".feistel-mini-diagram-leaf-group");
    if (!leaf) throw new Error("add-k leaf missing");
    fireEvent.click(leaf);
    const expectedIdx = traceFrames.findIndex((f) => f.stepId.startsWith("round.1.add-k"));
    expect(useFrameIndex()()).toBe(expectedIdx);
  });

  it("round 2 (feistel-no-swap) renders the swapped output labels", () => {
    const { round2AddK } = seed();
    const { container } = render(() => <FeistelMiniDiagram frame={round2AddK} />);
    expect(container.textContent).toContain("feistel-no-swap");
    // Output labels for feistel-no-swap: leftLabel = "L⊕F", rightLabel = "R".
    // 4 halves: L, R (top inputs); then 2 outputs (the last 2).
    const halfLabels = Array.from(container.querySelectorAll(".feistel-mini-diagram-half-label"));
    expect(halfLabels.length).toBe(4);
    expect(halfLabels[2]?.textContent).toBe("L⊕F");
    expect(halfLabels[3]?.textContent).toBe("R");
  });
});
