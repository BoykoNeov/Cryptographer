// @vitest-environment jsdom

/**
 * `FeistelTrackContext` panel smoke — retargeted to the toy Feistel fixture
 * in B4 (universal-port Phase 4d). After the DES rebuild no shipped cipher
 * uses `feistel-round`, so this component is app-unreachable + Phase-5-doomed
 * (port-native rebuild is the obligatory follow-up). The component is
 * cipher-agnostic (reconstructs the round from the rejoin frame's stashed
 * params + the active frame's branchPath/path), so it is smoke-tested here
 * against `FEISTEL_TOY_SPEC` — the only surviving `feistel-round` construct.
 *
 * Toy shape: 2 rounds, L = bytes [0,1], R = bytes [2,3] (so R_in / R_out are
 * 2 bytes), one R-track leaf (`add-k`). Assertions adjusted to those counts;
 * the DES-only "later track step keeps round-entry clean" case is dropped
 * (the toy R-track has a single step, so there is no later step to hover).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { runSpec } from "@/core/runtime";
import type { TraceFrame } from "@/core/types";
import { FeistelTrackContext } from "@/ui/components/FeistelTrackContext";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetProvenanceHoverForTests, setProvenanceHover } from "@/ui/stores/provenance-hover";
import { __resetSpecForTests, __setSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const TOY_PT = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
  __resetProvenanceHoverForTests();
};

type SeedResult = {
  rejoinFrame: TraceFrame; // round.1:rejoin — no branchPath (root scope)
  rTrackFrame: TraceFrame; // round.1 add-k — the single R-track leaf
};

const seed = (): SeedResult => {
  __setSpecForTests(FEISTEL_TOY_SPEC);
  const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: TOY_PT },
  });
  setTrace(trace);
  const rejoinFrame = trace.frames.find((f) => f.stepId === "round.1:rejoin");
  const rTrackFrame = trace.frames.find((f) => f.stepId.startsWith("round.1.add-k"));
  if (!rejoinFrame || !rTrackFrame) throw new Error("expected toy frames missing from seed");
  return { rejoinFrame, rTrackFrame };
};

describe("FeistelTrackContext — toy Feistel rendering", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing when frame.branchPath is empty (root-scope rejoin frame)", () => {
    const { rejoinFrame } = seed();
    expect(rejoinFrame.branchPath).toBeUndefined();
    const { container } = render(() => <FeistelTrackContext frame={rejoinFrame} />);
    expect(container.querySelector(".feistel-track-context")).toBeNull();
  });

  it("renders the round context panel when inside an R-track frame", () => {
    const { rTrackFrame } = seed();
    expect(rTrackFrame.branchPath).toEqual(["R"]);
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    const panel = container.querySelector(".feistel-track-context");
    expect(panel).not.toBeNull();
    const text = panel?.textContent ?? "";
    expect(text).toContain("round.1");
    expect(text).toContain("R");
  });

  it("renders all three sections (round entry, right now, round output)", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    const sectionTitles = Array.from(
      container.querySelectorAll(".feistel-context-section-title"),
    ).map((el) => el.textContent ?? "");
    expect(sectionTitles).toEqual(["round entry", "right now", "round output"]);
  });

  it("flags the current track row with .feistel-context-track-current", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    const entrySection = container.querySelectorAll(".feistel-context-section")[0];
    if (!entrySection) throw new Error("round entry section missing");
    const rows = entrySection.querySelectorAll(".feistel-context-track-row");
    expect(rows.length).toBe(2);
    const trackNames = Array.from(rows).map(
      (row) => row.querySelector(".feistel-context-track-name")?.textContent ?? "",
    );
    expect(trackNames).toEqual(["L", "R"]);
    // L (index 0) is not current; R (index 1) is current.
    expect(rows[0]?.classList.contains("feistel-context-track-current")).toBe(false);
    expect(rows[1]?.classList.contains("feistel-context-track-current")).toBe(true);
  });

  it("renders new_L and new_R labels in the round output section", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    const outputSection = container.querySelectorAll(".feistel-context-section")[2];
    if (!outputSection) throw new Error("round output section missing");
    const names = Array.from(outputSection.querySelectorAll(".feistel-context-track-name")).map(
      (el) => el.textContent ?? "",
    );
    expect(names).toEqual(["L'", "R'"]);
  });
});

describe("FeistelTrackContext — cross-panel provenance overlay", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  const getRoundEntryRCells = (container: HTMLElement): NodeListOf<Element> => {
    const entrySection = container.querySelectorAll(".feistel-context-section")[0];
    if (!entrySection) throw new Error("round entry section missing");
    const rRow = entrySection.querySelectorAll(".feistel-context-track-row")[1];
    if (!rRow) throw new Error("R row missing");
    return rRow.querySelectorAll(".key-schedule-byte-cell");
  };

  const getRightNowCells = (container: HTMLElement): NodeListOf<Element> => {
    const nowSection = container.querySelectorAll(".feistel-context-section")[1];
    if (!nowSection) throw new Error("right now section missing");
    return nowSection.querySelectorAll(".key-schedule-byte-cell");
  };

  it("highlights R_in cells when hover targets the FIRST track step (add-k)", () => {
    const { rTrackFrame } = seed();
    // add-k is the (only) R-track leaf; its stateBefore is the round's R_in
    // by construction, so before-cell indices map 1:1 to round-entry R cells.
    expect(rTrackFrame.stepId.startsWith("round.1.add-k")).toBe(true);

    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    // Per the jsdom-pointer-events feedback, set the signal directly.
    setProvenanceHover({
      stepId: rTrackFrame.stepId,
      afterCellIndex: 0,
      sources: [{ kind: "before-cell", index: 0 }],
    });

    const rCells = getRoundEntryRCells(container);
    expect(rCells.length).toBe(2); // toy R-track sees a 2-byte R_in
    expect(rCells[0]?.classList.contains("provenance-source")).toBe(true);
    expect(rCells[1]?.classList.contains("provenance-source")).toBe(false);
  });

  it("ignores a hover whose stepId does not match the active frame", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    // Stale hover from a prior frame — different stepId. Must not paint.
    setProvenanceHover({
      stepId: "round.2.add-k:tR",
      afterCellIndex: 0,
      sources: [{ kind: "before-cell", index: 0 }],
    });
    const rCells = getRoundEntryRCells(container);
    for (const cell of Array.from(rCells)) {
      expect(cell.classList.contains("provenance-source")).toBe(false);
    }
  });

  it("outlines the hovered after-cell in the 'right now' row", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    // add-k writes a 2-byte stateAfter (R_out). Hover its cell 1.
    setProvenanceHover({
      stepId: rTrackFrame.stepId,
      afterCellIndex: 1,
      sources: [{ kind: "before-cell", index: 0 }],
    });
    const nowCells = getRightNowCells(container);
    expect(nowCells.length).toBe(2);
    for (let i = 0; i < nowCells.length; i++) {
      const expected = i === 1;
      expect(nowCells[i]?.classList.contains("provenance-source")).toBe(expected);
    }
  });

  it("clears all highlights when the hover is cleared", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    setProvenanceHover({
      stepId: rTrackFrame.stepId,
      afterCellIndex: 0,
      sources: [{ kind: "before-cell", index: 0 }],
    });
    setProvenanceHover(null);
    const rCells = getRoundEntryRCells(container);
    for (const cell of Array.from(rCells)) {
      expect(cell.classList.contains("provenance-source")).toBe(false);
    }
    const nowCells = getRightNowCells(container);
    for (const cell of Array.from(nowCells)) {
      expect(cell.classList.contains("provenance-source")).toBe(false);
    }
  });
});
