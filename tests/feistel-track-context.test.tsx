// @vitest-environment jsdom

/**
 * Phase 5a of `docs/plans/des-feistel.md` — `FeistelTrackContext` panel.
 *
 * The panel renders when the active frame's `branchPath` is non-empty
 * (i.e. inside a feistel-round body) and otherwise stays hidden. It
 * reconstructs the round's L_in / R_in from the rejoin frame's stashed
 * params (Phase 5c runtime change) and the round's outputs from
 * `rejoin.stateAfter` split at L_in.length.
 *
 * Pins:
 *   - Hidden when frame.branchPath is empty (root-scope frames: IP,
 *     FP, key-schedule).
 *   - Renders when frame.branchPath has an entry (DES R-track leaves).
 *   - Round entry / Right now / Round output sections all appear.
 *   - The current track's row carries `.feistel-context-track-current`
 *     while the other track's row does not.
 *   - The round id matches the spec (round.N for DES).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { TraceFrame } from "@/core/types";
import { FeistelTrackContext } from "@/ui/components/FeistelTrackContext";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetProvenanceHoverForTests, setProvenanceHover } from "@/ui/stores/provenance-hover";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
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
  __resetProvenanceHoverForTests();
};

type SeedResult = {
  ipFrame: TraceFrame; // root scope, no branchPath
  rTrackFrame: TraceFrame; // inside round 1 R track
};

const seed = (): SeedResult => {
  setCipher("des");
  const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: DES_PT },
    initialAux: new Map([["key", DES_KEY]]),
  });
  setTrace(trace);
  const ipFrame = trace.frames.find((f) => f.stepType === "des.initial-permutation@1");
  const rTrackFrame = trace.frames.find((f) => f.stepId.startsWith("round.1.expand-R"));
  if (!ipFrame || !rTrackFrame) throw new Error("expected frames missing from seed");
  return { ipFrame, rTrackFrame };
};

describe("FeistelTrackContext — DES rendering", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing when frame.branchPath is empty (root-scope IP frame)", () => {
    const { ipFrame } = seed();
    expect(ipFrame.branchPath).toBeUndefined();
    const { container } = render(() => <FeistelTrackContext frame={ipFrame} />);
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
    // Round entry has L + R rows. The R row (current track) should be
    // flagged; the L row should NOT be.
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

describe("FeistelTrackContext — cross-panel provenance overlay (Phase 5a polish)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  // Helper: pick the round-entry section's R row (the current-track row
  // when the active frame is inside the R track) and return its byte
  // cells. The round-entry section is the first `.feistel-context-section`;
  // L row is row 0, R row is row 1.
  const getRoundEntryRCells = (container: HTMLElement): NodeListOf<Element> => {
    const entrySection = container.querySelectorAll(".feistel-context-section")[0];
    if (!entrySection) throw new Error("round entry section missing");
    const rRow = entrySection.querySelectorAll(".feistel-context-track-row")[1];
    if (!rRow) throw new Error("R row missing");
    return rRow.querySelectorAll(".key-schedule-byte-cell");
  };

  // Helper: pick the "right now" section's single track row and return
  // its byte cells. "right now" is the second `.feistel-context-section`.
  const getRightNowCells = (container: HTMLElement): NodeListOf<Element> => {
    const nowSection = container.querySelectorAll(".feistel-context-section")[1];
    if (!nowSection) throw new Error("right now section missing");
    return nowSection.querySelectorAll(".key-schedule-byte-cell");
  };

  it("highlights R_in cells when hover targets the FIRST track step (expand-R)", () => {
    const { rTrackFrame } = seed();
    // expand-R is the first leaf in the R track; stateBefore is the
    // round's R_in by construction, so before-cell indices map 1:1 to
    // round-entry R cells.
    expect(rTrackFrame.stepId.startsWith("round.1.expand-R")).toBe(true);

    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);

    // Seed a hover that names "before-cell" indices 0 and 2. Per the
    // jsdom-pointer-events feedback, we set the signal directly rather
    // than simulating a mouseenter that wouldn't propagate through
    // CSS pointer-events anyway.
    setProvenanceHover({
      stepId: rTrackFrame.stepId,
      afterCellIndex: 0,
      sources: [
        { kind: "before-cell", index: 0 },
        { kind: "before-cell", index: 2 },
      ],
    });

    const rCells = getRoundEntryRCells(container);
    expect(rCells.length).toBe(4); // DES R-track sees a 4-byte R_in
    expect(rCells[0]?.classList.contains("provenance-source")).toBe(true);
    expect(rCells[1]?.classList.contains("provenance-source")).toBe(false);
    expect(rCells[2]?.classList.contains("provenance-source")).toBe(true);
    expect(rCells[3]?.classList.contains("provenance-source")).toBe(false);
  });

  it("does NOT highlight R_in cells when hover targets a LATER track step (s-boxes)", () => {
    setCipher("des");
    const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: DES_PT },
      initialAux: new Map([["key", DES_KEY]]),
    });
    setTrace(trace);
    // s-boxes is a later track step: its stateBefore is the 6-byte
    // E(R)⊕K_i, NOT the round's 4-byte R_in. Even with a valid hover,
    // the round-entry row stays clean — transitive provenance through
    // prior track leaves is out of scope.
    const sboxesFrame = trace.frames.find((f) => f.stepId.startsWith("round.1.s-boxes"));
    if (!sboxesFrame) throw new Error("s-boxes frame missing");

    const { container } = render(() => <FeistelTrackContext frame={sboxesFrame} />);
    setProvenanceHover({
      stepId: sboxesFrame.stepId,
      afterCellIndex: 0,
      sources: [
        { kind: "before-cell", index: 0 },
        { kind: "before-cell", index: 1 },
      ],
    });

    const rCells = getRoundEntryRCells(container);
    for (const cell of Array.from(rCells)) {
      expect(cell.classList.contains("provenance-source")).toBe(false);
    }
  });

  it("ignores a hover whose stepId does not match the active frame", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    // Stale hover from a prior frame — different stepId. Must not paint.
    setProvenanceHover({
      stepId: "round.5.expand-R:tR",
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
    // Expand-R writes a 6-byte stateAfter. Hover its cell 4.
    setProvenanceHover({
      stepId: rTrackFrame.stepId,
      afterCellIndex: 4,
      sources: [{ kind: "before-cell", index: 3 }],
    });
    const nowCells = getRightNowCells(container);
    expect(nowCells.length).toBe(6);
    // Cells other than index 4 are unhighlighted.
    for (let i = 0; i < nowCells.length; i++) {
      const expected = i === 4;
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
