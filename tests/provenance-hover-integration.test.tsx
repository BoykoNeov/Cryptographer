// @vitest-environment jsdom

/**
 * Hover-integration test for Phase 3 provenance overlay. Pins the
 * MatrixView → provenance-hover-store → before-grid + RoundKeyPanel
 * wiring end-to-end against a real AES-128 trace.
 *
 *   1. AES SubBytes: hover an `after` cell → same-index `before` cell
 *      gets `.provenance-source`. Hover-leave clears the highlight.
 *   2. AES ShiftRows: hover an `after` cell → SHIFTED-index `before`
 *      cell gets the highlight (pins the param-driven formula via the
 *      live executor's shifts [0,1,2,3]).
 *   3. AES AddRoundKey: hover an `after` cell → same-index `before`
 *      cell highlights AND same-index cell in the corresponding K_i
 *      of RoundKeyPanel highlights.
 *   4. Hover state is gated by frame.stepId — switching frames clears
 *      stale highlights.
 *   5. SubBytes hover: precedence — when both `.changed` and
 *      `.provenance-source` would apply on the same `before` cell,
 *      `.provenance-source` wins (the cell shouldn't carry both
 *      classes simultaneously).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, BytesState, MatrixState, TraceFrame } from "@/core/types";
import { BytesView } from "@/ui/components/BytesView";
import { MatrixView } from "@/ui/components/MatrixView";
import { RoundKeyPanel } from "@/ui/components/RoundKeyPanel";
import { matrixAes192Spec } from "./fixtures/matrix-aes-192";
import "@/ui/provenance/index"; // side-effect: registers fns
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetProvenanceHoverForTests } from "@/ui/stores/provenance-hover";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Matrix-cell provenance is a MatrixView-path feature (`generic.*` step types
// + MatrixState before/after). Every shipped single-block AES is byte-native as
// of Slice B1.3 — bytes stateAfter and port-native step types — so it no longer
// drives the MatrixView overlay (accepted regression — port-native cell
// provenance is deferred to Slice 2.9c-e). These 6 MatrixView tests therefore
// run on the shared MATRIX AES-192 fixture (`tests/fixtures/matrix-aes-192.ts`),
// hand-built from the still-registered `generic.*` lifted-legacy step types so
// it preserves the exact MatrixView coverage. 24-byte key (FIPS-197 §A.2),
// 16-byte block. The fixture survives to Phase C (when MatrixView provenance
// retires); the byte-native ciphers move to the BytesView path (like the
// Serpent tests below) once 2.9c-e ships.
const AES192_KEY = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const AES192_PT = "6bc1bee22e409f96e93d7e117393172a";

const seedAes192Trace = () => {
  const trace = runSpec(matrixAes192Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(AES192_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES192_KEY)]]),
  });
  setTrace(trace);
  return trace;
};

const findFrameByStepType = (
  trace: ReturnType<typeof seedAes192Trace>,
  predicate: (t: string) => boolean,
) => {
  const f = trace.frames.find((fr) => predicate(fr.stepType));
  if (!f) throw new Error("no matching frame");
  return f;
};

const renderMatrixView = (frame: TraceFrame) =>
  render(() => (
    <MatrixView
      before={frame.stateBefore as MatrixState}
      after={frame.stateAfter as MatrixState}
      frame={frame}
    />
  ));

describe("Provenance hover — MatrixView before-grid receives", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetProvenanceHoverForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetProvenanceHoverForTests();
  });

  it("AES-192 SubBytes: hovering an `after` cell highlights the same-index `before` cell", () => {
    const trace = seedAes192Trace();
    const subBytesFrame = findFrameByStepType(trace, (t) => t === "generic.byte-substitution@1");
    const { container } = renderMatrixView(subBytesFrame);
    const grids = container.querySelectorAll(".grid-block");
    expect(grids.length).toBe(2);
    const beforeCells = grids[0]?.querySelectorAll(".cell") ?? [];
    const afterCells = grids[1]?.querySelectorAll(".cell") ?? [];
    expect(afterCells.length).toBe(16);

    // Find the `after` cell at linear index 5 by data-grid position.
    // The grid is row + 4*col; cell index 5 means row 1, col 1 (since
    // 5 = 1 + 4*1). The DOM order from `For` matches the cells() array
    // order which iterates col-then-row, so index 5 IS the 6th cell.
    fireEvent.mouseEnter(afterCells[5] as Element);
    // After hover, before-cells[5] should carry `.provenance-source`.
    expect(beforeCells[5]?.classList.contains("provenance-source")).toBe(true);
    // No other before-cells should carry it.
    let othersWithClass = 0;
    for (let i = 0; i < 16; i++) {
      if (i !== 5 && beforeCells[i]?.classList.contains("provenance-source")) othersWithClass++;
    }
    expect(othersWithClass).toBe(0);

    // mouseLeave clears the highlight.
    fireEvent.mouseLeave(afterCells[5] as Element);
    expect(beforeCells[5]?.classList.contains("provenance-source")).toBe(false);
  });

  it("AES-192 ShiftRows: hovering an `after` cell highlights the SHIFTED-index `before` cell", () => {
    const trace = seedAes192Trace();
    const shiftRowsFrame = findFrameByStepType(trace, (t) => t === "generic.shift-rows@1");
    const { container } = renderMatrixView(shiftRowsFrame);
    const grids = container.querySelectorAll(".grid-block");
    const beforeCells = grids[0]?.querySelectorAll(".cell") ?? [];
    const afterCells = grids[1]?.querySelectorAll(".cell") ?? [];

    // Hover after[1+4*0] = row 1, col 0. Forward shifts[1]=1 → source
    // is row 1, col (0+1) mod 4 = 1, so before[1+4*1] = before[5].
    fireEvent.mouseEnter(afterCells[1] as Element);
    expect(beforeCells[5]?.classList.contains("provenance-source")).toBe(true);
    expect(beforeCells[1]?.classList.contains("provenance-source")).toBe(false);
  });

  it("AES-192 MixColumns: hovering an `after` cell renders coefficient labels on the 4 source cells", () => {
    // Regression guard for the MatrixView label-drop bug discovered
    // during the Phase 3 manual browser smoke (2026-05-18): the consumer
    // built the highlight set as a plain `Set<number>`, throwing away
    // the `.label` field that `aesMixColumnsProvenance` correctly emits.
    // The provenance fn was already pinned by `provenance-aes.test.ts`,
    // but no test covered the DOM render path — only the outline class
    // had a visible assertion. This test pins the rendered label text
    // through to the .provenance-label span inside each source cell.
    const trace = seedAes192Trace();
    const mixColsFrame = findFrameByStepType(trace, (t) => t === "generic.mix-columns@1");
    const { container } = renderMatrixView(mixColsFrame);
    const grids = container.querySelectorAll(".grid-block");
    const beforeCells = grids[0]?.querySelectorAll(".cell") ?? [];
    const afterCells = grids[1]?.querySelectorAll(".cell") ?? [];
    expect(afterCells.length).toBe(16);

    // Hover after-cell at linear index 0 (row 0, col 0). For the
    // canonical AES_MIX_MATRIX = [[02,03,01,01], ...] the four sources
    // in column 0 (indices 0, 1, 2, 3) carry labels:
    //   before[0] × 0x02
    //   before[1] × 0x03
    //   before[2] × 0x01  (identity — no label rendered)
    //   before[3] × 0x01  (identity — no label rendered)
    fireEvent.mouseEnter(afterCells[0] as Element);

    // All four sources outlined.
    expect(beforeCells[0]?.classList.contains("provenance-source")).toBe(true);
    expect(beforeCells[1]?.classList.contains("provenance-source")).toBe(true);
    expect(beforeCells[2]?.classList.contains("provenance-source")).toBe(true);
    expect(beforeCells[3]?.classList.contains("provenance-source")).toBe(true);

    // Coefficient labels rendered on the non-identity sources.
    const label0 = beforeCells[0]?.querySelector(".provenance-label");
    const label1 = beforeCells[1]?.querySelector(".provenance-label");
    expect(label0?.textContent).toBe("× 0x02");
    expect(label1?.textContent).toBe("× 0x03");

    // Identity-coefficient sources are highlighted but carry no label
    // (the "× 0x01" annotation is dropped by the provenance fn to
    // reduce visual noise).
    const label2 = beforeCells[2]?.querySelector(".provenance-label");
    const label3 = beforeCells[3]?.querySelector(".provenance-label");
    expect(label2).toBeNull();
    expect(label3).toBeNull();

    // Cells outside column 0 are neither outlined nor labelled.
    expect(beforeCells[4]?.classList.contains("provenance-source")).toBe(false);
    expect(beforeCells[4]?.querySelector(".provenance-label")).toBeNull();

    // Hover-leave clears both the outline AND the labels.
    fireEvent.mouseLeave(afterCells[0] as Element);
    expect(beforeCells[0]?.querySelector(".provenance-label")).toBeNull();
    expect(beforeCells[1]?.querySelector(".provenance-label")).toBeNull();
  });

  it("does NOT apply both `.changed` and `.provenance-source` to the same cell (precedence)", () => {
    const trace = seedAes192Trace();
    const subBytesFrame = findFrameByStepType(trace, (t) => t === "generic.byte-substitution@1");
    const { container } = renderMatrixView(subBytesFrame);
    const grids = container.querySelectorAll(".grid-block");
    const afterCells = grids[1]?.querySelectorAll(".cell") ?? [];

    // Hover the first `after` cell. SubBytes definitely changed the byte
    // (master key is 00..0f; S[0x00] = 0x63 etc). So after[0] would have
    // `.changed`. Provenance fn returns before-cell at the SAME index
    // (index 0) — and after-cell 0 is what we hovered. The hovered cell
    // itself is in the `after` grid, NOT the `before` grid — so the
    // precedence collision can't fire on the after cell (it's only
    // ever .changed, never .provenance-source by construction).
    //
    // But: the BEFORE cell at index 0 carries the `.provenance-source`
    // when hovered. It does NOT have `.changed` (that's only the after
    // grid). So this test instead pins the inverse claim: the before
    // grid never sees `.changed`, and the after grid never sees
    // `.provenance-source`. A future refactor that flipped the
    // hover-target grid would surface here.
    fireEvent.mouseEnter(afterCells[0] as Element);
    // Hovered after cell never carries `.provenance-source` (it's the
    // source GRID's target, not the receiver).
    expect(afterCells[0]?.classList.contains("provenance-source")).toBe(false);
    // The receiving before cell never carries `.changed` (which is an
    // after-grid-only modifier).
    const beforeCells = grids[0]?.querySelectorAll(".cell") ?? [];
    expect(beforeCells[0]?.classList.contains("changed")).toBe(false);
    expect(beforeCells[0]?.classList.contains("provenance-source")).toBe(true);
  });
});

describe("Provenance hover — RoundKeyPanel highlights aux-cell sources", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetProvenanceHoverForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetProvenanceHoverForTests();
  });

  it("AddRoundKey: hovering an `after` cell highlights the same-index cell of the consumed K_i", () => {
    const trace = seedAes192Trace();
    const addRoundKeyFrame = trace.frames.find(
      (f) => f.stepType === "generic.add-round-key@1" && f.auxRead.has("roundKey.3"),
    );
    expect(addRoundKeyFrame).toBeDefined();
    const frame = addRoundKeyFrame as TraceFrame;

    // Render BOTH MatrixView (where hover originates) and RoundKeyPanel
    // (where the aux-cell highlight lands). They share the
    // provenance-hover signal.
    const matrixDom = renderMatrixView(frame);
    const panelDom = render(() => <RoundKeyPanel frame={frame} />);

    const afterCells =
      matrixDom.container.querySelectorAll(".grid-block")[1]?.querySelectorAll(".cell") ?? [];

    // Hover after[7] — provenance points to before-cell[7] AND
    // roundKey.3[7] (the aux-cell source).
    fireEvent.mouseEnter(afterCells[7] as Element);

    // Find K_3 cell in the round-key panel (its title is "roundKey.3")
    // and check the tiny-cell at index 7 carries .provenance-source.
    const k3 = Array.from(panelDom.container.querySelectorAll<HTMLElement>(".round-key-cell")).find(
      (c) => c.getAttribute("title") === "roundKey.3",
    );
    expect(k3).toBeDefined();
    const k3TinyCells = k3?.querySelectorAll(".tiny-cell") ?? [];
    expect(k3TinyCells.length).toBe(16);
    // Linear index 7 in column-major storage = row 3, col 1. The
    // For loop in TinyMatrix iterates col-then-row, so DOM order index
    // 7 = same linear index 7 by construction.
    expect(k3TinyCells[7]?.classList.contains("provenance-source")).toBe(true);
    // No other K_i lights up.
    const k4 = Array.from(panelDom.container.querySelectorAll<HTMLElement>(".round-key-cell")).find(
      (c) => c.getAttribute("title") === "roundKey.4",
    );
    expect(k4).toBeDefined();
    const k4HasAny =
      Array.from(k4?.querySelectorAll(".tiny-cell") ?? []).some((c) =>
        c.classList.contains("provenance-source"),
      ) ?? false;
    expect(k4HasAny).toBe(false);
  });

  // ─── Serpent BytesView path ────────────────────────────────────────
  // Phase 3 follow-up: Serpent's per-step transformations render via
  // BytesView. Pins that the BytesView wiring fires the registered
  // Serpent provenance fns end-to-end.

  it("Serpent SubBytes (BytesView): hovering an `after` cell highlights the same-index `before` cell", () => {
    const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex("00112233445566778899aabbccddeeff")],
      ]),
    });
    setTrace(trace);
    const subBytesFrame = trace.frames.find((f) => f.stepType === "serpent.sub-bytes@1");
    expect(subBytesFrame).toBeDefined();
    const frame = subBytesFrame as TraceFrame;

    const { container } = render(() => (
      <BytesView
        before={frame.stateBefore as BytesState}
        after={frame.stateAfter as BytesState}
        frame={frame}
      />
    ));
    // Two rows: before (index 0) and after (index 1).
    const rows = container.querySelectorAll(".bytes-row-block");
    expect(rows.length).toBe(2);
    const beforeCells = rows[0]?.querySelectorAll(".bytes-cell") ?? [];
    const afterCells = rows[1]?.querySelectorAll(".bytes-cell") ?? [];
    expect(afterCells.length).toBe(16);

    // Hover after-cell index 9. SubBytes provenance is same-position
    // → before-cell 9 should outline.
    fireEvent.mouseEnter(afterCells[9] as Element);
    expect(beforeCells[9]?.classList.contains("provenance-source")).toBe(true);
    // No other before cells light up.
    let othersWithClass = 0;
    for (let i = 0; i < 16; i++) {
      if (i !== 9 && beforeCells[i]?.classList.contains("provenance-source")) othersWithClass++;
    }
    expect(othersWithClass).toBe(0);

    fireEvent.mouseLeave(afterCells[9] as Element);
    expect(beforeCells[9]?.classList.contains("provenance-source")).toBe(false);
  });

  it("Serpent AddRoundKey (BytesView): hover highlights before-cell AND consumed K_i cell in RoundKeyPanel", () => {
    const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex("00112233445566778899aabbccddeeff")],
      ]),
    });
    setTrace(trace);
    // Serpent's first AddRoundKey reads `roundKey.0` (K_0 → initial
    // whitening before round 0's S-box pass).
    const addRoundKeyFrame = trace.frames.find(
      (f) => f.stepType === "serpent.add-round-key@1" && f.auxRead.has("roundKey.0"),
    );
    expect(addRoundKeyFrame).toBeDefined();
    const frame = addRoundKeyFrame as TraceFrame;

    const bytesDom = render(() => (
      <BytesView
        before={frame.stateBefore as BytesState}
        after={frame.stateAfter as BytesState}
        frame={frame}
      />
    ));
    const panelDom = render(() => <RoundKeyPanel frame={frame} />);

    const afterCells =
      bytesDom.container.querySelectorAll(".bytes-row-block")[1]?.querySelectorAll(".bytes-cell") ??
      [];

    fireEvent.mouseEnter(afterCells[5] as Element);
    // Before-cell at index 5 lights up.
    const beforeCells =
      bytesDom.container.querySelectorAll(".bytes-row-block")[0]?.querySelectorAll(".bytes-cell") ??
      [];
    expect(beforeCells[5]?.classList.contains("provenance-source")).toBe(true);
    // K_0 cell in the panel: linear index 5 highlights.
    const k0 = Array.from(panelDom.container.querySelectorAll<HTMLElement>(".round-key-cell")).find(
      (c) => c.getAttribute("title") === "roundKey.0",
    );
    expect(k0).toBeDefined();
    const k0TinyCells = k0?.querySelectorAll(".tiny-cell") ?? [];
    expect(k0TinyCells.length).toBe(16);
    expect(k0TinyCells[5]?.classList.contains("provenance-source")).toBe(true);
  });

  it("hover for a DIFFERENT frame clears the previous frame's highlights (stepId gate)", () => {
    const trace = seedAes192Trace();
    const subBytesFrame = findFrameByStepType(trace, (t) => t === "generic.byte-substitution@1");
    const addRoundKeyFrame = trace.frames.find(
      (f) => f.stepType === "generic.add-round-key@1" && f.auxRead.has("roundKey.3"),
    );
    expect(addRoundKeyFrame).toBeDefined();

    // Render the round-key panel for the SUB-BYTES frame.
    const panelDom = render(() => <RoundKeyPanel frame={subBytesFrame} />);

    // Simulate hover on a DIFFERENT frame's matrix view — the
    // round-key panel rendered against subBytesFrame should ignore
    // hover sources keyed by the add-round-key frame's stepId.
    const matrixDom = renderMatrixView(addRoundKeyFrame as TraceFrame);
    const afterCells =
      matrixDom.container.querySelectorAll(".grid-block")[1]?.querySelectorAll(".cell") ?? [];
    fireEvent.mouseEnter(afterCells[0] as Element);

    // The round-key panel's K_3 should NOT light up — its frame is
    // the sub-bytes frame, but the hover's stepId is the add-round-key
    // frame.
    const k3 = Array.from(panelDom.container.querySelectorAll<HTMLElement>(".round-key-cell")).find(
      (c) => c.getAttribute("title") === "roundKey.3",
    );
    const k3HasAny =
      Array.from(k3?.querySelectorAll(".tiny-cell") ?? []).some((c) =>
        c.classList.contains("provenance-source"),
      ) ?? false;
    expect(k3HasAny).toBe(false);
  });
});
