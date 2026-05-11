// @vitest-environment jsdom

/**
 * Component test for MatrixView. Verifies that the read-only display path
 * for byte cells reacts to the global format toggle. Without this, only
 * editable cells (ByteCellInput) would update on format change while the
 * main matrix display stayed stuck in hex.
 */

import { matrixFromBytes } from "@/core/state/matrix";
import { MatrixView } from "@/ui/components/MatrixView";
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const sampleMatrix = () =>
  matrixFromBytes(
    new Uint8Array([
      0x00, 0x41, 0xff, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
      0x2b,
    ]),
  );

describe("MatrixView — format-aware cell rendering", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders cells in hex by default (the canonical crypto convention)", () => {
    const m = sampleMatrix();
    const { container } = render(() => <MatrixView before={m} after={m} />);
    const cells = container.querySelectorAll(".cell");
    // 16 cells × 2 grids = 32 cells total.
    expect(cells.length).toBe(32);
    // First cell of the "before" grid is byte 0 = 0x00 → "00".
    expect(cells[0]?.textContent).toBe("00");
    // 0xff renders as "ff".
    expect(Array.from(cells).some((c) => c.textContent === "ff")).toBe(true);
  });

  it("re-renders cells when the format toggles to decimal", () => {
    const m = sampleMatrix();
    const { container } = render(() => <MatrixView before={m} after={m} />);
    setByteFormat("decimal");
    const cells = container.querySelectorAll(".cell");
    // 0x00 → "0", 0xff → "255".
    expect(cells[0]?.textContent).toBe("0");
    expect(Array.from(cells).some((c) => c.textContent === "255")).toBe(true);
  });

  it("re-renders cells in ASCII (printable chars literal, escapes for the rest)", () => {
    const m = sampleMatrix();
    const { container } = render(() => <MatrixView before={m} after={m} />);
    setByteFormat("ascii");
    const cells = container.querySelectorAll(".cell");
    // 0x00 → "\x00" (4 chars), 0x41 → "A".
    expect(cells[0]?.textContent).toBe("\\x00");
    expect(Array.from(cells).some((c) => c.textContent === "A")).toBe(true);
  });

  it("highlights cells that changed between before and after states", () => {
    const before = matrixFromBytes(new Uint8Array(16));
    const afterBytes = new Uint8Array(16);
    afterBytes[0] = 0xff; // Only byte 0 differs.
    const after = matrixFromBytes(afterBytes);
    const { container } = render(() => <MatrixView before={before} after={after} />);

    // The "after" grid is the second .grid-block in the view; its cell 0
    // should carry the .changed class.
    const grids = container.querySelectorAll(".grid-block");
    expect(grids.length).toBe(2);
    const afterCells = grids[1]?.querySelectorAll(".cell") ?? [];
    expect(afterCells[0]?.classList.contains("changed")).toBe(true);
  });

  // ─── Phase 2b — previous-run overlay rendering ─────────────────────────

  it("renders a third grid when previousAfter is provided", () => {
    const state = sampleMatrix();
    const { container } = render(() => (
      <MatrixView before={state} after={state} previousAfter={state} />
    ));
    const grids = container.querySelectorAll(".grid-block");
    expect(grids.length).toBe(3);
    // Third grid is the previous-run column; its title must say so.
    expect(grids[2]?.querySelector(".grid-title")?.textContent).toBe("previous run");
  });

  it("omits the previous-run grid when previousAfter is null", () => {
    const state = sampleMatrix();
    const { container } = render(() => (
      <MatrixView before={state} after={state} previousAfter={null} />
    ));
    expect(container.querySelectorAll(".grid-block").length).toBe(2);
  });

  it("rings cells in the previous-run grid whose value differs from current after", () => {
    const after = matrixFromBytes(new Uint8Array(16)); // all zeros
    const prevBytes = new Uint8Array(16);
    prevBytes[0] = 0xab; // byte 0 differs from current after
    const previousAfter = matrixFromBytes(prevBytes);
    const { container } = render(() => (
      <MatrixView before={after} after={after} previousAfter={previousAfter} />
    ));
    const grids = container.querySelectorAll(".grid-block");
    expect(grids.length).toBe(3);
    const prevCells = grids[2]?.querySelectorAll(".cell") ?? [];
    // First cell of the previous-run grid (byte 0) differs → diff-vs-prev.
    expect(prevCells[0]?.classList.contains("diff-vs-prev")).toBe(true);
    // Other cells match (all zeros) → no ring.
    expect(prevCells[1]?.classList.contains("diff-vs-prev")).toBe(false);
  });
});
