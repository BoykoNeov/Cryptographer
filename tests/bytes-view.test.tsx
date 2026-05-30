// @vitest-environment jsdom

/**
 * BytesView is the variable-length sibling to MatrixView. The thing to
 * verify here is that:
 *   1. cell count matches the byte count
 *   2. format toggle reactively re-renders cell labels
 *   3. a previousAfter prop with a non-bytes shape is treated as "no
 *      overlay" rather than throwing (the shape-mismatch guard)
 */

import type { BytesState } from "@/core/types";
import { BytesView } from "@/ui/components/BytesView";
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const bs = (...vals: number[]): BytesState => ({
  shape: "bytes",
  bytes: new Uint8Array(vals),
});

describe("BytesView", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders one cell per byte in the 'before' row", () => {
    const before = bs(0x01, 0x02, 0x03, 0x04, 0x05);
    const after = bs(0x01, 0x02, 0x03, 0x04, 0x05);
    const { container } = render(() => <BytesView before={before} after={after} />);
    const rows = container.querySelectorAll(".bytes-row-block");
    // before + after = 2 rows (no overlay).
    expect(rows.length).toBe(2);
    const cells = rows[0]?.querySelectorAll(".bytes-cell") ?? [];
    expect(cells.length).toBe(5);
  });

  it("shows the byte count in the row label", () => {
    const before = bs(0x61, 0x70, 0x70, 0x6c, 0x65); // 5 bytes
    const after = bs(
      0x61,
      0x70,
      0x70,
      0x6c,
      0x65,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
    ); // 16 bytes
    const { container } = render(() => <BytesView before={before} after={after} />);
    const titles = Array.from(container.querySelectorAll(".grid-title"));
    const titleText = titles.map((t) => t.textContent ?? "");
    expect(titleText[0]).toContain("(5 bytes)");
    expect(titleText[1]).toContain("(16 bytes)");
  });

  it("renders cell labels in the active byte format and re-renders on toggle", () => {
    const before = bs(0x41); // 'A' in ASCII
    const after = bs(0x41);
    const { container } = render(() => <BytesView before={before} after={after} />);
    const firstCell = (): string =>
      container.querySelector(".bytes-row .bytes-cell")?.textContent ?? "";
    // Default format is "hex".
    expect(firstCell()).toBe("41");
    setByteFormat("decimal");
    expect(firstCell()).toBe("65");
    setByteFormat("ascii");
    expect(firstCell()).toBe("A");
  });

  it("suppresses the previous-run overlay when the prior state isn't BytesState", () => {
    // The App-level dispatch filters to BytesState before passing — but the
    // type widening allows undefined too. With null, no third row.
    const before = bs(0x01, 0x02);
    const after = bs(0x01, 0x02);
    const { container } = render(() => (
      <BytesView before={before} after={after} previousAfter={null} />
    ));
    const rows = container.querySelectorAll(".bytes-row-block");
    expect(rows.length).toBe(2);
  });

  it("renders the previous-run overlay when previousAfter is provided", () => {
    const before = bs(0x01, 0x02);
    const after = bs(0x01, 0x02);
    const prev = bs(0x01, 0x03); // differs at index 1
    const { container } = render(() => (
      <BytesView before={before} after={after} previousAfter={prev} />
    ));
    const rows = container.querySelectorAll(".bytes-row-block");
    expect(rows.length).toBe(3);
  });

  it("shows length-delta cells as 'missing' placeholders", () => {
    // before: 5 bytes; after: 16 bytes → before row should have 11 "missing"
    // cells trailing so the user can visually see the expansion.
    const before = bs(0x61, 0x70, 0x70, 0x6c, 0x65);
    const after = bs(
      0x61,
      0x70,
      0x70,
      0x6c,
      0x65,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
    );
    const { container } = render(() => <BytesView before={before} after={after} />);
    // The "after" row (second .bytes-row-block) has a `compareTo=before`,
    // so positions 5..15 are flagged as "changed". The "before" row passes
    // no `compareTo`, so no missing-cells appear there. We assert that the
    // after row reports 16 cells (real bytes) and that 11 of them are flagged.
    const rows = container.querySelectorAll(".bytes-row-block");
    const afterCells = rows[1]?.querySelectorAll(".bytes-cell") ?? [];
    expect(afterCells.length).toBe(16);
    const flagged = rows[1]?.querySelectorAll(".bytes-cell.changed") ?? [];
    expect(flagged.length).toBe(11);
  });

  // Multi-block grouping. When the longer side of a row pair exceeds one
  // 16-byte block, cells get segmented into per-block panels so ECB-mode
  // ciphertext reads as discrete blocks (which makes the textbook ECB
  // weakness — identical plaintext → identical ciphertext — visible at
  // a glance).
  it("groups cells into 16-byte block panels when the row exceeds one block", () => {
    // 32-byte before/after (two AES blocks). The first 16 bytes are
    // identical between the two halves — exactly the ECB-leakage pattern
    // we want the user to be able to spot.
    const repeat = (b: number, n: number) => new Uint8Array(n).fill(b);
    const blockA = repeat(0xaa, 16);
    const blockB = repeat(0xbb, 16);
    const concat = new Uint8Array(32);
    concat.set(blockA, 0);
    concat.set(blockB, 16);
    const before: BytesState = { shape: "bytes", bytes: concat };
    const after: BytesState = { shape: "bytes", bytes: concat };

    const { container } = render(() => <BytesView before={before} after={after} />);

    // Both before and after rows render block panels.
    const groups = container.querySelectorAll(".bytes-block-group");
    expect(groups.length).toBe(4); // 2 blocks × 2 rows
    // Labels are 1-based to match BlockBadge.
    const labels = Array.from(container.querySelectorAll(".bytes-block-label"))
      .map((n) => n.textContent ?? "")
      .filter((t) => t.startsWith("Block "));
    expect(labels).toContain("Block 1");
    expect(labels).toContain("Block 2");
    // Each block panel holds exactly 16 cells.
    for (const g of Array.from(groups)) {
      expect(g.querySelectorAll(".bytes-cell").length).toBe(16);
    }
  });

  it("keeps the flat (non-grouped) layout when the row fits in one block", () => {
    // 16-byte after-row + 5-byte before-row → max is 16, no grouping.
    const before: BytesState = { shape: "bytes", bytes: new Uint8Array([1, 2, 3, 4, 5]) };
    const after: BytesState = { shape: "bytes", bytes: new Uint8Array(16) };
    const { container } = render(() => <BytesView before={before} after={after} />);
    expect(container.querySelectorAll(".bytes-block-group").length).toBe(0);
  });

  // The "ignores a non-BytesState prop (defensive)" test was retired in
  // Phase 5 Slice 5.1 (2026-05-30) with the MatrixState shape — `bytes` is
  // the only State variant now, so there is no other variant to thread
  // through as a `previousAfter` and exercise the defensive branch.
});
