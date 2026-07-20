/**
 * ChaCha20 canonical DOUBLE-ROUND layout (`src/core/chacha-layout.ts`).
 *
 * The placement's whole claim is that a 98-leaf ARX group can be read as
 * structure rather than as a ribbon: eight quarter-round blocks, each the RFC's
 * four lines of three operations, in two tiers (column round above diagonal
 * round). These tests pin the geometric properties that claim rests on — that
 * rows really are the RFC's lines, that tiers really are separated, that
 * nothing overlaps and nothing is dropped.
 *
 * What they deliberately do NOT claim to cover: whether it LOOKS right. That is
 * a browser question, and this project has been bitten by exactly that gap
 * before (Twofish's round split scattered into replica chips with ~60 unit
 * tests green). See `tests/chacha-graph-replication.test.ts` for the specific
 * failure mode that bit Twofish, checked here against the real pipeline.
 */

import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import { chachaDoubleRoundPlacement } from "@/core/chacha-layout";
import { type ChaChaDoubleRoundShape, analyzeChaChaDoubleRound } from "@/core/chacha-shape";
import type { StepGroup, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const LEAF = { leafW: 96, leafH: 30 };

const firstRound = (): { shape: ChaChaDoubleRoundShape; group: StepGroup } => {
  let found: { shape: ChaChaDoubleRoundShape; group: StepGroup } | null = null;
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (found) return;
      if (n.kind === "group") {
        const shape = analyzeChaChaDoubleRound(n);
        if (shape) {
          found = { shape, group: n };
          return;
        }
        walk(n.children);
      } else if (n.kind === "iterate") walk(n.children);
    }
  };
  walk(chacha20EncryptSpec.steps);
  if (!found) throw new Error("no ChaCha double round found");
  return found;
};

const childIdsOf = (group: StepGroup): string[] =>
  group.children.filter((c) => c.kind === "step").map((c) => c.id);

describe("chachaDoubleRoundPlacement", () => {
  const { shape, group } = firstRound();
  const childIds = childIdsOf(group);
  const placement = chachaDoubleRoundPlacement(shape, childIds, LEAF);
  const at = (id: string) => placement.offsets.get(id);

  it("places every one of the group's 98 leaves", () => {
    expect(childIds).toHaveLength(98);
    for (const id of childIds) expect(at(id)).toBeDefined();
    expect(placement.offsets.size).toBe(98);
  });

  it("lays each quarter round out as the RFC's four lines of three", () => {
    // Row = one written line of RFC 8439 §2.1; column = position within it.
    // This is the property that makes the block readable as the published text.
    for (const qr of shape.quarterRounds) {
      const ys = qr.ops.map((o) => at(o.nodeId)?.dy);
      const xs = qr.ops.map((o) => at(o.nodeId)?.dx);
      // Ops 0,1,2 share a row; 3,4,5 the next; and so on.
      expect(ys[0]).toBe(ys[1]);
      expect(ys[1]).toBe(ys[2]);
      expect(ys[3]).toBe(ys[4]);
      expect(new Set(ys).size).toBe(4); // exactly four rows
      // Within a row the three ops step rightwards, and each line uses the
      // same three columns.
      expect(new Set(xs).size).toBe(3);
      expect(xs[0]).toBeLessThan(xs[1] as number);
      expect(xs[1]).toBeLessThan(xs[2] as number);
      expect(xs[3]).toBe(xs[0]);
    }
  });

  it("puts the four column quarter rounds above the four diagonal ones", () => {
    // RFC 8439 §2.3.1's structure made visible: the tier boundary is the point
    // where the state has been mixed by columns and is about to be mixed by
    // diagonals.
    const tierTop = (i: number) => at(shape.quarterRounds[i]?.ops[0]?.nodeId as string)?.dy ?? 0;
    const columnTier = [0, 1, 2, 3].map(tierTop);
    const diagonalTier = [4, 5, 6, 7].map(tierTop);
    expect(new Set(columnTier).size).toBe(1); // the four column blocks align
    expect(new Set(diagonalTier).size).toBe(1);
    expect(columnTier[0]).toBeLessThan(diagonalTier[0] as number);
  });

  it("puts the four blocks of a tier side by side, left to right in spec order", () => {
    const leftEdge = (i: number) => at(shape.quarterRounds[i]?.ops[0]?.nodeId as string)?.dx ?? 0;
    for (const tier of [
      [0, 1, 2, 3],
      [4, 5, 6, 7],
    ]) {
      const xs = tier.map(leftEdge);
      expect(xs[0]).toBeLessThan(xs[1] as number);
      expect(xs[1]).toBeLessThan(xs[2] as number);
      expect(xs[2]).toBeLessThan(xs[3] as number);
    }
  });

  it("puts the split above everything and the concat below everything", () => {
    // The honest reading of the group: 64 bytes in, 16 words through the two
    // tiers, 64 bytes out.
    const splitY = at(shape.splitId)?.dy ?? 0;
    const concatY = at(shape.concatId)?.dy ?? 0;
    for (const qr of shape.quarterRounds) {
      for (const op of qr.ops) {
        const y = at(op.nodeId)?.dy ?? 0;
        expect(y).toBeGreaterThan(splitY);
        expect(y).toBeLessThan(concatY);
      }
    }
  });

  it("never overlaps two boxes", () => {
    // The failure this catches is a block-pitch narrower than a block, which
    // would silently stack quarter rounds on top of each other.
    const boxes = [...placement.offsets.values()];
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i] as { dx: number; dy: number };
        const b = boxes[j] as { dx: number; dy: number };
        const overlaps = Math.abs(a.dx - b.dx) < LEAF.leafW && Math.abs(a.dy - b.dy) < LEAF.leafH;
        expect(overlaps).toBe(false);
      }
    }
  });

  it("reports a body extent that contains every placed box", () => {
    for (const o of placement.offsets.values()) {
      expect(o.dx + LEAF.leafW).toBeLessThanOrEqual(placement.bodyW);
      expect(o.dy + LEAF.leafH).toBeLessThanOrEqual(placement.bodyH);
    }
  });

  it("parks an unclassified child rather than dropping it", () => {
    // Defensive path. The partition gate means this shouldn't arise in
    // practice, but a vanished node is the one failure a user cannot diagnose.
    const withExtra = chachaDoubleRoundPlacement(shape, [...childIds, "stray"], LEAF);
    expect(withExtra.offsets.get("stray")).toBeDefined();
  });

  it("is markedly wider than tall — the ribbon it replaces was the opposite", () => {
    // A sanity check on the whole point of the module: 98 leaves stacked
    // vertically is ~98 rows tall and one column wide. The canonical cell is
    // 12 columns wide and 10 rows tall.
    expect(placement.bodyW).toBeGreaterThan(placement.bodyH);
  });
});
