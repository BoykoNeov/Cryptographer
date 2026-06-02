/**
 * Canonical Feistel-round LAYOUT (`src/core/feistel-layout.ts`) — the pure
 * placement math behind the graph view's DES canonical-representation feature.
 *
 * These pin the structural invariants the renderer relies on (NOT exact
 * pixels, which are free to tune): split above everything, the F-stack in a
 * column to the RIGHT of the L rail (fxor), recombine below, and a round-key
 * replica parked right of the F column at its consumer's row.
 */

import { feistelRoundPlacement, feistelSwapWires } from "@/core/feistel-layout";
import type { FeistelRoundShape } from "@/core/feistel-shape";
import { describe, expect, it } from "vitest";

// A DES-shaped round descriptor (the fields `feistelRoundPlacement` reads).
const desRoundShape = (roundId: string): FeistelRoundShape => ({
  roundId,
  splitId: `${roundId}.split`,
  fxorId: `${roundId}.fxor`,
  recombineId: `${roundId}.recombine`,
  fStackIds: [
    `${roundId}.expand-R`,
    `${roundId}.xor-K`,
    `${roundId}.s-boxes`,
    `${roundId}.p-permute`,
  ],
  splitLPort: "output0",
  splitRPort: "output1",
  fxorOutPort: "output",
  fxorFInPort: "operand1",
  recombineOutPort: "output",
  swap: true,
  roundKeyAux: "roundKey.0",
});

const CONSTS = { leafW: 132, leafH: 28 };

describe("feistelRoundPlacement — canonical two-column structure", () => {
  const shape = desRoundShape("round.1");
  const childIds = [
    "round.1.split",
    "round.1.expand-R",
    "round.1.xor-K",
    "round.1.s-boxes",
    "round.1.p-permute",
    "round.1.fxor",
    "round.1.recombine",
  ];
  const place = feistelRoundPlacement(shape, childIds, {
    ...CONSTS,
    isReplica: () => false,
    consumerOf: () => undefined,
  });
  const at = (id: string) => {
    const o = place.offsets.get(id);
    if (!o) throw new Error(`no offset for ${id}`);
    return o;
  };

  it("places every child", () => {
    for (const id of childIds) expect(place.offsets.has(id), id).toBe(true);
  });

  it("stacks the F-function leaves in a single column, in spec order, top-to-bottom", () => {
    const f = shape.fStackIds.map(at);
    // Same x (one column).
    for (const o of f) expect(o.dx).toBe(f[0]?.dx);
    // Strictly increasing y, spec order.
    for (let i = 1; i < f.length; i++) {
      expect(f[i]?.dy).toBeGreaterThan(f[i - 1]?.dy ?? 0);
    }
  });

  it("puts the F column to the RIGHT of the L rail (fxor)", () => {
    expect(at("round.1.expand-R").dx).toBeGreaterThan(at("round.1.fxor").dx);
  });

  it("places split above the F stack and recombine below it", () => {
    const splitY = at("round.1.split").dy;
    const recombineY = at("round.1.recombine").dy;
    for (const id of shape.fStackIds) {
      expect(at(id).dy).toBeGreaterThan(splitY);
      expect(at(id).dy).toBeLessThanOrEqual(recombineY);
    }
    expect(recombineY).toBeGreaterThan(at("round.1.fxor").dy - 1);
  });

  it("levels fxor with the last F-stack leaf (so p-permute → fxor is a short hop)", () => {
    expect(at("round.1.fxor").dy).toBe(at("round.1.p-permute").dy);
  });

  it("centers split and recombine between the L and F columns (same x)", () => {
    expect(at("round.1.split").dx).toBe(at("round.1.recombine").dx);
    expect(at("round.1.split").dx).toBeGreaterThan(at("round.1.fxor").dx);
    expect(at("round.1.split").dx).toBeLessThan(at("round.1.expand-R").dx);
  });
});

describe("feistelRoundPlacement — round-key replica", () => {
  const shape = desRoundShape("round.1");
  const replicaId = "key-schedule.publish@->round.1.xor-K";
  const childIds = [
    "round.1.split",
    "round.1.expand-R",
    "round.1.xor-K",
    "round.1.s-boxes",
    "round.1.p-permute",
    "round.1.fxor",
    "round.1.recombine",
    replicaId,
  ];
  const place = feistelRoundPlacement(shape, childIds, {
    ...CONSTS,
    isReplica: (id) => id === replicaId,
    consumerOf: (id) => (id === replicaId ? "round.1.xor-K" : undefined),
  });

  it("parks the key replica RIGHT of the F column, at its consumer's (xor-K) row", () => {
    const rep = place.offsets.get(replicaId);
    const xorK = place.offsets.get("round.1.xor-K");
    expect(rep).toBeDefined();
    expect(xorK).toBeDefined();
    // Right of the F column.
    expect(rep?.dx).toBeGreaterThan((xorK?.dx ?? 0) + CONSTS.leafW);
    // Same row as xor-K (the key enters the F function there).
    expect(rep?.dy).toBe(xorK?.dy);
  });

  it("grows bodyW to contain the key replica", () => {
    const rep = place.offsets.get(replicaId);
    expect(place.bodyW).toBeGreaterThanOrEqual((rep?.dx ?? 0) + CONSTS.leafW);
  });
});

describe("feistelSwapWires — inter-round X geometry", () => {
  // recombine above (centered at x=100), next split below (centered at x=100).
  const recombineBox = { x: 50, y: 0, w: 100, h: 28 };
  const splitBox = { x: 50, y: 200, w: 100, h: 28 };
  const DX = 30;
  // Centers: rcx = 100, recombine bottom = 28; scx = 100, split top = 200.

  it("crosses byte-correctly when swap=true: R lands new_L (left), L⊕F lands new_R (right)", () => {
    const { lxorf, r } = feistelSwapWires(true, recombineBox, splitBox, DX);
    // Sources straddle the recombine center (100 ± 30): L⊕F left, R right.
    expect(lxorf.x1).toBe(70);
    expect(r.x1).toBe(130);
    expect(lxorf.y1).toBe(28);
    // THE BYTE MAPPING (recombine = concat(R, L⊕F) → new_L = R, new_R = L⊕F):
    // the R wire must land on split's LEFT (new_L), L⊕F on the RIGHT (new_R).
    expect(r.x2).toBe(70); // R → split-left (new_L)
    expect(lxorf.x2).toBe(130); // L⊕F → split-right (new_R)
    expect(r.y2).toBe(200);
    // Genuine crossing: each wire swaps its left/right side from source→target.
    expect(lxorf.x1 < r.x1).toBe(true);
    expect(lxorf.x2 > r.x2).toBe(true);
  });

  it("keeps each half on its own side when swap=false (straight; concat(L⊕F, R))", () => {
    const { lxorf, r } = feistelSwapWires(false, recombineBox, splitBox, DX);
    // No-swap last round: new_L = L⊕F (left), new_R = R (right).
    expect(lxorf.x1).toBe(70);
    expect(lxorf.x2).toBe(70); // L⊕F → split-left (new_L)
    expect(r.x1).toBe(130);
    expect(r.x2).toBe(130); // R → split-right (new_R)
    // No crossing: order preserved.
    expect(lxorf.x1 < r.x1).toBe(true);
    expect(lxorf.x2 < r.x2).toBe(true);
  });
});
