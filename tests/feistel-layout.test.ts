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
  railNodeIds: [],
  mixedHalf: "L",
  mixedRecombineInput: "input1",
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

// A Blowfish-shaped round descriptor: F mixed into the RIGHT half (mirrored),
// with the `xorP` key mix on the carried rail (excluded from the F stack).
const blowfishRoundShape = (roundId: string): FeistelRoundShape => ({
  roundId,
  splitId: `${roundId}.split`,
  fxorId: `${roundId}.xorR`,
  recombineId: `${roundId}.recombine`,
  fStackIds: [
    `${roundId}.splitF`,
    `${roundId}.s0`,
    `${roundId}.s1`,
    `${roundId}.s2`,
    `${roundId}.s3`,
    `${roundId}.add01`,
    `${roundId}.xor2`,
    `${roundId}.add3`,
  ],
  railNodeIds: [`${roundId}.xorP`],
  mixedHalf: "R",
  mixedRecombineInput: "input0",
  splitLPort: "output0",
  splitRPort: "output1",
  fxorOutPort: "output",
  fxorFInPort: "operand0",
  recombineOutPort: "output",
  swap: true,
  roundKeyAux: null,
});

describe("feistelRoundPlacement — mirrored Blowfish orientation", () => {
  const shape = blowfishRoundShape("round.1");
  const childIds = [
    "round.1.split",
    "round.1.xorP",
    "round.1.splitF",
    "round.1.s0",
    "round.1.s1",
    "round.1.s2",
    "round.1.s3",
    "round.1.add01",
    "round.1.xor2",
    "round.1.add3",
    "round.1.xorR",
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

  it("puts the F column to the LEFT of the fxor (mirror of DES)", () => {
    expect(at("round.1.splitF").dx).toBeLessThan(at("round.1.xorR").dx);
  });

  it("stacks the rail node (xorP) atop the F column, in the same column", () => {
    expect(at("round.1.xorP").dx).toBe(at("round.1.splitF").dx);
    expect(at("round.1.xorP").dy).toBeLessThan(at("round.1.splitF").dy);
    expect(at("round.1.xorP").dy).toBeGreaterThan(at("round.1.split").dy);
  });

  it("levels the fxor with the last F-stack leaf (short F-output hop)", () => {
    expect(at("round.1.xorR").dy).toBe(at("round.1.add3").dy);
  });

  it("keeps split and recombine centered between the columns", () => {
    expect(at("round.1.split").dx).toBe(at("round.1.recombine").dx);
    expect(at("round.1.split").dx).toBeGreaterThan(at("round.1.splitF").dx);
    expect(at("round.1.split").dx).toBeLessThan(at("round.1.xorR").dx);
  });
});

describe("feistelSwapWires — inter-round X geometry", () => {
  // recombine above (centered at x=100), next split below (centered at x=100).
  const recombineBox = { x: 50, y: 0, w: 100, h: 28 };
  const splitBox = { x: 50, y: 200, w: 100, h: 28 };
  const DX = 30;
  // Centers: rcx = 100, recombine bottom = 28; scx = 100, split top = 200.

  it("crosses byte-correctly for the DES swap orientation (mixed left→right, carry right→left)", () => {
    // DES rounds 1..15: fxor (L⊕F) on the LEFT (mixedHalf=L); the combined value
    // is the recombine's input1 → new_R (right). concat(R, L⊕F) → new_L=R.
    const { mixed, carry } = feistelSwapWires({
      mixedOriginSide: "left",
      mixedDestSide: "right",
      recombineBox,
      splitBox,
      dx: DX,
    });
    // Sources straddle the recombine center (100 ± 30): L⊕F left, R right.
    expect(mixed.x1).toBe(70);
    expect(carry.x1).toBe(130);
    expect(mixed.y1).toBe(28);
    // THE BYTE MAPPING: the carried R wire lands on split's LEFT (new_L), the
    // combined L⊕F on the RIGHT (new_R).
    expect(carry.x2).toBe(70); // R → split-left (new_L)
    expect(mixed.x2).toBe(130); // L⊕F → split-right (new_R)
    expect(carry.y2).toBe(200);
    // Genuine crossing: each wire swaps its left/right side from source→target.
    expect(mixed.x1 < carry.x1).toBe(true);
    expect(mixed.x2 > carry.x2).toBe(true);
  });

  it("keeps each half on its own side for the DES no-swap orientation (round 16)", () => {
    // DES round 16: combined value is input0 → new_L (left). concat(L⊕F, R).
    const { mixed, carry } = feistelSwapWires({
      mixedOriginSide: "left",
      mixedDestSide: "left",
      recombineBox,
      splitBox,
      dx: DX,
    });
    expect(mixed.x1).toBe(70);
    expect(mixed.x2).toBe(70); // L⊕F → split-left (new_L)
    expect(carry.x1).toBe(130);
    expect(carry.x2).toBe(130); // R → split-right (new_R)
    // No crossing: order preserved.
    expect(mixed.x1 < carry.x1).toBe(true);
    expect(mixed.x2 < carry.x2).toBe(true);
  });

  it("crosses byte-correctly for the mirrored Blowfish orientation (mixed right→left)", () => {
    // Blowfish: fxor (R⊕F) on the RIGHT (mixedHalf=R); combined value is input0
    // → new_L (left). concat(R⊕F, L⊕P) → new_L = R⊕F. So the combined half
    // originates on the RIGHT and crosses to the LEFT; the carried L half
    // crosses right.
    const { mixed, carry } = feistelSwapWires({
      mixedOriginSide: "right",
      mixedDestSide: "left",
      recombineBox,
      splitBox,
      dx: DX,
    });
    expect(mixed.x1).toBe(130); // combined leaves recombine-right
    expect(mixed.x2).toBe(70); // → new_L (left)
    expect(carry.x1).toBe(70); // carried leaves recombine-left
    expect(carry.x2).toBe(130); // → new_R (right)
    // Genuine crossing, mirrored from DES.
    expect(mixed.x1 > carry.x1).toBe(true);
    expect(mixed.x2 < carry.x2).toBe(true);
  });
});
