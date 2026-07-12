/**
 * Canonical Twofish-round LAYOUT (graph view — 4-rail sibling of
 * `feistel-layout.ts`).
 *
 * **Why this exists.** A Twofish round is a port-mode `group` whose body wires a
 * 4-way split, two parallel g functions, a pseudo-Hadamard transform (PHT), two
 * rotation-interleaved mix rails, and a 4-input concat (see
 * `twofish-shape.ts`). The generic group layout stacks its ~28 leaves in one
 * vertical column, so the two g functions, the PHT, and the R2/R3 rails read as
 * an undifferentiated cascade. This module computes a CANONICAL 4-rail
 * placement so the round reads like the published Twofish round diagram:
 *
 * ```
 *                    split                    ← R0 | R1 | R2 | R3
 *          ┌───────────┼───────────────┐
 *      [ g(R0) ]   [ ROL(R1,8) ]        │  R2, R3 carried down (right band)
 *      [   …   ]   [   g(·)     ]        │
 *          └──────┬────┘                 │
 *              [ PHT ]  → F0, F1         │
 *                 └──────────────► [ R2 ⊕ F0 ↻ ] [ ↺ R3 ⊕ F1 ]
 *                    recombine  ←───────────┘         ┘
 * ```
 *
 * The placement is PURE (no Solid, no DOM) so it unit-tests in the `node`
 * environment; `GraphView`'s `layoutNode` calls it from the group branch when a
 * round resolves to a `TwofishRoundShape`. The existing port-flow edges route as
 * the rails automatically once the leaves sit in these slots.
 */

import type { TwofishRoundShape } from "./twofish-shape";

/** Vertical gap between stacked rows inside the round. */
const ROW_GAP = 40;
/** Horizontal gap between adjacent columns/bands. */
const COL_GAP = 56;

/** A child's top-left offset relative to the round body's inner origin. */
export type TwofishChildOffset = { readonly dx: number; readonly dy: number };

export type TwofishPlacement = {
  /** Child id → offset (relative to the round body inner origin). */
  readonly offsets: ReadonlyMap<string, TwofishChildOffset>;
  /** Inner content width (excludes container padding). */
  readonly bodyW: number;
  /** Inner content height (excludes header + container padding). */
  readonly bodyH: number;
};

export type TwofishPlacementOpts = {
  readonly leafW: number;
  readonly leafH: number;
  /** True iff the child id is a replica node (synthetic fan-out chip). */
  readonly isReplica: (id: string) => boolean;
  /** The consumer leaf a replica feeds, or undefined. */
  readonly consumerOf: (id: string) => string | undefined;
};

/**
 * Compute canonical slot offsets for a Twofish round's children.
 *
 * Five bands (x), left→right: `g0` column, `g1` column (with the `rolR1` rail
 * atop it, OUTSIDE the g decoration box), a center band for `split` / `PHT` /
 * `recombine`, then the `r2Mix` and `r3Mix` columns on the right. Rows flow
 * top→bottom in true data order: `split` at the top, the two g stacks, then the
 * PHT below them (it consumes the g outputs), then the mix rails (they consume
 * the PHT's F0/F1), then `recombine` centered at the bottom.
 *
 * Any child not classified by the shape (defensive — a hand-edited round, or a
 * round-key replica) is parked in a spare far-right column so it never vanishes.
 */
export const twofishRoundPlacement = (
  shape: TwofishRoundShape,
  childIds: readonly string[],
  opts: TwofishPlacementOpts,
): TwofishPlacement => {
  const { leafW, leafH } = opts;
  const rowH = leafH + ROW_GAP;
  const colW = leafW + COL_GAP;

  // Bands.
  const g0X = 0;
  const g1X = colW;
  const centerX = 2 * colW;
  const r2X = 3 * colW;
  const r3X = 4 * colW;

  const offsets = new Map<string, TwofishChildOffset>();
  const set = (id: string, dx: number, dy: number): void => {
    offsets.set(id, { dx, dy });
  };

  // Row 0: split, centered over the whole cell.
  set(shape.splitId, centerX, 0);

  // Left band: g0 stack (rows 1..N) and g1 stack (rolR1 row 1, stack rows 2..N+1).
  shape.g0Ids.forEach((id, i) => set(id, g0X, (i + 1) * rowH));
  set(shape.rolNodeId, g1X, 1 * rowH);
  shape.g1Ids.forEach((id, i) => set(id, g1X, (i + 2) * rowH));

  // The g stacks bottom out here; the PHT sits one row below (it consumes them).
  const gBottomRow = Math.max(shape.g0Ids.length + 1, shape.g1Ids.length + 2);
  const phtTopRow = gBottomRow + 1;

  // PHT: the two subkey loads on the top PHT row (flanking), the f0/dbl2T1/f1
  // adds below — all placed by ROLE (from the shape's structural fields), never
  // by leaf id, so a renamed/rewired round still reads cleanly.
  const [f0Id, f1Id] = shape.fIds;
  const [loadK0Id, loadK1Id] = shape.loadIds;
  set(loadK0Id, g0X, phtTopRow * rowH);
  set(loadK1Id, g1X, phtTopRow * rowH);
  set(f0Id, g0X, (phtTopRow + 1) * rowH);
  set(shape.dblId, centerX, (phtTopRow + 1) * rowH);
  set(f1Id, g1X, (phtTopRow + 2) * rowH);

  // Right band: the R2 / R3 mix rails, stacked in spec order, below the PHT.
  const mixTopRow = phtTopRow + 3;
  shape.r2MixIds.forEach((id, i) => set(id, r2X, (mixTopRow + i) * rowH));
  shape.r3MixIds.forEach((id, i) => set(id, r3X, (mixTopRow + i) * rowH));

  // Bottom: recombine, centered, below the deepest mix leaf.
  const mixBottomRow = mixTopRow + Math.max(shape.r2MixIds.length, shape.r3MixIds.length, 1) - 1;
  const recombineRow = mixBottomRow + 1;
  set(shape.recombineId, centerX, recombineRow * rowH);

  // Defensive: any child the shape didn't classify (hand-edited round or a
  // round-key replica) parks far right so it never vanishes from the canvas.
  let spareRow = 0;
  const spareX = r3X + colW;
  for (const cid of childIds) {
    if (offsets.has(cid)) continue;
    set(cid, spareX, (spareRow + 1) * rowH);
    spareRow += 1;
  }

  // Body extent from the placed boxes.
  let bodyW = 0;
  let bodyH = 0;
  for (const o of offsets.values()) {
    bodyW = Math.max(bodyW, o.dx + leafW);
    bodyH = Math.max(bodyH, o.dy + leafH);
  }
  return { offsets, bodyW, bodyH };
};
