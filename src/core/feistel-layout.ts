/**
 * Canonical Feistel-round LAYOUT (graph view — DES canonical-representation
 * feature, 2026-06-02).
 *
 * **Why this exists.** In graph view a Feistel round is a port-mode `group`
 * whose body wires `split → expand-R → xor-K → s-boxes → p-permute → xor →
 * concat` (see `feistel-shape.ts`). The generic group layout stacks those
 * seven leaves in a single vertical column, so the two halves (L, R) and the
 * F-function read as an undifferentiated cascade — the user can't see the
 * textbook Feistel structure. This module computes a CANONICAL two-column
 * placement for the round's children so the round reads like the published DES
 * round diagram:
 *
 * ```
 *            split                 ← the 8-byte round input, split into L | R
 *           /     \
 *      (L) /       \ (R)
 *         |     [ expand-R ]  ┐
 *         |     [  xor-K   ]  │  ← the F-function, stacked in the RIGHT column
 *         |     [ s-boxes  ]  │     (xor-K also takes the round key K_i, drawn
 *         |     [ p-permute]  ┘     as a replica chip to the right when present)
 *      [ fxor ] ←──────────────┘  ← L ⊕ F   (the L rail is the LEFT column)
 *           \       /
 *          [ recombine ]          ← the round output (the swap lives in the
 *                                    concat argument order; the inter-round X
 *                                    overlay draws it between round boxes)
 * ```
 *
 * The placement is PURE (no Solid, no DOM) so it unit-tests in the `node`
 * environment and `GraphView`'s `layoutNode` calls it from the group branch
 * when a round resolves to a `FeistelRoundShape`. The existing port-flow edges
 * (`split→fxor`, `split→expand-R`, the F-chain, `p-permute→fxor`,
 * `fxor→recombine`, `split→recombine`) route as the rails automatically once
 * the leaves sit in these slots — no edge-derivation change needed.
 *
 * Cipher-agnostic: any `FeistelRoundShape` (DES today; a future TEA/XTEA built
 * the same way) lays out for free.
 */

import type { FeistelRoundShape } from "./feistel-shape";

/** Vertical gap between stacked rows inside the round (tighter than the
 *  generic group's STACK_GAP=60 so a 6-row Feistel cell stays compact). */
const ROW_GAP = 40;
/** Horizontal gap between the L rail (left column) and the F-function column. */
const COL_GAP = 72;
/** Horizontal gap between the F-function column and the round-key replica chip
 *  (when a `key-schedule.publish` replica is a child of this round). */
const KEY_GAP = 56;

/** A child's top-left offset relative to the round body's inner origin. */
export type FeistelChildOffset = { readonly dx: number; readonly dy: number };

export type FeistelPlacement = {
  /** Child id → offset (relative to the round body inner origin: the point
   *  just below the header, inside the container padding). */
  readonly offsets: ReadonlyMap<string, FeistelChildOffset>;
  /** Inner content width (excludes container padding). */
  readonly bodyW: number;
  /** Inner content height (excludes header + container padding). */
  readonly bodyH: number;
};

export type FeistelPlacementOpts = {
  readonly leafW: number;
  readonly leafH: number;
  /** True iff the child id is a replica node (synthetic fan-out chip). */
  readonly isReplica: (id: string) => boolean;
  /** The consumer leaf a replica feeds (e.g. the round's `xor-K`), or undefined. */
  readonly consumerOf: (id: string) => string | undefined;
};

/**
 * Compute canonical slot offsets for a Feistel round's children.
 *
 * Columns (x):
 *   - LEFT  (`leftX = 0`)               — the L rail: `fxor` sits low here.
 *   - RIGHT (`rightX = leafW + COL_GAP`) — the F-function stack, spec order.
 *   - `split` / `recombine` are centered between the two columns.
 *   - KEY   (`keyX`, right of the F column) — a round-key replica, placed at
 *     its consumer's row (the F leaf that reads `roundKeyAux`).
 *
 * Rows (y), each `leafH + ROW_GAP` tall:
 *   - row 0            → `split`
 *   - rows 1..N        → the N F-stack leaves
 *   - row N            → `fxor` (LEFT column, level with the last F leaf so
 *                        `p-permute → fxor` reads as a short horizontal hop)
 *   - row N+1          → `recombine`
 *
 * Any child not classified by the shape (defensive — a hand-edited round) is
 * parked in a spare far-right column so it never vanishes from the canvas.
 */
export const feistelRoundPlacement = (
  shape: FeistelRoundShape,
  childIds: readonly string[],
  opts: FeistelPlacementOpts,
): FeistelPlacement => {
  const { leafW, leafH } = opts;
  const rowH = leafH + ROW_GAP;
  const leftX = 0;
  const rightX = leafW + COL_GAP;
  const splitX = Math.round((leftX + rightX) / 2);
  const keyX = rightX + leafW + KEY_GAP;

  const offsets = new Map<string, FeistelChildOffset>();

  // split: top, centered over the L and F columns.
  offsets.set(shape.splitId, { dx: splitX, dy: 0 });

  // F-function stack: right column, one row each, in spec order.
  shape.fStackIds.forEach((id, i) => {
    offsets.set(id, { dx: rightX, dy: (i + 1) * rowH });
  });

  // fxor (L ⊕ F): left column, level with the LAST F-stack leaf so the
  // `p-permute → fxor` edge is a short horizontal hop and the `split → fxor`
  // L rail is a clean vertical down the left column.
  const fxorRow = Math.max(1, shape.fStackIds.length);
  offsets.set(shape.fxorId, { dx: leftX, dy: fxorRow * rowH });

  // recombine: centered, one row below fxor / the F stack.
  const recombineRow = fxorRow + 1;
  offsets.set(shape.recombineId, { dx: splitX, dy: recombineRow * rowH });

  // The F leaf that consumes the round key (its row is where the key enters).
  // `roundKeyAux` names the param; find the matching F-stack leaf by checking
  // it's the one the replica targets. We don't have params here, so we anchor
  // the key chip at its replica's declared consumer row instead.
  const fStackRowOf = (id: string): number | undefined => {
    const idx = shape.fStackIds.indexOf(id);
    return idx >= 0 ? idx + 1 : undefined;
  };

  // Round-key replica(s) + any other unclassified children.
  let spareRow = 0;
  for (const cid of childIds) {
    if (offsets.has(cid)) continue;
    if (opts.isReplica(cid)) {
      const consumer = opts.consumerOf(cid);
      const consumerRow = consumer !== undefined ? fStackRowOf(consumer) : undefined;
      // Default to the middle of the F stack if the consumer isn't an F leaf.
      const dy = (consumerRow ?? Math.ceil(shape.fStackIds.length / 2)) * rowH;
      offsets.set(cid, { dx: keyX, dy });
    } else {
      // Defensive: an unexpected child (hand-edited round). Park it far right.
      offsets.set(cid, { dx: keyX, dy: (recombineRow + 1 + spareRow) * rowH });
      spareRow += 1;
    }
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

/** A straight wire segment (consumed by the renderer, which curves it). */
export type FeistelSwapWire = { x1: number; y1: number; x2: number; y2: number };

/** A minimal box shape (the renderer's layout `Box` is structurally compatible). */
export type LayoutBox = { x: number; y: number; w: number; h: number };

/**
 * Endpoints of the two inter-round carry half-wires, between a round's
 * `recombine` (source, bottom edge) and the next round's `split` (target, top
 * edge). The two halves are named by the VALUE each carries, NOT by byte
 * position — because the swap lives in `recombine`'s concat order, so the raw
 * `recombine → split` byte flow is actually straight; the X is the rail-level
 * picture and the renderer LABELS each wire so a student can trace it:
 *
 *   - `lxorf` carries **L⊕F** (computed at `fxor` on the left rail), leaving
 *     recombine's left.
 *   - `r` carries **R** (`split.output1`, the right rail), leaving recombine's
 *     right.
 *
 * On a SWAP (`swap === true`) they CROSS to the OPPOSITE side of the next
 * split: **R → the next round's LEFT half (new_L)** and **L⊕F → its RIGHT half
 * (new_R)** — the textbook Feistel X, matching `recombine = concat(R, L⊕F)` →
 * `new_L = R`, `new_R = L⊕F`. On no-swap (`false`, DES round 16) they go
 * straight (L⊕F → new_L, R → new_R), matching `concat(L⊕F, R)`.
 *
 * Pure geometry so the crossing direction is unit-tested independently of the
 * SVG renderer (and verified against the byte mapping, not just "looks like an
 * X").
 */
export const feistelSwapWires = (
  swap: boolean,
  recombineBox: LayoutBox,
  splitBox: LayoutBox,
  dx: number,
): { lxorf: FeistelSwapWire; r: FeistelSwapWire } => {
  const rcx = recombineBox.x + recombineBox.w / 2;
  const rby = recombineBox.y + recombineBox.h; // recombine bottom edge
  const scx = splitBox.x + splitBox.w / 2;
  const sty = splitBox.y; // next split top edge
  const left = scx - dx;
  const right = scx + dx;
  return {
    // L⊕F: from recombine-left → new_R (right) on swap, else new_L (left).
    lxorf: { x1: rcx - dx, y1: rby, x2: swap ? right : left, y2: sty },
    // R: from recombine-right → new_L (left) on swap, else new_R (right).
    r: { x1: rcx + dx, y1: rby, x2: swap ? left : right, y2: sty },
  };
};
