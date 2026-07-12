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
 * **Orientation.** DES and Blowfish mirror each other in which half feeds F: in
 * DES the RIGHT half (R) feeds F and the fxor mixes it into the LEFT half; in
 * Blowfish the LEFT half (after the `xorP` key mix) feeds F and the fxor mixes
 * it into the RIGHT half. So the F-function column sits on the side of the
 * *carried* half (`shape.mixedHalf === "L"` → carried half is R → F on the
 * RIGHT, the DES orientation; `mixedHalf === "R"` → carried half is L → F on the
 * LEFT). The fxor always sits in the OPPOSITE column. Everything else is shared.
 *
 * Columns (x):
 *   - F column (`fColX`)     — the F-function stack + any pass-through rail
 *                              nodes (Blowfish's `xorP`), spec order.
 *   - fxor column (`fxorColX`, opposite side) — the fxor sits low here.
 *   - `split` / `recombine` are centered between the two columns.
 *   - KEY   (`keyX`, far right) — a round-key replica, placed at its consumer's
 *     row (the F leaf that reads `roundKeyAux`).
 *
 * Rows (y), each `leafH + ROW_GAP` tall (`k` = rail-node count, `N` = F-stack):
 *   - row 0            → `split`
 *   - rows 1..k        → the pass-through rail nodes (head of the carried half)
 *   - rows k+1..k+N    → the N F-stack leaves
 *   - row k+N          → `fxor` (fxor column, level with the last F leaf so the
 *                        F-output → fxor edge reads as a short horizontal hop)
 *   - row k+N+1        → `recombine`
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

  // Orientation: F on the RIGHT for the DES form (mixedHalf === "L"), on the
  // LEFT for the mirrored Blowfish form (mixedHalf === "R").
  const fOnRight = shape.mixedHalf === "L";
  const fColX = fOnRight ? rightX : leftX;
  const fxorColX = fOnRight ? leftX : rightX;

  const offsets = new Map<string, FeistelChildOffset>();

  // split: top, centered over the two columns.
  offsets.set(shape.splitId, { dx: splitX, dy: 0 });

  // Pass-through rail nodes: head of the carried half, atop the F column.
  const railCount = shape.railNodeIds.length;
  shape.railNodeIds.forEach((id, i) => {
    offsets.set(id, { dx: fColX, dy: (i + 1) * rowH });
  });

  // F-function stack: the F column, one row each, below the rail nodes.
  shape.fStackIds.forEach((id, i) => {
    offsets.set(id, { dx: fColX, dy: (railCount + i + 1) * rowH });
  });

  // fxor: the opposite column, level with the LAST F-stack leaf so the
  // `F-output → fxor` edge is a short horizontal hop.
  const fxorRow = railCount + Math.max(1, shape.fStackIds.length);
  offsets.set(shape.fxorId, { dx: fxorColX, dy: fxorRow * rowH });

  // recombine: centered, one row below fxor / the F stack.
  const recombineRow = fxorRow + 1;
  offsets.set(shape.recombineId, { dx: splitX, dy: recombineRow * rowH });

  // The F leaf that consumes the round key (its row is where the key enters).
  // `roundKeyAux` names the param; find the matching F-stack leaf by checking
  // it's the one the replica targets. We don't have params here, so we anchor
  // the key chip at its replica's declared consumer row instead.
  const fStackRowOf = (id: string): number | undefined => {
    const idx = shape.fStackIds.indexOf(id);
    return idx >= 0 ? railCount + idx + 1 : undefined;
  };

  // Round-key replica(s) + any other unclassified children.
  let spareRow = 0;
  for (const cid of childIds) {
    if (offsets.has(cid)) continue;
    if (opts.isReplica(cid)) {
      const consumer = opts.consumerOf(cid);
      const consumerRow = consumer !== undefined ? fStackRowOf(consumer) : undefined;
      // Default to the middle of the F stack if the consumer isn't an F leaf.
      const dy = (consumerRow ?? railCount + Math.ceil(shape.fStackIds.length / 2)) * rowH;
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

/** Which side of a box a wire endpoint sits on. */
export type FeistelSide = "left" | "right";

/**
 * Endpoints of the two inter-round carry half-wires, between a round's
 * `recombine` (source, bottom edge) and the next round's `split` (target, top
 * edge). The two halves are named by ROLE — the `mixed` (combined `X⊕F`) half
 * and the `carry` (pass-through) half — because the swap lives in `recombine`'s
 * concat order, so the raw `recombine → split` byte flow is actually straight;
 * the X is the rail-level picture and the renderer LABELS each wire so a student
 * can trace it.
 *
 * The geometry is driven entirely by two ORIENTATION facts read off the round's
 * shape, so it stays byte-honest across DES *and* the mirrored Blowfish form:
 *   - `mixedOriginSide` — which column the fxor sits in (where the combined half
 *     leaves the recombine): LEFT for DES (`L⊕F` on the left rail), RIGHT for
 *     Blowfish (`R⊕F` on the right rail).
 *   - `mixedDestSide` — which half of the next split the combined value lands in
 *     (from the recombine's argument order: `input0` → new_L = left, `input1` →
 *     new_R = right).
 *
 * The `carry` wire is the exact mirror (opposite origin AND opposite dest). A
 * genuine crossing (the Feistel X) appears iff `mixedOriginSide !==
 * mixedDestSide`. Pure geometry so the crossing is unit-tested independently of
 * the SVG renderer, verified against the byte mapping — not just "looks like an
 * X".
 */
export const feistelSwapWires = (opts: {
  readonly mixedOriginSide: FeistelSide;
  readonly mixedDestSide: FeistelSide;
  readonly recombineBox: LayoutBox;
  readonly splitBox: LayoutBox;
  readonly dx: number;
}): { mixed: FeistelSwapWire; carry: FeistelSwapWire } => {
  const { mixedOriginSide, mixedDestSide, recombineBox, splitBox, dx } = opts;
  const rcx = recombineBox.x + recombineBox.w / 2;
  const rby = recombineBox.y + recombineBox.h; // recombine bottom edge
  const scx = splitBox.x + splitBox.w / 2;
  const sty = splitBox.y; // next split top edge
  const opp = (s: FeistelSide): FeistelSide => (s === "left" ? "right" : "left");
  const originX = (s: FeistelSide): number => (s === "left" ? rcx - dx : rcx + dx);
  const destX = (s: FeistelSide): number => (s === "left" ? scx - dx : scx + dx);
  return {
    mixed: { x1: originX(mixedOriginSide), y1: rby, x2: destX(mixedDestSide), y2: sty },
    carry: { x1: originX(opp(mixedOriginSide)), y1: rby, x2: destX(opp(mixedDestSide)), y2: sty },
  };
};
