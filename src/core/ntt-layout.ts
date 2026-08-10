/**
 * Canonical **NTT BUTTERFLY layout** (graph view — the fourth sibling of
 * `feistel-layout.ts`, `twofish-layout.ts` and `arx-round-layout.ts`).
 *
 * **The problem, measured.** An NTT layer's body is eight leaves and the
 * generic iterate layout flows them horizontally: one ~1,650 px ribbon per
 * layer, seven layers end to end, a 12,752 × 546 canvas for the forward
 * transform. Every structural fact about a butterfly — two rails, a twiddle
 * multiply feeding both, a sum and a difference converging — is strung out in a
 * single line with the wires running the full width.
 *
 * **The arrangement.** Three columns and five rows: a ζ row across the top,
 * then the split, then the one mixing step, then the two rails with the modulus
 * between them, then the recombine.
 *
 * ```
 *   Cooley–Tukey (forward)              Gentleman–Sande (inverse)
 *
 *              zeta ► advance                    zeta ► advance
 *        split    │                        split    │
 *          │      │                          │      │
 *        twist ◄──┘                        hi−lo    │
 *       ╱  │  ╲                            ╱ │      │
 *  lo ── q ── hi                     lo ── q ── ζ·(hi−lo) ◄┘
 *    ╲       ╱                          ╲       ╱
 *    recombine                          recombine
 * ```
 *
 * **One slot table serves both butterflies, and that is not a shortcut.** The
 * two are genuinely different shapes — the forward multiplies before combining,
 * the inverse after — but `analyzeNttButterfly` has already resolved that into
 * ROLES, and the roles differ exactly where the shapes do: the leaf at the mid
 * slot is the twiddle multiply going forward (`twist`) and the subtraction
 * coming back (`diff`), and the leaf producing the high half is the subtraction
 * going forward and the multiply coming back. So the direction is fully encoded
 * before this module sees anything, and a `kind` branch here would be a second
 * copy of a decision already made. Nothing in this file reads `shape.kind`, a
 * leaf id, or a position.
 *
 * ## The grid was chosen by measuring the rendered wires, not by taste
 *
 * The graph's edge router draws a cubic that holds the SOURCE's y for the first
 * half of its x-span and settles onto the TARGET's y for the second. The
 * placements below were derived by auditing every rendered path against every
 * leaf box — sampling each path and asking which boxes it passes through that
 * are not its own endpoints — and the first two drafts of this file violated
 * them.
 *
 * **What that audit measures, for both directions of the standalone specs:**
 *
 * | | canvas | wires crossing a box |
 * |---|---|---|
 * | generic layout, forward | 12,752 × 546 | 34 |
 * | generic layout, inverse | 12,956 × 546 | 47 |
 * | this cell, forward | 6,536 × 702 | 1 |
 * | this cell, inverse | 6,740 × 702 | 1 |
 *
 * The one survivor in each direction is pre-existing and outside any cell — the
 * spec input's wire passing over the forward head's `cursor-split`, and
 * `ninv → scale` passing over `scale-q` in the inverse tail. Both are present
 * in the generic-layout numbers too, which is how they were identified as not
 * belonging to this work.
 *
 * **The modulus sits BETWEEN the rails.** `q` is read by all three arithmetic
 * leaves, so wherever it goes its wires fan across the cell. Put it beside the
 * rails (the obvious side-lane slot) and its wire to the FAR rail settles onto
 * that rail's y while still inside the NEAR rail's box — because the two rails
 * share a row, the far rail's y *is* the near rail's y-band. On screen that
 * reads as "hi feeds lo": a wire through a labelled box, the exact failure the
 * Twofish linear diagram documents. No position outside the rails can avoid it;
 * between them, both wires are short hops to adjacent columns and neither has
 * anything to cross.
 *
 * **The ζ row runs along the top, and its two nodes are at the RIGHT end of
 * it.** The rotating table enters each layer from the previous one and leaves
 * for the next, so one of those wires has to traverse the cell unless the pair
 * sits on a row of its own — hence the row. Their COLUMNS then took two more
 * measurements. `advance` is rightmost so the hop to the next layer leaves the
 * cell immediately instead of crossing back over it. And `zeta` sits directly
 * above the HIGH rail because that is where its one consumer is: the twiddle
 * multiply is the mid slot going forward and the high rail coming back, and a
 * ζ read placed at the far left reached the inverse's multiply by cutting
 * straight through the split. One column serves both, because a wire from
 * above the high rail reaches the mid slot by a short hop to the left.
 *
 * The placement is PURE (no Solid, no DOM) so it unit-tests in the `node`
 * environment; `GraphView`'s `layoutNode` calls it from the ITERATE branch when
 * a layer resolves to a butterfly shape. That branch is new — the three earlier
 * cells all gate on `kind === "group"` — and is safe because a collapsed
 * iterate's body is replaced by block chips before layout runs, so a cell and a
 * chip row can never both apply.
 */

import type { NttButterflyRole, NttButterflyShape } from "./ntt-shape";

/** Vertical gap between the four rows. */
const ROW_GAP = 32;
/** Horizontal gap between the three columns. */
const COL_GAP = 48;

/** Low rail, centre (split / mix / modulus / recombine), high rail, ζ tail. */
const COLUMNS = 4;
/** ζ row / split / mix / rails / recombine. */
const ROWS = 5;

/** A child's top-left offset relative to the body's inner origin. */
export type NttChildOffset = { readonly dx: number; readonly dy: number };

export type NttPlacement = {
  /** Child id → offset (relative to the layer body's inner origin). */
  readonly offsets: ReadonlyMap<string, NttChildOffset>;
  /** Inner content width (excludes container padding). */
  readonly bodyW: number;
  /** Inner content height (excludes header + container padding). */
  readonly bodyH: number;
};

export type NttPlacementOpts = {
  readonly leafW: number;
  readonly leafH: number;
};

/** A slot in the 3 × 4 grid. `col` is fractional where a node centres between rails. */
type Slot = { readonly col: number; readonly row: number };

/**
 * The whole cell, keyed by role.
 *
 * `twist` and `diff` share the mid slot and `hi` is a single entry because the
 * two butterflies' role sets are disjoint exactly there: a Cooley–Tukey body
 * has {twist, hi} and never a `diff`, a Gentleman–Sande body has {diff, hi} and
 * never a `twist`. See the header — this is the direction decision arriving
 * pre-made, not a collision.
 */
const SLOTS: Readonly<Record<NttButterflyRole, Slot>> = {
  // Row 0 — the ζ table's own row. `zeta` sits above the HIGH rail's column
  // (see the header: that is where its one consumer lives in either
  // direction), and `advance` to its right so the hop to the next layer leaves
  // the cell without re-entering it.
  zeta: { col: 2, row: 0 },
  advance: { col: 3, row: 0 },
  // The centre column carries the whole of the coefficients' path except the
  // two rails, which flank it.
  split: { col: 1, row: 1 },
  twist: { col: 1, row: 2 },
  diff: { col: 1, row: 2 },
  lo: { col: 0, row: 3 },
  modulus: { col: 1, row: 3 },
  hi: { col: 2, row: 3 },
  recombine: { col: 1, row: 4 },
};

/**
 * Compute canonical slot offsets for one NTT layer's butterfly children.
 *
 * Any child the shape didn't classify is parked in a spare column to the right
 * so it can never vanish from the canvas. In practice the partition gate in
 * `analyzeNttButterfly` means there are none — an unclassified leaf makes the
 * whole layer decline to the generic layout — but the fallback costs nothing
 * and keeps this function total.
 */
export const nttButterflyPlacement = (
  shape: NttButterflyShape,
  childIds: readonly string[],
  opts: NttPlacementOpts,
): NttPlacement => {
  const { leafW, leafH } = opts;
  const rowH = leafH + ROW_GAP;
  const colW = leafW + COL_GAP;

  const offsets = new Map<string, NttChildOffset>();
  for (const op of shape.ops) {
    const slot = SLOTS[op.role];
    offsets.set(op.nodeId, { dx: slot.col * colW, dy: slot.row * rowH });
  }

  // Defensive: park anything the shape didn't classify rather than dropping it.
  const gridW = COLUMNS * colW - COL_GAP;
  let spareRow = 0;
  for (const cid of childIds) {
    if (offsets.has(cid)) continue;
    offsets.set(cid, { dx: gridW + COL_GAP, dy: spareRow * rowH });
    spareRow += 1;
  }

  // Size from the placed boxes rather than from the grid constants, so a parked
  // stray widens the body instead of overflowing it.
  let bodyW = 0;
  let bodyH = 0;
  for (const o of offsets.values()) {
    bodyW = Math.max(bodyW, o.dx + leafW);
    bodyH = Math.max(bodyH, o.dy + leafH);
  }
  // Floor at the nominal grid so an (impossible) empty shape still reserves the
  // cell's footprint.
  bodyW = Math.max(bodyW, gridW);
  bodyH = Math.max(bodyH, ROWS * rowH - ROW_GAP);
  return { offsets, bodyW, bodyH };
};
