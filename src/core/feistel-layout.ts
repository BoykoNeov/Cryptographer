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
/** Horizontal gap between PARALLEL F-stack leaves in the same dependency layer
 *  (Blowfish's four independent S-box lookups, laid side-by-side to keep the
 *  cell short instead of stacking them). Tighter than COL_GAP. */
const F_LEAF_GAP = 24;

// ── Wide-band spread (Blowfish only; `maxLayerSize > 1`) ─────────────────────
// A round whose F stack has a PARALLEL layer (Blowfish's four S-boxes) reads as
// an edge tangle when packed at the DES gaps: the S-box row, its four aux
// (S-box table) feeds, and the add/xor cascade all crowd. So the wide form gets
// larger gaps plus a zig-zag (alternating offsets) that pulls neighbouring
// leaves off a shared axis, giving each edge room to breathe. DES's single-leaf
// layers (`maxLayerSize === 1`) never take this path, so its canonical cell is
// byte-for-byte unchanged.
const WIDE_ROW_GAP = 64;
const WIDE_COL_GAP = 96;
const WIDE_F_LEAF_GAP = 40;
/** Vertical zig-zag: every other leaf of a parallel layer drops this far, so the
 *  fan-in (aux feeds) and fan-out edges of adjacent S-boxes don't overlap. */
const ZIGZAG_Y = 20;
/** Horizontal zig-zag: successive single-leaf cascade rows (Blowfish's
 *  add01→xor2→add3) alternate ±this off centre, so the vertical spine reads as a
 *  zig-zag instead of a dead-straight stack of coincident arrows. */
const ZIGZAG_X = 44;

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

  // The F stack, grouped into dependency layers (parallel leaves share a row).
  // Restrict to children actually present. Fall back to one-leaf-per-layer for
  // a shape that predates `fStackLayers` (keeps hand-built test shapes
  // single-column).
  const present = new Set(childIds);
  const rawLayers =
    shape.fStackLayers && shape.fStackLayers.length > 0
      ? shape.fStackLayers
      : shape.fStackIds.map((id) => [id]);
  const layers = rawLayers
    .map((layer) => layer.filter((id) => present.has(id)))
    .filter((layer) => layer.length > 0);

  // The F "band" is as wide as the widest layer (Blowfish's 4 S-boxes); a
  // linear DES chain has width-1 layers, so the band is one leaf wide.
  const maxLayerSize = layers.reduce((m, l) => Math.max(m, l.length), 1);

  // Wide form (Blowfish): a parallel layer exists, so give the cell extra spread
  // + zig-zag. DES (`maxLayerSize === 1`) keeps every original gap and takes no
  // zig-zag / aux-lane path, so its canonical cell is byte-for-byte unchanged.
  const isWide = maxLayerSize > 1;
  const rowGap = isWide ? WIDE_ROW_GAP : ROW_GAP;
  const colGap = isWide ? WIDE_COL_GAP : COL_GAP;
  const fLeafGap = isWide ? WIDE_F_LEAF_GAP : F_LEAF_GAP;
  const rowH = leafH + rowGap;

  const fBandW = maxLayerSize * leafW + (maxLayerSize - 1) * fLeafGap;

  // Orientation: F on the RIGHT for the DES form (mixedHalf === "L"), on the
  // LEFT for the mirrored Blowfish form (mixedHalf === "R"). The F band and the
  // fxor rail are the two super-columns, colGap apart.
  const fOnRight = shape.mixedHalf === "L";
  const fBandX0 = fOnRight ? leafW + colGap : 0;
  const fxorColX = fOnRight ? 0 : fBandW + colGap;
  const totalW = fBandW + colGap + leafW;
  const centerX = Math.round(totalW / 2 - leafW / 2);
  const keyX = totalW + KEY_GAP;

  /** X offsets to center a `k`-leaf layer horizontally within the F band. */
  const layerXs = (k: number): number[] => {
    const groupW = k * leafW + (k - 1) * fLeafGap;
    const startX = Math.round(fBandX0 + (fBandW - groupW) / 2);
    return Array.from({ length: k }, (_, i) => startX + i * (leafW + fLeafGap));
  };
  const bandCenterX = layerXs(1)[0] ?? fBandX0; // single-leaf centered in the band

  const railCount = shape.railNodeIds.length;

  // Aux lane (Blowfish): the S-box row's four table-source replicas would
  // otherwise pile onto one another (or onto the single leaf above the row). We
  // reserve one extra row directly ABOVE the first PARALLEL layer (the S-box
  // row) and drop each replica there, right over its consumer — a short vertical
  // aux edge and no overlap. The wide layer and every layer below it shift down
  // one row to make space. DES never inserts a lane (its lone key replica keeps
  // its far-right `keyX` slot), so `rowOfLayer` is identity for it.
  const wideLayerIndex = layers.findIndex((l) => l.length > 1);
  const auxTargets = new Set<string>(wideLayerIndex >= 0 ? (layers[wideLayerIndex] ?? []) : []);
  const auxReplicaIds = childIds.filter((cid) => {
    if (!opts.isReplica(cid)) return false;
    const consumer = opts.consumerOf(cid);
    return consumer !== undefined && auxTargets.has(consumer);
  });
  const hasAuxLane = isWide && wideLayerIndex >= 0 && auxReplicaIds.length > 0;
  const auxLaneRow = railCount + 1 + wideLayerIndex; // the reserved lane's row
  /** Canvas row of layer `li`, accounting for the inserted aux lane. */
  const rowOfLayer = (li: number): number =>
    railCount + 1 + li + (hasAuxLane && li >= wideLayerIndex ? 1 : 0);

  const offsets = new Map<string, FeistelChildOffset>();

  // split: top, centered over the whole cell.
  offsets.set(shape.splitId, { dx: centerX, dy: 0 });

  // Pass-through rail nodes: head of the carried half, atop the F band (centered).
  shape.railNodeIds.forEach((id, i) => {
    offsets.set(id, { dx: bandCenterX, dy: (i + 1) * rowH });
  });

  // F-function layers: one row each, leaves in a layer spread side-by-side.
  let lastLayerRow = railCount; // if the F stack is empty, fxor sits below the rails
  layers.forEach((layer, li) => {
    const row = rowOfLayer(li);
    const xs = layerXs(layer.length);
    const parallel = layer.length > 1;
    // Horizontal zig-zag: single-leaf cascade rows BELOW the wide layer alternate
    // ± off centre so the vertical spine of arrows isn't a dead-straight overlap.
    const zx =
      isWide && !parallel && li > wideLayerIndex ? (li % 2 === 0 ? -ZIGZAG_X : ZIGZAG_X) : 0;
    layer.forEach((id, ci) => {
      // Vertical zig-zag: every other leaf of a parallel layer drops a step so
      // adjacent S-boxes' fan-in/out edges separate.
      const zy = isWide && parallel && ci % 2 === 1 ? ZIGZAG_Y : 0;
      offsets.set(id, { dx: (xs[ci] ?? bandCenterX) + zx, dy: row * rowH + zy });
    });
    lastLayerRow = row;
  });

  // fxor: the opposite column, level with the LAST F layer so the
  // `F-output → fxor` edge is a short horizontal hop.
  offsets.set(shape.fxorId, { dx: fxorColX, dy: lastLayerRow * rowH });

  // recombine: centered, one row below fxor / the F stack.
  const recombineRow = lastLayerRow + 1;
  offsets.set(shape.recombineId, { dx: centerX, dy: recombineRow * rowH });

  // The row of the F leaf a replica feeds (the key enters the F function there).
  const fLeafRowOf = (id: string): number | undefined => {
    for (let li = 0; li < layers.length; li++) {
      if (layers[li]?.includes(id)) return rowOfLayer(li);
    }
    return undefined;
  };

  // ── Replica + unclassified placement, with a deterministic collision check ──
  // The user's ask: "it should not be possible for leaves or replicates to sit
  // on top of one another." Every structural leaf above is committed first; each
  // replica then takes its preferred slot, and if that cell is already taken it
  // slides DOWN one row at a time until a free cell is found (rows below the cell
  // body are always free, so this terminates). A coarse cell grid (one leaf wide
  // × one row tall) defines "same spot."
  const cellH = leafH + rowGap;
  const cellKey = (dx: number, dy: number): string =>
    `${Math.round(dx / leafW)}|${Math.round(dy / cellH)}`;
  const occupied = new Set<string>();
  for (const o of offsets.values()) occupied.add(cellKey(o.dx, o.dy));

  const auxLaneSet = new Set(auxReplicaIds);
  let spareRow = 0;
  for (const cid of childIds) {
    if (offsets.has(cid)) continue;
    let dx: number;
    let dy: number;
    if (hasAuxLane && auxLaneSet.has(cid)) {
      // Above its consumer S-box in the reserved lane.
      const consumer = opts.consumerOf(cid);
      const cOff = consumer !== undefined ? offsets.get(consumer) : undefined;
      dx = cOff?.dx ?? bandCenterX;
      dy = auxLaneRow * rowH;
    } else if (opts.isReplica(cid)) {
      // Far-right key column at the consumer's row (DES's key replica; any wide
      // replica whose consumer isn't the S-box row).
      const consumer = opts.consumerOf(cid);
      const consumerRow = consumer !== undefined ? fLeafRowOf(consumer) : undefined;
      dx = keyX;
      dy = (consumerRow ?? rowOfLayer(Math.floor(layers.length / 2))) * rowH;
    } else {
      // Defensive: an unexpected child (hand-edited round). Park it far right.
      dx = keyX;
      dy = (recombineRow + 1 + spareRow) * rowH;
      spareRow += 1;
    }
    // Slide to the next free cell (down first — lanes stay narrow).
    let guard = 0;
    while (occupied.has(cellKey(dx, dy)) && guard < 128) {
      dy += rowH;
      guard += 1;
    }
    occupied.add(cellKey(dx, dy));
    offsets.set(cid, { dx, dy });
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
 * Should the inter-round carry be drawn as the swap "X" overlay, or as a plain
 * edge? Draw the X ONLY when the two rounds are STACKED VERTICALLY — the next
 * round's `split` sits below this round's `recombine`, in roughly the same
 * column. That is the DES arrangement (its rounds nest in an outer `rounds`
 * group and stack top-to-bottom), where the X is a short, readable crossing.
 *
 * Blowfish and Twofish rounds are TOP-LEVEL siblings tiled HORIZONTALLY, so the
 * next split is far to the side (and usually higher up). An X drawn there leaves
 * the recombine's bottom edge, doubles back UP and over the box, then meets the
 * next split from the top — the "makes no sense, crosses up and over" tangle the
 * user flagged. For those we fall back to the ordinary recombine→split edge,
 * which routes by the same rules as every other edge. Pure geometry so both the
 * carry-suppression set and the swap-wire geometry can gate on the SAME test.
 */
export const feistelRoundsStackVertically = (
  recombineBox: LayoutBox,
  splitBox: LayoutBox,
): boolean => {
  const rcx = recombineBox.x + recombineBox.w / 2;
  const scx = splitBox.x + splitBox.w / 2;
  return splitBox.y > recombineBox.y && Math.abs(scx - rcx) < recombineBox.w * 1.5;
};

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
