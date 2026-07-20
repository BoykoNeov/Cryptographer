/**
 * Canonical **ARX DOUBLE-ROUND layout** (graph view — the sibling of
 * `feistel-layout.ts` and `twofish-layout.ts`). Shared by ChaCha20 and Salsa20.
 *
 * **The problem.** An ARX double round is a group of 98 leaves: a 16-way split,
 * eight quarter rounds of twelve bare ARX operations each, and a 16-way concat.
 * The generic group layout stacks them in one vertical column, which is a
 * 98-chip ribbon with no visible structure at all — the worst case in the app.
 *
 * **The arrangement, and why this one.** Both ciphers write the quarter round as
 * four lines of three operations (RFC 8439 §2.1 for ChaCha; Bernstein's Salsa20
 * spec for Salsa):
 *
 * ```
 *   a += b;   d ^= a;   d <<<= 16;
 *   c += d;   b ^= c;   b <<<= 12;
 *   a += b;   d ^= a;   d <<<= 8;
 *   c += d;   b ^= c;   b <<<= 7;
 * ```
 *
 * So each quarter round is placed as a 3-wide × 4-tall block whose rows ARE
 * those lines. Read left to right and you are reading the specification. The
 * eight blocks then sit in two tiers of four, which is the double round's own
 * structure: the four quarter rounds that read the split directly (ChaCha's
 * COLUMN round, Salsa's COLUMN round) above the four that consume their outputs
 * (ChaCha's DIAGONAL round, Salsa's ROW round).
 *
 * ```
 *                            split                          ← 16 words
 *      ┌──────────┬──────────┬──────────┬──────────┐
 *      │  QR 0    │  QR 1    │  QR 2    │  QR 3    │        ← each 3×4
 *      └──────────┴──────────┴──────────┴──────────┘
 *      ┌──────────┬──────────┬──────────┬──────────┐
 *      │  QR 4    │  QR 5    │  QR 6    │  QR 7    │
 *      └──────────┴──────────┴──────────┴──────────┘
 *                           concat                          ← back to 64 bytes
 * ```
 *
 * **What this deliberately does NOT attempt.** The sixteen words travel from the
 * first tier to the second in a permuted pattern — that is the whole point of
 * alternating the two — and drawing those crossings as an aligned 4×4 matrix
 * would spread each quarter round's four rails far apart and make its
 * twelve-operation chain zigzag across the canvas. That is the tangle Twofish's
 * swap-X hit and was removed for. The inter-tier wires route generically here;
 * the rail-level picture of ONE quarter round is the LINEAR view's job, at a
 * scale where it is legible (see `chacha-diagram.ts`).
 *
 * The placement is PURE (no Solid, no DOM) so it unit-tests in the `node`
 * environment; `GraphView`'s `layoutNode` calls it from the group branch when a
 * group resolves to an ARX double-round shape. It reads only `splitId`,
 * `concatId` and `ops[].nodeId`, so it is genuinely cipher-agnostic — nothing
 * here knows a rotation constant or a rail name.
 */

import type { ArxDoubleRoundShape } from "./arx-round-shape";

/** Vertical gap between stacked rows inside a quarter-round block. */
const ROW_GAP = 28;
/** Horizontal gap between the three columns of a quarter-round block. */
const COL_GAP = 40;
/** Extra horizontal separation between adjacent quarter-round blocks. */
const BLOCK_GAP = 64;
/** Extra vertical separation between the split, the two tiers, and the concat. */
const TIER_GAP = 44;

/** Operations per written line, and lines per quarter round — the block's grid. */
const OPS_PER_LINE = 3;
const LINES_PER_QUARTER_ROUND = 4;
/** Quarter rounds per tier: four that read the split, then four that don't. */
const BLOCKS_PER_TIER = 4;

/** A child's top-left offset relative to the round body's inner origin. */
export type ArxChildOffset = { readonly dx: number; readonly dy: number };

export type ArxPlacement = {
  /** Child id → offset (relative to the round body inner origin). */
  readonly offsets: ReadonlyMap<string, ArxChildOffset>;
  /** Inner content width (excludes container padding). */
  readonly bodyW: number;
  /** Inner content height (excludes header + container padding). */
  readonly bodyH: number;
};

export type ArxPlacementOpts = {
  readonly leafW: number;
  readonly leafH: number;
};

/**
 * Compute canonical slot offsets for an ARX double round's children.
 *
 * Any child the shape didn't classify is parked in a spare column to the right
 * so it can never vanish from the canvas. In practice the partition gate in
 * `analyzeArxDoubleRound` means there are none — an unclassified leaf makes the
 * whole round decline to the generic layout — but the fallback costs nothing and
 * keeps this function total.
 */
export const arxDoubleRoundPlacement = (
  shape: ArxDoubleRoundShape,
  childIds: readonly string[],
  opts: ArxPlacementOpts,
): ArxPlacement => {
  const { leafW, leafH } = opts;
  const rowH = leafH + ROW_GAP;
  const colW = leafW + COL_GAP;

  // A quarter-round block spans three columns; the trailing gap isn't part of it.
  const blockW = OPS_PER_LINE * colW - COL_GAP;
  const blockPitch = blockW + BLOCK_GAP;
  const tierH = LINES_PER_QUARTER_ROUND * rowH;

  const offsets = new Map<string, ArxChildOffset>();
  const set = (id: string, dx: number, dy: number): void => {
    offsets.set(id, { dx, dy });
  };

  // Total width is set by the four blocks of the widest tier; the split and the
  // concat center on it.
  const contentW = BLOCKS_PER_TIER * blockPitch - BLOCK_GAP;
  const centerX = Math.max(0, (contentW - leafW) / 2);

  // Row 0: the split, centered over both tiers.
  set(shape.splitId, centerX, 0);

  // The two tiers of four quarter-round blocks.
  const tierTop = (tier: number): number => rowH + TIER_GAP + tier * (tierH + TIER_GAP);
  shape.quarterRounds.forEach((qr, i) => {
    const tier = Math.floor(i / BLOCKS_PER_TIER);
    const slot = i % BLOCKS_PER_TIER;
    const blockX = slot * blockPitch;
    const blockY = tierTop(tier);
    // `ops` is in the specification's own order, so index → (column, line) lays
    // the block out as the four written lines of the quarter round.
    qr.ops.forEach((op, j) => {
      set(
        op.nodeId,
        blockX + (j % OPS_PER_LINE) * colW,
        blockY + Math.floor(j / OPS_PER_LINE) * rowH,
      );
    });
  });

  // Bottom: the concat, centered below the second tier.
  const concatY = tierTop(1) + tierH + TIER_GAP;
  set(shape.concatId, centerX, concatY);

  // Defensive: park anything the shape didn't classify rather than dropping it.
  let spareRow = 0;
  const spareX = contentW + BLOCK_GAP;
  for (const cid of childIds) {
    if (offsets.has(cid)) continue;
    set(cid, spareX, spareRow * rowH);
    spareRow += 1;
  }

  let bodyW = 0;
  let bodyH = 0;
  for (const o of offsets.values()) {
    bodyW = Math.max(bodyW, o.dx + leafW);
    bodyH = Math.max(bodyH, o.dy + leafH);
  }
  return { offsets, bodyW, bodyH };
};
