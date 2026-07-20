/**
 * Port-native **ChaCha20 quarter-round** shape analysis — the ARX sibling of
 * `feistel-shape.ts` (2-way) and `twofish-shape.ts` (4-rail).
 *
 * **Why a third recognizer.** DES/Blowfish rounds are `split → F → xor →
 * concat`; Twofish's is a 4-rail split/g/PHT/recombine. ChaCha20's round is
 * neither: it is twelve bare ARX leaves — four adds, four XORs, four rotations
 * — with no split, no concat and no group of its own. Neither existing analyzer
 * can express it, so it gets its own, and both existing paths stay
 * byte-identically untouched.
 *
 * **The structural difference that shapes this whole module.** For Twofish, one
 * group IS one round IS one canonical cell. For ChaCha20 the group is a DOUBLE
 * round containing EIGHT quarter rounds laid out flat (a quarter round consumes
 * four words, and a group body is seeded with exactly one value — see
 * `chacha20.ts`'s header). So the recognizer's unit is the double-round group,
 * and it returns eight quarter-round shapes:
 *
 * ```
 * double-round.N  (group, seeded with the 64-byte state)
 *   split-bytes[4 × 16]  → 16 words
 *   qr0..qr3   column   quarter rounds   (read the split directly)
 *   qr4..qr7   diagonal quarter rounds   (read qr0..qr3's outputs)
 *   concat[16]                            → the 64-byte state back out
 * ```
 *
 * **What lives here, and what moved.** The double-round ENVELOPE — find the
 * concat via `bodyOutput`, find the sole 16-way split, collect the eight
 * rotation anchors, run the walk, apply the partition gate — is shared with
 * Salsa20 and lives in `arx-round-shape.ts`. What stays here is the one thing
 * that is irreducibly ChaCha's: the twelve-op walk itself, because ChaCha
 * accumulates in place (`a += b; d ^= a; d <<<= 16`) while Salsa assigns into a
 * fresh rail (`z1 = y1 ^ ((y0+y3) <<< 7)`) — different dependency graphs, not a
 * reordering. So this module is an adapter: `anchorBits: 7` plus the walk.
 *
 * **Why the match is an explicit 12-leaf walk and not a backward cone.**
 * `twofish-shape.ts` cones outward from an anchor because its round is bounded
 * by a split it can stop at. That does not work here: the diagonal quarter
 * rounds consume the column quarter rounds' outputs, so a backward cone from
 * qr4's final rotation would run straight back through qr0–qr3 and swallow half
 * the double round. Instead we walk the RFC 8439 §2.1 dependency chain
 * explicitly, anchored on the `<<< 7` rotation that ends every quarter round.
 * The walk is self-bounding: it visits exactly twelve leaves and stops at the
 * four input bindings, wherever those come from.
 *
 * Every step of the walk is cross-checked against a second path to the same
 * leaf (e.g. `a_cd1` is reached both from `a_cd2`'s operand and from `x_bc1`'s),
 * so a mis-wired round fails to match rather than matching wrongly. Recognition
 * is entirely wiring-derived — no leaf ids, no spec tag — and needs no
 * direction-awareness at all, since ChaCha20's encrypt and decrypt specs are
 * structurally identical.
 *
 * The two derivations mirror the other two shape modules:
 *   - `analyzeChaChaDoubleRound(group)` — pure, spec-only. Returns the eight
 *     quarter-round descriptors, or null.
 *   - `findActiveChaChaQuarterRound(frame, spec)` — walk `frame.path` for the
 *     double round containing the active leaf, then pick the quarter round that
 *     owns it.
 */

import {
  type ArxDoubleRoundShape,
  type ArxRail,
  type ArxRailedQuarterRound,
  analyzeArxDoubleRound,
  findActiveArxQuarterRound,
  isBinary,
  partitionOperands,
  rotateBits,
  sameBinding,
  soleInput,
} from "./arx-round-shape";
import type { CipherSpec, PortBinding, StepGroup, StepLeaf, TraceFrame } from "./types";

// Primitive type strings the shape is built from. Matched by value so
// recognition is decoupled from ChaCha20's leaf ids.
const ADD_TYPE = "add-mod-32@1";
const XOR_TYPE = "xor@1";

/** Twelve ARX operations per quarter round (RFC 8439 §2.1). */
const OPS_PER_QUARTER_ROUND = 12;
/** RFC 8439 §2.1: every quarter round ends on `b <<<= 7`. That is the anchor. */
const ANCHOR_BITS = 7;

/**
 * The four words a quarter round mixes, named as RFC 8439 §2.1 names them.
 * Structurally identical to the family's positional rails.
 */
export type ChaChaRail = ArxRail;

/**
 * One of the twelve operations of a quarter round, with its role derived from
 * the wiring rather than from the leaf's id.
 *
 * `target` is the rail the result is written back to; `source` is the other
 * operand's rail. Together they let every label in the diagram
 * (`a += b`, `d ^= a`, `d <<< 16`) be generated rather than hardcoded.
 */
export type ChaChaOp =
  | {
      readonly kind: "add";
      readonly nodeId: string;
      readonly target: ChaChaRail;
      readonly source: ChaChaRail;
    }
  | {
      readonly kind: "xor";
      readonly nodeId: string;
      readonly target: ChaChaRail;
      readonly source: ChaChaRail;
    }
  | {
      readonly kind: "rotate";
      readonly nodeId: string;
      readonly target: ChaChaRail;
      readonly bits: number;
    };

/**
 * Structural descriptor of one port-native ChaCha20 quarter round. Every field
 * is derived from real child wiring, so it survives a rewire and is identical
 * for encrypt and decrypt.
 */
export type ChaChaQuarterRoundShape = ArxRailedQuarterRound<ChaChaOp> & {
  /**
   * Stable identity: the id of the final `<<< 7` rotation, which is the walk's
   * anchor and is unique per quarter round. Used as the map key and as the
   * diagram's identity across re-runs.
   */
  readonly id: string;
  /** Where each rail's value came from on entry (bindings outside this round). */
  readonly inputs: Readonly<Record<ChaChaRail, PortBinding>>;
  /** The leaf producing each rail's final value: a, b, c, d. */
  readonly outputs: Readonly<Record<ChaChaRail, string>>;
};

/**
 * Structural descriptor of a ChaCha20 DOUBLE round — the group the graph view
 * lays out, holding the eight quarter rounds it contains.
 */
export type ChaChaDoubleRoundShape = ArxDoubleRoundShape<ChaChaQuarterRoundShape>;

/**
 * Match one quarter round by walking RFC 8439 §2.1's dependency chain backwards
 * from its final `<<< 7` rotation.
 *
 * ```
 *   a += b;  d ^= a;  d <<<= 16;      (a_ab1, x_da1, r_d16)
 *   c += d;  b ^= c;  b <<<= 12;      (a_cd1, x_bc1, r_b12)
 *   a += b;  d ^= a;  d <<<= 8;       (a_ab2, x_da2, r_d8)
 *   c += d;  b ^= c;  b <<<= 7;       (a_cd2, x_bc2, r_b7)  ← anchor
 * ```
 *
 * The walk order below is chosen so each unknown is pinned by a leaf already
 * identified, never by operand position — which is what makes it robust to a
 * user swapping an XOR's two inputs, and what lets each of the four input
 * bindings be identified as "the operand that ISN'T the one we already know".
 */
const matchQuarterRound = (
  anchor: StepLeaf,
  byId: ReadonlyMap<string, StepLeaf>,
): ChaChaQuarterRoundShape | null => {
  const leafOf = (b: PortBinding): StepLeaf | undefined => byId.get(b.node);

  // ── line 4: c += d; b ^= c; b <<<= 7 ──────────────────────────────────
  const r_b7 = anchor; // by construction: rotate-left, bits 7
  const b7In = soleInput(r_b7);
  if (!b7In) return null;
  const x_bc2 = leafOf(b7In);
  if (!isBinary(x_bc2, XOR_TYPE) || x_bc2 === undefined) return null;

  // x_bc2 = b ^ c, where b arrived via `<<< 12` and c via the second c-add.
  const bc2 = partitionOperands(x_bc2, (b) => rotateBits(leafOf(b)) === 12);
  if (!bc2) return null;
  const r_b12 = leafOf(bc2.matched);
  const a_cd2 = leafOf(bc2.other);
  if (r_b12 === undefined || !isBinary(a_cd2, ADD_TYPE) || a_cd2 === undefined) return null;

  // ── line 3: a += b; d ^= a; d <<<= 8 ──────────────────────────────────
  const cd2 = partitionOperands(a_cd2, (b) => rotateBits(leafOf(b)) === 8);
  if (!cd2) return null;
  const r_d8 = leafOf(cd2.matched);
  const a_cd1 = leafOf(cd2.other);
  if (r_d8 === undefined || !isBinary(a_cd1, ADD_TYPE) || a_cd1 === undefined) return null;

  const d8In = soleInput(r_d8);
  if (!d8In) return null;
  const x_da2 = leafOf(d8In);
  if (!isBinary(x_da2, XOR_TYPE) || x_da2 === undefined) return null;

  const da2 = partitionOperands(x_da2, (b) => rotateBits(leafOf(b)) === 16);
  if (!da2) return null;
  const r_d16 = leafOf(da2.matched);
  const a_ab2 = leafOf(da2.other);
  if (r_d16 === undefined || !isBinary(a_ab2, ADD_TYPE) || a_ab2 === undefined) return null;

  // ── lines 1–2, and the four inputs ────────────────────────────────────
  const b12In = soleInput(r_b12);
  const d16In = soleInput(r_d16);
  if (!b12In || !d16In) return null;
  const x_bc1 = leafOf(b12In);
  const x_da1 = leafOf(d16In);
  if (!isBinary(x_bc1, XOR_TYPE) || x_bc1 === undefined) return null;
  if (!isBinary(x_da1, XOR_TYPE) || x_da1 === undefined) return null;

  // a_ab2 = a_ab1 + (b after <<< 12). The rotate side is already known, so the
  // other operand pins a_ab1 — no reliance on which operand index it occupies.
  const ab2 = partitionOperands(a_ab2, (b) => b.node === r_b12.id);
  if (!ab2) return null;
  const a_ab1 = leafOf(ab2.other);
  if (!isBinary(a_ab1, ADD_TYPE) || a_ab1 === undefined) return null;

  // a_cd1 = c_in + (d after <<< 16) → the non-rotate operand IS c's input.
  const cd1 = partitionOperands(a_cd1, (b) => b.node === r_d16.id);
  if (!cd1) return null;
  const cIn = cd1.other;

  // x_bc1 = b_in ^ (c after the first c-add) → the other operand is b's input.
  const bc1 = partitionOperands(x_bc1, (b) => b.node === a_cd1.id);
  if (!bc1) return null;
  const bIn = bc1.other;

  // x_da1 = d_in ^ (a after the first a-add) → the other operand is d's input.
  const da1 = partitionOperands(x_da1, (b) => b.node === a_ab1.id);
  if (!da1) return null;
  const dIn = da1.other;

  // a_ab1 = a_in + b_in. b's input is already known, so the other operand is a's.
  const ab1 = partitionOperands(a_ab1, (b) => sameBinding(b, bIn));
  if (!ab1) return null;
  const aIn = ab1.other;

  // Twelve DISTINCT leaves, or this isn't a quarter round — a degenerate
  // self-referential wiring could otherwise satisfy every check above.
  const members = [
    a_ab1,
    x_da1,
    r_d16,
    a_cd1,
    x_bc1,
    r_b12,
    a_ab2,
    x_da2,
    r_d8,
    a_cd2,
    x_bc2,
    r_b7,
  ];
  const memberIds = members.map((l) => l.id);
  if (new Set(memberIds).size !== OPS_PER_QUARTER_ROUND) return null;

  // The op list, in the RFC's own order. Targets and sources are structural
  // facts of the shape we just matched, so every diagram label derives from here.
  const ops: ChaChaOp[] = [
    { kind: "add", nodeId: a_ab1.id, target: "a", source: "b" },
    { kind: "xor", nodeId: x_da1.id, target: "d", source: "a" },
    { kind: "rotate", nodeId: r_d16.id, target: "d", bits: 16 },
    { kind: "add", nodeId: a_cd1.id, target: "c", source: "d" },
    { kind: "xor", nodeId: x_bc1.id, target: "b", source: "c" },
    { kind: "rotate", nodeId: r_b12.id, target: "b", bits: 12 },
    { kind: "add", nodeId: a_ab2.id, target: "a", source: "b" },
    { kind: "xor", nodeId: x_da2.id, target: "d", source: "a" },
    { kind: "rotate", nodeId: r_d8.id, target: "d", bits: 8 },
    { kind: "add", nodeId: a_cd2.id, target: "c", source: "d" },
    { kind: "xor", nodeId: x_bc2.id, target: "b", source: "c" },
    { kind: "rotate", nodeId: r_b7.id, target: "b", bits: 7 },
  ];

  return {
    id: r_b7.id,
    memberIds,
    ops,
    inputs: { a: aIn, b: bIn, c: cIn, d: dIn },
    outputs: { a: a_ab2.id, b: r_b7.id, c: a_cd2.id, d: r_d8.id },
  };
};

/**
 * Analyze a `group` and return its ChaCha20 double-round structure, or null if
 * the wiring doesn't match. Pure (spec-only — no trace).
 *
 * Returns null gracefully for every other cipher's rounds and for a
 * half-edited ChaCha round, so the caller falls back to the generic vertical
 * stack rather than rendering a broken cell. The envelope's partition gate does
 * that work; see `analyzeArxDoubleRound`.
 */
export const analyzeChaChaDoubleRound = (group: StepGroup): ChaChaDoubleRoundShape | null =>
  analyzeArxDoubleRound(group, { anchorBits: ANCHOR_BITS, matchQuarterRound });

/**
 * Resolve the ChaCha20 quarter round containing the active frame. Walks the
 * frame's group-ancestor `path` innermost → outermost for a double round that
 * analyzes cleanly, then picks the quarter round owning the active leaf.
 *
 * Returns null when the active leaf is the split or the concat: those belong to
 * the double round as a whole, not to any one quarter round, so there is no
 * single quarter round for the diagram to draw.
 */
export const findActiveChaChaQuarterRound = (
  frame: TraceFrame,
  spec: CipherSpec,
): {
  group: StepGroup;
  round: ChaChaDoubleRoundShape;
  quarterRound: ChaChaQuarterRoundShape;
  /** 0-based position within the double round: 0–3 column, 4–7 diagonal. */
  quarterRoundIndex: number;
} | null => findActiveArxQuarterRound(frame, spec, analyzeChaChaDoubleRound);
