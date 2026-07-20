/**
 * Port-native **Salsa20 quarter-round** shape analysis — the second consumer of
 * the ARX family machinery in `arx-round-shape.ts`, alongside `chacha-shape.ts`.
 *
 * **What is shared, and what is not.** The double-round ENVELOPE is shared and
 * lives in `arx-round-shape.ts`: find the concat via `bodyOutput`, find the sole
 * 16-way split, collect the eight rotation anchors, run the walk, apply the
 * partition gate. What lives here is the one thing that is irreducibly Salsa's —
 * the twelve-op walk — because the two ciphers have genuinely different
 * dependency graphs, not a reordering of the same three tokens:
 *
 * ```
 * ChaCha   a += b;  d ^= a;  d <<<= 16        in-place accumulate
 * Salsa    z1 = y1 ^ ((y0 + y3) <<<  7)       add → rotate → xor into a FRESH rail
 * ```
 *
 * **Bernstein's quarterround, the four written lines this walk recognizes:**
 *
 * ```
 *   z1 = y1 ^ ((y0 + y3) <<<  7)      (add7,  rot7,  xor7 )
 *   z2 = y2 ^ ((z1 + y0) <<<  9)      (add9,  rot9,  xor9 )
 *   z3 = y3 ^ ((z2 + z1) <<< 13)      (add13, rot13, xor13)
 *   z0 = y0 ^ ((z3 + z2) <<< 18)      (add18, rot18, xor18)
 * ```
 *
 * The rails are the family's positional a/b/c/d, mapped onto Bernstein's names
 * as a=y0, b=y1, c=y2, d=y3. Each of the four words is written exactly ONCE, by
 * its line's XOR — which is the structural difference from ChaCha, where each
 * rail is mutated three or four times.
 *
 * **Anchor: the `<<< 18`.** Rotation constants 7/9/13/18 are distinct within a
 * quarter round, so the last line's rotate identifies exactly one quarter round
 * and there are exactly eight of them per double round — the same discipline as
 * ChaCha's `<<< 7`, with a different constant, which is precisely what
 * `anchorBits` was parameterized for.
 *
 * **One asymmetry the ChaCha walk does not have.** ChaCha's anchor ENDS its
 * quarter round, so a purely backward walk reaches all twelve leaves. Salsa's
 * terminal operation is the XOR, and the anchor rotate feeds it — so `xor18` is
 * found by a forward consumer scan and everything else by walking backwards.
 * Miss it and the envelope's partition gate correctly refuses the whole round.
 *
 * Every unknown is pinned by an already-identified leaf, never by operand
 * position, so a user who swaps an XOR's two (commutative) operands still gets a
 * recognized round. Recognition is entirely wiring-derived — no leaf ids, no spec
 * tag — and needs no direction-awareness, since Salsa20's encrypt and decrypt
 * specs are structurally identical.
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
// recognition is decoupled from Salsa20's leaf ids.
const ADD_TYPE = "add-mod-32@1";
const XOR_TYPE = "xor@1";

/** Twelve ARX operations per quarter round — four written lines of three. */
const OPS_PER_QUARTER_ROUND = 12;
/** Bernstein's quarterround ends on `z0 = y0 ^ (… <<< 18)`. That is the anchor. */
const ANCHOR_BITS = 18;

/**
 * The four words a quarter round mixes. Structurally the family's positional
 * rails; the diagram module prints them as Bernstein's y0..y3.
 */
export type SalsaRail = ArxRail;

/**
 * One of the twelve operations of a quarter round, with its role derived from
 * the wiring rather than from the leaf's id.
 *
 * Every op carries its LINE's rotation constant (`bits`), because 7/9/13/18
 * identify the four written lines and are what let the diagram assemble
 * `z1 = y1 ^ ((y0 + y3) <<< 7)` from three separate leaves.
 */
export type SalsaOp =
  | {
      /** `y_srcA + y_srcB` — the sum that is about to be rotated. */
      readonly kind: "add";
      readonly nodeId: string;
      readonly srcA: SalsaRail;
      readonly srcB: SalsaRail;
      readonly bits: number;
    }
  | {
      /** The rotate of that sum. Writes to no state word — a scratch rail. */
      readonly kind: "rotate";
      readonly nodeId: string;
      readonly bits: number;
    }
  | {
      /** The only op of the line that writes back: `y_target ^= rotated`. */
      readonly kind: "xor";
      readonly nodeId: string;
      readonly target: SalsaRail;
      readonly bits: number;
    };

/**
 * Structural descriptor of one port-native Salsa20 quarter round. Every field is
 * derived from real child wiring, so it survives a rewire and is identical for
 * encrypt and decrypt.
 */
export type SalsaQuarterRoundShape = ArxRailedQuarterRound<SalsaOp> & {
  /**
   * Stable identity: the id of the final `<<< 18` rotation, which is the walk's
   * anchor and is unique per quarter round.
   */
  readonly id: string;
  /** Where each rail's value came from on entry (bindings outside this round). */
  readonly inputs: Readonly<Record<SalsaRail, PortBinding>>;
  /** The leaf producing each rail's final value — always that rail's own XOR. */
  readonly outputs: Readonly<Record<SalsaRail, string>>;
};

/**
 * Structural descriptor of a Salsa20 DOUBLE round — the group the graph view
 * lays out, holding the eight quarter rounds it contains (four column, four row).
 */
export type SalsaDoubleRoundShape = ArxDoubleRoundShape<SalsaQuarterRoundShape>;

/**
 * The rotation constant *inside* a Salsa line, reached through that line's XOR.
 *
 * This is the bootstrap the ChaCha walk does not need. `add18`'s two operands
 * are both XORs (`z3` and `z2`), so they cannot be told apart by looking at them
 * directly — only by reaching through each to the rotate it consumes, whose bits
 * name the line. Returns undefined for anything that is not `x ^ ROL(...)`.
 */
const xorLineBits = (
  leaf: StepLeaf | undefined,
  leafOf: (b: PortBinding) => StepLeaf | undefined,
): number | undefined => {
  if (!isBinary(leaf, XOR_TYPE) || leaf === undefined) return undefined;
  const split = partitionOperands(leaf, (b) => rotateBits(leafOf(b)) !== undefined);
  if (!split) return undefined;
  return rotateBits(leafOf(split.matched));
};

/**
 * Match one quarter round by walking Bernstein's four lines backwards from the
 * `<<< 18` that ends the last of them.
 *
 * The walk order is chosen so each unknown is pinned by a leaf already
 * identified, never by operand position — which is what makes it robust to a
 * user swapping a commutative operand pair, and what lets each of the four input
 * bindings be identified as "the operand that ISN'T the one we already know".
 */
const matchQuarterRound = (
  anchor: StepLeaf,
  byId: ReadonlyMap<string, StepLeaf>,
): SalsaQuarterRoundShape | null => {
  const leafOf = (b: PortBinding): StepLeaf | undefined => byId.get(b.node);

  // ── line 4: z0 = y0 ^ ((z3 + z2) <<< 18) ──────────────────────────────
  const rot18 = anchor; // by construction: rotate-left, bits 18
  const rot18In = soleInput(rot18);
  if (!rot18In) return null;
  const add18 = leafOf(rot18In);
  if (!isBinary(add18, ADD_TYPE) || add18 === undefined) return null;

  // Both operands are XORs (z3 and z2), so discriminate by the rotation each
  // one consumed — the one bootstrap that cannot use an already-known leaf.
  const l4 = partitionOperands(add18, (b) => xorLineBits(leafOf(b), leafOf) === 13);
  if (!l4) return null;
  const xor13 = leafOf(l4.matched);
  const xor9 = leafOf(l4.other);
  if (xor13 === undefined || xor9 === undefined) return null;
  if (xorLineBits(xor9, leafOf) !== 9) return null;

  // ── line 3: z3 = y3 ^ ((z2 + z1) <<< 13) ──────────────────────────────
  const l3xor = partitionOperands(xor13, (b) => rotateBits(leafOf(b)) === 13);
  if (!l3xor) return null;
  const rot13 = leafOf(l3xor.matched);
  const y3In = l3xor.other; // the state word this line writes back into
  if (rot13 === undefined) return null;

  const rot13In = soleInput(rot13);
  if (!rot13In) return null;
  const add13 = leafOf(rot13In);
  if (!isBinary(add13, ADD_TYPE) || add13 === undefined) return null;

  // add13 = z2 + z1. z2 (= xor9) is known, so the other operand pins z1.
  const l3add = partitionOperands(add13, (b) => b.node === xor9.id);
  if (!l3add) return null;
  const xor7 = leafOf(l3add.other);
  if (!isBinary(xor7, XOR_TYPE) || xor7 === undefined) return null;

  // ── line 2: z2 = y2 ^ ((z1 + y0) <<< 9) ───────────────────────────────
  const l2xor = partitionOperands(xor9, (b) => rotateBits(leafOf(b)) === 9);
  if (!l2xor) return null;
  const rot9 = leafOf(l2xor.matched);
  const y2In = l2xor.other;
  if (rot9 === undefined) return null;

  const rot9In = soleInput(rot9);
  if (!rot9In) return null;
  const add9 = leafOf(rot9In);
  if (!isBinary(add9, ADD_TYPE) || add9 === undefined) return null;

  // add9 = z1 + y0. z1 (= xor7) is known, so the other operand IS y0's input —
  // the only place rail a's entry binding can be read from.
  const l2add = partitionOperands(add9, (b) => b.node === xor7.id);
  if (!l2add) return null;
  const y0In = l2add.other;

  // ── line 1: z1 = y1 ^ ((y0 + y3) <<< 7) ───────────────────────────────
  const l1xor = partitionOperands(xor7, (b) => rotateBits(leafOf(b)) === 7);
  if (!l1xor) return null;
  const rot7 = leafOf(l1xor.matched);
  const y1In = l1xor.other;
  if (rot7 === undefined) return null;

  const rot7In = soleInput(rot7);
  if (!rot7In) return null;
  const add7 = leafOf(rot7In);
  if (!isBinary(add7, ADD_TYPE) || add7 === undefined) return null;

  // add7 = y0 + y3, and BOTH are already known — so this is pure cross-check:
  // a round whose first line reads anything else is not this shape.
  const l1add = partitionOperands(add7, (b) => sameBinding(b, y0In));
  if (!l1add) return null;
  if (!sameBinding(l1add.other, y3In)) return null;

  // ── the anchor's consumer: z0 = y0 ^ (rot18) ──────────────────────────
  // Salsa's terminal op is the XOR, not the rotate, so this one leaf is reached
  // FORWARD. Without it the round is 11 leaves and the partition gate refuses.
  const xor18Candidates = [...byId.values()].filter(
    (l) =>
      isBinary(l, XOR_TYPE) && Object.values(l.portInputs ?? {}).some((b) => b.node === rot18.id),
  );
  if (xor18Candidates.length !== 1) return null;
  const xor18 = xor18Candidates[0] as StepLeaf;
  const l4xor = partitionOperands(xor18, (b) => b.node === rot18.id);
  if (!l4xor) return null;
  if (!sameBinding(l4xor.other, y0In)) return null;

  // Twelve DISTINCT leaves, or this isn't a quarter round — a degenerate
  // self-referential wiring could otherwise satisfy every check above.
  const members = [add7, rot7, xor7, add9, rot9, xor9, add13, rot13, xor13, add18, rot18, xor18];
  const memberIds = members.map((l) => l.id);
  if (new Set(memberIds).size !== OPS_PER_QUARTER_ROUND) return null;

  // The op list, in Bernstein's own written order — four lines of three. The
  // rails on each op are structural facts of the shape just matched, so every
  // diagram label derives from here rather than being hardcoded downstream.
  const ops: SalsaOp[] = [
    { kind: "add", nodeId: add7.id, srcA: "a", srcB: "d", bits: 7 },
    { kind: "rotate", nodeId: rot7.id, bits: 7 },
    { kind: "xor", nodeId: xor7.id, target: "b", bits: 7 },
    { kind: "add", nodeId: add9.id, srcA: "b", srcB: "a", bits: 9 },
    { kind: "rotate", nodeId: rot9.id, bits: 9 },
    { kind: "xor", nodeId: xor9.id, target: "c", bits: 9 },
    { kind: "add", nodeId: add13.id, srcA: "c", srcB: "b", bits: 13 },
    { kind: "rotate", nodeId: rot13.id, bits: 13 },
    { kind: "xor", nodeId: xor13.id, target: "d", bits: 13 },
    { kind: "add", nodeId: add18.id, srcA: "d", srcB: "c", bits: 18 },
    { kind: "rotate", nodeId: rot18.id, bits: 18 },
    { kind: "xor", nodeId: xor18.id, target: "a", bits: 18 },
  ];

  return {
    id: rot18.id,
    memberIds,
    ops,
    inputs: { a: y0In, b: y1In, c: y2In, d: y3In },
    // Each word is written exactly once, by its own line's XOR. The anchor
    // rotate is no rail's output — it lives on a scratch rail.
    outputs: { a: xor18.id, b: xor7.id, c: xor9.id, d: xor13.id },
  };
};

/**
 * Analyze a `group` and return its Salsa20 double-round structure, or null if
 * the wiring doesn't match. Pure (spec-only — no trace).
 *
 * Returns null gracefully for every other cipher's rounds and for a half-edited
 * Salsa round, so the caller falls back to the generic vertical stack rather
 * than rendering a broken cell. The envelope's partition gate does that work;
 * see `analyzeArxDoubleRound`.
 */
export const analyzeSalsaDoubleRound = (group: StepGroup): SalsaDoubleRoundShape | null =>
  analyzeArxDoubleRound(group, { anchorBits: ANCHOR_BITS, matchQuarterRound });

/**
 * Resolve the Salsa20 quarter round containing the active frame. Walks the
 * frame's group-ancestor `path` innermost → outermost for a double round that
 * analyzes cleanly, then picks the quarter round owning the active leaf.
 *
 * Returns null when the active leaf is the split or the concat: those belong to
 * the double round as a whole, not to any one quarter round, so there is no
 * single quarter round for the diagram to draw.
 */
export const findActiveSalsaQuarterRound = (
  frame: TraceFrame,
  spec: CipherSpec,
): {
  group: StepGroup;
  round: SalsaDoubleRoundShape;
  quarterRound: SalsaQuarterRoundShape;
  /** 0-based position within the double round: 0–3 column, 4–7 row. */
  quarterRoundIndex: number;
} | null => findActiveArxQuarterRound(frame, spec, analyzeSalsaDoubleRound);
