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

import { findStepAndParent } from "./spec-mutations";
import { canonicalStepId } from "./step-id";
import type { CipherSpec, PortBinding, StepGroup, StepLeaf, TraceFrame } from "./types";

// Primitive type strings the shape is built from. Matched by value so
// recognition is decoupled from ChaCha20's leaf ids.
const SPLIT_TYPE = "split-bytes@1";
const CONCAT_TYPE = "concat@1";
const ADD_TYPE = "add-mod-32@1";
const XOR_TYPE = "xor@1";
const ROTL_TYPE = "rotate-bits-left@1";

/** ChaCha20's state is sixteen 32-bit words. */
const STATE_WORDS = 16;
/** RFC 8439 §2.3.1: four column quarter rounds then four diagonal ones. */
const QUARTER_ROUNDS_PER_DOUBLE_ROUND = 8;
/** Twelve ARX operations per quarter round (RFC 8439 §2.1). */
const OPS_PER_QUARTER_ROUND = 12;

/** The four words a quarter round mixes, named as RFC 8439 §2.1 names them. */
export type ChaChaRail = "a" | "b" | "c" | "d";

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
export type ChaChaQuarterRoundShape = {
  /**
   * Stable identity: the id of the final `<<< 7` rotation, which is the walk's
   * anchor and is unique per quarter round. Used as the map key and as the
   * diagram's identity across re-runs.
   */
  readonly id: string;
  /** All twelve member leaves, in spec order. */
  readonly memberIds: readonly string[];
  /** The twelve operations in RFC 8439 §2.1 order — four lines of three. */
  readonly ops: readonly ChaChaOp[];
  /** Where each rail's value came from on entry (bindings outside this round). */
  readonly inputs: Readonly<Record<ChaChaRail, PortBinding>>;
  /** The leaf producing each rail's final value: a, b, c, d. */
  readonly outputs: Readonly<Record<ChaChaRail, string>>;
};

/**
 * Structural descriptor of a ChaCha20 DOUBLE round — the group the graph view
 * lays out, holding the eight quarter rounds it contains.
 */
export type ChaChaDoubleRoundShape = {
  /** The double-round group's id, e.g. "double-round.3". */
  readonly roundId: string;
  /** The 16-way `split-bytes@1` leaf producing the state's words. */
  readonly splitId: string;
  /** The 16-input `concat@1` leaf reassembling the state (= `bodyOutput`). */
  readonly concatId: string;
  /** Concat output port (= `group.bodyOutput.port`). */
  readonly concatOutPort: string;
  /** The eight quarter rounds, in spec order: four column, then four diagonal. */
  readonly quarterRounds: readonly ChaChaQuarterRoundShape[];
};

// ─── Local helpers (deliberately re-declared rather than shared, so the two
// existing shape modules stay untouched — they are trivial pure narrowers). ──

/** Narrow a `Json` params value to a string-keyed record, or null. */
const asRecord = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

/** Read a numeric leaf param, or undefined. */
const paramNumber = (leaf: StepLeaf, key: string): number | undefined => {
  const v = asRecord(leaf.params)?.[key];
  return typeof v === "number" ? v : undefined;
};

/** The port-input bindings of a leaf, or an empty record. */
const portInputsOf = (leaf: StepLeaf): Record<string, PortBinding> => leaf.portInputs ?? {};

/** Step (leaf) children of a group, in spec order. */
const leafChildren = (group: StepGroup): readonly StepLeaf[] =>
  group.children.filter((c): c is StepLeaf => c.kind === "step");

/** Two bindings name the same value iff both node and port agree. */
const sameBinding = (x: PortBinding, y: PortBinding): boolean =>
  x.node === y.node && x.port === y.port;

/** The rotation amount of a left-rotate leaf, or undefined if it isn't one. */
const rotateBits = (leaf: StepLeaf | undefined): number | undefined =>
  leaf !== undefined && leaf.type === ROTL_TYPE ? paramNumber(leaf, "bits") : undefined;

/** True iff `leaf` is a 2-input leaf of `type`. */
const isBinary = (leaf: StepLeaf | undefined, type: string): boolean =>
  leaf !== undefined && leaf.type === type && paramNumber(leaf, "inputCount") === 2;

/** The two operand bindings of a binary leaf, or null if it doesn't have two. */
const operandPair = (leaf: StepLeaf): readonly [PortBinding, PortBinding] | null => {
  const ops = Object.values(portInputsOf(leaf));
  return ops.length === 2 ? [ops[0] as PortBinding, ops[1] as PortBinding] : null;
};

/**
 * Split a binary leaf's operands into (the one matching `pick`, the other).
 * Returns null when neither or both match — either way the wiring isn't the
 * shape we're matching, so the caller bails to the generic layout.
 */
const partitionOperands = (
  leaf: StepLeaf,
  pick: (b: PortBinding) => boolean,
): { readonly matched: PortBinding; readonly other: PortBinding } | null => {
  const pair = operandPair(leaf);
  if (!pair) return null;
  const [first, second] = pair;
  const firstMatches = pick(first);
  const secondMatches = pick(second);
  if (firstMatches === secondMatches) return null; // neither, or ambiguous
  return firstMatches ? { matched: first, other: second } : { matched: second, other: first };
};

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
  const soleInput = (leaf: StepLeaf): PortBinding | undefined => {
    const ins = Object.values(portInputsOf(leaf));
    return ins.length === 1 ? ins[0] : undefined;
  };

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
 * stack rather than rendering a broken cell.
 *
 * The final PARTITION check is the real validity gate: the eight quarter-round
 * walks must together cover every leaf of the group except the split and the
 * concat, exactly once. A user who rewires one operation therefore drops the
 * whole double round to the generic layout instead of leaving a cell with a
 * silently orphaned leaf.
 */
export const analyzeChaChaDoubleRound = (group: StepGroup): ChaChaDoubleRoundShape | null => {
  if (group.kind !== "group") return null;
  const bodyOutput = group.bodyOutput;
  if (!bodyOutput) return null;

  const leaves = leafChildren(group);
  const byId = new Map(leaves.map((l) => [l.id, l] as const));

  // 1. The concat is the bodyOutput target, and must reassemble all 16 words.
  const concat = byId.get(bodyOutput.node);
  if (!concat || concat.type !== CONCAT_TYPE) return null;
  if (paramNumber(concat, "inputCount") !== STATE_WORDS) return null;

  // 2. Exactly one 16-way split — the state's decomposition into words.
  const splits = leaves.filter((l) => {
    if (l.type !== SPLIT_TYPE) return false;
    const widths = asRecord(l.params)?.widths;
    return Array.isArray(widths) && widths.length === STATE_WORDS;
  });
  if (splits.length !== 1) return null;
  const split = splits[0] as StepLeaf;

  // 3. Eight anchors: the `<<< 7` rotations that end each quarter round.
  const anchors = leaves.filter((l) => rotateBits(l) === 7);
  if (anchors.length !== QUARTER_ROUNDS_PER_DOUBLE_ROUND) return null;

  const quarterRounds: ChaChaQuarterRoundShape[] = [];
  for (const anchor of anchors) {
    const qr = matchQuarterRound(anchor, byId);
    if (!qr) return null;
    quarterRounds.push(qr);
  }

  // 4. Partition gate: the eight walks must tile the group's leaves exactly,
  //    with the split and concat the only non-members. Overlap or leftovers
  //    mean this is not (or is no longer) a canonical double round.
  const claimed = new Set<string>();
  for (const qr of quarterRounds) {
    for (const id of qr.memberIds) {
      if (claimed.has(id)) return null; // two quarter rounds claim one leaf
      claimed.add(id);
    }
  }
  if (claimed.size !== QUARTER_ROUNDS_PER_DOUBLE_ROUND * OPS_PER_QUARTER_ROUND) return null;
  for (const leaf of leaves) {
    if (leaf.id === split.id || leaf.id === concat.id) continue;
    if (!claimed.has(leaf.id)) return null; // an unclaimed leaf — not our shape
  }

  return {
    roundId: group.id,
    splitId: split.id,
    concatId: concat.id,
    concatOutPort: bodyOutput.port,
    quarterRounds,
  };
};

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
} | null => {
  const activeLeaf = canonicalStepId(frame.stepId);
  for (let i = frame.path.length - 1; i >= 0; i--) {
    const id = frame.path[i];
    if (id === undefined) continue;
    const located = findStepAndParent(spec, id);
    if (!located) continue;
    const node = located.node;
    if (node.kind !== "group") continue;
    const round = analyzeChaChaDoubleRound(node);
    if (!round) continue;
    const index = round.quarterRounds.findIndex((qr) => qr.memberIds.includes(activeLeaf));
    if (index < 0) continue;
    return {
      group: node,
      round,
      quarterRound: round.quarterRounds[index] as ChaChaQuarterRoundShape,
      quarterRoundIndex: index,
    };
  }
  return null;
};
