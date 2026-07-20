/**
 * Generic **ARX double-round** shape machinery — the shared spine behind
 * `chacha-shape.ts` and (from S3) `salsa-shape.ts`.
 *
 * **Why this module exists.** ChaCha20 and Salsa20 are the same designer's same
 * family: a 4×4 word state, a double round of eight quarter rounds, each quarter
 * round twelve add/rotate/xor operations, the whole thing wrapped in a group
 * that splits 64 bytes into sixteen words and concats them back. Everything in
 * that sentence is shared. What is NOT shared is the twelve-op dependency chain
 * itself:
 *
 * ```
 * ChaCha  a += b;  d ^= a;  d <<<= 16      in-place accumulate; each op mutates a named rail
 * Salsa   z1 = y1 ^ ((y0 + y3) <<< 7)      add → rotate → xor into a FRESH rail
 * ```
 *
 * Those are different dependency graphs, not a reordering of three tokens, so
 * the walk is irreducibly per-cipher. The seam therefore cuts AROUND the walk:
 * this module owns the envelope (find the concat, find the split, collect the
 * anchors, run the caller's walk, apply the partition gate) and the per-cipher
 * module owns the walk plus every label. That is the maximal honest sharing —
 * the alternative, a token-order parameter, would have to lie about the wiring.
 *
 * **Typing strategy.** The envelope is generic in the quarter-round descriptor,
 * constrained only to what the envelope and the layout actually read (`id`,
 * `memberIds`, `ops[].nodeId`). A cipher's richer descriptor — ChaCha's
 * target/source rails, Salsa's fresh-rail assignments — rides along untouched
 * and comes back out of `analyzeArxDoubleRound` fully typed, because `Q` infers
 * through the `matchQuarterRound` callback. So `ChaChaDoubleRoundShape` is a
 * plain alias, and no existing consumer or test changes.
 */

import { findStepAndParent } from "./spec-mutations";
import { canonicalStepId } from "./step-id";
import type { CipherSpec, PortBinding, StepGroup, StepLeaf, TraceFrame } from "./types";

// Primitive type strings the shapes are built from. Matched by value so
// recognition is decoupled from any cipher's leaf ids.
const SPLIT_TYPE = "split-bytes@1";
const CONCAT_TYPE = "concat@1";
const ROTL_TYPE = "rotate-bits-left@1";

/** Both ciphers' state is sixteen 32-bit words. */
export const ARX_STATE_WORDS = 16;
/** Eight quarter rounds per double round (ChaCha: column+diagonal; Salsa: column+row). */
export const ARX_QUARTER_ROUNDS_PER_DOUBLE_ROUND = 8;
/** Twelve ARX operations per quarter round — four written lines of three. */
export const ARX_OPS_PER_QUARTER_ROUND = 12;

/**
 * The four rails a quarter round mixes, named positionally. ChaCha's RFC calls
 * them a/b/c/d; Salsa's paper calls them y0..y3 — the per-cipher diagram module
 * supplies the printed name, so the structural type stays one shape.
 */
export type ArxRail = "a" | "b" | "c" | "d";

/** The four rails in order, top to bottom. */
export const ARX_RAILS: readonly ArxRail[] = ["a", "b", "c", "d"];

/** The one thing every ARX operation must expose: the leaf it was matched to. */
export type ArxOpBase = { readonly nodeId: string };

/**
 * The minimum a quarter-round descriptor must carry for the envelope's
 * partition gate and the canonical layout to work. Ciphers extend it.
 */
export type ArxQuarterRoundShape<O extends ArxOpBase = ArxOpBase> = {
  /** Stable identity — by convention the anchor rotation's leaf id. */
  readonly id: string;
  /** All twelve member leaves. */
  readonly memberIds: readonly string[];
  /** The twelve operations, in the order the cipher's own spec writes them. */
  readonly ops: readonly O[];
};

/**
 * A quarter round that additionally names where each rail came from and which
 * leaf produced its final value. Required by `deriveArxWordIndices`; both
 * shipped ciphers satisfy it.
 */
export type ArxRailedQuarterRound<O extends ArxOpBase = ArxOpBase> = ArxQuarterRoundShape<O> & {
  /** Where each rail's value came from on entry (bindings outside this round). */
  readonly inputs: Readonly<Record<ArxRail, PortBinding>>;
  /** The leaf producing each rail's final value. */
  readonly outputs: Readonly<Record<ArxRail, string>>;
};

/**
 * Structural descriptor of an ARX DOUBLE round — the group the graph view lays
 * out, holding the eight quarter rounds it contains.
 */
export type ArxDoubleRoundShape<Q extends ArxQuarterRoundShape = ArxQuarterRoundShape> = {
  /** The double-round group's id, e.g. "double-round.3". */
  readonly roundId: string;
  /** The 16-way `split-bytes@1` leaf producing the state's words. */
  readonly splitId: string;
  /** The 16-input `concat@1` leaf reassembling the state (= `bodyOutput`). */
  readonly concatId: string;
  /** Concat output port (= `group.bodyOutput.port`). */
  readonly concatOutPort: string;
  /** The eight quarter rounds, in spec order: first tier, then second tier. */
  readonly quarterRounds: readonly Q[];
};

// ─── Pure narrowing helpers, shared by every ARX walk ──────────────────────

/** Narrow a `Json` params value to a string-keyed record, or null. */
export const asRecord = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

/** Read a numeric leaf param, or undefined. */
export const paramNumber = (leaf: StepLeaf, key: string): number | undefined => {
  const v = asRecord(leaf.params)?.[key];
  return typeof v === "number" ? v : undefined;
};

/** The port-input bindings of a leaf, or an empty record. */
export const portInputsOf = (leaf: StepLeaf): Record<string, PortBinding> => leaf.portInputs ?? {};

/** Step (leaf) children of a group, in spec order. */
export const leafChildren = (group: StepGroup): readonly StepLeaf[] =>
  group.children.filter((c): c is StepLeaf => c.kind === "step");

/** Two bindings name the same value iff both node and port agree. */
export const sameBinding = (x: PortBinding, y: PortBinding): boolean =>
  x.node === y.node && x.port === y.port;

/** The rotation amount of a left-rotate leaf, or undefined if it isn't one. */
export const rotateBits = (leaf: StepLeaf | undefined): number | undefined =>
  leaf !== undefined && leaf.type === ROTL_TYPE ? paramNumber(leaf, "bits") : undefined;

/** True iff `leaf` is a 2-input leaf of `type`. */
export const isBinary = (leaf: StepLeaf | undefined, type: string): boolean =>
  leaf !== undefined && leaf.type === type && paramNumber(leaf, "inputCount") === 2;

/** The two operand bindings of a binary leaf, or null if it doesn't have two. */
export const operandPair = (leaf: StepLeaf): readonly [PortBinding, PortBinding] | null => {
  const ops = Object.values(portInputsOf(leaf));
  return ops.length === 2 ? [ops[0] as PortBinding, ops[1] as PortBinding] : null;
};

/**
 * Split a binary leaf's operands into (the one matching `pick`, the other).
 * Returns null when neither or both match — either way the wiring isn't the
 * shape we're matching, so the caller bails to the generic layout.
 */
export const partitionOperands = (
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

/** The sole port input of a leaf, or undefined when it has 0 or ≥2. */
export const soleInput = (leaf: StepLeaf): PortBinding | undefined => {
  const ins = Object.values(portInputsOf(leaf));
  return ins.length === 1 ? ins[0] : undefined;
};

// ─── The envelope ───────────────────────────────────────────────────────────

export type ArxDoubleRoundOptions<Q extends ArxQuarterRoundShape> = {
  /**
   * The rotation amount that ENDS a quarter round — the walk's anchor, and the
   * only structural constant that differs between the two ciphers' envelopes
   * (ChaCha `<<< 7`, Salsa `<<< 18`). There must be exactly eight of them.
   */
  readonly anchorBits: number;
  /**
   * The cipher's own twelve-op walk, run backwards from each anchor. Returns
   * null when the wiring doesn't match, which drops the whole double round to
   * the generic layout.
   */
  readonly matchQuarterRound: (anchor: StepLeaf, byId: ReadonlyMap<string, StepLeaf>) => Q | null;
};

/**
 * Analyze a `group` and return its ARX double-round structure, or null if the
 * wiring doesn't match. Pure (spec-only — no trace).
 *
 * Returns null gracefully for every other cipher's rounds and for a half-edited
 * round, so the caller falls back to the generic vertical stack rather than
 * rendering a broken cell.
 *
 * The final PARTITION check is the real validity gate: the eight quarter-round
 * walks must together cover every leaf of the group except the split and the
 * concat, exactly once. A user who rewires one operation therefore drops the
 * whole double round to the generic layout instead of leaving a cell with a
 * silently orphaned leaf.
 */
export const analyzeArxDoubleRound = <Q extends ArxQuarterRoundShape>(
  group: StepGroup,
  opts: ArxDoubleRoundOptions<Q>,
): ArxDoubleRoundShape<Q> | null => {
  if (group.kind !== "group") return null;
  const bodyOutput = group.bodyOutput;
  if (!bodyOutput) return null;

  const leaves = leafChildren(group);
  const byId = new Map(leaves.map((l) => [l.id, l] as const));

  // 1. The concat is the bodyOutput target, and must reassemble all 16 words.
  const concat = byId.get(bodyOutput.node);
  if (!concat || concat.type !== CONCAT_TYPE) return null;
  if (paramNumber(concat, "inputCount") !== ARX_STATE_WORDS) return null;

  // 2. Exactly one 16-way split — the state's decomposition into words.
  const splits = leaves.filter((l) => {
    if (l.type !== SPLIT_TYPE) return false;
    const widths = asRecord(l.params)?.widths;
    return Array.isArray(widths) && widths.length === ARX_STATE_WORDS;
  });
  if (splits.length !== 1) return null;
  const split = splits[0] as StepLeaf;

  // 3. Eight anchors: the rotations that end each quarter round.
  const anchors = leaves.filter((l) => rotateBits(l) === opts.anchorBits);
  if (anchors.length !== ARX_QUARTER_ROUNDS_PER_DOUBLE_ROUND) return null;

  const quarterRounds: Q[] = [];
  for (const anchor of anchors) {
    const qr = opts.matchQuarterRound(anchor, byId);
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
  if (claimed.size !== ARX_QUARTER_ROUNDS_PER_DOUBLE_ROUND * ARX_OPS_PER_QUARTER_ROUND) return null;
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
 * Resolve the ARX quarter round containing the active frame. Walks the frame's
 * group-ancestor `path` innermost → outermost for a double round that analyzes
 * cleanly, then picks the quarter round owning the active leaf.
 *
 * Returns null when the active leaf is the split or the concat: those belong to
 * the double round as a whole, not to any one quarter round, so there is no
 * single quarter round for the diagram to draw.
 */
export const findActiveArxQuarterRound = <Q extends ArxQuarterRoundShape>(
  frame: TraceFrame,
  spec: CipherSpec,
  analyze: (group: StepGroup) => ArxDoubleRoundShape<Q> | null,
): {
  group: StepGroup;
  round: ArxDoubleRoundShape<Q>;
  quarterRound: Q;
  /** 0-based position within the double round: 0–3 first tier, 4–7 second. */
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
    const round = analyze(node);
    if (!round) continue;
    const index = round.quarterRounds.findIndex((qr) => qr.memberIds.includes(activeLeaf));
    if (index < 0) continue;
    return {
      group: node,
      round,
      quarterRound: round.quarterRounds[index] as Q,
      quarterRoundIndex: index,
    };
  }
  return null;
};

// ─── Word-index threading (shared by the linear diagrams) ───────────────────

/** Key a port binding for the word-index map. */
const bindingKey = (node: string, port: string): string => `${node}:${port}`;

/**
 * Thread state-word indices through a double round.
 *
 * The split's `outputN` IS word N. Each quarter round then reads four words and
 * writes its four results back to the same four positions — that is what makes
 * an ARX state a fixed 16-word array rather than a growing dataflow. So we walk
 * the quarter rounds in spec order, resolve each one's inputs against the map,
 * and register its outputs at the same indices for whoever reads them next.
 *
 * Returns a map from quarter-round id → its four rails' word indices. A rail
 * that could not be threaded back to the split (a hand-edited round) comes back
 * null so the caller can degrade to the bare rail name rather than print a
 * wrong number.
 */
export const deriveArxWordIndices = (
  round: ArxDoubleRoundShape<ArxRailedQuarterRound>,
): ReadonlyMap<string, Readonly<Record<ArxRail, number | null>>> => {
  // Seed: the split's sixteen outputs are words 0..15.
  const wordAt = new Map<string, number>();
  for (let i = 0; i < ARX_STATE_WORDS; i++) {
    wordAt.set(bindingKey(round.splitId, `output${i}`), i);
  }

  const result = new Map<string, Readonly<Record<ArxRail, number | null>>>();
  for (const qr of round.quarterRounds) {
    const indices: Record<ArxRail, number | null> = { a: null, b: null, c: null, d: null };
    for (const rail of ARX_RAILS) {
      const input = qr.inputs[rail];
      indices[rail] = wordAt.get(bindingKey(input.node, input.port)) ?? null;
    }
    result.set(qr.id, indices);
    // This quarter round's outputs occupy the same four word positions.
    for (const rail of ARX_RAILS) {
      const index = indices[rail];
      if (index === null) continue;
      wordAt.set(bindingKey(qr.outputs[rail], "output"), index);
    }
  }
  return result;
};
