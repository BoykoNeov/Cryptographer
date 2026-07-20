/**
 * Pure presentation model for the **ChaCha20 quarter-round linear diagram** —
 * the ARX sibling of `twofish-diagram.ts`.
 *
 * **Why this is separate from `chacha-shape.ts`.** `analyzeChaChaDoubleRound`
 * answers "what IS this group?" — the structural facts the graph's canonical
 * two-tier layout needs. The diagram wants a second, smaller set of facts on
 * top: which of the sixteen STATE WORDS each of the four rails carries, and a
 * written label for every operation. Deriving those here keeps the
 * graph-critical shape module byte-identical (the Twofish precedent) and keeps
 * the component purely presentational.
 *
 * **The word indices are the payload.** RFC 8439 §2.3.1 describes a double
 * round as four COLUMN quarter rounds followed by four DIAGONAL ones, and names
 * them by the state words they touch:
 *
 * ```
 *   QUARTERROUND(0, 4,  8, 12)     ← the columns
 *   QUARTERROUND(1, 5,  9, 13)
 *   ...
 *   QUARTERROUND(0, 5, 10, 15)     ← the diagonals
 *   QUARTERROUND(1, 6, 11, 12)
 * ```
 *
 * Scrubbing twelve bare ARX leaves cannot tell you which of those you are
 * inside — every quarter round looks identical, because every quarter round IS
 * identical. The word indices are the one fact that distinguishes them, and
 * they are exactly what makes "column" versus "diagonal" visible rather than
 * asserted. They are recovered by threading the double round's wiring forward
 * from the split, so they follow a rewire and never come from a leaf id.
 *
 * Nothing here is direction-aware: ChaCha20's encrypt and decrypt specs are
 * structurally identical, so one model serves both.
 */

import type {
  ChaChaDoubleRoundShape,
  ChaChaOp,
  ChaChaQuarterRoundShape,
  ChaChaRail,
} from "./chacha-shape";

/** The four rails, top to bottom, as RFC 8439 §2.1 orders them. */
export const CHACHA_RAILS: readonly ChaChaRail[] = ["a", "b", "c", "d"];

/** One operation, with the label the diagram prints on it. */
export type ChaChaDiagramOp = ChaChaOp & {
  /** Written form, e.g. `a += b`, `d ^= a`, `d <<< 16`. */
  readonly label: string;
};

/** One rail of the quarter round: which state word it carries, in and out. */
export type ChaChaDiagramRail = {
  readonly rail: ChaChaRail;
  /**
   * The state-word index (0–15) this rail carries, or null when the wiring
   * could not be threaded back to the split (a hand-edited round). Rendering
   * degrades to the bare rail letter rather than printing a wrong number.
   */
  readonly wordIndex: number | null;
  /** The leaf producing this rail's final value — the click-to-scrub target. */
  readonly outputId: string;
};

export type ChaChaDiagramModel = {
  readonly roundId: string;
  readonly quarterRoundId: string;
  /** 0-based position in the double round: 0–3 column, 4–7 diagonal. */
  readonly quarterRoundIndex: number;
  /**
   * Which half of the double round this is, derived from whether every input
   * reads the split directly — NOT from the index, so it stays honest under a
   * rewire.
   */
  readonly kind: "column" | "diagonal";
  /** The four rails, in a/b/c/d order. */
  readonly rails: readonly ChaChaDiagramRail[];
  /** The twelve operations in RFC 8439 §2.1 order — four lines of three. */
  readonly ops: readonly ChaChaDiagramOp[];
  /**
   * The RFC's own name for this quarter round, e.g. `QUARTERROUND(0, 5, 10, 15)`,
   * or null when the word indices could not be derived.
   */
  readonly rfcLabel: string | null;
};

/** Key a port binding for the word-index map. */
const bindingKey = (node: string, port: string): string => `${node}:${port}`;

/**
 * Thread state-word indices through a double round.
 *
 * The split's `outputN` IS word N. Each quarter round then reads four words and
 * writes its four results back to the same four positions — that is what makes
 * ChaCha's state a fixed 16-word array rather than a growing dataflow. So we
 * walk the quarter rounds in spec order, resolve each one's inputs against the
 * map, and register its outputs at the same indices for whoever reads them next.
 *
 * Returns a map from quarter-round id → its four rails' word indices.
 */
const deriveWordIndices = (
  round: ChaChaDoubleRoundShape,
): ReadonlyMap<string, Readonly<Record<ChaChaRail, number | null>>> => {
  // Seed: the split's sixteen outputs are words 0..15.
  const wordAt = new Map<string, number>();
  for (let i = 0; i < 16; i++) {
    wordAt.set(bindingKey(round.splitId, `output${i}`), i);
  }

  const result = new Map<string, Readonly<Record<ChaChaRail, number | null>>>();
  for (const qr of round.quarterRounds) {
    const indices: Record<ChaChaRail, number | null> = { a: null, b: null, c: null, d: null };
    for (const rail of CHACHA_RAILS) {
      const input = qr.inputs[rail];
      indices[rail] = wordAt.get(bindingKey(input.node, input.port)) ?? null;
    }
    result.set(qr.id, indices);
    // This quarter round's outputs occupy the same four word positions.
    for (const rail of CHACHA_RAILS) {
      const index = indices[rail];
      if (index === null) continue;
      wordAt.set(bindingKey(qr.outputs[rail], "output"), index);
    }
  }
  return result;
};

/** The written form of an operation, as RFC 8439 §2.1 writes it. */
const opLabel = (op: ChaChaOp): string => {
  switch (op.kind) {
    case "add":
      return `${op.target} += ${op.source}`;
    case "xor":
      return `${op.target} ^= ${op.source}`;
    case "rotate":
      return `${op.target} <<< ${op.bits}`;
  }
};

/**
 * Build the diagram model for one quarter round of a double round.
 *
 * @param round the containing double round — needed because the word indices
 *   can only be threaded from the split, which is a property of the whole group
 * @param quarterRoundIndex which of the eight to draw
 */
export const chachaDiagramModel = (
  round: ChaChaDoubleRoundShape,
  quarterRoundIndex: number,
): ChaChaDiagramModel | null => {
  const qr: ChaChaQuarterRoundShape | undefined = round.quarterRounds[quarterRoundIndex];
  if (!qr) return null;

  const indices = deriveWordIndices(round).get(qr.id) ?? { a: null, b: null, c: null, d: null };

  const rails: ChaChaDiagramRail[] = CHACHA_RAILS.map((rail) => ({
    rail,
    wordIndex: indices[rail],
    outputId: qr.outputs[rail],
  }));

  // "Column" iff every input comes straight off the split. Derived from wiring
  // rather than from the index, so a reordered spec still labels itself right.
  const readsSplit = CHACHA_RAILS.every((rail) => qr.inputs[rail].node === round.splitId);

  const words = CHACHA_RAILS.map((rail) => indices[rail]);
  const rfcLabel = words.every((w) => w !== null) ? `QUARTERROUND(${words.join(", ")})` : null;

  return {
    roundId: round.roundId,
    quarterRoundId: qr.id,
    quarterRoundIndex,
    kind: readsSplit ? "column" : "diagonal",
    rails,
    ops: qr.ops.map((op) => ({ ...op, label: opLabel(op) })),
    rfcLabel,
  };
};
