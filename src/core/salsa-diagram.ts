/**
 * Pure presentation model for the **Salsa20 quarter-round linear diagram** — the
 * ARX sibling of `chacha-diagram.ts` and `twofish-diagram.ts`.
 *
 * **Why this is separate from `salsa-shape.ts`.** `analyzeSalsaDoubleRound`
 * answers "what IS this group?" — the structural facts the graph's canonical
 * two-tier layout needs. The diagram wants a second, smaller set of facts on
 * top: which of the sixteen STATE WORDS each of the four rails carries, and a
 * written label for every operation and every line. Deriving those here keeps
 * the graph-critical shape module byte-identical (the Twofish/ChaCha precedent)
 * and keeps the component purely presentational.
 *
 * **The word indices are the payload**, exactly as they are for ChaCha. Twelve
 * bare ARX leaves cannot tell you which of the eight quarter rounds you are
 * inside — every quarter round IS identical. The word indices are the one fact
 * that distinguishes them, and they are recovered by threading the double
 * round's wiring forward from the split, so they follow a rewire and never come
 * from a leaf id. Salsa's quads are printed in RAIL ORDER and never sorted:
 * column round 1 is `(5, 9, 13, 1)`, which STARTS ON THE DIAGONAL. Sorting it
 * would print `(1, 5, 9, 13)` and quietly destroy the diagonal-start fact that
 * is the reason Salsa's state layout looks the way it does.
 *
 * **Where this model differs from ChaCha's, and why the difference is the whole
 * point.** ChaCha accumulates in place, so all twelve of its operations sit on
 * one of the four rails. Salsa computes into a FRESH rail —
 * `z1 = y1 ^ ((y0 + y3) <<< 7)` — so of each line's three operations, the add
 * and the rotate touch NO state word at all and only the XOR writes back. This
 * model therefore tags each op with the `lane` it belongs on ("scratch" for the
 * add and the rotate, the target rail for the XOR), and the component draws the
 * scratch lane as a real fifth line. That is a structural fact about Salsa20,
 * not a rendering preference.
 *
 * **Rail naming follows Bernstein.** A rail prints as `y_n` before its line has
 * written it and `z_n` afterwards, so line 2's add reads `z1 + y0` exactly as
 * the specification writes it. Which line writes which rail is read off the
 * shape's own ops, so this survives a reordered spec.
 *
 * Nothing here is direction-aware: Salsa20's encrypt and decrypt specs are
 * structurally identical, so one model serves both.
 */

import { ARX_RAILS, deriveArxWordIndices } from "./arx-round-shape";
import type {
  SalsaDoubleRoundShape,
  SalsaOp,
  SalsaQuarterRoundShape,
  SalsaRail,
} from "./salsa-shape";

/** The four rails, top to bottom, as Bernstein orders the quarter round's words. */
export const SALSA_RAILS: readonly SalsaRail[] = ARX_RAILS;

/**
 * Which horizontal line an operation is drawn on.
 *
 * `"scratch"` is the fifth lane below the four rails: the add and the rotate
 * compute a value that is not yet any state word. Only the XOR returns to a
 * rail, which is Salsa's defining difference from ChaCha's in-place form.
 */
export type SalsaLane =
  | { readonly kind: "rail"; readonly rail: SalsaRail }
  | { readonly kind: "scratch" };

/** One operation, with the labels and lane the diagram draws it with. */
export type SalsaDiagramOp = SalsaOp & {
  /** Which lane the box sits on. */
  readonly lane: SalsaLane;
  /** Short in-box label, e.g. `y0+y3`, `≪7`, `⊕`. */
  readonly short: string;
  /** Full written form for the tooltip, e.g. `z1 = y1 ^ ((y0 + y3) <<< 7)`. */
  readonly label: string;
  /** 0-based written line (0–3) — the banding unit. */
  readonly line: number;
  /** For an add: the two source rails, already named in Bernstein's y/z form. */
  readonly sourceNames: readonly string[];
};

/** One rail of the quarter round: which state word it carries, in and out. */
export type SalsaDiagramRail = {
  readonly rail: SalsaRail;
  /** Bernstein's name for this rail's FINAL value, e.g. `z1`. */
  readonly name: string;
  /**
   * The state-word index (0–15) this rail carries, or null when the wiring
   * could not be threaded back to the split (a hand-edited round). Rendering
   * degrades to the bare rail name rather than printing a wrong number.
   */
  readonly wordIndex: number | null;
  /** The leaf producing this rail's final value — the click-to-scrub target. */
  readonly outputId: string;
};

export type SalsaDiagramModel = {
  readonly roundId: string;
  readonly quarterRoundId: string;
  /** 0-based position in the double round: 0–3 column, 4–7 row. */
  readonly quarterRoundIndex: number;
  /**
   * Which half of the double round this is, derived from whether every input
   * reads the split directly — NOT from the index, so it stays honest under a
   * rewire. Bernstein's terms are column and row (ChaCha's second half is
   * "diagonal" instead; the state layouts differ, so the names do too).
   */
  readonly kind: "column" | "row";
  /** The four rails, in y0..y3 order. */
  readonly rails: readonly SalsaDiagramRail[];
  /** The twelve operations in Bernstein's written order — four lines of three. */
  readonly ops: readonly SalsaDiagramOp[];
  /** The four written lines, e.g. `z1 = y1 ^ ((y0 + y3) <<< 7)`. */
  readonly lines: readonly string[];
  /**
   * Bernstein's own name for this quarter round, e.g. `quarterround(x5, x9, x13,
   * x1)`, or null when the word indices could not be derived. The order is the
   * rails' order and is never sorted — a column quarter round starts on the
   * state's diagonal, and that is exactly what this label exists to show.
   */
  readonly quadLabel: string | null;
};

/** Positional index of a rail: a→0, b→1, c→2, d→3. */
const railIndex = (rail: SalsaRail): number => SALSA_RAILS.indexOf(rail);

/**
 * Build the diagram model for one quarter round of a double round.
 *
 * @param round the containing double round — needed because the word indices
 *   can only be threaded from the split, which is a property of the whole group
 * @param quarterRoundIndex which of the eight to draw
 */
export const salsaDiagramModel = (
  round: SalsaDoubleRoundShape,
  quarterRoundIndex: number,
): SalsaDiagramModel | null => {
  const qr: SalsaQuarterRoundShape | undefined = round.quarterRounds[quarterRoundIndex];
  if (!qr) return null;

  // Threading the words from the split is family machinery, not Salsa's — the
  // rule "each quarter round writes its results back to the four positions it
  // read" is equally ChaCha's. See `deriveArxWordIndices`.
  const indices = deriveArxWordIndices(round).get(qr.id) ?? { a: null, b: null, c: null, d: null };

  // Which written line writes which rail, read off the shape's own ops rather
  // than assumed — this is what makes the y→z naming survive a reordered spec.
  const writtenAtLine = new Map<SalsaRail, number>();
  qr.ops.forEach((op, i) => {
    if (op.kind === "xor") writtenAtLine.set(op.target, Math.floor(i / 3));
  });

  /** Bernstein's name for a rail as of `line`: `y_n` before it is written, `z_n` after. */
  const nameAt = (rail: SalsaRail, line: number): string => {
    const written = writtenAtLine.get(rail);
    const prefix = written !== undefined && written < line ? "z" : "y";
    return `${prefix}${railIndex(rail)}`;
  };

  const rails: SalsaDiagramRail[] = SALSA_RAILS.map((rail) => ({
    rail,
    // The final value: every rail is written exactly once, so past the last
    // line every rail reads as `z`.
    name: nameAt(rail, 4),
    wordIndex: indices[rail],
    outputId: qr.outputs[rail],
  }));

  // The four written lines, assembled from each line's three ops. Built first
  // because every op's tooltip prints its whole line, not just its own token.
  const lines: string[] = [];
  for (let line = 0; line < 4; line++) {
    const add = qr.ops[line * 3];
    const xor = qr.ops[line * 3 + 2];
    if (add?.kind !== "add" || xor?.kind !== "xor") return null;
    const target = xor.target;
    lines.push(
      `${nameAt(target, line + 1)} = ${nameAt(target, line)} ^ ` +
        `((${nameAt(add.srcA, line)} + ${nameAt(add.srcB, line)}) <<< ${add.bits})`,
    );
  }

  const ops: SalsaDiagramOp[] = qr.ops.map((op, i) => {
    const line = Math.floor(i / 3);
    const label = lines[line] as string;
    switch (op.kind) {
      case "add":
        return {
          ...op,
          // The sum is not yet a state word — it lives on the scratch lane.
          lane: { kind: "scratch" },
          short: `${nameAt(op.srcA, line)}+${nameAt(op.srcB, line)}`,
          label,
          line,
          sourceNames: [nameAt(op.srcA, line), nameAt(op.srcB, line)],
        };
      case "rotate":
        return {
          ...op,
          lane: { kind: "scratch" },
          short: `≪${op.bits}`,
          label,
          line,
          sourceNames: [],
        };
      case "xor":
        return {
          ...op,
          // The only op of the line that returns to the state.
          lane: { kind: "rail", rail: op.target },
          short: "⊕",
          label,
          line,
          sourceNames: [],
        };
    }
  });

  // "Column" iff every input comes straight off the split. Derived from wiring
  // rather than from the index, so a reordered spec still labels itself right.
  const readsSplit = SALSA_RAILS.every((rail) => qr.inputs[rail].node === round.splitId);

  const words = SALSA_RAILS.map((rail) => indices[rail]);
  const quadLabel = words.every((w) => w !== null)
    ? `quarterround(${words.map((w) => `x${w}`).join(", ")})`
    : null;

  return {
    roundId: round.roundId,
    quarterRoundId: qr.id,
    quarterRoundIndex,
    kind: readsSplit ? "column" : "row",
    rails,
    ops,
    lines,
    quadLabel,
  };
};
