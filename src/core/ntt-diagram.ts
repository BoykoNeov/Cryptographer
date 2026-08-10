/**
 * Pure presentation models for the **lattice linear-view diagrams** — the
 * butterfly, and the degree-1 base-case multiplication. Siblings of
 * `twofish-diagram.ts`, `chacha-diagram.ts` and `salsa-diagram.ts`.
 *
 * **Why this is separate from `ntt-shape.ts`.** `analyzeNttButterfly` answers
 * "what IS this loop body?" — the structural facts the graph's canonical cell
 * needs. A diagram wants a second, smaller set on top: a written label for every
 * operation, and the arithmetic facts that distinguish one butterfly group from
 * its 63 identical siblings. Deriving those here keeps the graph-critical shape
 * module untouched (the Twofish precedent) and the components purely
 * presentational.
 *
 * ## The butterfly diagram draws TWO forms, and that is the difference from ARX
 *
 * ChaCha20's and Salsa20's diagrams are direction-blind, because those ciphers'
 * encrypt and decrypt specs are structurally identical. The NTT's are not: the
 * forward multiplies before combining and the inverse after, so this model
 * emits a different column order for each. Twofish is the closer precedent —
 * its two rotations swap by direction.
 *
 * ```
 *  Cooley–Tukey (forward)                 Gentleman–Sande (inverse)
 *
 *  lo ──────────────●────── lo + t        lo ────●─────────────── lo + hi
 *                  ╱ ╲                            ╲╱
 *  hi ──[× ζ]──────●────── lo − t         hi ────╱╲───[× ζ]────── ζ(hi − lo)
 * ```
 *
 * In both, the interesting picture is the CROSSING: two values go in, two come
 * out, and each output depends on both inputs. That is what makes the transform
 * invertible rather than merely a mixing function, and it is invisible when the
 * same eight leaves are read one frame at a time.
 *
 * ## The payload is the pairing distance and the group index
 *
 * Scrubbing a butterfly frame cannot tell you which of a layer's groups you are
 * in, because every group runs identical arithmetic — the only things that
 * differ are the coefficients and this group's ζ. So the model carries the
 * layer's PAIRING DISTANCE (coefficient `j` meets coefficient `j + d`), the
 * group's coefficient count, and which group this is. That is the NTT's
 * equivalent of the ARX diagrams' state-word indices: the one fact that names
 * the frame you are looking at.
 *
 * Everything is derived from wiring and params — the pairing distance from the
 * iterate's own block width and the vector steps' element width, the roles from
 * `analyzeNttButterfly` — so nothing here breaks under a rewire or reads an id.
 */

import { paramNumber } from "./arx-round-shape";
import {
  type NttButterflyKind,
  type NttButterflyRole,
  type NttButterflyShape,
  analyzeNttButterfly,
} from "./ntt-shape";
import { findStepAndParent } from "./spec-mutations";
import { canonicalStepId } from "./step-id";
import type { CipherSpec, IterateGroup, StepLeaf, TraceFrame } from "./types";

/** The step type the base-case-multiply diagram draws. */
export const BASE_CASE_MUL_TYPE = "zq-base-case-mul@1";

// ─── The butterfly diagram ──────────────────────────────────────────────────

/** The two halves a butterfly mixes. */
export type NttDiagramRail = "lo" | "hi";

/** One labelled box on a rail — a single leaf, so it scrubs exactly. */
export type NttDiagramBox = {
  readonly nodeId: string;
  readonly rail: NttDiagramRail;
  readonly role: NttButterflyRole;
  /** Short glyph for the box itself, e.g. `× ζ`, `+`, `−`. */
  readonly glyph: string;
  /** The line of the algorithm this box is, e.g. `hi′ = lo − t`. */
  readonly line: string;
};

/**
 * One vertical slice of the diagram. A column with `crossing` set is the one
 * where each rail's box reads the OTHER rail as well — the X.
 */
export type NttDiagramColumn = {
  readonly boxes: readonly NttDiagramBox[];
  readonly crossing: boolean;
};

export type NttButterflyDiagramModel = {
  readonly layerId: string;
  readonly kind: NttButterflyKind;
  /** Printed name of the butterfly, e.g. `Cooley–Tukey`. */
  readonly butterflyName: string;
  /** FIPS 203's algorithm number for this butterfly. */
  readonly reference: string;
  /** Coefficients this group covers (both halves together). */
  readonly groupCoefficients: number;
  /** Coefficient `j` is paired with coefficient `j + pairingDistance`. */
  readonly pairingDistance: number;
  /** 0-based group within the layer, from the frame; null outside an iteration. */
  readonly groupIndex: number | null;
  /** Groups this layer runs, when the caller could count them; else null. */
  readonly groupCount: number | null;
  /** The split feeding both rails — the diagram's left endpoint. */
  readonly splitId: string;
  /** The recombine — the right endpoint. */
  readonly recombineId: string;
  /** The ζ read, drawn as the twiddle multiply's second input. */
  readonly zetaId: string;
  /** Left to right, in execution order. */
  readonly columns: readonly NttDiagramColumn[];
  /** Every leaf the diagram draws — the set click-to-scrub resolves against. */
  readonly drawnIds: readonly string[];
};

/**
 * Locate the butterfly containing the active frame.
 *
 * Walks the frame's container `path` innermost → outermost for an iterate that
 * analyzes cleanly. `path` is the chain of CONTAINERS and excludes the leaf's
 * own id, so the leaf comes from `stepId` — with its `:b{i}` iteration suffix
 * stripped, since the shape's member ids are spec ids.
 */
export const findActiveNttButterfly = (
  frame: TraceFrame,
  spec: CipherSpec,
): { readonly layer: IterateGroup; readonly shape: NttButterflyShape } | null => {
  const activeLeaf = canonicalStepId(frame.stepId);
  for (let i = frame.path.length - 1; i >= 0; i--) {
    const id = frame.path[i];
    if (id === undefined) continue;
    const located = findStepAndParent(spec, id);
    if (!located || located.node.kind !== "iterate") continue;
    const shape = analyzeNttButterfly(located.node);
    if (!shape) continue;
    if (!shape.memberIds.includes(activeLeaf)) continue;
    return { layer: located.node, shape };
  }
  return null;
};

/** The element width the vector steps operate at, read off one of them. */
const coeffBytesOf = (layer: IterateGroup, shape: NttButterflyShape): number | null => {
  const leaf = layer.children.find((c): c is StepLeaf => c.kind === "step" && c.id === shape.addId);
  if (!leaf) return null;
  const n = paramNumber(leaf, "coeffBytes");
  return typeof n === "number" && n > 0 ? n : null;
};

const box = (
  nodeId: string,
  rail: NttDiagramRail,
  role: NttButterflyRole,
  glyph: string,
  line: string,
): NttDiagramBox => ({ nodeId, rail, role, glyph, line });

/**
 * Build the diagram model for one butterfly.
 *
 * @param groupIndex the frame's `blockIndex` — which group of the layer this is
 * @param groupCount how many groups the layer runs, when the caller counted
 *   them. It MUST be counted per layer scope: the NTT has seven sibling
 *   iterates running 1, 2, 4 … 64 groups, so a trace-wide maximum labels layer
 *   1's only group "1 of 64" (see `iterateScopeKey`).
 */
export const nttButterflyDiagramModel = (
  layer: IterateGroup,
  shape: NttButterflyShape,
  groupIndex: number | null,
  groupCount: number | null,
): NttButterflyDiagramModel | null => {
  const coeffBytes = coeffBytesOf(layer, shape);
  const blockBytes = layer.blockByteLength;
  if (coeffBytes === null || blockBytes === undefined) return null;
  const groupCoefficients = Math.floor(blockBytes / coeffBytes);
  if (groupCoefficients < 2) return null;
  const pairingDistance = groupCoefficients / 2;

  const forward = shape.kind === "cooley-tukey";

  // The twiddle multiply always lives on the HIGH rail: going forward it scales
  // the high half before combining, coming back it scales the difference that
  // becomes the high half. So the same rail carries it in both directions, and
  // only its POSITION relative to the crossing changes.
  const twist = forward
    ? box(shape.twistId, "hi", "twist", "× ζ", "t = ζ · hi")
    : box(shape.twistId, "hi", "hi", "× ζ", "hi′ = ζ · (hi − lo)");

  const crossing: NttDiagramColumn = {
    crossing: true,
    boxes: forward
      ? [
          box(shape.addId, "lo", "lo", "+", "lo′ = lo + t"),
          box(shape.subId, "hi", "hi", "−", "hi′ = lo − t"),
        ]
      : [
          box(shape.addId, "lo", "lo", "+", "lo′ = lo + hi"),
          box(shape.subId, "hi", "diff", "−", "hi − lo"),
        ],
  };
  const twistColumn: NttDiagramColumn = { crossing: false, boxes: [twist] };

  // The ONE structural difference between the two butterflies: multiply before
  // combining, or after.
  const columns = forward ? [twistColumn, crossing] : [crossing, twistColumn];

  return {
    layerId: shape.layerId,
    kind: shape.kind,
    butterflyName: forward ? "Cooley–Tukey" : "Gentleman–Sande",
    reference: forward ? "FIPS 203 Algorithm 9" : "FIPS 203 Algorithm 10",
    groupCoefficients,
    pairingDistance,
    groupIndex,
    groupCount,
    splitId: shape.splitId,
    recombineId: shape.recombineId,
    zetaId: shape.zetaId,
    columns,
    drawnIds: [
      shape.splitId,
      ...columns.flatMap((c) => c.boxes.map((b) => b.nodeId)),
      shape.recombineId,
      shape.zetaId,
    ],
  };
};

// ─── The base-case-multiply diagram ─────────────────────────────────────────

/**
 * One of the four products FIPS 203 Algorithm 12 forms, with the reason it
 * lands where it does.
 */
export type BaseCaseTerm = {
  /** Which output coefficient this term contributes to. */
  readonly into: 0 | 1;
  /** Written form, e.g. `a₁·b₁·γ`. */
  readonly label: string;
  /** True for the one term that came back from degree 2 via `X² = γ`. */
  readonly folded: boolean;
};

export type BaseCaseMulDiagramModel = {
  readonly nodeId: string;
  /** Pairs multiplied in one frame — 128 for a full ML-KEM polynomial. */
  readonly pairs: number;
  /** The four products, in the order the algorithm writes them. */
  readonly terms: readonly BaseCaseTerm[];
  readonly reference: string;
};

/**
 * Build the model for a `zq-base-case-mul@1` frame, or null for anything else.
 *
 * **Why this leaf gets a diagram of its own.** It is the one step in the whole
 * lattice layer whose name has to break the `zq-vec-` family prefix, because it
 * is NOT element-wise: the transform stops at 128 degree-1 polynomials, so a
 * "multiplication" here is 128 separate little polynomial products in 128
 * separate rings `Z_q[X]/(X² − γ)`. Multiplying two linear polynomials gives a
 * quadratic, and the `X²` term has nowhere to go — except that in this ring
 * `X² = γ`, so it folds back onto the constant term. That fold is the entire
 * content of the step and it is a picture, not a sentence.
 */
export const baseCaseMulDiagramModel = (
  frame: TraceFrame,
  spec: CipherSpec,
): BaseCaseMulDiagramModel | null => {
  const located = findStepAndParent(spec, canonicalStepId(frame.stepId));
  if (!located || located.node.kind !== "step") return null;
  const leaf = located.node;
  if (leaf.type !== BASE_CASE_MUL_TYPE) return null;

  const coeffBytes = paramNumber(leaf, "coeffBytes");
  if (coeffBytes === undefined || coeffBytes <= 0) return null;
  // The frame's own input width says how many coefficients arrived, and they
  // pair up — so the count is derived from the value rather than from a param
  // that could disagree with it.
  const inputBytes = frame.portInputs?.get("a")?.byteLength;
  if (inputBytes === undefined) return null;
  const pairs = Math.floor(inputBytes / coeffBytes / 2);
  if (pairs < 1) return null;

  return {
    nodeId: leaf.id,
    pairs,
    terms: [
      { into: 0, label: "a₀·b₀", folded: false },
      { into: 0, label: "a₁·b₁·γ", folded: true },
      { into: 1, label: "a₀·b₁", folded: false },
      { into: 1, label: "a₁·b₀", folded: false },
    ],
    reference: "FIPS 203 Algorithm 12",
  };
};
