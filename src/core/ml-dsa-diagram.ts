/**
 * The rounding picture behind ML-DSA's Decompose / MakeHint / UseHint — the
 * presentation model the linear view's rounding diagram draws (P5 of
 * `docs/plans/refactored-petting-tide.md`).
 *
 * ## What the picture teaches
 *
 * A signature commits only to the HIGH bits of a value: the range 0 … q − 1 is
 * cut into m buckets, each 2γ2 wide, and the high bits are just the bucket
 * number. The low bits — how far the value sits from its bucket's centre — are
 * noise the signature drops. That is what makes signatures short, and it is
 * also what can go wrong: the verifier recomputes the value slightly
 * differently (it never saw `c·t0`), and a value near a bucket edge can land in
 * the NEIGHBOURING bucket. One hint bit per coefficient repairs that, and the
 * low part's sign says which neighbour.
 *
 * Prose can say all of that; it cannot show a value sitting a hair inside an
 * edge, or an arrow hopping across it. So the model is a CLOSE-UP of three
 * buckets — the value's own and its two neighbours — rather than the whole
 * number line, on which a 44-bucket ruler would make the low part invisible.
 * The component adds a strip of all m buckets so the learner still sees where
 * the close-up sits on the circle.
 *
 * ## Three rules the model keeps
 *
 * 1. **Position by the low part, never the raw residue.** A value is drawn at
 *    `centre(its bucket) + r0`. Plotting the raw residue on 0 … q − 1 would put
 *    a wrapped value (one within γ2 of q − 1, which FIPS 204 assigns to bucket
 *    0 with a negative offset) at the far right while its bucket is drawn at the
 *    far left — a dot outside its own box.
 * 2. **Draw what the step produced.** Bucket numbers, low parts, the hint bit
 *    and UseHint's corrected bucket come from the frame's OUTPUT ports. The
 *    model recomputes only geometry, and if that recomputation disagrees with
 *    the ports (a learner's half-rewired spec) it returns null rather than draw
 *    a picture the step did not produce.
 * 3. **γ2 and q come from the frame's ports.** A learner who edits γ2 sees the
 *    bucket count and width change; nothing here assumes ML-DSA-44's 44.
 *
 * No Solid in this file: frame in, plain data out.
 */

import { decompose, modPm, readMlDsaModulus } from "./ml-dsa-arith";
import type { TraceFrame } from "./types";
import { type ZqVecParams, readCoeff, readScalarPort, readZqVecParams } from "./zq-vector";

export const DECOMPOSE_TYPE = "ml-dsa.decompose@1";
export const MAKE_HINT_TYPE = "ml-dsa.make-hint@1";
export const USE_HINT_TYPE = "ml-dsa.use-hint@1";

export type RoundingKind = "decompose" | "make-hint" | "use-hint";

const KIND_OF: Readonly<Record<string, RoundingKind>> = {
  [DECOMPOSE_TYPE]: "decompose",
  [MAKE_HINT_TYPE]: "make-hint",
  [USE_HINT_TYPE]: "use-hint",
};

/**
 * Where a value sits: its bucket and its offset from that bucket's centre.
 *
 * `offset` is FIPS 204's r0, so it lies in (−γ2, γ2] — except in the wrap case,
 * where bucket 0 also takes the values just below q − 1 and r0 reaches −γ2
 * exactly. Bucket 0 is therefore one value wider than the rest (q = m·2γ2 + 1
 * values over m buckets), and its drawn range is closed at BOTH ends.
 */
export type Placement = {
  readonly bucket: number;
  readonly offset: number;
  readonly wrapped: boolean;
};

/** Place a residue on the bucket ruler — the one function rule 1 lives in. */
export const placeValue = (r: number, gamma2: number, q: number): Placement => {
  const d = decompose(r, gamma2, q);
  return { bucket: d.r1, offset: d.r0, wrapped: d.wrapped };
};

/**
 * Does a drawn offset fall inside a bucket's drawn range, relative to that
 * bucket's centre? `(−γ2, γ2]`, closed at the low end for bucket 0 (the wrap).
 */
export const offsetInBucket = (offset: number, bucket: number, gamma2: number): boolean =>
  (bucket === 0 ? offset >= -gamma2 : offset > -gamma2) && offset <= gamma2;

/**
 * The coefficient the narrator and the diagram both talk about, so the picture
 * and the prose never describe different numbers: the first one whose hint bit
 * is 1, or `undefined` when no coefficient needed a hint.
 */
export const firstHinted = (h: readonly number[]): number | undefined => {
  const i = h.indexOf(1);
  return i < 0 ? undefined : i;
};

/** Decompose's narrator describes coefficient 0; so does the diagram. */
export const DECOMPOSE_EXAMPLE_INDEX = 0;

/** One of the three buckets in the close-up. */
export type CloseUpBucket = {
  /** −1, 0 or +1: left neighbour, the value's own bucket, right neighbour. */
  readonly slot: -1 | 0 | 1;
  /** Its number on the circle, 0 … m − 1 (neighbours wrap). */
  readonly index: number;
  /** Its centre on 0 … q − 1, i.e. `index · 2γ2`. */
  readonly centreValue: number;
};

/** A value drawn in the close-up. */
export type CloseUpPoint = {
  /** "r", "r + z" or "a" — the step's own port names. */
  readonly label: string;
  readonly value: number;
  readonly placement: Placement;
  /** −1, 0 or +1: which of the three buckets it is drawn in. */
  readonly slot: -1 | 0 | 1;
  /**
   * Position relative to the HOME bucket's centre: `slot · 2γ2 + offset`. The
   * component maps this straight to x.
   */
  readonly x: number;
};

export type RoundingDiagramModel = {
  readonly kind: RoundingKind;
  /** Which coefficient of the vector is drawn. */
  readonly coefficient: number;
  /** How many coefficients the frame holds (1,024 for ML-DSA-44's k = 4). */
  readonly count: number;
  readonly q: number;
  readonly gamma2: number;
  /** Bucket count, `(q − 1) / 2γ2`. */
  readonly m: number;
  /** The value's own bucket. */
  readonly home: number;
  /** Left neighbour, home, right neighbour — wrapping modulo m. */
  readonly buckets: readonly [CloseUpBucket, CloseUpBucket, CloseUpBucket];
  /** The primary value first; MakeHint adds `r + z`. */
  readonly points: readonly CloseUpPoint[];
  /** The hint bit (MakeHint's output, UseHint's input); null for Decompose. */
  readonly hint: 0 | 1 | null;
  /**
   * The bucket the arrow points to: for MakeHint the bucket `r + z` lands in;
   * for UseHint the corrected bucket the step OUTPUT. Null for Decompose.
   */
  readonly target: number | null;
  /** How many coefficients on this frame have a hint bit of 1 (null for Decompose). */
  readonly hintedCount: number | null;
};

// ─── frame reading ────────────────────────────────────────────────────────

const vecParams = (frame: TraceFrame): ZqVecParams | null => {
  try {
    return readZqVecParams(frame.params, frame.stepType);
  } catch {
    return null;
  }
};

const vec = (
  ports: ReadonlyMap<string, Uint8Array> | undefined,
  name: string,
  p: ZqVecParams,
): number[] | null => {
  const bytes = ports?.get(name);
  if (!(bytes instanceof Uint8Array) || bytes.length % p.coeffBytes !== 0) return null;
  const out: number[] = [];
  for (let i = 0; i < bytes.length / p.coeffBytes; i++) out.push(Number(readCoeff(bytes, i, p)));
  return out;
};

/**
 * q and γ2, read by the SAME functions the steps' executors use — so the
 * picture can never decode a constant differently from the step that ran.
 * (γ2 is a whole-port integer, q a one-coefficient vector; they differ.)
 */
const constants = (frame: TraceFrame, p: ZqVecParams): { q: number; gamma2: number } | null => {
  const inputs = frame.portInputs;
  if (inputs === undefined) return null;
  try {
    const q = readMlDsaModulus(inputs, p, frame.stepType);
    const gamma2 = readScalarPort(inputs, "gamma2", frame.stepType);
    return q > 0 && gamma2 > 0 ? { q, gamma2 } : null;
  } catch {
    return null;
  }
};

// ─── geometry ─────────────────────────────────────────────────────────────

const wrapBucket = (k: number, m: number): number => ((k % m) + m) % m;

const closeUp = (
  home: number,
  m: number,
  gamma2: number,
): [CloseUpBucket, CloseUpBucket, CloseUpBucket] => {
  const at = (slot: -1 | 0 | 1): CloseUpBucket => {
    const index = wrapBucket(home + slot, m);
    return { slot, index, centreValue: index * 2 * gamma2 };
  };
  return [at(-1), at(0), at(1)];
};

/** Which close-up slot a bucket number occupies, or null if it is not one of the three. */
const slotOf = (bucket: number, home: number, m: number): -1 | 0 | 1 | null => {
  if (bucket === home) return 0;
  if (bucket === wrapBucket(home + 1, m)) return 1;
  if (bucket === wrapBucket(home - 1, m)) return -1;
  return null;
};

const point = (
  label: string,
  value: number,
  placement: Placement,
  slot: -1 | 0 | 1,
  gamma2: number,
): CloseUpPoint => ({ label, value, placement, slot, x: slot * 2 * gamma2 + placement.offset });

// ─── the model ────────────────────────────────────────────────────────────

/**
 * The diagram for one Decompose / MakeHint / UseHint frame, or null for any
 * other step — and for a frame whose ports are missing, malformed, or disagree
 * with the geometry (rule 2).
 *
 * `coefficient` overrides the featured one (tests walk every coefficient; the
 * UI always shows the featured one, matching the narrator).
 */
export const roundingDiagramModel = (
  frame: TraceFrame,
  coefficient?: number,
): RoundingDiagramModel | null => {
  const kind = KIND_OF[frame.stepType];
  if (kind === undefined) return null;
  const p = vecParams(frame);
  if (p === null) return null;
  const c = constants(frame, p);
  if (c === null) return null;
  const { q, gamma2 } = c;
  if ((q - 1) % (2 * gamma2) !== 0) return null;
  const m = (q - 1) / (2 * gamma2);
  // Three distinct buckets in the close-up need m ≥ 3; FIPS 204's sets have 44 and 16.
  if (m < 3) return null;
  const base = { kind, q, gamma2, m };

  if (kind === "decompose") {
    const a = vec(frame.portInputs, "a", p);
    const high = vec(frame.portOutputs, "high", p);
    const low = vec(frame.portOutputs, "low", p);
    if (a === null || high === null || low === null) return null;
    if (a.length === 0 || high.length !== a.length || low.length !== a.length) return null;
    const i = coefficient ?? DECOMPOSE_EXAMPLE_INDEX;
    const ai = a[i];
    const hi = high[i];
    const li = low[i];
    if (ai === undefined || hi === undefined || li === undefined) return null;
    // The step's outputs are the truth; geometry must agree with them.
    const placed = placeValue(ai, gamma2, q);
    const lowSigned = modPm(li, q);
    if (placed.bucket !== hi || placed.offset !== lowSigned) return null;
    return {
      ...base,
      coefficient: i,
      count: a.length,
      home: hi,
      buckets: closeUp(hi, m, gamma2),
      points: [point("a", ai, { ...placed, bucket: hi, offset: lowSigned }, 0, gamma2)],
      hint: null,
      target: null,
      hintedCount: null,
    };
  }

  if (kind === "make-hint") {
    const z = vec(frame.portInputs, "z", p);
    const r = vec(frame.portInputs, "r", p);
    const h = vec(frame.portOutputs, "output", p);
    if (z === null || r === null || h === null) return null;
    if (h.length === 0 || r.length !== h.length || z.length !== h.length) return null;
    const i = coefficient ?? firstHinted(h) ?? 0;
    const ri = r[i];
    const zi = z[i];
    const hi = h[i];
    if (ri === undefined || zi === undefined || (hi !== 0 && hi !== 1)) return null;
    const from = placeValue(ri, gamma2, q);
    const to = placeValue((ri + zi) % q, gamma2, q);
    // The hint bit says "the bucket changed"; the geometry must say so too.
    if ((from.bucket !== to.bucket) !== (hi === 1)) return null;
    const toSlot = slotOf(to.bucket, from.bucket, m);
    if (toSlot === null) return null;
    const second = point("r + z", (ri + zi) % q, to, toSlot, gamma2);
    // Drawn by its own low part, r + z must still sit where r + (signed z)
    // puts it. One unit of slack: bucket 0 is one value wider than the rest,
    // so hopping the 0 ↔ m − 1 edge shifts the ruler by exactly one.
    if (Math.abs(second.x - (from.offset + modPm(zi, q))) > 1) return null;
    return {
      ...base,
      coefficient: i,
      count: h.length,
      home: from.bucket,
      buckets: closeUp(from.bucket, m, gamma2),
      points: [point("r", ri, from, 0, gamma2), second],
      hint: hi,
      target: to.bucket,
      hintedCount: h.filter((b) => b === 1).length,
    };
  }

  // use-hint
  const h = vec(frame.portInputs, "h", p);
  const r = vec(frame.portInputs, "r", p);
  const out = vec(frame.portOutputs, "output", p);
  if (h === null || r === null || out === null) return null;
  if (h.length === 0 || r.length !== h.length || out.length !== h.length) return null;
  const i = coefficient ?? firstHinted(h) ?? 0;
  const ri = r[i];
  const hi = h[i];
  const oi = out[i];
  if (ri === undefined || oi === undefined || (hi !== 0 && hi !== 1)) return null;
  const at = placeValue(ri, gamma2, q);
  // The corrected bucket is the step's OUTPUT. It must be the value's own
  // bucket when the hint is 0 and a neighbour when it is 1.
  const outSlot = slotOf(oi, at.bucket, m);
  if (outSlot === null || (outSlot === 0) !== (hi === 0)) return null;
  return {
    ...base,
    coefficient: i,
    count: h.length,
    home: at.bucket,
    buckets: closeUp(at.bucket, m, gamma2),
    points: [point("r", ri, at, 0, gamma2)],
    hint: hi,
    target: oi,
    hintedCount: h.filter((b) => b === 1).length,
  };
};
