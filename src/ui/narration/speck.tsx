/**
 * Speck narrators — Phase 2 of the per-frame value-prose plan.
 *
 * Two step types:
 *
 *   - `speck.round@1` → 3 ARX sub-op units:
 *       1. x ← (ROR(x, α) + y) mod 2^n
 *       2. x ← x ⊕ k_i
 *       3. y ← ROL(y, β) ⊕ x
 *
 *   - `speck.round-inverse@1` → 3 inverse sub-op units, applied back-to-
 *     front to undo a forward round:
 *       1. y ← ROR(y' ⊕ x', β)
 *       2. x ← ROL((x' ⊕ k_i) − y, α)         (subtraction mod 2^n)
 *
 *     (Inverse is 2 conceptual statements; we still emit 3 units —
 *     introducing intermediate `y` separately from "compute x" lets the
 *     prose show the mod-2^n subtraction step cleanly.)
 *
 * Codec: the narrator reuses `decodeBlock`/`decodeWord` from
 * `speck-word-codec.ts` so its decoded `(x, y)` and `k` agree byte-for-
 * byte with what the executor consumed. Both `byteOrder` values
 * (`"be-paper"` and `"le-nsa"`) flow through the same code path; the
 * codec absorbs the difference. Tests pin BOTH conventions.
 *
 * Word values are rendered in `wordBits/4`-digit hex with an `0x`
 * prefix (Speck literature convention — e.g. Speck32/64 words display
 * as `0x6574`). The byte-format toggle still drives byte-level views
 * (input/output `ByteRow`s in the structural prose), but word arithmetic
 * is paper-natural in hex regardless of toggle.
 */

import type { BytesState, Json, TraceFrame } from "@/core/types";
import {
  type SpeckByteOrder,
  decodeBlock,
  decodeWord,
  readByteOrder,
} from "../../steps/speck-word-codec";
import type { NarrationFn, NarrationUnit } from "./registry";

// ─── Speck forward round ─────────────────────────────────────────────

/**
 * Forward Speck round. Three disclosable sub-ops show the cipher's ARX
 * structure step-by-step. We decode `(x, y)` from `stateBefore.bytes`,
 * `k` from the consumed round-key aux, and compute the same intermediate
 * `x'` the executor would compute (modular add then XOR). The prose
 * names the rotation amounts (`α`, `β`) and the word width.
 */
export const speckRoundNarration: NarrationFn = (frame) => {
  const ctx = readSpeckFrame(frame, "speck.round");
  if (!ctx) return null;
  const { p, x0, y0, k, mask } = ctx;
  const xRot = ror(x0, p.alpha, p.wordBits);
  const sum = (xRot + y0) & mask;
  const xAfterXor = sum ^ k;
  const yRot = rol(y0, p.beta, p.wordBits);
  const yFinal = yRot ^ xAfterXor;
  const w = p.wordBits;

  const units: NarrationUnit[] = [];

  units.push({
    key: "arx:1",
    label: "1. x ← (ROR(x, α) + y) mod 2^n",
    Prose: () => (
      <div>
        <p>
          Rotate <code>x</code> right by α = {p.alpha} bits, then add <code>y</code> modulo 2
          <sup>{w}</sup>. This is where the cipher's non-linearity lives — the carry chain inside
          the addition is key-dependent and unpredictable.
        </p>
        <ul class="step-narration-mixcol-list">
          <li>
            ROR({hexWord(x0, w)}, {p.alpha}) = {hexWord(xRot, w)}
          </li>
          <li>
            ({hexWord(xRot, w)} + {hexWord(y0, w)}) mod 2<sup>{w}</sup> = {hexWord(sum, w)}
          </li>
        </ul>
      </div>
    ),
  });

  units.push({
    key: "arx:2",
    label: "2. x ← x ⊕ k_i",
    Prose: () => (
      <div>
        <p>XOR the round key into x. This is the only place the key enters this round.</p>
        <ul class="step-narration-mixcol-list">
          <li>
            {hexWord(sum, w)} ⊕ {hexWord(k, w)} = {hexWord(xAfterXor, w)}
          </li>
        </ul>
      </div>
    ),
  });

  units.push({
    key: "arx:3",
    label: "3. y ← ROL(y, β) ⊕ x",
    Prose: () => (
      <div>
        <p>
          Rotate <code>y</code> left by β = {p.beta} bits, then XOR with the new <code>x</code>.
          This feedback step is what couples the two words — without it Speck wouldn't diffuse
          changes between x and y.
        </p>
        <ul class="step-narration-mixcol-list">
          <li>
            ROL({hexWord(y0, w)}, {p.beta}) = {hexWord(yRot, w)}
          </li>
          <li>
            {hexWord(yRot, w)} ⊕ {hexWord(xAfterXor, w)} = {hexWord(yFinal, w)}
          </li>
        </ul>
      </div>
    ),
  });

  return units;
};

// ─── Speck inverse round ─────────────────────────────────────────────

/**
 * Inverse Speck round. Recovers `(x, y)` from `(x', y')` and `k_i` by
 * running the forward equations back-to-front:
 *
 *     y = ROR(y' ⊕ x', β)
 *     x = ROL((x' ⊕ k_i) − y, α)        (subtraction mod 2^n)
 *
 * Three disclosure units mirror the forward count — the math is two
 * statements, but separating the subtraction step from the rotation
 * gives the prose room to show the mod-2^n wrap explicitly.
 */
export const speckRoundInverseNarration: NarrationFn = (frame) => {
  const ctx = readSpeckFrame(frame, "speck.round-inverse");
  if (!ctx) return null;
  const { p, x0: xPrime, y0: yPrime, k, mask } = ctx;
  // Inverse: y = ROR(y' XOR x', beta)
  const yMix = yPrime ^ xPrime;
  const y = ror(yMix, p.beta, p.wordBits);
  // x = ROL((x' XOR k) - y mod 2^n, alpha). Add `mask + 1` before
  // subtracting so JS arithmetic doesn't dip negative; trailing mask
  // normalises.
  const xXork = xPrime ^ k;
  const sub = (xXork - y + mask + 1) & mask;
  const x = rol(sub, p.alpha, p.wordBits);
  const w = p.wordBits;

  const units: NarrationUnit[] = [];

  units.push({
    key: "inv:1",
    label: "1. y ← ROR(y′ ⊕ x′, β)",
    Prose: () => (
      <div>
        <p>
          The forward round's last statement was <code>y' = ROL(y, β) ⊕ x'</code>. Undoing it: XOR
          x' off first, then rotate right by β = {p.beta} to undo the rotate- left.
        </p>
        <ul class="step-narration-mixcol-list">
          <li>
            {hexWord(yPrime, w)} ⊕ {hexWord(xPrime, w)} = {hexWord(yMix, w)}
          </li>
          <li>
            ROR({hexWord(yMix, w)}, {p.beta}) = {hexWord(y, w)}
          </li>
        </ul>
      </div>
    ),
  });

  units.push({
    key: "inv:2",
    label: "2. (x′ ⊕ k_i) − y  (mod 2^n)",
    Prose: () => (
      <div>
        <p>
          The forward round's first two statements were <code>x' = (ROR(x, α) + y) ⊕ k</code>. XOR k
          off, then subtract y modulo 2<sup>{w}</sup> to recover ROR(x, α).
        </p>
        <ul class="step-narration-mixcol-list">
          <li>
            {hexWord(xPrime, w)} ⊕ {hexWord(k, w)} = {hexWord(xXork, w)}
          </li>
          <li>
            ({hexWord(xXork, w)} − {hexWord(y, w)}) mod 2<sup>{w}</sup> = {hexWord(sub, w)}
          </li>
        </ul>
      </div>
    ),
  });

  units.push({
    key: "inv:3",
    label: "3. x ← ROL(…, α)",
    Prose: () => (
      <div>
        <p>
          The subtraction left ROR(x, α). Undo the right-rotate by rotating left by α = {p.alpha} to
          recover x.
        </p>
        <ul class="step-narration-mixcol-list">
          <li>
            ROL({hexWord(sub, w)}, {p.alpha}) = {hexWord(x, w)}
          </li>
        </ul>
      </div>
    ),
  });

  return units;
};

// ─── Shared helpers ──────────────────────────────────────────────────

/**
 * Common frame decode for both Speck narrators. Returns null on any
 * shape / param / aux mismatch — the narrator then renders nothing for
 * that frame.
 */
type SpeckFrame = {
  readonly p: {
    readonly alpha: number;
    readonly beta: number;
    readonly wordBits: number;
    readonly byteOrder: SpeckByteOrder;
    readonly roundKeyAux: string;
  };
  readonly x0: number;
  readonly y0: number;
  readonly k: number;
  readonly mask: number;
};

const readSpeckFrame = (
  frame: TraceFrame,
  stepName: "speck.round" | "speck.round-inverse",
): SpeckFrame | null => {
  const beforeBytes = readBytesState(frame.stateBefore);
  const afterBytes = readBytesState(frame.stateAfter);
  if (!beforeBytes || !afterBytes) return null;

  const params = frame.params;
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const pp = params as Record<string, Json>;
  const alpha = readPositiveInt(pp.alpha);
  const beta = readPositiveInt(pp.beta);
  const wordBits = readPositiveInt(pp.wordBits);
  if (alpha === null || beta === null || wordBits === null) return null;
  let byteOrder: SpeckByteOrder;
  try {
    byteOrder = readByteOrder(params, stepName);
  } catch {
    return null;
  }
  const roundKeyAux = pp.roundKeyAux;
  if (typeof roundKeyAux !== "string" || roundKeyAux.length === 0) return null;

  const wb = wordBits / 8;
  if (beforeBytes.length !== 2 * wb || afterBytes.length !== 2 * wb) return null;

  const auxValue = frame.auxRead.get(roundKeyAux);
  if (!(auxValue instanceof Uint8Array) || auxValue.length !== wb) return null;

  const [x0, y0] = decodeBlock(beforeBytes, wordBits, byteOrder);
  const k = decodeWord(auxValue, 0, wordBits, byteOrder);
  const mask = wordBits === 32 ? 0xffffffff : (1 << wordBits) - 1;

  return {
    p: { alpha, beta, wordBits, byteOrder, roundKeyAux },
    x0,
    y0,
    k,
    mask,
  };
};

/** Pull the bytes out of a BytesState; null on shape mismatch. */
const readBytesState = (state: TraceFrame["stateBefore"] | null): Uint8Array | null => {
  if (!state) return null;
  if (state.shape !== "bytes") return null;
  return (state as BytesState).bytes;
};

/**
 * Validate that a JSON value is a positive integer; return it or null.
 * Accepts undefined (from `Record<string, Json>` indexing under
 * `noUncheckedIndexedAccess`) so callers can `readPositiveInt(pp.alpha)`
 * without first narrowing.
 */
const readPositiveInt = (v: Json | undefined): number | null => {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1) return null;
  return v;
};

/** `wordBits/4`-digit hex with `0x` prefix. `0x6574` for a 16-bit word. */
const hexWord = (w: number, bits: number): string => {
  const mask = bits === 32 ? 0xffffffff : (1 << bits) - 1;
  return `0x${((w >>> 0) & mask).toString(16).padStart(bits / 4, "0")}`;
};

/**
 * Word rotation helpers. Duplicated from `speck-round.ts` / `speck-round-
 * inverse.ts` to keep narration self-contained — the executor has its
 * own copies; centralising them in a "speck-arithmetic.ts" utility would
 * be premature for three one-line functions. Both copies are bit-
 * identical and pinned through the cipher KAT.
 */
const wordMask = (bits: number): number => (bits === 32 ? 0xffffffff : (1 << bits) - 1);
const rol = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  return ((xm << n) | (xm >>> (bits - n))) & mask;
};
const ror = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  return ((xm >>> n) | (xm << (bits - n))) & mask;
};
