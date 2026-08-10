/**
 * Keccak-f[1600] and the FIPS 202 sponge, computed in one call — for ML-KEM's
 * monolithic hash steps (P3 of `docs/plans/unified-stargazing-quasar.md`).
 *
 * ## Why this module exists
 *
 * Everywhere else in this app a sponge is a *spec*: `keccak-f.ts` builds 24
 * round groups of nine leaves each, the runtime walks them, and the learner
 * watches 216 frames go by. ML-KEM cannot afford that. It makes roughly
 * seventeen sponge calls per key generation, and at 240 spec nodes apiece that
 * is ~4,080 nodes — about 6.7 seconds of re-run and a canvas nobody can read —
 * before a single coefficient has been multiplied. So inside ML-KEM each hash
 * is ONE frame, and this module is what that frame calls.
 *
 * ## Why it is not a second Keccak implementation
 *
 * A monolith that reimplemented the permutation would be a second copy of the
 * algorithm, free to drift from the one the SHA-3 and SHAKE traces show. That
 * would quietly break the promise the ML-KEM steps make in their own
 * descriptions — "this is the same sponge you can watch under the Hash
 * selector, collapsed to one frame".
 *
 * So it is not reimplemented. `permuteState` below calls the **same nine step
 * executors the runtime calls**, in the same order, with the same constants
 * imported from `keccak-f.ts`:
 *
 *     keccak.theta@1 → rotate-lanes@1 (ρ) → permute@1 (π)
 *       → permute@1 ×2 (χ's row gathers) → not@1 → and@1 → xor@1
 *       → keccak.iota@1
 *
 * Compare `buildKeccakRound` in `keccak-f.ts`: that function emits exactly this
 * chain as spec nodes. This one runs it. Padding likewise goes through the
 * shipped `keccak.pad@1` executor rather than an inline pad10*1. What is
 * duplicated here is only the *wiring* — which port feeds which — and
 * `tests/keccak-compute.test.ts` pins the result against both `node:crypto` and
 * the app's own traced SHA3-256 spec, so a divergence cannot survive CI.
 *
 * The cost of the executor-driven route is allocation: each round allocates
 * nine 200-byte arrays. Measured, not assumed — an ML-KEM-768-keygen-sized
 * workload (nine SampleNTT squeezes, six PRF calls, one G) costs **~48 ms**,
 * comfortably inside the re-run budget the ChaCha20 CSPRNG already occupies.
 *
 * **References:** FIPS 202 §3.2 (the five step mappings), §4 (the sponge),
 * §5.1 (pad10*1), §B.2 (domain separation).
 */

import type { Json, StepContext, StepInputs } from "../core/types";
import { and } from "../steps/and";
import { keccakIota } from "../steps/keccak-iota";
import { keccakPad } from "../steps/keccak-pad";
import { keccakTheta } from "../steps/keccak-theta";
import { not } from "../steps/not";
import { permute } from "../steps/permute";
import { rotateLanes } from "../steps/rotate-lanes";
import { xor } from "../steps/xor";
import {
  CHI_SHIFT1,
  CHI_SHIFT2,
  PI_INDICES,
  RC_BYTES,
  RHO_OFFSETS,
  ROUNDS,
  STATE_BYTES,
} from "./keccak-f";

// ─── Sponge parameters, by function ─────────────────────────────────────────

/**
 * Rate in bytes = (1600 − 2·capacity) / 8. The capacity is twice the security
 * strength, which is why SHA3-512 absorbs less per permutation than SHA3-256.
 */
export const RATE_SHA3_256 = 136;
export const RATE_SHA3_512 = 72;
export const RATE_SHAKE128 = 168;
export const RATE_SHAKE256 = 136;

/** Domain-separation suffixes (FIPS 202 §B.2), carrying the pad's leading bit. */
export const DOMAIN_SHA3 = 0x06;
export const DOMAIN_SHAKE = 0x1f;

// ─── Executor plumbing ──────────────────────────────────────────────────────

// The executors take a `StepContext` but none of the eight used here reads it;
// ι takes its round constant from a PORT (the runtime projects aux onto it), so
// the aux map stays empty and the RC table is passed explicitly below.
const CTX: StepContext = { stepId: "keccak-compute", path: [], aux: new Map() };

const RHO_PARAMS: Json = { wordBits: 64, offsets: [...RHO_OFFSETS], littleEndian: true };
const PI_PARAMS: Json = { indices: [...PI_INDICES] };
const CHI_B_PARAMS: Json = { indices: [...CHI_SHIFT1] };
const CHI_C_PARAMS: Json = { indices: [...CHI_SHIFT2] };
const TWO_OPERANDS: Json = { inputCount: 2 };

const one = (name: string, bytes: Uint8Array): StepInputs => new Map([[name, bytes]]);

/** Read a step's single `output` port, failing loudly if the contract changed. */
const outputOf = (outputs: ReadonlyMap<string, Uint8Array>, what: string): Uint8Array => {
  const value = outputs.get("output");
  if (value === undefined) {
    throw new Error(`keccak-compute: ${what} produced no "output" port`);
  }
  return value;
};

// ─── The permutation ────────────────────────────────────────────────────────

/**
 * Keccak-f[1600] over a 200-byte state, performed by the shipped executors.
 *
 * Mirrors `buildKeccakRound` node for node. If that builder's chain ever
 * changes, this must change with it — `tests/keccak-compute.test.ts` compares
 * this function's SHA3-256 against the traced spec's, so the two cannot silently
 * disagree.
 */
export const keccakPermuteBytes = (state: Uint8Array): Uint8Array => {
  if (state.length !== STATE_BYTES) {
    throw new Error(`keccak-compute: state must be ${STATE_BYTES} bytes, got ${state.length}`);
  }
  let s = state;
  for (let round = 0; round < ROUNDS; round++) {
    // θ — column parity mixed back into every lane.
    const theta = outputOf(keccakTheta(one("input", s), {}, CTX), "θ");
    // ρ — per-lane left rotate, lanes little-endian.
    const rho = outputOf(rotateLanes(one("input", theta), RHO_PARAMS, CTX), "ρ");
    // π — lane transposition.
    const pi = outputOf(permute(one("input", rho), PI_PARAMS, CTX), "π");
    // χ — A[x] ⊕ (¬A[x+1] ∧ A[x+2]), decomposed exactly as the trace shows it.
    const shifted1 = outputOf(permute(one("input", pi), CHI_B_PARAMS, CTX), "χ's A[x+1] gather");
    const shifted2 = outputOf(permute(one("input", pi), CHI_C_PARAMS, CTX), "χ's A[x+2] gather");
    const inverted = outputOf(not(one("input", shifted1), {}, CTX), "χ's NOT");
    const anded = outputOf(
      and(
        new Map([
          ["operand0", inverted],
          ["operand1", shifted2],
        ]),
        TWO_OPERANDS,
        CTX,
      ),
      "χ's AND",
    );
    const chi = outputOf(
      xor(
        new Map([
          ["operand0", pi],
          ["operand1", anded],
        ]),
        TWO_OPERANDS,
        CTX,
      ),
      "χ",
    );
    // ι — XOR this round's constant into lane (0,0). The runtime would project
    // aux["RC"] onto the `rc` port; a direct caller supplies the table itself.
    s = outputOf(
      keccakIota(
        new Map([
          ["input", chi],
          ["rc", RC_BYTES],
        ]),
        { round, auxName: "RC" },
        CTX,
      ),
      "ι",
    );
  }
  return s;
};

// ─── The sponge ─────────────────────────────────────────────────────────────

/**
 * FIPS 202 §4's sponge: pad the message, absorb it `rate` bytes at a time, then
 * squeeze `outputBytes` out — permuting between squeezed blocks but not before
 * the first, which is why a digest shorter than the rate costs no extra
 * permutation.
 */
export const keccakSponge = (
  message: Uint8Array,
  rate: number,
  domainByte: number,
  outputBytes: number,
): Uint8Array => {
  if (outputBytes < 0) {
    throw new Error(`keccak-compute: outputBytes must be non-negative, got ${outputBytes}`);
  }
  const padded = outputOf(keccakPad(one("input", message), { rate, domainByte }, CTX), "pad10*1");

  // Annotated because `new Uint8Array(n)` narrows to `Uint8Array<ArrayBuffer>`
  // while the executors return the `ArrayBufferLike` default, and this variable
  // is assigned from both.
  let state: Uint8Array = new Uint8Array(STATE_BYTES);
  for (let offset = 0; offset < padded.length; offset += rate) {
    const absorbed = new Uint8Array(state);
    for (let i = 0; i < rate; i++) {
      absorbed[i] = (absorbed[i] as number) ^ (padded[offset + i] as number);
    }
    state = keccakPermuteBytes(absorbed);
  }

  const out = new Uint8Array(outputBytes);
  let written = 0;
  while (written < outputBytes) {
    const take = Math.min(rate, outputBytes - written);
    out.set(state.subarray(0, take), written);
    written += take;
    if (written < outputBytes) state = keccakPermuteBytes(state);
  }
  return out;
};

// ─── The four functions ML-KEM uses ─────────────────────────────────────────

/** SHA3-256 — ML-KEM's `H`. */
export const sha3_256 = (message: Uint8Array): Uint8Array =>
  keccakSponge(message, RATE_SHA3_256, DOMAIN_SHA3, 32);

/** SHA3-512 — ML-KEM's `G`, whose 64 bytes split into `(ρ, σ)`. */
export const sha3_512 = (message: Uint8Array): Uint8Array =>
  keccakSponge(message, RATE_SHA3_512, DOMAIN_SHA3, 64);

/** SHAKE128 — ML-KEM's `XOF`, squeezed until `SampleNTT` has 256 coefficients. */
export const shake128 = (message: Uint8Array, outputBytes: number): Uint8Array =>
  keccakSponge(message, RATE_SHAKE128, DOMAIN_SHAKE, outputBytes);

/** SHAKE256 — ML-KEM's `PRF` and `J`. */
export const shake256 = (message: Uint8Array, outputBytes: number): Uint8Array =>
  keccakSponge(message, RATE_SHAKE256, DOMAIN_SHAKE, outputBytes);

/**
 * An incremental SHAKE128 squeeze, for `SampleNTT`.
 *
 * `SampleNTT` rejects candidate coefficients `≥ q` and cannot know in advance
 * how many bytes it will need — the count is a random variable with no fixed
 * bound. Squeezing a hardcoded number of blocks is therefore a *silently wrong
 * matrix on some seeds*: the same failure class as an under-sized RSA unroll.
 * This returns a stateful reader so the caller's loop condition can be the
 * accepted-coefficient count, which is the only correct one.
 */
export const shake128Reader = (message: Uint8Array): (() => Uint8Array) => {
  const padded = outputOf(
    keccakPad(one("input", message), { rate: RATE_SHAKE128, domainByte: DOMAIN_SHAKE }, CTX),
    "pad10*1",
  );
  let state: Uint8Array = new Uint8Array(STATE_BYTES);
  for (let offset = 0; offset < padded.length; offset += RATE_SHAKE128) {
    const absorbed = new Uint8Array(state);
    for (let i = 0; i < RATE_SHAKE128; i++) {
      absorbed[i] = (absorbed[i] as number) ^ (padded[offset + i] as number);
    }
    state = keccakPermuteBytes(absorbed);
  }
  let first = true;
  /** Squeeze the next 168-byte block. */
  return (): Uint8Array => {
    if (!first) state = keccakPermuteBytes(state);
    first = false;
    return state.slice(0, RATE_SHAKE128);
  };
};
