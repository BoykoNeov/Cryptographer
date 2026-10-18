/**
 * ML-DSA rounding arithmetic — the pure functions behind the `ml-dsa.*`
 * rounding and hint steps (FIPS 204 §7.4, Algorithms 35–40).
 *
 * `docs/plans/refactored-petting-tide.md`, P2. Kept as plain functions over
 * `number` so the step executors, the narrators and the tests all call ONE
 * implementation of each rule — the same reason `zq-vector.ts` owns the
 * coefficient codec. (The tests' own oracles are deliberately NOT these
 * functions: see `tests/ml-dsa-rounding.test.ts`, which derives each answer a
 * different way.)
 *
 * ## Why `number` and not `bigint` here
 *
 * Every value these functions see is a coefficient below `q = 8380417 < 2²³`,
 * or a sum of two of them. That is far inside a double's exact range (2⁵³), so
 * `number` is exact and much easier to read. The step executors still read
 * their ports with `readCoeff` (bigint) and convert once at the boundary, after
 * checking the value fits.
 *
 * ## Centred values never travel a wire
 *
 * Several of these rules produce a NEGATIVE number — `r0` in Power2Round and
 * Decompose is centred on zero. On a port every coefficient is a residue in
 * `[0, q)`, so the executors write `r0 mod q` (−5 travels as `q − 5`, exactly
 * the convention `zq-vec-sub@1` documents). The centred form exists only here,
 * inside the arithmetic, where the rules are stated in terms of it.
 */

import {
  type ZqVecParams,
  readCoeff,
  readZqModulus,
  requireZqPort,
  writeCoeff,
  zqElementCount,
} from "./zq-vector";

// ─── Centred reduction ────────────────────────────────────────────────────

/**
 * `r mod± α` (FIPS 204 §2.3): the unique `m ≡ r (mod α)` with
 * `−⌈α/2⌉ < m ≤ ⌊α/2⌋`. For even α that is `(−α/2, α/2]`; for the odd modulus
 * `q` it is `[−(q−1)/2, (q−1)/2]`.
 *
 * This is the one place a sign appears, and both rounding rules below are
 * written in terms of it — which is why it is its own function rather than an
 * inline expression repeated four times.
 */
export const modPm = (r: number, alpha: number): number => {
  const m = ((r % alpha) + alpha) % alpha;
  return m > Math.floor(alpha / 2) ? m - alpha : m;
};

/** `r mod q`, always non-negative — how a centred value is put back on a wire. */
export const toResidue = (r: number, q: number): number => ((r % q) + q) % q;

/** Bit length of a non-negative integer: `bitlen(0) = 0`, `bitlen(5) = 3`. */
export const bitlen = (x: number): number => (x <= 0 ? 0 : Math.floor(Math.log2(x)) + 1);

// ─── Power2Round (Algorithm 35) ───────────────────────────────────────────

/**
 * Split `r` into a high part and a `d`-bit centred low part:
 * `r ≡ r1·2^d + r0` with `−2^(d−1) < r0 ≤ 2^(d−1)`.
 *
 * Key generation applies this to `t`: the high part `t1` goes into the public
 * key, the low part `t0` stays in the private key. Dropping 13 bits per
 * coefficient is what makes the public key 1312 bytes instead of 2976.
 */
export const power2Round = (r: number, d: number, q: number): { r1: number; r0: number } => {
  const rPlus = toResidue(r, q);
  const r0 = modPm(rPlus, 2 ** d);
  return { r1: (rPlus - r0) / 2 ** d, r0 };
};

// ─── Decompose / HighBits / LowBits (Algorithms 36–38) ────────────────────

/**
 * Throw unless `2γ2` divides `q − 1`. Decompose's buckets are `2γ2` wide and
 * there must be a whole number of them, `m = (q−1)/(2γ2)`; the special case
 * below is the fix-up for the ONE place the last bucket would otherwise wrap
 * past `q − 1`. With a γ2 that does not divide, that fix-up is no longer
 * correct and the hint arithmetic silently stops working — so a learner
 * editing γ2 gets an error naming the rule instead.
 */
export const checkGamma2 = (gamma2: number, q: number, step: string): void => {
  if (!Number.isInteger(gamma2) || gamma2 < 1 || (q - 1) % (2 * gamma2) !== 0) {
    throw new Error(
      `${step}: γ2 = ${gamma2} does not divide (q − 1)/2 = ${(q - 1) / 2}; Decompose needs a whole number of 2γ2-wide buckets`,
    );
  }
};

/**
 * Split `r` into a bucket index `r1` and a centred offset `r0` within that
 * bucket: `r ≡ r1·2γ2 + r0` with `−γ2 < r0 ≤ γ2`.
 *
 * **The special case** (`r⁺ − r0 = q − 1`): the topmost values sit within γ2
 * of `q − 1 ≡ −1`, so they are really "just below zero". Without the fix-up
 * they would get bucket index `m = (q−1)/(2γ2)`, one past the last real bucket.
 * FIPS folds them into bucket 0 instead and shifts `r0` down by one so that
 * `r1·2γ2 + r0 ≡ r` still holds. Miss this and `HighBits` occasionally returns
 * 44 at ML-DSA-44's parameters, where the real buckets are 0…43 — a value
 * outside the range `w1Encode` is defined on.
 */
export const decompose = (
  r: number,
  gamma2: number,
  q: number,
): { r1: number; r0: number; wrapped: boolean } => {
  const rPlus = toResidue(r, q);
  const r0 = modPm(rPlus, 2 * gamma2);
  if (rPlus - r0 === q - 1) return { r1: 0, r0: r0 - 1, wrapped: true };
  return { r1: (rPlus - r0) / (2 * gamma2), r0, wrapped: false };
};

export const highBits = (r: number, gamma2: number, q: number): number =>
  decompose(r, gamma2, q).r1;

export const lowBits = (r: number, gamma2: number, q: number): number => decompose(r, gamma2, q).r0;

// ─── MakeHint / UseHint (Algorithms 39–40) ────────────────────────────────

/**
 * Does adding `z` to `r` change its high bits? That single bit is the hint.
 *
 * The signer knows both `r` and the small correction `z`; the verifier will
 * only be able to compute `r + z`. One bit per coefficient is enough for the
 * verifier to recover `HighBits(r)` anyway — see `useHint`.
 */
export const makeHint = (z: number, r: number, gamma2: number, q: number): 0 | 1 =>
  highBits(r, gamma2, q) === highBits(r + z, gamma2, q) ? 0 : 1;

/**
 * Recover the high bits the signer meant, from a value that may have drifted
 * into the neighbouring bucket.
 *
 * If the hint says "you are in the wrong bucket", the low part says WHICH
 * neighbour: a positive offset means the value is in the upper half of its
 * bucket, so the intended one is the next bucket up; otherwise the one below.
 * Bucket indices wrap modulo `m`, because the buckets sit on a circle of
 * circumference `q`.
 */
export const useHint = (h: number, r: number, gamma2: number, q: number): number => {
  const m = (q - 1) / (2 * gamma2);
  const { r1, r0 } = decompose(r, gamma2, q);
  if (h === 1 && r0 > 0) return (r1 + 1) % m;
  if (h === 1) return (r1 - 1 + m) % m;
  return r1;
};

// ─── Port codec helpers for the ml-dsa.* executors ────────────────────────

/**
 * Every coefficient of a vector port, as numbers. Reads through `readCoeff`,
 * the function the whole Z_q family uses, so an ML-DSA step and a `zq-` step
 * can never disagree about where one coefficient ends and the next begins.
 */
export const coeffNumbers = (bytes: Uint8Array, p: ZqVecParams): number[] => {
  const n = Math.floor(bytes.length / p.coeffBytes);
  const out: number[] = [];
  for (let i = 0; i < n; i++) out.push(Number(readCoeff(bytes, i, p)));
  return out;
};

/** Pack non-negative numbers into a vector port, same codec. */
export const packNumbers = (values: readonly number[], p: ZqVecParams): Uint8Array => {
  const out = new Uint8Array(values.length * p.coeffBytes);
  values.forEach((v, i) => writeCoeff(out, i, BigInt(v), p));
  return out;
};

/** A one-byte yes/no — the shape every accept/reject check emits. */
export const flagByte = (yes: boolean): Uint8Array => new Uint8Array([yes ? 1 : 0]);

/** A two-byte big-endian count. */
export const countBytes = (n: number): Uint8Array => new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);

/**
 * The modulus port as a `number`, for the `ml-dsa.*` executors. Same checks as
 * `readZqModulus` (positive, fits a coefficient), plus one more: the rounding
 * rules above add two residues, so `2q` must stay exact in a double.
 */
export const readMlDsaModulus = (
  inputs: ReadonlyMap<string, Uint8Array>,
  p: ZqVecParams,
  step: string,
): number => {
  const q = readZqModulus(inputs.get("modulus"), p, step);
  if (q > 2n ** 51n) {
    throw new Error(`${step}: modulus ${q} is too large for this step's arithmetic`);
  }
  return Number(q);
};

/**
 * Read a vector port into numbers, checking every coefficient is a residue
 * below `q`. A value ≥ q is not "some large coefficient" here — Decompose and
 * Power2Round both reduce first, and a learner whose wiring hands them an
 * unreduced value should hear about it rather than get a silently-reduced
 * answer from a step that claims not to reduce.
 */
export const readResidues = (
  inputs: ReadonlyMap<string, Uint8Array>,
  portName: string,
  p: ZqVecParams,
  q: number,
  step: string,
): number[] => {
  const bytes = requireZqPort(inputs, portName, step);
  zqElementCount(bytes, p, portName, step);
  const values = coeffNumbers(bytes, p);
  values.forEach((v, i) => {
    if (v >= q) {
      throw new Error(
        `${step}: coefficient ${i} on port "${portName}" is ${v}, not a residue below q = ${q}`,
      );
    }
  });
  return values;
};
