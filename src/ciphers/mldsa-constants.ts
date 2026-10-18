/**
 * ML-DSA lattice constants — the ring `R_q = Z_q[X]/(X²⁵⁶+1)` with
 * `q = 8380417`, the number-theoretic transform over it, and the ML-DSA-44
 * parameter set (FIPS 204).
 *
 * `docs/plans/refactored-petting-tide.md`. Module constants, never spec params —
 * the same posture `mlkem-constants.ts` takes, for the same reason: a 1024-byte
 * table of published values has no business riding in every saved and shared
 * document. What IS editable rides `spec.cipherConstants`.
 *
 * ## Same ring, different prime — and the prime decides everything
 *
 * | constant | ML-KEM | ML-DSA | why |
 * |---|---|---|---|
 * | `q` | 3329 | 8380417 | prime in both |
 * | `q − 1` | 2⁸ · 13 | 2¹³ · 3 · 11 · 31 | how many factors of 2 |
 * | root of unity | 17 (order 256) | 1753 (order **512**) | |
 * | layers | 7 | **8** | |
 * | final scaling | `128⁻¹` | `256⁻¹` = 8347681 | |
 *
 * A root of unity of order `k` exists modulo a prime `q` exactly when `k`
 * divides `q − 1`. ML-KEM's prime has only eight factors of 2, so no 512th root
 * exists and its transform stops one layer short, at 128 little degree-1
 * polynomials. **This prime has thirteen**, so a primitive 512th root exists
 * (1753), the transform runs all **eight** layers down to 256 single numbers,
 * and multiplication in the transformed domain is plain element-wise — the
 * exact opposite of ML-KEM's "per pair, never element-wise" rule. The two
 * transforms are the same algorithm; the prime is the whole difference.
 *
 * `q = 2²³ − 2¹³ + 1`, which is why a coefficient needs 23 bits and therefore
 * four bytes on a port.
 *
 * ## The ζ table
 *
 * `ZETAS[k] = 1753^BitRev8(k) mod q` — FIPS 204 Appendix B, in **consumption
 * order**: layer 1 uses entry 1, layer 2 entries 2–3, layer 3 entries 4–7, …,
 * layer 8 entries 128–255. That is what lets the spec carry the table as a
 * cursor that advances one entry per butterfly group and never computes an
 * index (the ML-KEM design, unchanged).
 *
 * **Entry 0 is listed as 0, not as ζ⁰ = 1.** Neither direction ever reads it
 * (forward consumes 1 … 255, inverse 255 … 1), and the reference table records
 * it as 0. It is kept verbatim so the table can be checked against the published
 * one entry by entry; `tests/ntt-8380417-256-kat.test.ts` re-derives entries
 * 1 … 255 from `1753^BitRev8(k)` independently, and separately shows that
 * changing entry 0 changes nothing.
 */

// ─── The ring ─────────────────────────────────────────────────────────────

/** The prime modulus, `2²³ − 2¹³ + 1`. `q − 1 = 2¹³ · 3 · 11 · 31`, so roots of
 *  unity of order 512 exist. */
export const ML_DSA_Q = 8380417;

/** Polynomial degree bound — a ring element is 256 coefficients. */
export const ML_DSA_N = 256;

/** Bytes per coefficient on a port. Four, since `q` needs 23 bits. */
export const ML_DSA_COEFF_BYTES = 4;

/** A polynomial on a port: 256 coefficients × 4 bytes. */
export const ML_DSA_POLY_BYTES = ML_DSA_N * ML_DSA_COEFF_BYTES;

// ─── The transform ────────────────────────────────────────────────────────

/** A primitive 512th root of unity mod q: `1753²⁵⁶ ≡ −1` and `1753⁵¹² ≡ 1`. */
export const ML_DSA_NTT_ROOT = 1753;

/** Layers in the transform. Eight — all the way down. */
export const ML_DSA_NTT_LAYERS = 8;

/** `256⁻¹ mod q`. The inverse transform's final scaling. */
export const ML_DSA_N_INV_256 = 8347681;

/**
 * `ZETAS[k] = 1753^BitRev8(k) mod 8380417`, k = 0…255 — FIPS 204 Appendix B,
 * verbatim, in consumption order. Entry 0 is listed as 0 and never read.
 */
export const ML_DSA_ZETAS: readonly number[] = [
  0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288,
  2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975, 7946292,
  676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733, 3602218,
  3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148, 928749, 1095468, 4874037,
  2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429,
  4430364, 5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416, 3073009, 1277625,
  5744944, 3852015, 4183372, 5157610, 5258977, 8106357, 2508980, 2028118, 1937570, 4564692, 2811291,
  5396636, 7270901, 4158088, 1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
  4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328,
  6125690, 3482206, 4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756,
  2925816, 3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812,
  8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527,
  2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502,
  4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264, 4969849,
  2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938, 6653329, 2387513,
  4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
  2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950, 7921677, 6458423, 4040196,
  4908348, 2039144, 6500539, 7561656, 6201452, 6757063, 2105286, 6006015, 6346610, 586241, 7200804,
  527981, 5637006, 6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891, 5346675,
  8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229,
  1665318, 2028038, 1163598, 5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376,
  7609976, 3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265, 6195333, 3123762,
  2358373, 6187330, 5365997, 6663603, 2926054, 7987710, 8077412, 3531229, 4405932, 4606686, 1900052,
  7598542, 1054478, 7648983,
];

// ─── ML-DSA-44 parameters (FIPS 204 Table 1) ──────────────────────────────
//
// Used from P2 onwards. Collected here so the whole parameter set reads in one
// place, the way the standard prints it.

/** Rows of the matrix A (and of t, w, h). */
export const ML_DSA_44_K = 4;
/** Columns of the matrix A (and length of s1, y, z). */
export const ML_DSA_44_L = 4;
/** Secret coefficients are drawn from [−η, η]. */
export const ML_DSA_44_ETA = 2;
/** Number of ±1 coefficients in the challenge polynomial c. */
export const ML_DSA_44_TAU = 39;
/** Bits dropped from t by Power2Round. */
export const ML_DSA_D = 13;
/** Range of the masking vector y: coefficients in (−γ1, γ1]. */
export const ML_DSA_44_GAMMA1 = 1 << 17;
/** Low-order rounding range: `(q − 1) / 88`. */
export const ML_DSA_44_GAMMA2 = (ML_DSA_Q - 1) / 88;
/** `τ · η` — the largest any coefficient of c·s1 or c·s2 can be. */
export const ML_DSA_44_BETA = ML_DSA_44_TAU * ML_DSA_44_ETA;
/** Maximum number of 1s in the hint. */
export const ML_DSA_44_OMEGA = 80;
/** Collision strength in bits; the challenge seed c̃ is λ/4 = 32 bytes. */
export const ML_DSA_44_LAMBDA = 128;

// ─── Byte encodings (big-endian, the app's port convention) ───────────────

/** Encode one coefficient as four big-endian bytes. */
export const mlDsaCoeffBytes = (value: number): Uint8Array =>
  new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);

/** `q` on a port. */
export const ML_DSA_Q_BYTES: Uint8Array = mlDsaCoeffBytes(ML_DSA_Q);

/** `256⁻¹ mod q` on a port. */
export const ML_DSA_N_INV_BYTES: Uint8Array = mlDsaCoeffBytes(ML_DSA_N_INV_256);

/**
 * The ζ table as 1024 bytes — 256 entries, ascending index, big-endian each. The
 * value that rides each layer's cross-iteration chain as a rotating cursor.
 */
export const ML_DSA_ZETA_TABLE_BYTES: Uint8Array = (() => {
  const out = new Uint8Array(ML_DSA_ZETAS.length * ML_DSA_COEFF_BYTES);
  ML_DSA_ZETAS.forEach((z, i) => out.set(mlDsaCoeffBytes(z), i * ML_DSA_COEFF_BYTES));
  return out;
})();

/** Pack a coefficient list into the flat port representation. */
export const packMlDsaPoly = (coeffs: readonly number[]): Uint8Array => {
  const out = new Uint8Array(coeffs.length * ML_DSA_COEFF_BYTES);
  coeffs.forEach((c, i) => out.set(mlDsaCoeffBytes(c), i * ML_DSA_COEFF_BYTES));
  return out;
};

/** Unpack the flat port representation into a coefficient list. */
export const unpackMlDsaPoly = (bytes: Uint8Array): number[] => {
  const out: number[] = [];
  for (let i = 0; i < bytes.length; i += ML_DSA_COEFF_BYTES) {
    out.push(
      (bytes[i] as number) * 2 ** 24 +
        (bytes[i + 1] as number) * 2 ** 16 +
        (bytes[i + 2] as number) * 2 ** 8 +
        (bytes[i + 3] as number),
    );
  }
  return out;
};
