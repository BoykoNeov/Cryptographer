/**
 * ML-KEM lattice constants — the ring `R_q = Z_q[X]/(X²⁵⁶+1)` and the
 * number-theoretic transform over it (FIPS 203).
 *
 * `docs/plans/unified-stargazing-quasar.md`, P1. Module constants, never spec
 * params — the Blowfish π-table precedent (`blowfish-constants.ts`): a 256-byte
 * table has no business riding in every saved and shared document, and these are
 * published values rather than design knobs. What IS editable rides
 * `spec.cipherConstants` (see `ntt-3329-256.ts`), which is a different thing:
 * one live source of truth the runtime seeds into aux, so editing `q` in the app
 * moves every consumer in lockstep.
 *
 * ## The four numbers that matter
 *
 * | constant | value | why it is that value |
 * |---|---|---|
 * | `ML_KEM_Q` | 3329 | prime, and `q ≡ 1 (mod 512)` |
 * | `ML_KEM_N` | 256 | the polynomial degree bound |
 * | `NTT_ROOT` | 17 | a primitive 256th root of unity mod q |
 * | `N_INV_128` | 3303 | `128⁻¹ mod q` — note 128, **not** 256 |
 *
 * **Why `q ≡ 1 (mod 512)` is the whole ballgame.** A number-theoretic transform
 * needs a root of unity of the right order to exist in the field, and one of
 * order `k` exists mod a prime `q` exactly when `k` divides `q − 1`. Here
 * `q − 1 = 3328 = 2⁸ · 13`, so roots of order 256 exist and roots of order 512
 * do not. That single arithmetic fact decides the shape of everything below.
 *
 * **Why `128⁻¹` and not `256⁻¹`** — the mistake this file exists to prevent.
 * Because there is no primitive 512th root, the transform cannot split the
 * polynomial all the way down to 256 constants. It stops one layer short, at
 * **128 degree-1 polynomials**, so it runs **seven** layers rather than eight
 * and the factor that accumulates over the inverse is `2⁷ = 128`. Scaling by
 * `256⁻¹ = 3316` at the end produces a self-consistent transform that is wrong
 * by a factor of 2 and matches no implementation in the world.
 *
 * ## The ζ table, and the one thing to get right about it
 *
 * `ZETAS[i] = 17^BitRev7(i) mod 3329` — the exact table printed in FIPS 203
 * Appendix A. It is stored in **consumption order**, not in ascending order of
 * exponent: layer 1 uses `ZETAS[1]`, layer 2 uses `ZETAS[2]` and `ZETAS[3]`,
 * layer 3 uses `ZETAS[4..7]`, and so on. That is what lets the spec carry the
 * table as a cursor that advances by one entry per butterfly group and never
 * needs to compute an index. A table in exponent order would produce a
 * transform that is perfectly self-consistent and agrees with nothing.
 *
 * `ZETAS[0] = 1` is never consumed by either direction (the forward transform
 * runs i = 1…127, the inverse i = 127…1). It is present because it is in the
 * published table, and because keeping the index alignment means the table can
 * be checked against FIPS 203 entry by entry.
 *
 * `tests/ntt-3329-256-kat.test.ts` re-derives every entry from `17^BitRev7(i)`
 * independently, so a transcription slip here fails rather than propagating.
 */

// ─── The ring ─────────────────────────────────────────────────────────────

/** The prime modulus. Prime, and `q − 1 = 2⁸ · 13`, so 256th roots of unity
 *  exist and 512th ones do not. */
export const ML_KEM_Q = 3329;

/** Polynomial degree bound — a ring element is 256 coefficients. */
export const ML_KEM_N = 256;

/** Bytes per coefficient on a port. Two, since `q` needs 12 bits; the 12-bit
 *  packing ML-KEM uses on the wire is a separate, visible step (P2's
 *  `zq-byte-encode@1`), not something the arithmetic does silently. */
export const COEFF_BYTES = 2;

/** A polynomial on a port: 256 coefficients × 2 bytes. */
export const POLY_BYTES = ML_KEM_N * COEFF_BYTES;

// ─── The transform ────────────────────────────────────────────────────────

/** A primitive 256th root of unity mod q: `17²⁵⁶ ≡ 1` and `17¹²⁸ ≡ −1`. */
export const NTT_ROOT = 17;

/** Layers in the transform. Seven, not eight — see the file header. */
export const NTT_LAYERS = 7;

/** `128⁻¹ mod 3329`. The inverse transform's final scaling. NOT `256⁻¹`. */
export const N_INV_128 = 3303;

/**
 * `ZETAS[i] = 17^BitRev7(i) mod 3329`, i = 0…127 — FIPS 203 Appendix A,
 * verbatim, in consumption order.
 */
export const ZETAS: readonly number[] = [
  1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447,
  1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253,
  1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452,
  1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637,
  723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952,
  1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090,
  1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
  1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

// ─── Byte encodings (big-endian, the app's port convention) ───────────────

/** Encode one coefficient as `COEFF_BYTES` big-endian bytes. */
export const coeffBytes = (value: number): Uint8Array =>
  new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);

/** `q` on a port. */
export const Q_BYTES: Uint8Array = coeffBytes(ML_KEM_Q);

/** `128⁻¹ mod q` on a port. */
export const N_INV_BYTES: Uint8Array = coeffBytes(N_INV_128);

/**
 * The ζ table as 256 bytes — 128 entries, ascending index, big-endian each.
 *
 * This is the value that rides the iterate's cross-iteration chain as a
 * rotating cursor. The forward transform pre-rotates it by one entry so the
 * front holds `ζ¹`; the inverse consumes from the BACK, starting at `ζ¹²⁷`, so
 * it takes this table as-is.
 */
export const ZETA_TABLE_BYTES: Uint8Array = (() => {
  const out = new Uint8Array(ZETAS.length * COEFF_BYTES);
  ZETAS.forEach((z, i) => out.set(coeffBytes(z), i * COEFF_BYTES));
  return out;
})();

/** Pack a coefficient list into the flat port representation. */
export const packPoly = (coeffs: readonly number[]): Uint8Array => {
  const out = new Uint8Array(coeffs.length * COEFF_BYTES);
  coeffs.forEach((c, i) => out.set(coeffBytes(c), i * COEFF_BYTES));
  return out;
};

/** Unpack the flat port representation into a coefficient list. */
export const unpackPoly = (bytes: Uint8Array): number[] => {
  const out: number[] = [];
  for (let i = 0; i < bytes.length; i += COEFF_BYTES) {
    out.push((bytes[i] as number) * 256 + (bytes[i + 1] as number));
  }
  return out;
};
