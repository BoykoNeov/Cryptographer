/**
 * Big-endian word codec — bytes ↔ N-bit words plus right-rotation
 * primitives at the four canonical cryptographic word widths.
 *
 * Consolidated 2026-05-24 in universal-port plan **Phase 2 Slice 2.2**
 * from duplicate inline helpers that had landed in `src/steps/rotate-
 * bits-right.ts` (Slice 2.1a) and `src/steps/add-mod-32.ts` (Slice
 * 2.1b). Both files carried TODO comments anticipating this slice.
 *
 * **Why "(a+) shared codec, no layout tag" over "(b) codec + new
 * `word-array-be-32` PortContract layout tag":** under the universal-
 * port plan's Q1 hybrid posture, layout tags are advisory only — the
 * runtime always passes raw `Uint8Array`. No editor / graph view /
 * inspector surface in Phase 2's scope reads a port's `layout` field
 * as data; per-leaf "this is a 32-bit BE word" prose lives in
 * `narrationOverride` (Slice 1.10). The `matrix-cm-4x4` precedent is
 * NOT analogous — that tag carries runtime info for `State[]` aux
 * passthrough in `port-projection.ts` (Slice 2.0b-ii). A word-array
 * tag would have no equivalent load-bearing job today. If Phase 2.10's
 * graph view eventually needs grey-out logic between word-typed and
 * raw-typed ports, adding the tag then is a small follow-on commit.
 *
 * **API shape: per-width fns.** Each width gets its own `decodeBE{N}`
 * / `encodeBE{N}` / `ror{N}` exports. A unified `decodeBEWord(bytes,
 * offset, bits)` returning `number | bigint` would be uglier at every
 * call site (`as number` casts on the 8/16/32 paths) and would force
 * BigInt allocation on the hot 32-bit path. The per-width split also
 * lets consumers that know their width at compile time (e.g.,
 * `add-mod-32` which is fixed-width 32) import only what they need.
 *
 * **Width coverage 8/16/32/64.** Carries beyond the immediate SHA-256
 * (32-bit) consumer to:
 *  - **Speck rebuild from medium primitives** (Phase 4b) — Speck32/64
 *    uses 16-bit words; Speck64/128 uses 32; Speck128/256 uses 64.
 *  - **SHA-512 / Blake2b / Argon2** (Phase 2c+) — 64-bit-word hashes.
 *  - **Byte-substitute / per-byte transforms** — 8-bit reads land here
 *    too (`decodeBE8` is trivially `bytes[offset]`, but exporting it
 *    keeps the API uniform).
 *
 * **64-bit handling.** JavaScript number bitwise operators (`>>>`,
 * `<<`, `|`, `^`) truncate to 32-bit unsigned, so 64-bit arithmetic
 * MUST use `bigint`. The `decodeBE64` / `encodeBE64` / `ror64` exports
 * accept and return `bigint`; consumers wrap their loops in BigInt
 * conversions at the width boundary.
 */

// ─── Decode helpers ───────────────────────────────────────────────────────
//
// All decoders assume the caller bounds-checked `offset + width/8 ≤
// bytes.length`. Decoders accept any non-negative offset; out-of-bounds
// reads silently use `undefined` under `noUncheckedIndexedAccess`, which
// then NaN's the arithmetic — fail loudly upstream rather than have the
// decoder guard.

/**
 * Read one byte as an 8-bit unsigned integer. Mostly a uniformity
 * export — direct indexing is equivalent — but lets consumers that
 * dispatch by `wordBits` use a single call shape across all widths.
 */
export const decodeBE8 = (bytes: Uint8Array, offset: number): number => {
  return bytes[offset] as number;
};

/** Read 2 bytes as a big-endian unsigned 16-bit integer. */
export const decodeBE16 = (bytes: Uint8Array, offset: number): number => {
  return (((bytes[offset] as number) << 8) | (bytes[offset + 1] as number)) >>> 0;
};

/**
 * Read 4 bytes as a big-endian unsigned 32-bit integer.
 *
 * The trailing `>>> 0` forces the result back into the unsigned 32-bit
 * domain. Without it, a top byte ≥ 0x80 would set bit 31 inside JS's
 * signed-int semantics for bitwise OR, returning a NEGATIVE number that
 * silently breaks downstream `+` arithmetic.
 */
export const decodeBE32 = (bytes: Uint8Array, offset: number): number => {
  return (
    (((bytes[offset] as number) << 24) |
      ((bytes[offset + 1] as number) << 16) |
      ((bytes[offset + 2] as number) << 8) |
      (bytes[offset + 3] as number)) >>>
    0
  );
};

/**
 * Read 8 bytes as a big-endian unsigned 64-bit integer (`bigint`).
 *
 * Returns `bigint`, not `number`: JS numbers are IEEE doubles with only
 * 53 mantissa bits — values above 2^53 lose low-bit precision, which
 * would silently corrupt hash + cipher arithmetic. BigInt is the only
 * safe 64-bit container in JS.
 */
export const decodeBE64 = (bytes: Uint8Array, offset: number): bigint => {
  let word = 0n;
  for (let j = 0; j < 8; j++) {
    word = (word << 8n) | BigInt(bytes[offset + j] as number);
  }
  return word;
};

// ─── Encode helpers ───────────────────────────────────────────────────────
//
// All encoders write the word in big-endian byte order starting at
// `offset`. `out` must have at least `offset + width/8` bytes allocated.
// Encoders mask each byte with `0xff` defensively — callers that pass
// values outside the declared word range (e.g., 0x100 to `encodeBE8`)
// truncate to the low 8 bits, matching mathematical "mod 2^width"
// semantics without throwing.

/** Write 1 byte (low 8 bits of `word`). */
export const encodeBE8 = (out: Uint8Array, offset: number, word: number): void => {
  out[offset] = word & 0xff;
};

/** Write 2 bytes (low 16 bits of `word`), big-endian. */
export const encodeBE16 = (out: Uint8Array, offset: number, word: number): void => {
  out[offset] = (word >>> 8) & 0xff;
  out[offset + 1] = word & 0xff;
};

/** Write 4 bytes (low 32 bits of `word`), big-endian. */
export const encodeBE32 = (out: Uint8Array, offset: number, word: number): void => {
  out[offset] = (word >>> 24) & 0xff;
  out[offset + 1] = (word >>> 16) & 0xff;
  out[offset + 2] = (word >>> 8) & 0xff;
  out[offset + 3] = word & 0xff;
};

/** Write 8 bytes (low 64 bits of `word`), big-endian. */
export const encodeBE64 = (out: Uint8Array, offset: number, word: bigint): void => {
  for (let j = 0; j < 8; j++) {
    out[offset + j] = Number((word >> BigInt(8 * (7 - j))) & 0xffn);
  }
};

// ─── Right-rotation helpers ───────────────────────────────────────────────
//
// Cyclic right-rotation: top bits stay at the top after rotating;
// bits shifted off the bottom wrap to the top. Symmetric pseudocode at
// every width:
//
//   ROR(w, n) = ((w >> n) | (w << (B - n))) & mask
//
// Where B is the word width in bits and `mask = 2^B - 1`.
//
// `n` should be canonicalized to `[0, B)` by the caller (e.g.,
// `params.bits % wordBits`). The math still works for n=0 because JS
// `>>> 0` is identity AND `<< B` mod-32-truncates the shift amount to
// 0 → `xm | xm = xm`. The 64-bit path needs the explicit mask since
// `<< 64n` doesn't truncate (BigInt has no shift truncation).

/** Right-rotate an 8-bit word by `n` positions. `n` ∈ [0, 8). */
export const ror8 = (x: number, n: number): number => {
  const xm = x & 0xff;
  return ((xm >>> n) | (xm << (8 - n))) & 0xff;
};

/** Right-rotate a 16-bit word by `n` positions. `n` ∈ [0, 16). */
export const ror16 = (x: number, n: number): number => {
  const xm = x & 0xffff;
  return ((xm >>> n) | (xm << (16 - n))) & 0xffff;
};

/**
 * Right-rotate a 32-bit word by `n` positions. `n` ∈ [0, 32).
 *
 * The trailing `>>> 0` is the standard "as unsigned" coercion — without
 * it, `((xm >>> n) | (xm << (32 - n)))` re-introduces a signed view of
 * the high bit, which silently breaks downstream comparisons.
 */
export const ror32 = (x: number, n: number): number => {
  const xm = x >>> 0;
  return ((xm >>> n) | (xm << (32 - n))) >>> 0;
};

/**
 * Right-rotate a 64-bit word by `n` positions. `n` ∈ [0, 64).
 *
 * `n` is `bigint`, not `number`, because the right-shift below is a
 * BigInt op and JS requires both operands of `>>` to be `bigint` when
 * either is. Callers that have an integer `n: number` pass `BigInt(n)`.
 */
export const ror64 = (x: bigint, n: bigint): bigint => {
  const mask = (1n << 64n) - 1n;
  const xm = x & mask;
  return ((xm >> n) | (xm << (64n - n))) & mask;
};

// ─── Logical right-shift helpers ──────────────────────────────────────────
//
// Logical shift right: bits shifted off the bottom DROP; the top is
// zero-filled. Distinct from `ror{N}` (which wraps the bottom bits to the
// top). Math at every width:
//
//   SHR(w, n) = (w >> n) & mask     (top bits zero-filled)
//
// Where `mask = 2^B - 1`. Callers MUST canonicalize `n` to `[0, B)` — the
// executor in `src/steps/shift-bits-right.ts` handles `n >= B` by short-
// circuiting to all-zero output BEFORE calling these helpers, because JS
// `>>>` truncates the shift amount modulo 32, which would silently produce
// wrong results for `shr32(x, 32)` (returns `x`, not 0).
//
// Shipped in **Slice 2.5** alongside `shift-bits-right@1` as the third
// foundational ARX primitive after `rotate-bits-right@1` (Slice 2.1a) and
// `add-mod-32@1` (Slice 2.1b). Required for SHA-256's σ0/σ1 (FIPS 180-4
// §4.1.2) where the third operand is SHR (not ROR — common plan-trap).
// Also lands for ChaCha20 quarter-rounds (32-bit) and BLAKE2 (32-/64-bit)
// in their future rebuilds.

/** Logical right-shift an 8-bit word by `n` positions. `n` ∈ [0, 8). */
export const shr8 = (x: number, n: number): number => {
  return ((x & 0xff) >>> n) & 0xff;
};

/** Logical right-shift a 16-bit word by `n` positions. `n` ∈ [0, 16). */
export const shr16 = (x: number, n: number): number => {
  return ((x & 0xffff) >>> n) & 0xffff;
};

/**
 * Logical right-shift a 32-bit word by `n` positions. `n` ∈ [0, 32).
 *
 * The leading `>>> 0` coerces a potentially-signed input back to its
 * unsigned-32-bit view BEFORE the shift. Without it, a caller passing
 * `0x80000000` as a (signed) `-2147483648` would arithmetic-shift via
 * `>>>`'s left operand promotion and produce the wrong high bits. Output
 * is always unsigned-32 by construction (`>>>` returns unsigned).
 */
export const shr32 = (x: number, n: number): number => {
  return (x >>> 0) >>> n;
};

/**
 * Logical right-shift a 64-bit word by `n` positions. `n` ∈ [0, 64).
 *
 * `n` is `bigint` for the same reason as `ror64` — JS forces both
 * operands of `>>` to be `bigint` when either is. The mask is applied
 * once on input to defend against callers passing values outside
 * `[0, 2^64)`. Bigint `>>` is arithmetic for negative inputs; masking
 * to unsigned-64 before shifting makes the result always
 * non-negative.
 */
export const shr64 = (x: bigint, n: bigint): bigint => {
  const mask = (1n << 64n) - 1n;
  return (x & mask) >> n;
};
