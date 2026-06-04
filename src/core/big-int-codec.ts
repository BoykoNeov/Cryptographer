/**
 * Big-endian arbitrary-width integer codec — `Uint8Array` ↔ `bigint`.
 *
 * The siblings of `src/core/word-codec.ts`'s fixed 8/16/32/64-bit helpers,
 * for the case where the width is NOT one of those four constants: RSA's
 * modular arithmetic works over a uniform W-byte width (W is a builder
 * constant — 2 bytes for the textbook n≈3233 example), and every value
 * (p, q, e, n, φ, d, the running exponentiation accumulator) crosses a port
 * as a W-byte big-endian integer.
 *
 * Per `feedback_all_specs_port_native` / the `core/types.ts` bignum note,
 * specialized math (here, `bigint`) lives INSIDE executors and only ever
 * exchanges raw `Uint8Array` at the port boundary — so these helpers are the
 * single conversion seam the RSA primitives share.
 *
 * **Big-endian, like every other codec in this codebase** (AES State,
 * SHA-256 words, DES). Byte 0 is the most-significant byte.
 */

/**
 * Decode a big-endian byte sequence as a non-negative `bigint`. An empty
 * array decodes to `0n`. Leading zero bytes are harmless (they contribute
 * nothing) — so the same integer can have many byte representations of
 * different widths; callers that need value equality compare the `bigint`,
 * not the bytes.
 */
export const bytesToBigInt = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8n) | BigInt(bytes[i] as number);
  }
  return value;
};

/**
 * Encode a non-negative `bigint` as a big-endian byte sequence of exactly
 * `width` bytes (left-padded with zeros). Throws on a negative value or one
 * that does not fit — the "fit" check is what surfaces RSA's "primes too
 * large for the working width" error loudly rather than silently truncating
 * the modulus (which would corrupt every downstream computation).
 */
export const bigIntToBytes = (value: bigint, width: number): Uint8Array => {
  if (!Number.isInteger(width) || width < 1) {
    throw new Error(`bigIntToBytes: width must be a positive integer, got ${String(width)}`);
  }
  if (value < 0n) {
    throw new Error(`bigIntToBytes: value must be non-negative, got ${value}`);
  }
  const out = new Uint8Array(width);
  let v = value;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new Error(
      `bigIntToBytes: value ${value} does not fit in ${width} byte(s) (needs a wider working width)`,
    );
  }
  return out;
};
