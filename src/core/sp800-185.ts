/**
 * NIST SP 800-185 §2.3 integer-to-byte-string encodings — the shared pure
 * helpers behind the `encode-string@1`, `bytepad@1`, and `right-encode@1`
 * port-native steps, 2026-07-13.
 *
 * These two functions are the whole reason cSHAKE and KMAC can never collide
 * with a plain SHAKE (or with each other): they prefix/suffix a byte string
 * with an unambiguous, self-describing length so that a parser can tell where
 * one field ends and the next begins. `left_encode` puts the length **first**;
 * `right_encode` puts it **last**.
 *
 * Living in `core/` (not `steps/`) because they are pure math reused by three
 * different step executors and by the tests — the same posture as
 * `core/state/gf-matrix.ts`.
 *
 * **Reference:** NIST SP 800-185 §2.3.1 (`left_encode`, `right_encode`).
 */

/**
 * Encode `x` as the minimal big-endian byte string, returning `[bytes…]` and
 * the byte count `n` (always ≥ 1; `x = 0` encodes as the single byte `0x00`).
 * Shared core of both `left_encode` and `right_encode`.
 */
const minimalBigEndian = (x: number): number[] => {
  if (!Number.isInteger(x) || x < 0) {
    throw new Error(`sp800-185: value to encode must be a non-negative integer, got ${String(x)}`);
  }
  if (x === 0) return [0]; // n = 1, the single zero byte
  const bytes: number[] = [];
  let v = x;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  // SP 800-185 caps the length prefix at one byte ⇒ n ≤ 255 (x < 2^2040).
  if (bytes.length > 255) {
    throw new Error(`sp800-185: value ${x} is too large to encode (needs > 255 bytes)`);
  }
  return bytes;
};

/**
 * `left_encode(x)` = `byte(n) || x_as_n_bytes_big_endian`, where `n` is the
 * number of bytes needed to hold `x` (minimum 1). E.g. `left_encode(0) = 01 00`,
 * `left_encode(168) = 01 A8`, `left_encode(256) = 02 01 00`. (SP 800-185 §2.3.1)
 */
export const leftEncode = (x: number): Uint8Array => {
  const bytes = minimalBigEndian(x);
  return Uint8Array.from([bytes.length, ...bytes]);
};

/**
 * `right_encode(x)` = `x_as_n_bytes_big_endian || byte(n)` — the length byte
 * comes **last**. E.g. `right_encode(0) = 00 01`, `right_encode(256) = 01 00 02`.
 * KMAC appends `right_encode(L)` (L = output length in **bits**) so a truncated
 * tag can never be reinterpreted at a different length. (SP 800-185 §2.3.1)
 */
export const rightEncode = (x: number): Uint8Array => {
  const bytes = minimalBigEndian(x);
  return Uint8Array.from([...bytes, bytes.length]);
};
