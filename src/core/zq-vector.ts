/**
 * Z_q vector codec — the shared reading/writing rules for the `zq-vec-*@1`
 * step family (ML-KEM P1, `docs/plans/unified-stargazing-quasar.md`).
 *
 * ## What a "Z_q vector" is on a port
 *
 * A polynomial in `R_q = Z_q[X]/(X²⁵⁶+1)` is 256 coefficients, each an integer
 * in `[0, q)` with `q = 3329`. On a port it is a flat byte array: **256 × 2 =
 * 512 bytes**, one coefficient per fixed-width unsigned integer, laid out in
 * ascending degree. Nothing about that layout is specific to ML-KEM, which is
 * why it lives here and takes the element width as a parameter.
 *
 * ## Two parameters, both deliberate
 *
 * - **`coeffBytes`** — the element width. 2 for ML-KEM (q = 3329 needs 12 bits,
 *   and 12-bit packing is a separate, visible step — `zq-byte-encode@1` in P2 —
 *   rather than something the arithmetic silently does).
 * - **`littleEndian`** — how each element's bytes are ordered. `false` here,
 *   matching the app's standing "every port carries a non-negative big-endian
 *   integer" convention (Twofish's words, RSA's integers, ChaCha's rails). It is
 *   a *parameter* rather than a constant because ML-KEM's own `ByteEncode` /
 *   `ByteDecode` are little-endian, so the crossing is real — and following
 *   `rotate-lanes@1`'s precedent it should be a value a learner can see and flip
 *   rather than a fact buried in an executor. Flipping it produces a
 *   self-consistent transform that matches nothing, which is exactly the lesson.
 *
 * ## Why `bigint`
 *
 * The modulus arrives on a **port**, at whatever width it was wired at, so the
 * executors cannot assume it fits any particular machine type. Products are
 * formed at full precision and reduced once — the same discipline `mod-mul@1`
 * documents, and for the same reason: letting a product wrap first and reducing
 * after is a different (and wrong) function.
 */

import type { Json } from "./types";

// ─── Params ───────────────────────────────────────────────────────────────

export type ZqVecParams = {
  /** Bytes per coefficient. 2 for ML-KEM's q = 3329. */
  readonly coeffBytes: number;
  /** Byte order within one coefficient. `false` (big-endian) for ML-KEM here. */
  readonly littleEndian: boolean;
};

/**
 * Upper bound on `coeffBytes`. Not a mathematical limit — the arithmetic is
 * `bigint` and would work at any width — but a vector whose elements are wider
 * than 8 bytes is far outside anything this app renders, and an accidental
 * enormous value would produce a trace nobody can read. Fail loudly instead.
 */
const MAX_COEFF_BYTES = 8;

export const readZqVecParams = (params: Json, step: string): ZqVecParams => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error(`${step}: params must be an object`);
  }
  const p = params as Record<string, Json>;
  const coeffBytes = p.coeffBytes;
  if (
    typeof coeffBytes !== "number" ||
    !Number.isInteger(coeffBytes) ||
    coeffBytes < 1 ||
    coeffBytes > MAX_COEFF_BYTES
  ) {
    throw new Error(
      `${step}: params.coeffBytes must be an integer in 1..${MAX_COEFF_BYTES}, got ${String(coeffBytes)}`,
    );
  }
  const littleEndian = p.littleEndian;
  if (typeof littleEndian !== "boolean") {
    throw new Error(`${step}: params.littleEndian must be a boolean, got ${String(littleEndian)}`);
  }
  return { coeffBytes, littleEndian };
};

/**
 * Read a bit-width parameter (`d` for the compression and packing steps, `eta`
 * for centred-binomial sampling).
 *
 * Kept here rather than in each step because all four P2 steps want the same
 * error message and the same "must fit an element" reasoning: a `d` wider than
 * the coefficient it is written back into would silently lose its top bits, the
 * identical failure mode `readZqModulus` guards against for `q`.
 */
export const readZqBitWidth = (params: Json, step: string, key: string, max: number): number => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error(`${step}: params must be an object`);
  }
  const value = (params as Record<string, Json>)[key];
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > max) {
    throw new Error(`${step}: params.${key} must be an integer in 1..${max}, got ${String(value)}`);
  }
  return value;
};

// ─── Element codec ────────────────────────────────────────────────────────

/** Read element `i` of a packed vector as an integer. */
export const readCoeff = (bytes: Uint8Array, i: number, p: ZqVecParams): bigint => {
  let v = 0n;
  const base = i * p.coeffBytes;
  for (let k = 0; k < p.coeffBytes; k++) {
    // Big-endian walks the element's bytes most-significant first; little-endian
    // walks it in reverse. One loop, one index expression — so the two orders
    // cannot drift apart between the reader and the writer below.
    const byte = bytes[base + (p.littleEndian ? p.coeffBytes - 1 - k : k)];
    v = (v << 8n) | BigInt(byte ?? 0);
  }
  return v;
};

/** Write `value` into element `i` of a packed vector, same byte order. */
export const writeCoeff = (out: Uint8Array, i: number, value: bigint, p: ZqVecParams): void => {
  const base = i * p.coeffBytes;
  let v = value;
  for (let k = p.coeffBytes - 1; k >= 0; k--) {
    const offset = base + (p.littleEndian ? p.coeffBytes - 1 - k : k);
    out[offset] = Number(v & 0xffn);
    v >>= 8n;
  }
};

// ─── Shared validation ────────────────────────────────────────────────────

/**
 * Read the modulus from its port and check that residues actually fit an
 * element.
 *
 * The fit check matters: `q` is wired, `coeffBytes` is a param, and nothing
 * else relates them. A modulus of 70000 with 2-byte elements would produce
 * residues that silently lose their top bits on the way out — a wrong answer
 * with no error, which is precisely the failure mode a learner editing the
 * modulus would hit first.
 */
export const readZqModulus = (
  modulusBytes: Uint8Array | undefined,
  p: ZqVecParams,
  step: string,
): bigint => {
  if (modulusBytes === undefined) {
    throw new Error(`${step}: missing required input port "modulus"`);
  }
  let q = 0n;
  for (const b of modulusBytes) q = (q << 8n) | BigInt(b);
  if (q <= 0n) {
    throw new Error(`${step}: modulus must be a positive integer, got ${q}`);
  }
  const capacity = 1n << BigInt(8 * p.coeffBytes);
  if (q > capacity) {
    throw new Error(
      `${step}: modulus ${q} does not fit ${p.coeffBytes}-byte coefficients (max ${capacity}); widen coeffBytes or lower the modulus`,
    );
  }
  return q;
};

/** Element count of a vector port, with the "whole number of coefficients" check. */
export const zqElementCount = (
  bytes: Uint8Array,
  p: ZqVecParams,
  portName: string,
  step: string,
): number => {
  if (bytes.length % p.coeffBytes !== 0) {
    throw new Error(
      `${step}: input port "${portName}" is ${bytes.length} bytes, not a whole number of ${p.coeffBytes}-byte coefficients`,
    );
  }
  return bytes.length / p.coeffBytes;
};

/** Fetch a required vector port. */
export const requireZqPort = (
  inputs: ReadonlyMap<string, Uint8Array>,
  portName: string,
  step: string,
): Uint8Array => {
  const bytes = inputs.get(portName);
  if (bytes === undefined) {
    throw new Error(`${step}: missing required input port "${portName}"`);
  }
  return bytes;
};
