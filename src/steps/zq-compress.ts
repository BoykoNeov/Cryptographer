/**
 * zq-compress — throw away the low-order bits of every coefficient in a Z_q
 * vector (FIPS 203 §4.2.1, `Compress_d`).
 *
 * Two input ports: `a` (the vector) and `modulus` (q). One output port
 * `output`, the same element count and the same element width, carrying values
 * in `[0, 2^d)` instead of `[0, q)`.
 *
 * ## This is the only lossy step in ML-KEM, and that is the point
 *
 * Every other operation in the lattice layer is exact — the transform is exact,
 * the arithmetic is exact, the inverse recovers its input byte for byte.
 * `Compress_d` is where ML-KEM deliberately discards information: it maps the
 * `q = 3329` possible values of a coefficient onto `2^d` buckets, with `d` as
 * small as 1 for the ciphertext's message polynomial. That is what makes the
 * ciphertext small, and it is also why **decapsulation can be correct without
 * the ciphertext being invertible**: the noise ML-KEM adds is small enough that
 * rounding it away still leaves the message recoverable. A learner who has only
 * seen exact steps needs this said out loud.
 *
 * ## The rounding rule is round-to-nearest, ties up — not truncation
 *
 * `Compress_d(x) = ⌈(2^d / q) · x⌋ mod 2^d`, where `⌈·⌋` rounds to the nearest
 * integer and rounds a tie **up**. Integer division (truncation) is the obvious
 * wrong implementation, and it is wrong by up to a whole bucket at the top of
 * every bucket. Computed here as
 *
 * ```
 * floor((2·2^d·x + q) / (2q)) mod 2^d
 * ```
 *
 * — one exact `bigint` division, no floating point anywhere. Note a fact worth
 * knowing when reading tests of this step: **`q` is odd, so compression can
 * never land exactly on a tie.** `2^(d+1)·x` is even and `q` is not, so the two
 * are never congruent mod `2q`. The tie rule is observable only in
 * `zq-decompress@1`, where `2^d` is even. A truncating implementation of *this*
 * step is still wrong — just never at a half-way point.
 *
 * ## Why the `mod 2^d` is not decoration
 *
 * Rounding to nearest can carry: for `d = 1` and `q = 3329`, any `x ≥ 2497`
 * rounds to `2`, which is out of range for one bit. FIPS 203 wraps it back to
 * `0`, so the largest coefficients compress to the same bucket as the smallest —
 * which is correct, because the ring wraps too.
 *
 * ## Packing is a separate step
 *
 * The output still occupies `coeffBytes` bytes per element. Squeezing `d`-bit
 * values into a dense byte string is `zq-byte-encode@1`'s job, deliberately
 * kept apart so the trace shows the loss and the packing as two different
 * things happening.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. Both vector ports are
 * polymorphic in length.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readCoeff,
  readZqBitWidth,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
  zqElementCount,
} from "../core/zq-vector";

const STEP = "zq-compress";

export const zqCompressPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqCompress: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  // `d` cannot exceed what one element can hold on the way out — the same "does
  // it fit?" check `readZqModulus` performs for q, for the same reason.
  const d = readZqBitWidth(params, STEP, "d", 8 * p.coeffBytes);
  const a = requireZqPort(inputs, "a", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const n = zqElementCount(a, p, "a", STEP);

  const twoD = 1n << BigInt(d);
  const out = new Uint8Array(a.length);
  for (let i = 0; i < n; i++) {
    const x = readCoeff(a, i, p);
    // Round to nearest, ties up, in exact integer arithmetic: adding half the
    // denominator before flooring IS rounding. No Number, no division by a
    // float — a coefficient product here reaches ~2²³ and the numerator more.
    writeCoeff(out, i, ((2n * twoD * x + q) / (2n * q)) % twoD, p);
  }
  return new Map([["output", out]]);
};

export const zqCompressDoc: StepDocumentation = {
  name: "Compress mod q",
  summary:
    "Rounds every coefficient from the range [0, q) down to d bits, deliberately losing information.",
  detail: `# Compress mod q

Squeezes each number in a list from the range 0…\`q\`−1 into the much smaller
range 0…2^\`d\`−1, by rounding to the nearest of \`2^d\` evenly spaced buckets.

\`\`\`
output[i] = round( (2^d / q) · a[i] )  mod 2^d
\`\`\`

## This step throws information away on purpose

Everything else in this family is exact. This one is not, and that is its whole
reason for existing. With \`q = 3329\` a coefficient needs 12 bits; compressed to
\`d = 4\` it needs four, so the value that comes out cannot possibly identify
which of the ~208 original values went in.

That is how a lattice ciphertext stays small. It is also why the algorithm this
belongs to can still decrypt correctly: the scheme adds small random noise on
purpose, and rounding is exactly the operation that removes something small. As
long as the noise is smaller than half a bucket, throwing away the low bits
throws away the noise along with them, and the message survives.

So "the ciphertext is not invertible" and "decryption is correct" are both true
at once — a combination that surprises everyone the first time.

## Round to nearest, not chop

Rounding means rounding, and a tie rounds **up**. Truncating instead — the
obvious shortcut, and what plain integer division does — is wrong by nearly a
whole bucket for every value near the top of its bucket, and it biases every
coefficient downward. The step computes the rounding in exact whole numbers,
never with decimals.

## Why results can wrap

Rounding up can push a value past the last bucket. With \`d = 1\` and
\`q = 3329\`, anything from 2497 upward rounds to 2 — which does not fit in one
bit — and wraps back to 0. That is correct rather than a fudge: the numbers live
on a circle, so the largest coefficients really are neighbours of the smallest.

## Packing happens separately

Each output still occupies the same number of bytes as the input did; only the
*value* got smaller. Cramming \`d\`-bit values into a dense byte string is a
different step, kept separate so you can watch the loss and the packing happen
one at a time.`,
  params: new Map([
    [
      "coeffBytes",
      "How many bytes each coefficient occupies, in and out. 2 here — the value shrinks, the slot it travels in does not.",
    ],
    [
      "littleEndian",
      "Byte order within one coefficient. False (big-endian) matches how every other value in this app travels a wire.",
    ],
    [
      "d",
      "How many bits survive. The algorithm this belongs to uses 1 for the message, 4 or 5 for the noisy part of a ciphertext, 10 or 11 for the bulk of it, and 12 (no loss at all) for a public key.",
    ],
  ]),
  references: [
    "FIPS 203 §4.2.1 — Compress_d and Decompress_d",
    "FIPS 203 §5.1 / §5.2 — where each value of d is used",
  ],
};
