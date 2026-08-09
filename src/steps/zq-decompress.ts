/**
 * zq-decompress — spread `d`-bit values back across the range `[0, q)`
 * (FIPS 203 §4.2.1, `Decompress_d`).
 *
 * Two input ports: `a` (the compressed vector) and `modulus` (q). One output
 * port `output`, the same element count and width, carrying values in `[0, q)`.
 *
 * ## It is not the inverse, and the name says so
 *
 * `zq-compress@1` discards information, so nothing can put it back. What this
 * step does is pick the **centre of the bucket**: given the bucket index `y` it
 * returns the value in `[0, q)` closest to `(q / 2^d) · y`. Composing the two
 * gives a value near the original, never necessarily the original —
 * `Decompress(Compress(x))` differs from `x` by at most about `q / 2^(d+1)`.
 * That error bound is the number ML-KEM's whole correctness argument is built
 * on, and `tests/zq-compress-decompress.test.ts` pins it exhaustively.
 *
 * The other direction *does* round-trip: `Compress(Decompress(y)) = y` for every
 * `y` in range, because a bucket's centre is unambiguously in that bucket —
 * **as long as `2^d ≤ q`**. Pinned exhaustively rather than assumed, and the
 * qualifier is there because the exhaustive check found it: at `d = 12` there
 * are 4096 bucket indices and only 3329 values to hold them, so the map cannot
 * be injective no matter how it rounds. That is precisely why FIPS 203 defines
 * this pair for `d < 12` and gives the uncompressed case its own encoding
 * (`ByteEncode_12`) instead of compressing at all.
 *
 * ## This is the side where ties happen
 *
 * `Decompress_d(y) = ⌈(q / 2^d) · y⌋`, round-to-nearest with ties **up**,
 * computed as
 *
 * ```
 * floor((2·q·y + 2^d) / 2^(d+1))
 * ```
 *
 * Its denominator `2^d` is even and `q` is odd, so exact half-way values really
 * do occur — `d = 1, y = 1` gives `3329/2 = 1664.5`, which must become 1665 and
 * not 1664. Compression can never hit a tie (see `zq-compress.ts`), so this is
 * the only place in the pair where the tie rule is observable at all. An
 * implementation that truncates passes a great many spot checks before it fails
 * here.
 *
 * ## The trailing reduction
 *
 * The result is reduced mod `q` for totality. At every `d` ML-KEM uses it never
 * fires: `round(q·y / 2^d) < q` for all `y < 2^d` as long as `2^d < 2q`, i.e.
 * `d ≤ 12`. It exists so a learner who edits `d` to 13 gets a Z_q vector out
 * rather than a value that overflows the range every downstream step assumes.
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

const STEP = "zq-decompress";

export const zqDecompressPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqDecompress: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const d = readZqBitWidth(params, STEP, "d", 8 * p.coeffBytes);
  const a = requireZqPort(inputs, "a", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const n = zqElementCount(a, p, "a", STEP);

  const twoD = 1n << BigInt(d);
  const out = new Uint8Array(a.length);
  for (let i = 0; i < n; i++) {
    const y = readCoeff(a, i, p);
    // Round to nearest, ties up — and here the ties are real, because 2^d is
    // even while q is odd. See the file header.
    writeCoeff(out, i, ((2n * q * y + twoD) / (2n * twoD)) % q, p);
  }
  return new Map([["output", out]]);
};

export const zqDecompressDoc: StepDocumentation = {
  name: "Decompress mod q",
  summary:
    "Spreads d-bit values back across the range [0, q) by taking the centre of each bucket — an approximation, not an undo.",
  detail: `# Decompress mod q

Takes numbers in the small range 0…2^\`d\`−1 and spreads them back across the
full range 0…\`q\`−1.

\`\`\`
output[i] = round( (q / 2^d) · a[i] )
\`\`\`

## It cannot undo the compression, and does not pretend to

Compression threw information away. Nothing brings it back. What this step does
is pick the **middle of the bucket**: if compression said "your value was
somewhere in bucket 3", this returns the value in the centre of bucket 3.

So compressing and then decompressing gives you something *near* the number you
started with — off by at most about half a bucket — and almost never exactly it.
Half a bucket is \`q / 2^(d+1)\`, which is where every error bound in the
surrounding algorithm ultimately comes from.

Going the other way round *does* land exactly: decompress a bucket index and
compress the result, and you get the same index back, because the centre of a
bucket is unambiguously inside it.

## Ties round up, and here ties really happen

Rounding needs a rule for exact half-way values. The rule is "round up". In the
compression direction a half-way value can never occur, because \`q\` is odd. In
*this* direction it can: with \`d = 1\`, bucket 1 sits at \`3329 / 2 = 1664.5\`,
and the answer must be 1665. An implementation that just chops off the fraction
gets 1664 — and gets almost everything else right, which is what makes it such a
durable bug.

## Where it is used

Decompression is what a recipient does first: a ciphertext arrives with its
coefficients squeezed down to a few bits each, and they must be spread back out
before any arithmetic can happen. The gap between what was sent and what comes
back out is exactly the noise the scheme is designed to tolerate.`,
  params: new Map([
    [
      "coeffBytes",
      "How many bytes each coefficient occupies, in and out. 2 here — the value grows, the slot it travels in does not.",
    ],
    [
      "littleEndian",
      "Byte order within one coefficient. False (big-endian) matches how every other value in this app travels a wire.",
    ],
    [
      "d",
      "How many bits the incoming values occupy. Must match the d that compressed them — a mismatch is not an error anywhere, it just quietly produces the wrong numbers.",
    ],
  ]),
  references: [
    "FIPS 203 §4.2.1 — Compress_d and Decompress_d",
    "FIPS 203 §5.1 / §5.2 — where each value of d is used",
  ],
};
