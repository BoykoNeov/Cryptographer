/**
 * zq-cbd — sample a noise polynomial from a centred binomial distribution
 * (FIPS 203 Algorithm 8, `SamplePolyCBD_η`).
 *
 * Two input ports: `a` (uniformly random bytes) and `modulus` (q). One output
 * port `output`, one coefficient per `2η` bits of input, each drawn from
 * `{−η, …, η}` and represented in `[0, q)`.
 *
 * ## This is where the secret and the noise come from
 *
 * Everything else in the lattice layer is deterministic rearrangement. This is
 * the step that turns randomness into ring elements — and specifically into
 * ring elements that are **small**. ML-KEM's security rests on the difficulty of
 * separating `A·s + e` from uniform noise; its *correctness* rests on `s` and
 * `e` being small enough that compression rounds them away. Both properties are
 * decided here.
 *
 * ## What "centred binomial" means, concretely
 *
 * Count the 1 bits in one window of `η` bits, count the 1 bits in the next `η`,
 * subtract. With `η = 2` that is `(0..2) − (0..2)`, so the result is in
 * `{−2, −1, 0, 1, 2}` with probabilities `1/16, 4/16, 6/16, 4/16, 1/16`. It is
 * cheap (nothing but bit counting — no rejection, no division, no table) and it
 * is centred on zero, which is what a *noise* distribution has to be.
 *
 * Why not a uniform value in some small interval? Because the binomial shape is
 * what the security reduction was written against, and because it costs
 * nothing: the sampler is constant-time by construction, which a rejection
 * sampler is not.
 *
 * ## Negative values become `q − |v|`, and that surprises everyone
 *
 * There are no negative numbers in `Z_q`. A sampled `−1` is written as 3328, and
 * a trace full of 3328s and 3327s is not a bug — it is what "small" looks like
 * here. Small means *close to zero on the circle*, so values just under `q` are
 * every bit as small as values just over 0.
 *
 * ## The bit order is FIPS 203's, not the `littleEndian` param
 *
 * Same distinction `zq-byte-encode.ts` spells out in full: bits are taken from
 * each byte least significant first (Algorithm 4, `BytesToBits`), fixed by the
 * specification. `littleEndian` describes only how each finished coefficient is
 * written into its outgoing slot.
 *
 * ## The input length is not padded
 *
 * ML-KEM feeds exactly `64η` bytes, which is `512η` bits, which is exactly 256
 * coefficients — the sizes line up on purpose. Any length that is a whole number
 * of coefficients works here; anything else throws rather than being padded,
 * because a padded tail would silently contribute a run of sampled zeros that
 * nothing asked for.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. Port lengths are
 * wiring-determined.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readZqBitWidth,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
} from "../core/zq-vector";

const STEP = "zq-cbd";

export const zqCbdPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqCbd: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const eta = readZqBitWidth(params, STEP, "eta", 8 * p.coeffBytes);
  const a = requireZqPort(inputs, "a", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);

  const bitsPerCoeff = 2 * eta;
  const totalBits = a.length * 8;
  if (totalBits % bitsPerCoeff !== 0) {
    throw new Error(
      `${STEP}: ${a.length} bytes is ${totalBits} bits, not a whole number of ${bitsPerCoeff}-bit samples (η = ${eta} consumes 2η bits per coefficient); ML-KEM feeds exactly 64η bytes`,
    );
  }
  if (BigInt(eta) >= q) {
    throw new Error(
      `${STEP}: η = ${eta} is not smaller than the modulus ${q}, so the sampled range does not fit the ring`,
    );
  }
  const n = totalBits / bitsPerCoeff;

  /** Bit `k` of the input stream, least significant bit of each byte first. */
  const bit = (k: number): number => ((a[k >> 3] as number) >> (k & 7)) & 1;

  const out = new Uint8Array(n * p.coeffBytes);
  for (let i = 0; i < n; i++) {
    const base = i * bitsPerCoeff;
    let x = 0;
    let y = 0;
    for (let j = 0; j < eta; j++) {
      x += bit(base + j);
      y += bit(base + eta + j);
    }
    // `x - y` is in [-η, η]. Z_q has no negatives, so a negative sample is
    // written as its representative q - |v| — the thing that makes a noise
    // polynomial look like it is full of enormous numbers when it is not.
    const v = BigInt(x - y);
    writeCoeff(out, i, ((v % q) + q) % q, p);
  }
  return new Map([["output", out]]);
};

export const zqCbdDoc: StepDocumentation = {
  name: "Sample noise (centred binomial)",
  summary:
    "Turns random bytes into a polynomial of small values centred on zero, by counting bits in one window and subtracting the count from the next.",
  detail: `# Sample noise (centred binomial)

Turns uniformly random bytes into a list of **small** numbers centred on zero.

For each coefficient it takes \`2η\` bits, counts the 1 bits in the first half,
counts the 1 bits in the second half, and subtracts:

\`\`\`
output[i] = (ones in the first η bits) − (ones in the next η bits)
\`\`\`

With \`η = 2\` the result lands in −2…2 with probabilities 1/16, 4/16, 6/16,
4/16, 1/16 — a little triangle centred on zero.

## Why this step exists

Everything else in this family rearranges numbers deterministically. This is the
one place randomness enters, and it produces the secret key and the noise. The
security of the whole scheme rests on nobody being able to separate "secret
times matrix, plus noise" from pure randomness. Its *correctness* rests on that
noise being small enough that rounding removes it. Both properties are decided
right here, by the value of \`η\`.

Turn \`η\` up and the noise gets bigger: harder to break, but at some point too
big to round away, and decryption starts failing. That trade-off is the entire
design tension of a lattice scheme, and it is one number.

## Why not just pick a small number uniformly?

Two reasons. The binomial shape is what the security proof was written for. And
counting bits takes exactly the same amount of work no matter what the bits are,
so the sampler leaks nothing through timing — a sampler that retried until it
liked its answer would.

## Negative values look enormous, and that is correct

There are no negative numbers here. A sampled −1 is written as \`q − 1\` = 3328.
So a freshly sampled noise polynomial is full of 0s, 1s, 2s, 3327s and 3328s,
and every one of those is "small" — small means *close to zero going around the
circle*, and 3328 is one step below zero the short way round.

## Bit order

Bits are taken from each byte least significant first, fixed by the
specification. The byte-order parameter below describes only how each finished
coefficient is written into its slot.`,
  params: new Map([
    ["coeffBytes", "How many bytes each sampled coefficient occupies. 2 here."],
    [
      "littleEndian",
      "Byte order within one OUTGOING coefficient. It does not affect how the random input is read, whose bit order is fixed by the specification.",
    ],
    [
      "eta",
      "Half the number of coin flips per coefficient. ML-KEM uses 2 or 3, giving noise in −2…2 or −3…3. Larger means more noise: harder to break, and closer to the point where decryption starts to fail.",
    ],
  ]),
  references: [
    "FIPS 203 Algorithm 8 — SamplePolyCBD_η",
    "FIPS 203 Algorithm 4 — BytesToBits (the least-significant-bit-first bit order)",
    "FIPS 203 §8 — the parameter sets, and where η₁ and η₂ are used",
  ],
};
