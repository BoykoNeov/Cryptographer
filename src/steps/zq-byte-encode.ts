/**
 * zq-byte-encode — pack a Z_q vector into a dense bit string (FIPS 203
 * Algorithm 5, `ByteEncode_d`).
 *
 * Two input ports: `a` (the vector, one coefficient per `coeffBytes`-wide
 * element) and `modulus` (q). One output port `output`, exactly `n·d/8` bytes
 * for `n` coefficients of `d` bits each.
 *
 * ## What it is for
 *
 * Every other step in this family works on a comfortable fixed-width layout —
 * two bytes per coefficient, easy to read in a trace. That layout wastes space:
 * `q = 3329` needs 12 bits, so a 256-coefficient polynomial occupies 512 bytes
 * on a wire but only 384 on the network. This step is the crossing between the
 * two, and it is why an ML-KEM public key is 1184 bytes rather than 1568.
 *
 * ## The bit order is FIXED by the spec, and is NOT the `littleEndian` param
 *
 * This is the one genuinely confusing thing about the step, so it is said three
 * times (here, in the doc `detail`, and in the param blurb). There are two
 * independent orderings in play:
 *
 * | ordering | what it covers | who decides |
 * |---|---|---|
 * | `littleEndian` | the bytes **within one element** of the input vector | this app's param |
 * | LSB-first bit stream | how `d`-bit values are laid into the **output** | FIPS 203, fixed |
 *
 * FIPS 203 emits each coefficient least-significant bit first, and packs the
 * resulting bit stream into bytes least-significant bit first as well
 * (Algorithm 3, `BitsToBytes`). Flipping `littleEndian` changes which *numbers*
 * are read off the input; it does not and must not change the packing. Getting
 * this wrong produces a perfectly self-consistent encoding that agrees with no
 * other implementation, and — per the plan — one that P3's aggregate `ek`
 * comparison would only catch in combination with everything else.
 *
 * ## Values must fit
 *
 * A coefficient that does not fit in `d` bits throws rather than losing its top
 * bits. The limit is `min(2^d, q)`, which reproduces FIPS 203's own rule
 * (`m = 2^d` for `d < 12`, `m = q` for `d = 12`) without hardcoding 12: at
 * `q = 3329` the modulus is the binding constraint exactly when `2^d ≥ q`.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. Port lengths are
 * wiring-determined.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readCoeff,
  readZqBitWidth,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  zqElementCount,
} from "../core/zq-vector";

const STEP = "zq-byte-encode";

export const zqByteEncodePortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqByteEncode: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const d = readZqBitWidth(params, STEP, "d", 8 * p.coeffBytes);
  const a = requireZqPort(inputs, "a", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const n = zqElementCount(a, p, "a", STEP);

  const totalBits = n * d;
  if (totalBits % 8 !== 0) {
    throw new Error(
      `${STEP}: ${n} coefficients × ${d} bits = ${totalBits} bits is not a whole number of bytes; the packed form has no room for a partial byte`,
    );
  }
  // FIPS 203's `m`: 2^d below the modulus, q at or above it. Written as a min so
  // the rule generalises instead of hardcoding "d = 12 is special".
  const twoD = 1n << BigInt(d);
  const limit = twoD < q ? twoD : q;

  const out = new Uint8Array(totalBits / 8);
  for (let i = 0; i < n; i++) {
    const v = readCoeff(a, i, p);
    if (v >= limit) {
      throw new Error(
        `${STEP}: coefficient ${i} is ${v}, which does not fit ${d} bits under modulus ${q} (limit ${limit})`,
      );
    }
    for (let j = 0; j < d; j++) {
      // LSB of the coefficient first, LSB of the byte first. Both halves are
      // FIPS 203's, and neither is the `littleEndian` param. See the header.
      if (((v >> BigInt(j)) & 1n) === 1n) {
        const bit = i * d + j;
        out[bit >> 3] = (out[bit >> 3] as number) | (1 << (bit & 7));
      }
    }
  }
  return new Map([["output", out]]);
};

export const zqByteEncodeDoc: StepDocumentation = {
  name: "Pack to d-bit stream",
  summary:
    "Squeezes each coefficient into exactly d bits and packs them end to end, with no gaps between coefficients.",
  detail: `# Pack to d-bit stream

Takes a list of numbers, each small enough to fit in \`d\` bits, and writes them
out back to back as a dense string of bits — no padding, no alignment, no gaps.

## Why bother

Up to this point every coefficient has travelled in a comfortable two-byte slot,
which is easy to read but wasteful: with \`q = 3329\` a coefficient only needs 12
bits, so a quarter of every wire is zeros. Packing 256 coefficients at 12 bits
each turns 512 bytes into 384.

That is not a micro-optimisation. It is why a post-quantum public key is 1184
bytes instead of 1568, and the packed form is what actually gets transmitted —
so this encoding is part of the data format, not an implementation detail.

## Bits come out least significant first

Each coefficient is written low bit first, and the resulting bit stream is
poured into bytes low bit first as well. So the first byte of the output holds
the bottom 8 bits of coefficient 0, the second byte holds coefficient 0's top 4
bits in its low half and coefficient 1's bottom 4 bits in its high half, and so
on. Coefficients do **not** start on byte boundaries, which is exactly the point.

## This is not the "byte order" setting

There are two different orderings here and confusing them is the classic mistake:

- **Byte order** (the parameter below) describes how the bytes of one incoming
  coefficient are arranged in its slot. It decides which *numbers* get read.
- **Bit order** (fixed, not a setting) is the least-significant-first rule
  above. It decides how those numbers are packed.

Changing the first does not change the second. An implementation that lets them
get tangled produces an encoding that is perfectly consistent with itself and
matches nothing anyone else produces.

## Values that do not fit are an error

A coefficient too large for \`d\` bits is rejected rather than quietly truncated.
The ceiling is whichever is smaller: \`2^d\`, or \`q\` itself — so at \`d = 12\`,
where 12 bits could hold 4096 values but the ring only has 3329, the ring wins.`,
  params: new Map([
    ["coeffBytes", "How many bytes each incoming coefficient occupies. 2 here."],
    [
      "littleEndian",
      "Byte order within one INCOMING coefficient. It does not affect the packed output, whose bit order is fixed by the specification (least significant bit first).",
    ],
    [
      "d",
      "Bits per coefficient in the packed output. 12 for a public key or an uncompressed polynomial; 1, 4, 5, 10 or 11 for the compressed parts of a ciphertext.",
    ],
  ]),
  references: [
    "FIPS 203 Algorithm 5 — ByteEncode_d",
    "FIPS 203 Algorithm 3 — BitsToBytes (the least-significant-bit-first packing)",
  ],
};
