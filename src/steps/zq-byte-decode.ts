/**
 * zq-byte-decode — unpack a dense `d`-bit stream back into a Z_q vector
 * (FIPS 203 Algorithm 6, `ByteDecode_d`).
 *
 * Two input ports: `a` (the packed bytes) and `modulus` (q). One output port
 * `output`, `8·len/d` coefficients at `coeffBytes` each.
 *
 * ## The element count comes from the wire, not from a param
 *
 * `n = 8·len / d`. Deliberately derived rather than declared: an
 * `elementCount` param could disagree with the bytes actually arriving, and the
 * disagreement would be silent — a short read produces a valid-looking shorter
 * polynomial. A length that is not a whole number of coefficients throws.
 *
 * ## The reduction, and why it is a `min` rather than a check for `d = 12`
 *
 * FIPS 203 reduces mod `m`, where `m = 2^d` for `d < 12` and `m = q` for
 * `d = 12`. That rule exists because 12 bits can express 4096 values while the
 * ring only has 3329, so a hostile or corrupt input can carry a coefficient that
 * is not a ring element at all; every narrower `d` cannot. Written here as
 * `min(2^d, q)`, which reproduces the rule exactly at `q = 3329` and keeps
 * behaving sensibly if a learner edits `q` — where a literal `d === 12` branch
 * would silently become wrong.
 *
 * **This reduction is not cosmetic.** `ByteDecode_12` is the entry point for
 * an attacker-supplied public key, and it is the only thing standing between a
 * malformed encoding and arithmetic that assumes its inputs are in `[0, q)`.
 *
 * ## Bit order is the specification's, not the `littleEndian` param's
 *
 * Same warning as `zq-byte-encode.ts`, which spells it out in full: the bit
 * stream is least-significant-bit first and is fixed; `littleEndian` describes
 * the byte order of the OUTPUT elements only.
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

const STEP = "zq-byte-decode";

export const zqByteDecodePortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqByteDecode: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const d = readZqBitWidth(params, STEP, "d", 8 * p.coeffBytes);
  const a = requireZqPort(inputs, "a", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);

  const totalBits = a.length * 8;
  if (totalBits % d !== 0) {
    throw new Error(
      `${STEP}: ${a.length} bytes is ${totalBits} bits, not a whole number of ${d}-bit coefficients`,
    );
  }
  const n = totalBits / d;
  const twoD = 1n << BigInt(d);
  const m = twoD < q ? twoD : q;

  const out = new Uint8Array(n * p.coeffBytes);
  for (let i = 0; i < n; i++) {
    let v = 0n;
    for (let j = 0; j < d; j++) {
      // Mirror of the encoder: LSB of the byte first, LSB of the coefficient
      // first. Fixed by FIPS 203 — see the header.
      const bit = i * d + j;
      if ((((a[bit >> 3] as number) >> (bit & 7)) & 1) === 1) v |= 1n << BigInt(j);
    }
    writeCoeff(out, i, v % m, p);
  }
  return new Map([["output", out]]);
};

export const zqByteDecodeDoc: StepDocumentation = {
  name: "Unpack from d-bit stream",
  summary:
    "Reads a dense stream of d-bit values back out into one coefficient per slot, reducing anything out of range.",
  detail: `# Unpack from d-bit stream

The exact reverse of the packing step: walks a dense bit string \`d\` bits at a
time and writes each value back into its own fixed-width slot.

## How many coefficients come out

However many the bytes contain: \`8 × length ÷ d\`. That is deliberately read off
the wire rather than configured. A configured count could disagree with the
bytes that actually arrived, and the disagreement would be invisible — you would
get a shorter polynomial that looks entirely valid.

## Out-of-range values are reduced, and that matters

With \`d = 12\` a packed value can be anything up to 4095, but the ring only has
3329 elements — so a corrupt or hostile encoding can contain something that is
not a ring element at all. Those values are reduced modulo \`q\`. At every
narrower \`d\` the reduction never fires, because \`2^d\` values all fit.

This is not tidying up. Unpacking is the first thing that happens to a public
key that arrived over a network, and it is the only thing standing between a
malformed encoding and arithmetic that assumes every input is in range.

## Bit order is fixed, and is not the byte-order setting

Values are read least significant bit first, out of bytes read least significant
bit first — the mirror of the packing step, and set by the specification rather
than by any parameter here. The byte-order parameter below describes only how
each recovered coefficient is written into its outgoing slot.`,
  params: new Map([
    ["coeffBytes", "How many bytes each recovered coefficient occupies. 2 here."],
    [
      "littleEndian",
      "Byte order within one OUTGOING coefficient. It does not affect how the packed input is read, whose bit order is fixed by the specification (least significant bit first).",
    ],
    [
      "d",
      "Bits per coefficient in the packed input. Must match the d that packed them — nothing in the bytes records it, so a mismatch silently produces different numbers rather than an error.",
    ],
  ]),
  references: [
    "FIPS 203 Algorithm 6 — ByteDecode_d",
    "FIPS 203 Algorithm 4 — BytesToBits (the least-significant-bit-first unpacking)",
  ],
};
