/**
 * ml-dsa.w1-encode — pack the commitment's high bits for hashing (FIPS 204
 * Algorithm 28, `w1Encode`).
 *
 * Three input ports: `a` (the vector w1, every coefficient a bucket index in
 * `[0, m)`), `gamma2` (γ2) and `modulus` (q). One output port `output`: each
 * coefficient in `bitlen(m − 1)` bits, least significant first, with
 * `m = (q − 1)/(2γ2)`.
 *
 * ## Why this is its own step and not `zq-byte-encode@1`
 *
 * Mechanically it IS `SimpleBitPack` — the same LSB-first stream
 * `zq-byte-encode@1` writes. The difference is where the width comes from.
 * There it is a param `d`; here it is derived from γ2, because the number of
 * buckets is `(q − 1)/(2γ2)` and the packing must be exactly wide enough for
 * them: 6 bits for ML-DSA-44's 44 buckets (and 4 bits for the 16 buckets of
 * ML-DSA-65 and -87).
 *
 * That is the P2 rule in action: γ2 is a wired constant a learner may edit, and
 * every step that depends on it must read the same wire. A `zq-byte-encode@1`
 * with `d = 6` would keep packing 6 bits after a γ2 edit had changed the bucket
 * count — and the signer and verifier would hash different bytes.
 *
 * ## Strict
 *
 * A coefficient that is not a real bucket index (≥ m) throws. Decompose never
 * produces one — its wrap-round case exists precisely to fold the would-be
 * bucket m back to 0 — so a value here that is out of range means the wiring
 * is wrong.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { bitlen, checkGamma2, coeffNumbers, readMlDsaModulus } from "../core/ml-dsa-arith";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readScalarPort, readZqVecParams, requireZqPort, zqElementCount } from "../core/zq-vector";

const STEP = "ml-dsa.w1-encode";

export const mlDsaW1EncodePortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["gamma2", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mlDsaW1Encode: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const q = readMlDsaModulus(inputs, p, STEP);
  const gamma2 = readScalarPort(inputs, "gamma2", STEP);
  checkGamma2(gamma2, q, STEP);
  const vec = requireZqPort(inputs, "a", STEP);
  const n = zqElementCount(vec, p, "a", STEP);
  const m = (q - 1) / (2 * gamma2);
  const width = bitlen(m - 1);
  if ((n * width) % 8 !== 0) {
    throw new Error(`${STEP}: ${n} coefficients × ${width} bits is not a whole number of bytes`);
  }
  const out = new Uint8Array((n * width) / 8);
  coeffNumbers(vec, p).forEach((v, i) => {
    if (v >= m) {
      throw new Error(
        `${STEP}: coefficient ${i} is ${v}, not a bucket index below m = ${m} — w1 comes from HighBits`,
      );
    }
    for (let j = 0; j < width; j++) {
      if (((v >> j) & 1) === 1) {
        const bit = i * width + j;
        out[bit >> 3] = (out[bit >> 3] as number) | (1 << (bit & 7));
      }
    }
  });
  return new Map([["output", out]]);
};

export const mlDsaW1EncodeDoc: StepDocumentation = {
  name: "w1Encode — pack the commitment's high bits",
  summary:
    "Packs each high-bits bucket index into exactly as many bits as the number of buckets needs — 6 for ML-DSA-44 — ready to be hashed into the challenge.",
  detail: `# w1Encode

Packs the commitment's high bits, w1, into a byte string for hashing. Every
coefficient of w1 is a bucket index from Decompose, between 0 and \`m − 1\`,
where

\`\`\`
m = (q − 1) / (2γ2)        44 for ML-DSA-44
\`\`\`

Each index is written in \`bitlen(m − 1)\` bits — 6 here — low bit first, end to
end. A vector of four polynomials becomes 4 × 256 × 6 / 8 = 768 bytes.

## What it is for

The signer hashes μ together with these bytes to get the challenge seed c̃. The
verifier recomputes w1 from the signature, packs it the same way, and hashes
again: if the two hashes match, the signature is valid. So signer and verifier
must produce the *same bytes*, which is why the width is derived from γ2
rather than set by hand.

## Why the width follows γ2

γ2 is a wired constant. Change it and the number of buckets changes, and with
it the number of bits each index needs. A step with a fixed width would go on
packing the old number of bits, and the signature would stop verifying for a
reason that is nowhere on screen.`,
  params: new Map([
    ["coeffBytes", "How many bytes each incoming coefficient occupies. 4."],
    [
      "littleEndian",
      "Byte order within one INCOMING coefficient. The packed output's bit order is fixed (least significant bit first).",
    ],
  ]),
  references: ["FIPS 204 Algorithm 28 — w1Encode", "FIPS 204 Algorithm 16 — SimpleBitPack"],
};
