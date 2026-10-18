/**
 * zq-vec-mul — element-wise multiplication of two vectors over Z_q.
 *
 * Three input ports: `a`, `b` (the vectors, equal length) and `modulus` (q).
 * One output port `output`, the same length, carrying `(a[i] · b[i]) mod q`.
 *
 * ## Why this exists beside `zq-base-case-mul@1`, and why that is the lesson
 *
 * ML-KEM's transformed polynomials are 128 little degree-1 polynomials, so
 * multiplying two of them is per PAIR (`zq-base-case-mul@1`, five products a
 * pair) — and element-wise multiplication is the classic wrong answer there.
 *
 * ML-DSA's prime is `q = 8380417`, and `q − 1` has THIRTEEN factors of 2 where
 * 3329 − 1 has eight. So a 512th root of unity exists (1753), the transform runs
 * all eight layers down to 256 single numbers, and multiplication in the
 * transformed domain really is element-wise. This step is that multiplication.
 *
 * The same ring `Z_q[X]/(X²⁵⁶+1)`, the same transform algorithm, opposite
 * multiplication rules — and the whole difference is how many times 2 divides
 * `q − 1`. Having both steps in the palette, side by side, is how a learner
 * meets that fact rather than reading about it. FIPS 204 calls this
 * `MultiplyNTT` (Algorithm 45).
 *
 * ## Full precision, then one reduction
 *
 * Two coefficients below 8380417 multiply to about 2⁴⁶, past 32 bits, so the
 * product is formed in `bigint` and reduced once — the discipline
 * `zq-vec-mul-scalar@1` and `mod-mul@1` document.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. Vector port lengths
 * are wiring-determined.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readCoeff,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
  zqElementCount,
} from "../core/zq-vector";

const STEP = "zq-vec-mul";

export const zqVecMulPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["b", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqVecMul: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const a = requireZqPort(inputs, "a", STEP);
  const b = requireZqPort(inputs, "b", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const n = zqElementCount(a, p, "a", STEP);
  if (b.length !== a.length) {
    throw new Error(
      `${STEP}: ports "a" (${a.length} bytes) and "b" (${b.length} bytes) must be the same length — element-wise multiplication pairs coefficient i with coefficient i`,
    );
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < n; i++) {
    writeCoeff(out, i, (readCoeff(a, i, p) * readCoeff(b, i, p)) % q, p);
  }
  return new Map([["output", out]]);
};

export const zqVecMulDoc: StepDocumentation = {
  name: "Vector multiply mod q (element-wise)",
  summary:
    "Multiplies two lists of numbers position by position, mod q — the product of two transformed polynomials when the transform runs all the way down.",
  detail: `# Vector multiply mod q

Multiplies two equal-length lists position by position, keeping each result in
the range 0 up to \`q − 1\`:

\`\`\`
output[i] = (a[i] · b[i]) mod q
\`\`\`

## When this is the right way to multiply polynomials

Multiplying two polynomials directly costs 256 × 256 products. A transform
turns that into something cheaper — but *how much* cheaper depends on the
modulus.

- **Modulo 8380417** (ML-DSA), the transform runs all eight layers and splits a
  polynomial into 256 single numbers. Multiplying two transformed polynomials
  is then exactly this step: one product per position, 256 in all.
- **Modulo 3329** (ML-KEM), the transform has to stop one layer early, at 128
  pairs. Multiplying position by position there gives a wrong answer that looks
  perfectly reasonable. That case is the other multiply step in the palette,
  "Multiply transformed polynomials", which works on pairs.

The reason is a fact about the two primes. Splitting all the way down needs a
512th root of unity, which exists only when 512 divides \`q − 1\`. It divides
8380416. It does not divide 3328.

## Large intermediate values

Two coefficients just under 8380417 multiply to about 7 × 10¹³ — far more than
fits in 32 bits. The product is computed exactly before it is reduced; reducing
a product that had already overflowed would give a different, wrong answer.`,
  params: new Map([
    [
      "coeffBytes",
      "How many bytes each coefficient occupies — 4 for ML-DSA's 23-bit modulus, 2 for ML-KEM's.",
    ],
    [
      "littleEndian",
      "Byte order within one coefficient. False (big-endian, most significant byte first) matches how every other value in this app travels a wire.",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 45 — MultiplyNTT",
    "FIPS 204 §7.5 — the NTT over Z_8380417, all eight layers",
  ],
};
