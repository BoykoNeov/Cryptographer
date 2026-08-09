/**
 * zq-vec-mul-scalar — multiply every element of a Z_q vector by one scalar.
 *
 * Three input ports: `a` (the vector), `scalar` (a single coefficient) and
 * `modulus` (q). One output port `output`, the same length as `a`, carrying
 * `(a[i] · s) mod q` for every coefficient position `i`.
 *
 * ## This is where the twiddle factor enters
 *
 * Of the three `zq-vec-*@1` primitives this is the only one that does anything
 * a learner has not seen before, because the scalar is the **twiddle factor** ζ
 * — a power of 17, the number whose 256th power is 1 mod 3329 and whose 128th
 * is −1. Scaling a half-vector by ζ is the "twist" in the transform; the add and
 * the subtract either side of it are bookkeeping.
 *
 * ```
 * t      = ζ · hi          ← this step
 * lo'    = lo + t          (zq-vec-add@1)
 * hi'    = lo − t          (zq-vec-sub@1)
 * ```
 *
 * ## Two other jobs it does unchanged
 *
 * - The inverse transform's **final scaling** by `128⁻¹ mod 3329 = 3303`. Note
 *   128, not 256: ML-KEM's transform stops one layer short of a full
 *   decomposition (there is no primitive 512th root of unity mod 3329), so the
 *   accumulated factor is 2⁷, not 2⁸. Using 256⁻¹ is a plausible-looking
 *   mistake that produces a self-consistent wrong answer.
 * - Multiplying a polynomial by a constant, anywhere in P2 onward.
 *
 * ## Full precision, then one reduction
 *
 * `a[i] · s` exceeds a 2-byte element for almost every pair — up to
 * `3328 · 3328 ≈ 2²³·³`. The product is formed in `bigint` and reduced once, the
 * same discipline `mod-mul@1` documents. Reducing the operands first and letting
 * the product wrap would be a different, wrong function.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. `a` and `output` are
 * polymorphic (the NTT's layers run 512 bytes down to 8); `scalar` declares its
 * width from `coeffBytes` so the editor's coercion glyph can flag a mis-wired
 * source at spec-edit time.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  StepDocumentation,
} from "../core/types";
import {
  readCoeff,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
  zqElementCount,
} from "../core/zq-vector";

const STEP = "zq-vec-mul-scalar";

export const zqVecMulScalarPortContract: PortContract = {
  inputs: (params: Json) => {
    const { coeffBytes } = readZqVecParams(params, STEP);
    const scalar: PortShape = { layout: "raw", byteLength: coeffBytes };
    return new Map<string, PortShape>([
      ["a", { layout: "raw" }],
      ["scalar", scalar],
      ["modulus", { layout: "raw" }],
    ]);
  },
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqVecMulScalar: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const a = requireZqPort(inputs, "a", STEP);
  const scalarBytes = requireZqPort(inputs, "scalar", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const n = zqElementCount(a, p, "a", STEP);
  // The scalar is ONE coefficient. A wider port would silently have all but its
  // first element ignored — say so instead.
  if (scalarBytes.length !== p.coeffBytes) {
    throw new Error(
      `${STEP}: input port "scalar" is ${scalarBytes.length} bytes but must be exactly one ${p.coeffBytes}-byte coefficient`,
    );
  }
  const s = readCoeff(scalarBytes, 0, p) % q;
  const out = new Uint8Array(a.length);
  for (let i = 0; i < n; i++) {
    // Full precision, then one reduction — see the file header.
    writeCoeff(out, i, (readCoeff(a, i, p) * s) % q, p);
  }
  return new Map([["output", out]]);
};

export const zqVecMulScalarDoc: StepDocumentation = {
  name: "Vector × scalar mod q",
  summary: "Multiplies every number in a list by one shared number, reducing each result modulo q.",
  detail: `# Vector × scalar mod q

Multiplies every element of a list by a single shared value, reducing each
product modulo \`q\` so it stays in the range 0 up to (but not including) \`q\`.

## Math

\`\`\`
output[i] = (a[i] · s) mod q
\`\`\`

## The scalar is the interesting part

In the transform this step belongs to, \`s\` is a **twiddle factor** — a power of
17. That number is special modulo 3329: raise it to the 128th power and you get
\`q − 1\` (which is −1 here), raise it to the 256th and you get 1. A number that
cycles back to 1 after exactly 256 steps is what lets a 256-coefficient
polynomial be split apart and put back together, and every layer of the
transform uses a different power of it.

Watch the scalar change from one step to the next in the trace: that advancing
value is the transform's engine.

## Full precision, then one reduction

Two coefficients below 3329 multiply to something as large as about 11 million —
far more than fits in the two bytes a coefficient occupies. This step forms the
whole product first and reduces it once. Doing it the other way round, letting
the product overflow and reducing afterwards, gives a different and wrong answer
while still looking like plausible noise. That is a classic bug in this family of
algorithms.

## Where it fits

- **The twist in the butterfly.** The half-vector is scaled by the twiddle
  factor; the add and subtract around it do the rest.
- **The inverse transform's final scaling**, by \`128⁻¹ mod 3329 = 3303\`. Note
  128 and not 256: the transform stops one layer short of splitting the
  polynomial all the way down, so the factor that accumulates is 2⁷.`,
  params: new Map([
    [
      "coeffBytes",
      "How many bytes each coefficient occupies. 2 here — enough to hold any value below 3329.",
    ],
    [
      "littleEndian",
      "Byte order within one coefficient, applied to the list and to the scalar alike. False (big-endian) matches how every other value in this app travels a wire.",
    ],
  ]),
  references: [
    "FIPS 203 §2.4.4 — the ring R_q = Z_q[X]/(X^256+1)",
    "FIPS 203 Algorithm 9 / Algorithm 10 — the twiddle-factor multiply and the final 128⁻¹ scaling",
  ],
};
