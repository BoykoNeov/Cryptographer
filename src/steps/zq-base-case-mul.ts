/**
 * zq-base-case-mul — multiply two transformed polynomials, one coefficient PAIR
 * at a time (FIPS 203 Algorithm 12, `BaseCaseMultiply`; Algorithm 11,
 * `MultiplyNTTs`, is this step applied to all 128 pairs at once).
 *
 * Four input ports: `a` and `b` (2k coefficients each), `gamma` (k
 * coefficients, one per pair) and `modulus` (q). One output port `output`, 2k
 * coefficients.
 *
 * ## This is NOT element-wise, and the name says so
 *
 * The plan this step comes from calls it "pointwise multiplication", which is
 * what the operation is called in every other transform anyone has met: in an
 * FFT you multiply spectra element by element and that is the convolution
 * theorem. **Here that is simply wrong**, and it is the classic first mistake
 * with ML-KEM. The name deliberately breaks the `zq-vec-*@1` family prefix to
 * say so at the palette.
 *
 * The reason is P1's headline fact. `q − 1 = 2⁸ · 13` admits no primitive 512th
 * root of unity, so the transform cannot split the polynomial all the way down
 * to 256 constants — it stops one layer short, at **128 degree-1 polynomials**.
 * A transformed polynomial is therefore not 256 numbers; it is 128 little
 * polynomials `a₀ + a₁X`, and multiplying two of them means multiplying in
 *
 * ```
 * Z_q[X] / (X² − γ)
 * ```
 *
 * where `γ` is that pair's own modulus. Written out:
 *
 * ```
 * (a₀ + a₁X)(b₀ + b₁X) = a₀b₀ + a₁b₁X² + (a₀b₁ + a₁b₀)X
 *                      = (a₀b₀ + a₁b₁·γ) + (a₀b₁ + a₁b₀)X     [X² = γ]
 * ```
 *
 * So each output pair costs five multiplications, not one. An element-wise
 * implementation produces a self-consistent answer that is not the product of
 * the two polynomials.
 *
 * ## Polymorphic over `k`, on purpose
 *
 * `k = 128` with the whole γ table wired is `MultiplyNTTs` — the whole-
 * polynomial form. `k = 1` is one `BaseCaseMultiply`, the form that drops inside
 * an iterate with the γ values arriving one at a time. Both are the same
 * executor; the port widths decide which. The alternative, two step types, would
 * have made the loop form look like a different operation from the bulk form
 * when it is exactly the same one.
 *
 * ## Where γ comes from
 *
 * `γᵢ = ζ^(2·BitRev7(i) + 1)`, listed as `GAMMAS` in `mlkem-constants.ts`. The
 * `+ 1` matters and is easy to lose — see that file, which also records the
 * cross-check against FIPS 203 Appendix A that the ± pairing gives.
 *
 * ## Full precision, then one reduction
 *
 * Every product is formed in `bigint` before reducing, and the `a₁b₁·γ` term is
 * a product of three values below `q` — up to about 2³⁵. The same discipline
 * `zq-vec-mul-scalar@1` and `mod-mul@1` document.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. All port lengths are
 * wiring-determined.
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

const STEP = "zq-base-case-mul";

export const zqBaseCaseMulPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["b", { layout: "raw" }],
    ["gamma", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqBaseCaseMul: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const a = requireZqPort(inputs, "a", STEP);
  const b = requireZqPort(inputs, "b", STEP);
  const gamma = requireZqPort(inputs, "gamma", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);

  const n = zqElementCount(a, p, "a", STEP);
  if (b.length !== a.length) {
    throw new Error(
      `${STEP}: ports "a" (${a.length} bytes) and "b" (${b.length} bytes) must be the same length`,
    );
  }
  // Pairs, not elements: this is the property the whole step exists to express,
  // so an odd count is an error rather than something to round down.
  if (n % 2 !== 0) {
    throw new Error(
      `${STEP}: "a" holds ${n} coefficients, which is not a whole number of PAIRS — a transformed polynomial is 128 degree-1 polynomials, not 256 numbers`,
    );
  }
  const pairs = n / 2;
  const gammaCount = zqElementCount(gamma, p, "gamma", STEP);
  if (gammaCount !== pairs) {
    throw new Error(
      `${STEP}: "gamma" holds ${gammaCount} coefficients but there are ${pairs} pairs — each pair multiplies in its OWN ring Z_q[X]/(X²−γ), so it needs its own γ`,
    );
  }

  const out = new Uint8Array(a.length);
  for (let i = 0; i < pairs; i++) {
    const a0 = readCoeff(a, 2 * i, p);
    const a1 = readCoeff(a, 2 * i + 1, p);
    const b0 = readCoeff(b, 2 * i, p);
    const b1 = readCoeff(b, 2 * i + 1, p);
    const g = readCoeff(gamma, i, p) % q;
    // X² = γ folds the a₁b₁ term back down into the constant. Full precision
    // first — a₁·b₁·γ reaches ~2³⁵ at q = 3329.
    writeCoeff(out, 2 * i, (a0 * b0 + a1 * b1 * g) % q, p);
    writeCoeff(out, 2 * i + 1, (a0 * b1 + a1 * b0) % q, p);
  }
  return new Map([["output", out]]);
};

export const zqBaseCaseMulDoc: StepDocumentation = {
  name: "Multiply transformed polynomials",
  summary:
    "Multiplies two transformed polynomials two coefficients at a time — NOT element by element, which is the classic mistake here.",
  detail: `# Multiply transformed polynomials

Multiplies two polynomials that are already in the transformed domain. It works
on **pairs** of coefficients, not on single coefficients.

## Why not element by element?

Because that is what a transform normally buys you, and here it does not.

In an ordinary transform, multiplying two spectra element by element corresponds
to multiplying the original polynomials. That works when the transform has split
the polynomial all the way down into individual numbers. This one cannot: it
would need a 512th root of unity modulo 3329, and none exists, because 3329 − 1
factors as 2⁸ × 13 — eight twos, not nine.

So the transform stops one step short. What comes out is not 256 numbers, it is
**128 little two-term polynomials**, and multiplying two of them is a small
polynomial multiplication rather than a single product:

\`\`\`
(a₀ + a₁X)(b₀ + b₁X) = a₀b₀ + (a₀b₁ + a₁b₀)X + a₁b₁X²
\`\`\`

That \`X²\` has to go somewhere. Each pair lives in its own little world where
\`X² = γ\` for that pair's own value of γ, so it folds back into the constant:

\`\`\`
output[2i]   = a₀b₀ + a₁b₁·γ
output[2i+1] = a₀b₁ + a₁b₀
\`\`\`

Five multiplications per pair instead of one. Multiplying element by element
instead produces a perfectly consistent answer that is **not** the product of
the two polynomials — and it is the first thing almost everyone tries.

## Each pair has its own γ

The \`gamma\` port carries one value per pair, never one shared value. Pair \`i\`
uses \`γᵢ\`, and consecutive pairs use values that are negatives of each other.
Wire a single γ to all of them and the arithmetic still runs; the answer is just
wrong.

## One pair or all of them

The step does not care how many pairs arrive. Feed it two whole transformed
polynomials and the whole γ table and it multiplies all 128 pairs at once; feed
it one pair and one γ and it does exactly one. It is the same operation either
way — the trace just shows it at a different grain.`,
  params: new Map([
    [
      "coeffBytes",
      "How many bytes each coefficient occupies. 2 here — enough to hold any value below 3329.",
    ],
    [
      "littleEndian",
      "Byte order within one coefficient, applied to both inputs, the γ list and the output alike. False (big-endian) matches how every other value in this app travels a wire.",
    ],
  ]),
  references: [
    "FIPS 203 Algorithm 12 — BaseCaseMultiply",
    "FIPS 203 Algorithm 11 — MultiplyNTTs (this step over all 128 pairs)",
    "FIPS 203 §2.4.4 — why the transform stops at degree-1 polynomials",
  ],
};
