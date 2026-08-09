/**
 * zq-vec-add — element-wise addition of two vectors over Z_q.
 *
 * Three input ports: `a`, `b` (the vectors, equal length) and `modulus` (q).
 * One output port `output`, the same length as the inputs, carrying
 * `(a[i] + b[i]) mod q` for every coefficient position `i`.
 *
 * ## Where it fits
 *
 * The upper half of the Cooley–Tukey butterfly that the NTT is built from
 * (FIPS 203 Algorithm 9):
 *
 * ```
 * t      = ζ · hi          (zq-vec-mul-scalar@1)
 * lo'    = lo + t          ← this step
 * hi'    = lo − t          (zq-vec-sub@1)
 * ```
 *
 * From P2 onward it is also plain polynomial addition in `R_q`, unchanged —
 * adding two polynomials really is adding their coefficient lists.
 *
 * ## Why the modulus arrives on a port
 *
 * The same argument `add-mod@1` makes, with more force. `q = 3329` is not a
 * register width: it is prime, and it is `≡ 1 (mod 512)`, and those two facts
 * together are the entire reason a number-theoretic transform exists over this
 * ring at all. A modulus that is a design decision belongs on a wire the learner
 * can follow and edit, not inside an executor.
 *
 * ## Not to be confused with `add-mod@1`
 *
 * | step | operates on | modulus |
 * |---|---|---|
 * | `add-mod@1` | ONE big-endian integer per port | a wired port |
 * | `zq-vec-add@1` (this one) | a VECTOR of `coeffBytes`-wide elements | a wired port |
 *
 * `add-mod@1` would read a 512-byte polynomial as a single 4096-bit number and
 * add it to another — arithmetic that is perfectly well defined and has nothing
 * to do with polynomials. The element width is the whole difference.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. Vector port lengths
 * are wiring-determined (the NTT's layers run 512 bytes down to 8), so the
 * contract declares them polymorphic.
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

const STEP = "zq-vec-add";

export const zqVecAddPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["b", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqVecAdd: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const a = requireZqPort(inputs, "a", STEP);
  const b = requireZqPort(inputs, "b", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const n = zqElementCount(a, p, "a", STEP);
  // Element-wise means element-for-element: a length mismatch is a wiring bug,
  // not something to pad around. `add-mod@1`'s "operands need not match" rule
  // is right for integers and wrong here — coefficient 5 of one polynomial has
  // no business meeting coefficient 4 of another.
  if (b.length !== a.length) {
    throw new Error(
      `${STEP}: ports "a" (${a.length} bytes) and "b" (${b.length} bytes) must be the same length — element-wise addition pairs coefficient i with coefficient i`,
    );
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < n; i++) {
    writeCoeff(out, i, (readCoeff(a, i, p) + readCoeff(b, i, p)) % q, p);
  }
  return new Map([["output", out]]);
};

export const zqVecAddDoc: StepDocumentation = {
  name: "Vector add mod q",
  summary:
    "Adds two lists of numbers position by position, reducing each result modulo q so it stays within [0, q).",
  detail: `# Vector add mod q

Adds two equal-length lists of numbers, pairing the first with the first, the
second with the second, and so on. Each sum is reduced modulo \`q\`, so every
result stays in the range 0 up to (but not including) \`q\`.

## Math

\`\`\`
output[i] = (a[i] + b[i]) mod q
\`\`\`

## The lists are polynomials

Each element is one **coefficient** of a polynomial — the list
\`[3, 1, 0, 4, …]\` means \`3 + 1·X + 0·X² + 4·X³ + …\`. Adding two polynomials
really is nothing more than adding their coefficient lists position by position,
which is why this step is so plain: the interesting arithmetic is in the
multiply, never the add.

Each coefficient occupies a fixed number of bytes, set by \`coeffBytes\`. The
step never mixes neighbours — coefficient 5 of one list only ever meets
coefficient 5 of the other.

## The modulus arrives on a wire

\`q\` is not a setting here; it comes in on a port, like the numbers being added.
For the transform this step is part of, \`q = 3329\` — and it is not an arbitrary
choice. It is prime, and dividing it by 512 leaves remainder 1. Those two facts
together are what make the whole number-theoretic transform possible. A number
that load-bearing should be visible.

## Where it fits

- **The butterfly.** Half of the two-line core of the transform: one line adds
  the twisted value, the other subtracts it.
- **Polynomial addition.** Wherever two polynomials in the ring are added.`,
  params: new Map([
    [
      "coeffBytes",
      "How many bytes each coefficient occupies. 2 here — enough to hold any value below 3329.",
    ],
    [
      "littleEndian",
      "Byte order within one coefficient. False (big-endian, most significant byte first) matches how every other value in this app travels a wire. Flip it and the arithmetic still runs — it just computes with different numbers.",
    ],
  ]),
  references: [
    "FIPS 203 §2.4.4 — the ring R_q = Z_q[X]/(X^256+1)",
    "FIPS 203 Algorithm 9 — NTT (the butterfly this step is half of)",
  ],
};
