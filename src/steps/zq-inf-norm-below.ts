/**
 * zq-inf-norm-below — is every coefficient of a vector SMALL? (FIPS 204 §2.3,
 * the infinity norm `‖w‖∞`.)
 *
 * Three input ports: `a` (the vector), `bound` (an integer, big-endian, any
 * width) and `modulus` (q). Two output ports:
 *
 * - `output` — one byte, `1` if `‖a‖∞ < bound`, else `0`;
 * - `norm` — `‖a‖∞` itself, one coefficient wide.
 *
 * ## "Small" means close to zero, and zero is in the middle
 *
 * A coefficient on a wire is a residue in `[0, q)`. To ask how BIG it is, it
 * first has to be read as a signed number centred on zero: `q − 5` is −5,
 * which is small, not 8380412, which is not. So each coefficient is reduced
 * `mod± q` (into `[−(q−1)/2, (q−1)/2]`) and its absolute value taken; the norm
 * is the largest of those.
 *
 * ## The comparison is STRICT, and that is not a style choice
 *
 * Every norm check FIPS 204 makes is `<` — `‖z‖∞ < γ1 − β` in signing,
 * `‖z‖∞ < γ1 − β` again in verification. A `≤` accepts one extra value at the
 * edge, which in signing is a candidate the standard rejects: a signature whose
 * `z` sits exactly on the bound leaks a little about the secret key. Contrast
 * `ml-dsa.hint-count@1`, whose check really is `≤ ω`. The two are pinned by
 * ±1 tests for exactly that reason.
 *
 * ## Why the bound is on a port
 *
 * The bound is `γ1 − β` or `γ2 − β` — numbers a learner is meant to edit. On a
 * port, one constant feeds every check that depends on it, and editing it
 * moves all of them together; as a param, two copies could quietly disagree.
 *
 * ## Why `norm` is an output too
 *
 * The flag is what the rest of the computation uses. The norm is what a
 * learner needs to SEE: "attempt 2 rejected" means nothing until it says
 * "‖z‖∞ = 131,040, and the limit is 130,994". Publishing it on a port lets the
 * narrator and the rejection panel read the real value rather than recompute
 * it.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. The vector's length
 * is wiring-determined; `output` is one byte and `norm` one coefficient.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readCoeff,
  readScalarPort,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
  zqElementCount,
} from "../core/zq-vector";

const STEP = "zq-inf-norm-below";

export const zqInfNormBelowPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["bound", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: (params: Json) => {
    const { coeffBytes } = readZqVecParams(params, STEP);
    return new Map([
      ["output", { layout: "raw" as const, byteLength: 1 }],
      ["norm", { layout: "raw" as const, byteLength: coeffBytes }],
    ]);
  },
};

/** `|v mod± q|` for a residue `v ∈ [0, q)`. */
const centredMagnitude = (v: bigint, q: bigint): bigint => {
  const r = v % q;
  // Above ⌊q/2⌋ the residue is really a negative number; its size is the
  // distance back down to q.
  return r > q / 2n ? q - r : r;
};

export const zqInfNormBelow: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const a = requireZqPort(inputs, "a", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const bound = BigInt(readScalarPort(inputs, "bound", STEP));
  const n = zqElementCount(a, p, "a", STEP);

  let norm = 0n;
  for (let i = 0; i < n; i++) {
    const m = centredMagnitude(readCoeff(a, i, p), q);
    if (m > norm) norm = m;
  }
  const normBytes = new Uint8Array(p.coeffBytes);
  writeCoeff(normBytes, 0, norm, p);
  return new Map([
    // STRICT — see the header.
    ["output", new Uint8Array([norm < bound ? 1 : 0])],
    ["norm", normBytes],
  ]);
};

export const zqInfNormBelowDoc: StepDocumentation = {
  name: "Check every coefficient is small",
  summary:
    "Finds the largest coefficient, measured as a distance from zero, and reports whether it is strictly below a bound.",
  detail: `# Check every coefficient is small

Answers one question: is **every** coefficient of this vector close to zero?

## Close to zero, on a circle

Coefficients live on a clock face with \`q\` positions, so "close to zero" means
close on *either* side. A coefficient of \`q − 5\` is five steps below zero —
small — even though as a plain number it is huge. So each value is first read
as a signed number between \`−(q−1)/2\` and \`(q−1)/2\`, and its size is its
distance from zero:

\`\`\`
‖a‖∞ = max over i of | a[i] mod± q |
output = 1  if ‖a‖∞ < bound,  else 0
\`\`\`

That maximum is called the **infinity norm**. The step publishes it on its own
port, \`norm\`, beside the yes/no answer.

## Strictly below

The test is \`<\`, never \`≤\`. In signing, a candidate exactly on the bound is
one the standard throws away, because accepting it would leak a sliver of
information about the secret key. Compare the hint-count check, which really is
\`≤\` — the two are easy to mix up and are deliberately tested one value either
side.

## Where it is used

ML-DSA signing makes a candidate signature and then checks it. Two of its four
checks are this step: the response \`z\` must satisfy \`‖z‖∞ < γ1 − β\`, and the
low part of the commitment must satisfy \`‖r0‖∞ < γ2 − β\`. A candidate that
fails either is discarded and the signer tries again.

## The bound is wired, not set here

The bound arrives on a port, so a single constant can feed every check that
uses it. Edit that constant and every check moves with it.`,
  params: new Map([
    ["coeffBytes", "How many bytes each coefficient occupies. 4 for ML-DSA."],
    [
      "littleEndian",
      "Byte order within one coefficient, for the vector and the published norm alike. False (big-endian) matches every other wire in this app.",
    ],
  ]),
  references: [
    "FIPS 204 §2.3 — the infinity norm ‖w‖∞ and centred reduction mod±",
    "FIPS 204 Algorithm 7 (ML-DSA.Sign_internal) — the signing loop's norm checks",
  ],
};
