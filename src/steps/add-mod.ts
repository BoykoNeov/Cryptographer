/**
 * add-mod — port-native modular addition `(a + b) mod n`.
 *
 * Three input ports: `a`, `b` (the addends) and `modulus` (n). One output port
 * `output`, carrying `(a + b) mod n` big-endian at the modulus' byte width. The
 * exact sibling of `mod-mul@1` (`steps/mod-mul.ts`), down to the operand rules:
 * **operands need NOT match in length** — each is read as a big-endian integer —
 * and the output is always the modulus width, since the residue is `< n`.
 *
 * ## Not to be confused with `add-mod-32@1`
 *
 * The palette carries both, and the names are close enough to pick wrong.
 *
 * | step | modulus | where it comes from |
 * |---|---|---|
 * | `add-mod-32@1` | fixed 2³² | a param-free ARX primitive; the modulus is the machine word, so there is nothing to wire |
 * | `add-mod@1` (this one) | **a wired input port** | the modulus is data, visible in the trace and editable in place |
 *
 * That difference is the whole reason this step exists. In a generator the
 * modulus is not an implementation detail of the register width — it is the
 * design decision that decides whether the low bits are random or worthless, so
 * it has to be a value the learner can see and change. A `add-mod-32@1` followed
 * by an `and@1` mask would reproduce today's ANSI-C arithmetic exactly, and
 * would teach the useful fact that "mod 2^k is a bitmask" — but it is correct
 * ONLY for power-of-two moduli, and in an app whose premise is editing params,
 * that is a modulus the user can silently edit into wrongness.
 *
 * ## Where it fits
 *
 * The mixed (affine) congruential generators in `ciphers/lcg.ts`:
 *
 * ```
 * x ← (a · x + c) mod m
 *      └── mod-mul@1 ──┘
 *     └────── add-mod@1 ──────┘
 * ```
 *
 * A purely multiplicative generator (MINSTD, c = 0) needs only `mod-mul@1`, so
 * this step is what the multiplicative → mixed step up actually costs: one leaf.
 *
 * ## Authoring conventions
 *
 * Port-native: omit `legacy`, `meta`, `shapeContract`. Polymorphic input ports
 * (lengths wiring-determined); `bigint` math generalizes to any size.
 */

import { bigIntToBytes, bytesToBigInt } from "../core/big-int-codec";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

export const addModPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["b", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const addMod: PortedExecutor = (inputs, _params, _ctx) => {
  const a = inputs.get("a");
  const b = inputs.get("b");
  const modulusBytes = inputs.get("modulus");
  if (a === undefined) throw new Error('add-mod: missing required input port "a"');
  if (b === undefined) throw new Error('add-mod: missing required input port "b"');
  if (modulusBytes === undefined) throw new Error('add-mod: missing required input port "modulus"');
  const n = bytesToBigInt(modulusBytes);
  if (n <= 0n) {
    throw new Error(`add-mod: modulus must be a positive integer, got ${n}`);
  }
  // The sum is formed at full precision and reduced once. Letting it wrap first
  // and reducing after would be a different (and wrong) function — the same
  // class of bug `mod-mul@1` warns about for the product.
  const sum = (bytesToBigInt(a) + bytesToBigInt(b)) % n;
  // Residue is in [0, n), so it always fits the modulus' byte width.
  return new Map([["output", bigIntToBytes(sum, modulusBytes.length)]]);
};

export const addModDoc: StepDocumentation = {
  name: "Modular add",
  summary: "Adds two numbers and reduces the result modulo n, so it stays within [0, n).",
  detail: `# Modular add

Adds \`a\` to \`b\` and reduces the result modulo \`n\`, keeping it within the
range 0 up to (but not including) \`n\`.

## Math

\`\`\`
output = (a + b) mod n
\`\`\`

## The modulus is an input, not a setting

Notice that \`n\` arrives on a **wire**, like the numbers being added. That is
deliberate, and it is the difference between this step and \`add-mod-32@1\`,
which is hard-wired to 2³² because its modulus is just the width of a machine
register.

Here the modulus is part of the design. In a linear congruential generator, the
choice between a prime modulus and a power of two decides whether the generator's
low bits carry any randomness at all — so it belongs in the picture as a value
you can look at and change, not as something hidden inside a step.

## Where it fits

- **Mixed linear congruential generators** — \`x ← (a·x + c) mod m\`. The
  multiply is a modular multiply; this step is the "+ c". A generator with
  \`c = 0\` (a *multiplicative* generator, such as MINSTD) omits this step
  entirely, which is precisely what distinguishes the two forms.`,
  references: [
    "Knuth, TAOCP Vol. 2 §3.2.1 — The linear congruential method",
    "ISO/IEC 9899 §7.22.2 — rand / srand (the standard's sample implementation)",
  ],
};
