/**
 * mod-mul — port-native modular multiplication `a · b mod n` (RSA core).
 *
 * Three input ports: `a`, `b` (the factors) and `modulus` (n). One output
 * port `output`, carrying `(a · b) mod n` big-endian at the modulus' byte
 * width. **Operands need NOT match in length** — each is read as a
 * big-endian integer, so a short message `m` multiplied against a wider
 * accumulator works without padding. Output is always the modulus width
 * (the residue is `< n`, so it fits), giving the exponentiation ladder a
 * uniform port width.
 *
 * **Squaring reuses this primitive** — wire `a` and `b` to the SAME upstream
 * port. There is deliberately no separate `mod-square@1`; `a · a mod n` is
 * the square. This is the minimal-primitive instinct the plan locked in.
 *
 * **Where it fits (RSA, `docs/plans/shimmying-booping-moth.md`).** Every
 * rung of the square-and-multiply exponentiation ladder: the unconditional
 * square (`result · result mod n`) and — via `cond-mod-mul@1` — the
 * conditional multiply (`result · m mod n`).
 *
 * **Authoring conventions.** Port-native: omit `legacy`, `meta`,
 * `shapeContract`. Polymorphic input ports (lengths wiring-determined);
 * `bigint` math generalizes to any size.
 */

import { bigIntToBytes, bytesToBigInt } from "../core/big-int-codec";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

export const modMulPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["b", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const modMul: PortedExecutor = (inputs, _params, _ctx) => {
  const a = inputs.get("a");
  const b = inputs.get("b");
  const modulusBytes = inputs.get("modulus");
  if (a === undefined) throw new Error('mod-mul: missing required input port "a"');
  if (b === undefined) throw new Error('mod-mul: missing required input port "b"');
  if (modulusBytes === undefined) throw new Error('mod-mul: missing required input port "modulus"');
  const n = bytesToBigInt(modulusBytes);
  if (n <= 0n) {
    throw new Error(`mod-mul: modulus must be a positive integer, got ${n}`);
  }
  const product = (bytesToBigInt(a) * bytesToBigInt(b)) % n;
  // Residue is in [0, n), so it always fits the modulus' byte width — the
  // uniform port width the ladder threads.
  return new Map([["output", bigIntToBytes(product, modulusBytes.length)]]);
};

export const modMulDoc: StepDocumentation = {
  name: "Modular multiply",
  summary:
    "Compute (a · b) mod n over big-endian operands. Squaring = wire a and b to the same source. Output is modulus-width.",
  detail: `# Modular multiply

Reads factors \`a\`, \`b\` and the modulus \`n\` (port \`modulus\`) as
big-endian integers and emits \`(a · b) mod n\` on \`output\`, big-endian,
at the modulus' byte width.

## Math

\`\`\`
output = (a · b) mod n
\`\`\`

Operand lengths need not match — a short message multiplied against a wider
accumulator is read by value. The residue is always in \`[0, n)\`, so it
fits the modulus width; the exponentiation ladder threads a uniform width.

## Squaring

There is no separate square primitive — to compute \`x² mod n\`, wire BOTH
\`a\` and \`b\` to the same upstream port. \`x · x mod n\` is the square.

## Where it fits

- **RSA square-and-multiply**: each ladder rung's unconditional square
  (\`result² mod n\`), and the conditional multiply by the message
  (\`result · m mod n\`) inside \`cond-mod-mul@1\`.

## Errors

- Throws if port \`a\`, \`b\`, or \`modulus\` is unwired.
- Throws if the modulus is not positive.`,
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
    "Knuth, TAOCP Vol. 2 §4.6.3 — Evaluation of powers (binary exponentiation)",
  ],
};
