/**
 * mul — port-native big-integer multiplication (RSA key generation).
 *
 * Two input ports `a`, `b`; one output port `output`. Each input is read as
 * a big-endian non-negative integer (any length — operands need NOT match),
 * the product is computed in `bigint`, and re-encoded big-endian at a width
 * of `max(a.length, b.length)` bytes. Throws if the product does not fit in
 * that width — RSA's working integers are uniform W-byte (the modulus n and
 * φ both fit in W by construction for valid textbook params), so an overflow
 * means "primes too large for the working width," surfaced loudly.
 *
 * **Where it fits (RSA, `docs/plans/shimmying-booping-moth.md`).**
 *   - `n   = p · q`            (the public modulus)
 *   - `φ(n) = (p-1) · (q-1)`   (Euler's totient, for deriving d)
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`, omit
 * `shapeContract` — same posture as `xor.ts` / `add-mod-32.ts`. Polymorphic
 * ports (no declared `byteLength`): the wiring determines lengths, the
 * executor reads whatever arrives as a BE integer. The math is `bigint`, so
 * it generalizes to any size; the textbook explorer just uses small numbers.
 */

import { bigIntToBytes, bytesToBigInt } from "../core/big-int-codec";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

export const mulPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["b", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mul: PortedExecutor = (inputs, _params, _ctx) => {
  const a = inputs.get("a");
  const b = inputs.get("b");
  if (a === undefined) throw new Error('mul: missing required input port "a"');
  if (b === undefined) throw new Error('mul: missing required input port "b"');
  // Output width is the wider of the two operands: the product of two
  // uniform W-byte RSA integers fits in W bytes (n, φ < 2^(W·8) for valid
  // params); `bigIntToBytes` throws if it doesn't.
  const width = Math.max(a.length, b.length);
  const product = bytesToBigInt(a) * bytesToBigInt(b);
  return new Map([["output", bigIntToBytes(product, width)]]);
};

export const mulDoc: StepDocumentation = {
  name: "Multiply (integer)",
  summary: "Multiplies two whole numbers exactly — plain integer multiplication, no wrap-around.",
  detail: `# Multiply (integer)

Multiplies two non-negative whole numbers, \`a\` and \`b\`, and produces their
exact product.

## Math

\`\`\`
output = a · b
\`\`\`

This is ordinary integer multiplication — there is no modulus and no
wrap-around, so the result is the true product.

## Where it fits

- **RSA key generation**: the two secret primes \`p\` and \`q\` are multiplied
  to form the public modulus \`n = p · q\`, and \`(p − 1) · (q − 1)\` gives
  Euler's totient φ(n), which the key generation uses to derive the private
  exponent.`,
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
  ],
};
