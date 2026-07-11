/**
 * sub — port-native big-integer subtraction (RSA key generation).
 *
 * Two input ports `a` (minuend), `b` (subtrahend); one output port
 * `output`. Each input is read as a big-endian non-negative integer (any
 * length), the difference `a − b` is computed in `bigint`, and re-encoded
 * big-endian at `max(a.length, b.length)` bytes. Throws if the result would
 * be negative — RSA only ever subtracts 1 from a prime (`p − 1`, `q − 1`),
 * which is always non-negative, so a negative result is a wiring bug.
 *
 * **Where it fits (RSA, `docs/plans/shimmying-booping-moth.md`).** The two
 * factors of Euler's totient: `φ(n) = (p − 1)(q − 1)`. Paired with a
 * `constant-load@1` emitting the literal `1`.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, `meta`,
 * `shapeContract` — same posture as `mul.ts`.
 */

import { bigIntToBytes, bytesToBigInt } from "../core/big-int-codec";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

export const subPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["b", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const sub: PortedExecutor = (inputs, _params, _ctx) => {
  const a = inputs.get("a");
  const b = inputs.get("b");
  if (a === undefined) throw new Error('sub: missing required input port "a"');
  if (b === undefined) throw new Error('sub: missing required input port "b"');
  const difference = bytesToBigInt(a) - bytesToBigInt(b);
  if (difference < 0n) {
    throw new Error(
      `sub: result is negative (a − b = ${difference}); this primitive is unsigned (RSA only subtracts 1 from a prime)`,
    );
  }
  const width = Math.max(a.length, b.length);
  return new Map([["output", bigIntToBytes(difference, width)]]);
};

export const subDoc: StepDocumentation = {
  name: "Subtract (integer)",
  summary: "Subtracts one whole number from another. The result must not go below zero.",
  detail: `# Subtract (integer)

Subtracts \`b\` from \`a\` and produces the difference. The result is treated
as a plain non-negative whole number, so \`a\` must be at least as large as
\`b\`.

## Math

\`\`\`
output = a − b      (must be ≥ 0)
\`\`\`

## Where it fits

- **RSA key generation**: computing \`p − 1\` and \`q − 1\`, whose product is
  Euler's totient φ(n) = (p − 1)(q − 1) — a value the key generation needs to
  find the private exponent.`,
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
  ],
};
