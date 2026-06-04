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
  summary:
    "Unsigned big-integer difference a − b over big-endian operands. Output width = max(a, b) bytes; throws if negative.",
  detail: `# Subtract (integer)

Reads two big-endian non-negative integers from ports \`a\` (minuend) and
\`b\` (subtrahend) and emits \`a − b\` on \`output\`, big-endian, at
\`max(a.length, b.length)\` bytes.

## Math

\`\`\`
output = a − b      (must be ≥ 0)
\`\`\`

Unsigned: a result below zero throws rather than wrapping into two's
complement, because the only RSA use is \`p − 1\` / \`q − 1\` where the
result is always positive.

## Where it fits

- **RSA key generation**: the two factors of Euler's totient
  \`φ(n) = (p − 1)(q − 1)\`. The constant \`1\` arrives from a
  \`constant-load@1\` leaf.

## Errors

- Throws if port \`a\` or \`b\` is unwired.
- Throws if \`a − b\` is negative.`,
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
  ],
};
