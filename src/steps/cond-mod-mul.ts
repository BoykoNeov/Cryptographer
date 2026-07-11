/**
 * cond-mod-mul — port-native CONDITIONAL modular multiply, the live-editable
 * heart of RSA's square-and-multiply exponentiation ladder.
 *
 * Four input ports: `base` (the running accumulator), `factor` (the value to
 * multiply IN — the message m on encrypt, the ciphertext c on decrypt),
 * `exponent` (the FULL exponent bytes — e or d), and `modulus` (n). One
 * scalar param `bitIndex`. One output port `output`.
 *
 * Behaviour: read bit `bitIndex` (LSB = bit 0) of the exponent integer.
 *   - bit = 1 → `output = (base · factor) mod n`   (multiply this rung)
 *   - bit = 0 → `output = base` (unchanged)         (carry forward)
 *
 * **Why this keeps the exponent live-editable** (the whole premise of the
 * explorer — `docs/plans/shimmying-booping-moth.md`). The ladder is unrolled
 * to a FIXED `N = W·8` rungs (one per modulus-width bit), and each rung reads
 * its exponent bit AT RUNTIME from the wired `exponent` port. So editing the
 * exponent (`e` directly, or `p,q` → the derived `d`) flips exactly the rungs
 * whose bit changed, and the trace re-runs — no spec rebuild. A baked-in
 * ladder (bits fixed at build) could not do this, and would mislead a learner
 * who edits `e` and sees nothing change.
 *
 * 0-bit rungs emit an honest identity frame ("bit i = 0 → carry forward, no
 * multiply"). Combined with the always-present square (a `mod-mul@1` leaf),
 * the trace reads as the textbook square-and-multiply ladder.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, `meta`,
 * `shapeContract`. Polymorphic ports; `bigint` math generalizes.
 */

import { bigIntToBytes, bytesToBigInt } from "../core/big-int-codec";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

type Params = {
  readonly bitIndex: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("cond-mod-mul: params must be an object");
  }
  const p = params as Record<string, Json>;
  const bitIndex = p.bitIndex;
  if (typeof bitIndex !== "number" || !Number.isInteger(bitIndex) || bitIndex < 0) {
    throw new Error(
      `cond-mod-mul: params.bitIndex must be a non-negative integer, got ${String(bitIndex)}`,
    );
  }
  return { bitIndex };
};

export const condModMulPortContract: PortContract = {
  inputs: new Map([
    ["base", { layout: "raw" }],
    ["factor", { layout: "raw" }],
    ["exponent", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const condModMul: PortedExecutor = (inputs, params, _ctx) => {
  const { bitIndex } = readParams(params);
  const base = inputs.get("base");
  const factor = inputs.get("factor");
  const exponentBytes = inputs.get("exponent");
  const modulusBytes = inputs.get("modulus");
  if (base === undefined) throw new Error('cond-mod-mul: missing required input port "base"');
  if (factor === undefined) throw new Error('cond-mod-mul: missing required input port "factor"');
  if (exponentBytes === undefined)
    throw new Error('cond-mod-mul: missing required input port "exponent"');
  if (modulusBytes === undefined)
    throw new Error('cond-mod-mul: missing required input port "modulus"');
  const n = bytesToBigInt(modulusBytes);
  if (n <= 0n) {
    throw new Error(`cond-mod-mul: modulus must be a positive integer, got ${n}`);
  }
  const width = modulusBytes.length;
  const baseValue = bytesToBigInt(base);
  const bitSet = ((bytesToBigInt(exponentBytes) >> BigInt(bitIndex)) & 1n) === 1n;
  const result = bitSet ? (baseValue * bytesToBigInt(factor)) % n : baseValue % n;
  return new Map([["output", bigIntToBytes(result, width)]]);
};

export const condModMulDoc: StepDocumentation = {
  name: "Conditional modular multiply",
  summary:
    "If bit `bitIndex` of the exponent is set, output (base · factor) mod n; otherwise pass base through. One rung of square-and-multiply.",
  detail: `# Conditional modular multiply

The "multiply" half of RSA's **square-and-multiply** method for raising a
number to a power. Raising to a large power directly is impractical, so RSA
scans the exponent one bit at a time: at every bit it squares the running
result, and only when the bit is 1 does it also multiply in the base value.
This step is that conditional multiply for one bit.

## Behaviour

\`\`\`
bit = the exponent bit at position bitIndex
output = if bit is 1:  (base · factor) mod n
         if bit is 0:  base            (carry forward, no multiply)
\`\`\`

When the bit is 0 the value simply passes through. Paired with the square
that always runs, this is the classic square-and-multiply ladder — and
because each step reads its exponent bit live, changing the exponent (or the
primes that derive it) instantly changes which steps multiply.

## Where it fits

- **RSA encryption** \`c = mᵉ mod n\` and **decryption** \`m = cᵈ mod n\`:
  one of these per bit of the exponent, following that bit's square.`,
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
    "Knuth, TAOCP Vol. 2 §4.6.3 — Evaluation of powers (binary exponentiation)",
  ],
  params: new Map([
    [
      "bitIndex",
      "Which bit of the exponent this step looks at (counting from 0 at the least-significant bit).",
    ],
  ]),
};
