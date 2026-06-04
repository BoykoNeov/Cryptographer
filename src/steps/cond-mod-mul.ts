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

The multiply half of an RSA square-and-multiply ladder rung. Reads the
running accumulator \`base\`, the value to fold in \`factor\` (the message on
encrypt, ciphertext on decrypt), the full \`exponent\` bytes, and the
\`modulus\` n. The scalar param \`bitIndex\` selects which exponent bit this
rung tests.

## Behaviour

\`\`\`
bit = (exponent >> bitIndex) & 1
output = bit == 1 ? (base · factor) mod n
                  : base            // carry forward, no multiply
\`\`\`

## Why the exponent is a runtime input, not baked in

The ladder is unrolled to a fixed number of rungs (one per modulus-width
bit). Each rung reads its exponent bit at RUN time from the wired
\`exponent\` port — so editing the exponent (e directly, or p/q which derive
d) flips exactly the affected rungs and the trace re-runs live. That is what
makes "edit a param, watch it re-run" hold for RSA's exponent.

A 0-bit rung is an honest identity step: the accumulator carries forward
unchanged. Paired with the always-present square (\`mod-mul@1\`), the trace
reads as the classic square-and-multiply ladder.

## Where it fits

- **RSA encryption** \`c = mᵉ mod n\` and **decryption** \`m = cᵈ mod n\`:
  one of these per ladder rung, after the rung's square.

## Errors

- Throws if any of \`base\`, \`factor\`, \`exponent\`, \`modulus\` is unwired.
- Throws if \`params.bitIndex\` is missing or not a non-negative integer.
- Throws if the modulus is not positive.`,
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
    "Knuth, TAOCP Vol. 2 §4.6.3 — Evaluation of powers (binary exponentiation)",
  ],
  params: new Map([
    [
      "bitIndex",
      "Which exponent bit this rung tests (LSB = 0). For an N-rung ladder, rung j tests bit N-1-j (MSB first).",
    ],
  ]),
};
