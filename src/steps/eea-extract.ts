/**
 * eea-extract — the terminal step of the traced extended-Euclid chain (Phase 4
 * of `docs/plans/shimmying-booping-moth.md`). Reads the chain's final
 * `(r, t)` slot and emits the modular inverse `d`, or throws if no inverse
 * exists.
 *
 * After the last `eea-step@1` rung, the running tuple has reached its fixed
 * point: `newR = 0`, and the answer is the CURRENT slot — `r` is
 * `gcd(value, modulus)` and `t` is the (mod-φ-reduced) Bézout coefficient =
 * `value⁻¹ mod modulus`. **Reading the wrong slot is the classic extended-Euclid
 * bug**: `newR`/`newT` at termination are 0/junk, so this step wires to `gcd`
 * (the final `r`) and `value` (the final `t`), never `newR`/`newT`.
 *
 * Two input ports: `gcd` (the chain's final `r`) and `value` (the chain's final
 * `t`). One output port `output` carrying `value` when the gcd is 1. When the
 * gcd is NOT 1 there is no inverse — that is exactly RSA's coprimality
 * precondition `gcd(e, φ) = 1` failing — and this step throws with the same
 * message the v1 `mod-inverse@1` oracle threw, so the App error banner still
 * names a real, fixable key-validity problem.
 *
 * Because the upstream `eea-step@1` chain keeps the coefficient reduced into
 * `[0, modulus)`, `value` is ALREADY the canonical inverse in `[0, modulus)` —
 * this step does no normalization, only the gcd gate.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, `meta`, `shapeContract`.
 */

import { bytesToBigInt } from "../core/big-int-codec";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

export const eeaExtractPortContract: PortContract = {
  inputs: new Map([
    ["gcd", { layout: "raw" }],
    ["value", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const eeaExtract: PortedExecutor = (inputs, _params, _ctx) => {
  const gcdBytes = inputs.get("gcd");
  const valueBytes = inputs.get("value");
  if (gcdBytes === undefined) throw new Error('eea-extract: missing required input port "gcd"');
  if (valueBytes === undefined) throw new Error('eea-extract: missing required input port "value"');
  const gcd = bytesToBigInt(gcdBytes);
  if (gcd !== 1n) {
    throw new Error(
      `eea-extract: not invertible (gcd = ${gcd}, must be 1 — RSA requires gcd(e, φ) = 1)`,
    );
  }
  // The coefficient was kept reduced into [0, modulus) by the chain, so it is
  // already the canonical inverse. Pass it through at its own width.
  return new Map([["output", valueBytes.slice()]]);
};

export const eeaExtractDoc: StepDocumentation = {
  name: "Extract inverse (gcd gate)",
  summary:
    "Terminal of the extended-Euclid chain: emit the final coefficient as value⁻¹ mod modulus, or throw if gcd ≠ 1 (no inverse).",
  detail: `# Extract inverse (gcd gate)

The last step of the traced extended-Euclidean chain. Reads the chain's settled
\`(r, t)\` slot — \`gcd\` (the final \`r\`) and \`value\` (the final coefficient \`t\`) —
and emits the modular inverse on \`output\`.

## Behaviour

\`\`\`
gcd == 1 → output = value         (= value⁻¹ mod modulus, already in [0, modulus))
gcd != 1 → throw "not invertible" (no inverse exists)
\`\`\`

## Why read the (r, t) slot, not (newR, newT)

When the algorithm terminates, the remainder \`newR\` has reached 0 and the
companion \`newT\` is junk. The answer lives in the slot that has NOT yet been
overwritten: \`r\` = gcd, \`t\` = inverse. Wiring to \`newR\`/\`newT\` instead would
spuriously report gcd ≠ 1 — the classic extended-Euclid off-by-one.

## Where it fits

- **RSA key generation**: the tail of the \`eea-step@1\` chain that derives
  \`d = e⁻¹ mod φ(n)\`. A non-1 gcd means the chosen \`e\` shares a factor with φ —
  not a valid public exponent — which surfaces here as a thrown error.

## Errors

- Throws if port \`gcd\` or \`value\` is unwired.
- Throws if \`gcd ≠ 1\` (no modular inverse — e and φ are not coprime).`,
  references: [
    "Knuth, TAOCP Vol. 2 §4.5.2 — The extended Euclidean algorithm",
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
  ],
};
