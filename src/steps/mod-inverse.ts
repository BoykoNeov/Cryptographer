/**
 * mod-inverse — port-native modular multiplicative inverse via the extended
 * Euclidean algorithm. Computes RSA's private exponent `d = e⁻¹ mod φ(n)`.
 *
 * Two input ports: `value` (the number to invert — e) and `modulus` (the
 * modulus — φ(n)). One output port `output`, carrying `value⁻¹ mod modulus`
 * big-endian at the modulus' byte width. Throws when `gcd(value, modulus) ≠
 * 1` (no inverse exists) — that gcd ≠ 1 is exactly RSA's coprimality
 * precondition `gcd(e, φ) = 1`, so the error names a real key-validity
 * problem the user can fix by editing e (or p, q).
 *
 * **v1 = a single ORACLE frame.** The extended-Euclid loop runs INSIDE this
 * executor; the trace shows one frame (e, φ → d). This is the deliberate
 * coarse-then-decompose path SHA-256 and the key schedules took — the
 * genuinely hard part (signed intermediates, variable iteration count,
 * back-substitution) is deferred to Phase 4, which replaces this leaf with a
 * traced EEA loop. Until then the per-instance `narrationOverride` (Phase 2)
 * surfaces gcd = 1 and the Bézout coefficient so the one black box isn't
 * opaque.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, `meta`,
 * `shapeContract`. `bigint` math generalizes to any size.
 */

import { bigIntToBytes, bytesToBigInt } from "../core/big-int-codec";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

/**
 * Modular inverse via the iterative extended Euclidean algorithm. Returns
 * `a⁻¹ mod m` in `[0, m)`. Throws when `gcd(a, m) ≠ 1`. Exported so tests can
 * exercise the math directly (and a future Phase-4 traced loop can cross-
 * check against this oracle).
 */
export const modInverseBigInt = (a: bigint, m: bigint): bigint => {
  if (m <= 0n) {
    throw new Error(`mod-inverse: modulus must be a positive integer, got ${m}`);
  }
  // Track Bézout coefficient `t` such that t·a ≡ gcd(a, m) (mod m).
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = ((a % m) + m) % m; // normalize a into [0, m)
  while (newR !== 0n) {
    const quotient = r / newR; // BigInt floor division (operands ≥ 0)
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r > 1n) {
    throw new Error(
      `mod-inverse: ${a} is not invertible mod ${m} (gcd = ${r}, must be 1 — RSA requires gcd(e, φ) = 1)`,
    );
  }
  if (t < 0n) t += m;
  return t;
};

export const modInversePortContract: PortContract = {
  inputs: new Map([
    ["value", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const modInverse: PortedExecutor = (inputs, _params, _ctx) => {
  const valueBytes = inputs.get("value");
  const modulusBytes = inputs.get("modulus");
  if (valueBytes === undefined) throw new Error('mod-inverse: missing required input port "value"');
  if (modulusBytes === undefined)
    throw new Error('mod-inverse: missing required input port "modulus"');
  const inverse = modInverseBigInt(bytesToBigInt(valueBytes), bytesToBigInt(modulusBytes));
  return new Map([["output", bigIntToBytes(inverse, modulusBytes.length)]]);
};

export const modInverseDoc: StepDocumentation = {
  name: "Modular inverse",
  summary:
    "Compute value⁻¹ mod modulus via the extended Euclidean algorithm. RSA's d = e⁻¹ mod φ(n). Throws when not coprime.",
  detail: `# Modular inverse

Reads \`value\` and \`modulus\` as big-endian integers and emits
\`value⁻¹ mod modulus\` on \`output\` (big-endian, modulus-width) — the
unique \`x\` in \`[0, modulus)\` with \`value · x ≡ 1 (mod modulus)\`.

## Math

Computed with the **extended Euclidean algorithm**, which finds integers
\`x, y\` with \`value·x + modulus·y = gcd(value, modulus)\`. When the gcd is
1, \`x mod modulus\` is the inverse.

## Where it fits

- **RSA key generation**: the private exponent \`d = e⁻¹ mod φ(n)\`. The
  coprimality requirement \`gcd(e, φ) = 1\` is exactly the condition under
  which the inverse exists — pick an \`e\` sharing a factor with φ and this
  step throws, which is the honest "that e is not a valid public exponent."

## v1 is an oracle

The extended-Euclid loop runs inside this step; the trace shows one frame
(e, φ → d). A later phase decomposes the loop into traced quotient /
remainder / coefficient steps so the whole derivation is visible.

## Errors

- Throws if port \`value\` or \`modulus\` is unwired.
- Throws if the modulus is not positive.
- Throws if \`gcd(value, modulus) ≠ 1\` (no inverse — e and φ share a factor).`,
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
    "Knuth, TAOCP Vol. 2 §4.5.2 — The extended Euclidean algorithm",
  ],
};
