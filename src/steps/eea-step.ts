/**
 * eea-step — ONE traced iteration of the extended Euclidean algorithm, the
 * decomposition of RSA's `mod-inverse@1` oracle (Phase 4 of
 * `docs/plans/shimmying-booping-moth.md`).
 *
 * The v1 modular inverse (`mod-inverse.ts`) runs the whole Euclid loop inside a
 * single executor and emits ONE frame (e, φ → d). Phase 4 unrolls that loop
 * into a chain of these steps — one frame per division step — so the learner
 * watches `d = e⁻¹ mod φ` derived the same way a textbook derives it: a shrinking
 * remainder sequence with a Bézout coefficient tracked alongside.
 *
 * **State carried across the chain = the 4-tuple `(r, newR, t, newT)`.** Five
 * input ports (the tuple + the `modulus` φ); four output ports (the SHIFTED
 * tuple). Per iteration, with `q = ⌊r / newR⌋`:
 *
 *   r'    = newR
 *   newR' = r − q·newR        (= r mod newR — the Euclid remainder step)
 *   t'    = newT
 *   newT' = (t − q·newT) mod φ
 *
 * **Why the coefficient is reduced mod φ — the key design decision.** The raw
 * Bézout coefficient `t` goes NEGATIVE mid-loop, but every primitive in this
 * codebase (and the `bigIntToBytes` codec) is unsigned big-endian and throws on
 * a negative value — a two's-complement value riding a `layout:"raw"` port that
 * some downstream step reads as a giant unsigned integer is exactly the footgun
 * the "every port is a non-negative BE integer" convention exists to prevent. So
 * we track `t mod φ` instead. This is mathematically exact: the `r`/`newR`
 * sequence (hence the gcd) is independent of `t`, and `t ≡ true_t (mod φ)`
 * throughout, so the final `t` lands in `[0, φ)` and IS `d` directly — no
 * terminal normalization. The only visible cost is that a coefficient a textbook
 * would print as `−183` shows here as `φ − 183 = 2937`; the per-leaf narration
 * names this.
 *
 * **Fixed-unroll + identity carry-forward.** The chain is unrolled to a fixed
 * `eeaMaxIterations(W)` rungs (Euclid's worst case is bounded — Lamé's theorem),
 * and once `newR` reaches 0 the algorithm is DONE: a step with `newR == 0`
 * passes its tuple through unchanged, so the trailing rungs are honest identity
 * frames (exactly like the square-and-multiply ladder's 0-bit rungs). The
 * terminal `eea-extract@1` then reads the final `(r, t)` slot — `r` is the gcd,
 * `t` is the inverse.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, `meta`, `shapeContract`.
 * `bigint` math generalizes to any width.
 */

import { bigIntToBytes, bytesToBigInt } from "../core/big-int-codec";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

/**
 * Safe upper bound on the number of Euclidean-algorithm division steps for two
 * operands below `2^(8·W)`. Euclid's worst case is consecutive Fibonacci numbers
 * (Lamé's theorem): the step count is bounded by `≈ 1.4404 · log₂(N)`. The `+ 2`
 * margin absorbs a user-entered `e ≥ φ` (which costs one extra leading step) plus
 * rounding slack. Exported because both the RSA spec builder (how many rungs to
 * unroll) and the worst-case test (assert convergence within this bound) must
 * agree on it. The worst-case Fibonacci test is what PINS this number — if it is
 * ever too small the chain would silently produce a wrong `d` for some key.
 */
export const eeaMaxIterations = (W: number): number => {
  if (!Number.isInteger(W) || W < 1) {
    throw new Error(`eeaMaxIterations: width must be a positive integer, got ${String(W)}`);
  }
  return Math.ceil(1.4404 * 8 * W) + 2;
};

export const eeaStepPortContract: PortContract = {
  inputs: new Map([
    ["r", { layout: "raw" }],
    ["newR", { layout: "raw" }],
    ["t", { layout: "raw" }],
    ["newT", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([
    ["r", { layout: "raw" }],
    ["newR", { layout: "raw" }],
    ["t", { layout: "raw" }],
    ["newT", { layout: "raw" }],
  ]),
};

export const eeaStep: PortedExecutor = (inputs, _params, _ctx) => {
  const rBytes = inputs.get("r");
  const newRBytes = inputs.get("newR");
  const tBytes = inputs.get("t");
  const newTBytes = inputs.get("newT");
  const modulusBytes = inputs.get("modulus");
  if (rBytes === undefined) throw new Error('eea-step: missing required input port "r"');
  if (newRBytes === undefined) throw new Error('eea-step: missing required input port "newR"');
  if (tBytes === undefined) throw new Error('eea-step: missing required input port "t"');
  if (newTBytes === undefined) throw new Error('eea-step: missing required input port "newT"');
  if (modulusBytes === undefined)
    throw new Error('eea-step: missing required input port "modulus"');

  // Every value is encoded at the modulus' byte width (the uniform RSA working
  // width). The four tuple slots all stay in [0, modulus), so they fit.
  const width = modulusBytes.length;
  const m = bytesToBigInt(modulusBytes);
  if (m <= 0n) {
    throw new Error(`eea-step: modulus must be a positive integer, got ${m}`);
  }
  const r = bytesToBigInt(rBytes);
  const newR = bytesToBigInt(newRBytes);
  const t = bytesToBigInt(tBytes);
  const newT = bytesToBigInt(newTBytes);

  // Done: once the remainder hits 0 the gcd has been found. Carry the tuple
  // forward unchanged so the trailing unrolled rungs are honest identity frames
  // and the terminal extract reads a stable (r, t). (Also avoids a ÷0.)
  if (newR === 0n) {
    return new Map([
      ["r", bigIntToBytes(r, width)],
      ["newR", bigIntToBytes(0n, width)],
      ["t", bigIntToBytes(t, width)],
      ["newT", bigIntToBytes(newT, width)],
    ]);
  }

  const quotient = r / newR; // BigInt floor division (both operands ≥ 0)
  const nextNewR = r - quotient * newR; // = r mod newR, in [0, newR) ⊂ [0, m)
  // Coefficient recurrence, reduced into [0, m): t − q·newT can be negative, so
  // normalize with the (x % m + m) % m idiom. This keeps every port non-negative
  // while preserving t ≡ true Bézout coefficient (mod m). See the file header.
  const nextNewT = (((t - quotient * newT) % m) + m) % m;

  return new Map([
    ["r", bigIntToBytes(newR, width)], // r'   = newR
    ["newR", bigIntToBytes(nextNewR, width)], // newR' = r mod newR
    ["t", bigIntToBytes(newT, width)], // t'   = newT
    ["newT", bigIntToBytes(nextNewT, width)], // newT' = (t − q·newT) mod m
  ]);
};

export const eeaStepDoc: StepDocumentation = {
  name: "Extended-Euclid step",
  summary:
    "One division step of the extended Euclidean algorithm: shift the (r, newR, t, newT) tuple by q = ⌊r/newR⌋. Identity once newR = 0.",
  detail: `# Extended-Euclid step

One iteration of the **extended Euclidean algorithm**, the loop that computes
RSA's private exponent \`d = e⁻¹ mod φ(n)\`. The algorithm's running state is the
four-tuple \`(r, newR, t, newT)\`, carried from one step to the next on the four
matching ports; \`modulus\` is φ.

## The recurrence

With \`q = ⌊r / newR⌋\`:

\`\`\`
r'    = newR
newR' = r − q·newR        (= r mod newR, the Euclid remainder)
t'    = newT
newT' = (t − q·newT) mod φ
\`\`\`

The \`r\` / \`newR\` sequence is ordinary Euclid: a shrinking remainder chain whose
last non-zero value is \`gcd(e, φ)\`. The \`t\` / \`newT\` sequence tracks the Bézout
coefficient of \`e\` alongside it.

## Why the coefficient is shown reduced mod φ

The raw Bézout coefficient is signed — it dips negative mid-loop. Rather than
introduce a signed value on a port (every other value in this explorer is an
unsigned big-endian integer), this step keeps the coefficient **reduced into
\`[0, φ)\`**. That is mathematically exact for the inverse (the coefficient is only
ever needed modulo φ), so the final \`t\` is \`d\` directly. The visible consequence:
a coefficient a textbook prints as \`−183\` appears here as \`φ − 183\`.

## Done = identity

Once \`newR\` reaches 0 the gcd has been found, and the step passes its tuple
through unchanged. The chain is unrolled to a fixed worst-case number of rungs
(Lamé's theorem bounds Euclid's step count), so the trailing rungs are honest
identity frames — like the 0-bit rungs of the square-and-multiply ladder.

## Where it fits

- **RSA key generation**: chained \`eeaMaxIterations(W)\` times to derive
  \`d = e⁻¹ mod φ(n)\`, terminated by an \`eea-extract@1\` that reads the final
  \`(r, t)\` slot (gcd and inverse).

## Errors

- Throws if any of \`r\`, \`newR\`, \`t\`, \`newT\`, \`modulus\` is unwired.
- Throws if the modulus is not positive.`,
  references: [
    "Knuth, TAOCP Vol. 2 §4.5.2 — The extended Euclidean algorithm",
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
  ],
};
