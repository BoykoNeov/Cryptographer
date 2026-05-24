/**
 * Shift-bits-right — logical right-shift over each big-endian word
 * (universal-port plan **Phase 2 Slice 2.5**, 2026-05-25).
 *
 * Logical right-shift of each big-endian word in the input by `params.bits`
 * positions: the top `bits` positions zero-fill; the bottom `bits` are
 * discarded. Distinct from `rotate-bits-right@1` (Slice 2.1a), which wraps
 * the bottom bits to the top. The input port carries a flat `Uint8Array`
 * whose length must be a multiple of `wordBits/8`; the output is the same
 * length. No state, no aux — pure `(inputs, params) → outputs`.
 *
 * **Why this is the THIRD foundational ARX primitive.** SHR is the third
 * universal bit transform after `rotate-bits-right@1` and `add-mod-32@1`.
 * The forcing function is SHA-256's σ0 and σ1 functions (FIPS 180-4
 * §4.1.2):
 *
 *   σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
 *   σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
 *
 * Both helpers have one SHR term that CANNOT be expressed via ROR alone —
 * SHR drops bits, ROR wraps them, and the two diverge for any word with
 * non-zero low bits. Slice 2.5's authoring caught this against an earlier
 * plan-prose error that read "ROR 7/18/3 and ROR 17/19/10". Carries
 * beyond SHA-256 to ChaCha20 quarter-rounds (32-bit SHR), BLAKE2 (32-/
 * 64-bit), and any cipher that mixes shift + xor.
 *
 * **Authoring conventions.** Parallel to `rotate-bits-right.ts` — port-
 * native (`kind: "ported"`, no `legacy`, no `meta`, no `shapeContract`).
 * Param shape identical (`{bits, wordBits ∈ 8|16|32|64}`). Same per-width
 * dispatch hoisted out of the per-word loop. Same `layout: "raw"` on both
 * ports.
 *
 * **`bits >= wordBits` short-circuit.** Unlike ROR (which is naturally
 * periodic — `ROR(x, n + wordBits) === ROR(x, n)`), SHR by `n ≥ wordBits`
 * produces all-zero output. The executor checks this BEFORE invoking the
 * per-width SHR helper because JS `>>>` truncates the shift amount modulo
 * 32 — so `shr32(x, 32)` via raw `x >>> 32` would silently return `x`
 * instead of `0`. The short-circuit makes the math correct AND avoids a
 * per-call branch in the inner loop's hot path.
 *
 * **wordBits=64.** JavaScript's `>>>` truncates to 32-bit; the 64-bit
 * branch uses `BigInt` via `shr64` from `core/word-codec.ts`.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  decodeBE8,
  decodeBE16,
  decodeBE32,
  decodeBE64,
  encodeBE8,
  encodeBE16,
  encodeBE32,
  encodeBE64,
  shr8,
  shr16,
  shr32,
  shr64,
} from "../core/word-codec";

// ─── Params ───────────────────────────────────────────────────────────────

type WordBits = 8 | 16 | 32 | 64;

type Params = {
  readonly bits: number;
  readonly wordBits: WordBits;
};

const VALID_WORD_BITS: ReadonlySet<number> = new Set([8, 16, 32, 64]);

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("shift-bits-right: params must be an object");
  }
  const p = params as Record<string, Json>;
  const bits = p.bits;
  const wordBits = p.wordBits;
  if (typeof bits !== "number" || !Number.isInteger(bits) || bits < 0) {
    throw new Error("shift-bits-right: params.bits must be a non-negative integer");
  }
  if (typeof wordBits !== "number" || !VALID_WORD_BITS.has(wordBits)) {
    throw new Error("shift-bits-right: params.wordBits must be 8, 16, 32, or 64");
  }
  return { bits, wordBits: wordBits as WordBits };
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const shiftBitsRightPortContract: PortContract = {
  // Polymorphic byteLength on both ports — wiring at the consumer determines
  // the actual length; the executor checks it against the word-size
  // invariant at run time. `layout: "raw"` matches `rotate-bits-right@1`'s
  // posture (Slice 2.2's "no speculative word-array tag" pick).
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const shiftBitsRight: PortedExecutor = (inputs, params, _ctx) => {
  const { bits, wordBits } = readParams(params);
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error("shift-bits-right: missing required input port 'input'");
  }
  const bytesPerWord = wordBits / 8;
  if (inputBytes.length % bytesPerWord !== 0) {
    throw new Error(
      `shift-bits-right: input length ${inputBytes.length} is not a multiple of word size ${bytesPerWord} (wordBits=${wordBits})`,
    );
  }

  // SHR by ≥ wordBits is mathematically all-zero output. Short-circuit so
  // the per-width path can assume `bits ∈ [0, wordBits)` and rely on JS's
  // unconditional `>>>` semantics. Allocates a fresh zero-filled
  // Uint8Array per call (cheap; no per-byte loop needed).
  if (bits >= wordBits) {
    return new Map([["output", new Uint8Array(inputBytes.length)]]);
  }

  const out = new Uint8Array(inputBytes.length);

  // Dispatch on wordBits OUTSIDE the loop — picks the correct per-width
  // codec triple once. Same shape as rotate-bits-right.ts's hoisted
  // dispatch (Slice 2.2 consolidation pattern).
  if (wordBits === 64) {
    const bigN = BigInt(bits);
    for (let i = 0; i < inputBytes.length; i += 8) {
      encodeBE64(out, i, shr64(decodeBE64(inputBytes, i), bigN));
    }
  } else if (wordBits === 32) {
    for (let i = 0; i < inputBytes.length; i += 4) {
      encodeBE32(out, i, shr32(decodeBE32(inputBytes, i), bits));
    }
  } else if (wordBits === 16) {
    for (let i = 0; i < inputBytes.length; i += 2) {
      encodeBE16(out, i, shr16(decodeBE16(inputBytes, i), bits));
    }
  } else {
    // wordBits === 8
    for (let i = 0; i < inputBytes.length; i++) {
      encodeBE8(out, i, shr8(decodeBE8(inputBytes, i), bits));
    }
  }

  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const shiftBitsRightDoc: StepDocumentation = {
  name: "Shift bits right",
  summary:
    "Logical right-shift of each big-endian word in the input by `bits` positions: the top zero-fills; the bottom drops. Pure port-native primitive — no state, no aux.",
  detail: `# Shift bits right

A foundational ARX-family primitive paired with \`rotate-bits-right@1\`.
Split the input bytes into N big-endian words of width \`wordBits\`,
**logically** right-shift each word's bits by \`bits\` positions (the top
zero-fills; the bottom bits drop), and concatenate back to bytes.

## ROR vs SHR

| | ROR | SHR |
|---|---|---|
| Bottom \`n\` bits | wrap to top | drop |
| Top \`n\` bits | become old (B − n)..0 | zero-fill |
| Periodic | yes (period = wordBits) | no (SHR by ≥ wordBits = 0) |
| Reversible | yes (ROL by n) | no (information loss) |

SHR is **NOT** ROR with a different rotation amount — it's a different
operation. Any cipher whose definition writes "logical shift right"
needs SHR; any cipher whose definition writes "rotate" or "cyclic shift"
needs ROR. SHA-256's σ0 and σ1 use both:

\`\`\`
σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
\`\`\`

The two rotations + one shift gives σ0 and σ1 their characteristic
"high entropy + low-bit information drop" properties — load-bearing for
the message schedule's expansion.

## Math

For each word \`w\` of width \`B\` bits, with shift amount \`n\`:

\`\`\`
SHR(w, n, B) = (w >> n) & (2^B - 1)     for 0 ≤ n < B
SHR(w, n, B) = 0                        for n ≥ B
\`\`\`

\`n = 0\` is the identity. \`n = B\` (or more) wipes the word to zero.

## Where it fits

- **SHA-256 / SHA-224**: σ0 and σ1 in the message schedule expansion
  (FIPS 180-4 §4.1.2, §6.2.2).
- **SHA-512 / SHA-384**: same shape with 64-bit words and different
  rotation/shift amounts.
- **ChaCha20 / BLAKE2 family**: bit-shift terms in the quarter-round
  and mixing functions.
- **General-purpose bit transforms**: any time a cipher needs to
  zero-fill the high bits rather than wrap.

## Word-size guidance

| \`wordBits\` | When |
|---|---|
| 8  | Per-byte zero-fill shift; rare in modern ciphers. |
| 16 | Speck32/64 hybrids; some bit-permutation gadgets. |
| 32 | SHA-256, ChaCha20, BLAKE2s. |
| 64 | SHA-512, BLAKE2b, Argon2. |

## Implementation notes

The 8/16/32-bit paths use \`shr8\` / \`shr16\` / \`shr32\` from
\`src/core/word-codec.ts\` — thin wrappers around JS's \`>>>\` operator
with explicit unsigned-32 coercion. The 64-bit path uses \`shr64\`
(BigInt), because JS number bit ops truncate to 32-bit.

The executor short-circuits to all-zero output when \`bits ≥ wordBits\`
— JS's \`>>>\` operator truncates the shift amount modulo 32, so
\`x >>> 32\` returns \`x\` instead of \`0\`. The short-circuit makes
the math correct AND simplifies the per-width loop.

## Phase status

Shipped in Slice 2.5 of the universal-port-dataflow plan as the third
port-native step type (after \`rotate-bits-right@1\` and
\`add-mod-32@1\`). Codec helpers live in \`src/core/word-codec.ts\`
alongside their ROR siblings.`,
  params: new Map([
    [
      "bits",
      "Number of bit positions to shift right. Non-negative integer. `bits ≥ wordBits` produces all-zero output.",
    ],
    [
      "wordBits",
      "Word width in bits. One of 8, 16, 32, 64. Input length must be a multiple of `wordBits / 8`.",
    ],
  ]),
  references: [
    "FIPS 180-4 §4.1.2 (SHA-256 helper functions σ0, σ1)",
    "FIPS 180-4 §6.2.2 (SHA-256 message schedule W_t recurrence)",
    "Bernstein 2008, 'ChaCha, a variant of Salsa20'",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead. Mirrors rotate-bits-right@1's posture.
};
