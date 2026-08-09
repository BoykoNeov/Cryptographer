/**
 * Shift-bits-left — logical left-shift over each big-endian word
 * (2026-08-09, for MT19937's tempering).
 *
 * Logical left-shift of each big-endian word in the input by `params.bits`
 * positions: the bottom `bits` positions zero-fill; the top `bits` are
 * discarded. Distinct from `rotate-bits-left@1`, which wraps the top bits
 * back around to the bottom. The input port carries a flat `Uint8Array`
 * whose length must be a multiple of `wordBits/8`; the output is the same
 * length. No state, no aux — pure `(inputs, params) → outputs`.
 *
 * **The fourth foundational ARX primitive**, completing the square that
 * `rotate-bits-right@1`, `rotate-bits-left@1` and `shift-bits-right@1`
 * already occupy three corners of. The forcing function is MT19937's
 * tempering transform (Matsumoto & Nishimura 1998, §3), whose middle two
 * steps shift LEFT:
 *
 *   y ^= (y << 7)  & 0x9d2c5680
 *   y ^= (y << 15) & 0xefc60000
 *
 * **Why not express those with `rotate-bits-left@1`.** For these two
 * particular constants a rotation gives an identical answer: 0x9d2c5680's
 * low 7 bits are clear and 0xefc60000's low 15 bits are clear, so the bits
 * a rotation would wrap around to the bottom are exactly the bits the mask
 * then deletes. That is a coincidence of MT19937's published constants, not
 * a property of the algorithm — and it stops holding the moment a learner
 * edits a mask, which this app exists to let them do. The specification says
 * "shift", so the trace says "shift". This is precisely the argument
 * `rotate-bits-left@1` made for its own existence (RFC 8439 writes `<<< 7`,
 * so rendering it as ROR 25 would have shown a number appearing nowhere in
 * the RFC), pointed the other way.
 *
 * **Authoring conventions.** Parallel to `shift-bits-right.ts` — port-native
 * (`kind: "ported"`, no `legacy`, no `meta`, no `shapeContract`). Param shape
 * identical (`{bits, wordBits ∈ 8|16|32|64}`). Same per-width dispatch
 * hoisted out of the per-word loop. Same `layout: "raw"` on both ports.
 *
 * **`bits >= wordBits` short-circuit.** SHL by `n ≥ wordBits` produces
 * all-zero output. The executor checks this BEFORE invoking the per-width
 * helper because JS `<<` truncates the shift amount modulo 32 — so
 * `shl32(x, 32)` via a raw `x << 32` would silently return `x` instead of
 * `0`. Identical hazard, identical guard, as the right-shift sibling.
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
  shl8,
  shl16,
  shl32,
  shl64,
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
    throw new Error("shift-bits-left: params must be an object");
  }
  const p = params as Record<string, Json>;
  const bits = p.bits;
  const wordBits = p.wordBits;
  if (typeof bits !== "number" || !Number.isInteger(bits) || bits < 0) {
    throw new Error("shift-bits-left: params.bits must be a non-negative integer");
  }
  if (typeof wordBits !== "number" || !VALID_WORD_BITS.has(wordBits)) {
    throw new Error("shift-bits-left: params.wordBits must be 8, 16, 32, or 64");
  }
  return { bits, wordBits: wordBits as WordBits };
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const shiftBitsLeftPortContract: PortContract = {
  // Polymorphic byteLength on both ports — wiring at the consumer determines
  // the actual length; the executor checks it against the word-size invariant
  // at run time. `layout: "raw"` matches the whole rotate/shift family.
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const shiftBitsLeft: PortedExecutor = (inputs, params, _ctx) => {
  const { bits, wordBits } = readParams(params);
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error("shift-bits-left: missing required input port 'input'");
  }
  const bytesPerWord = wordBits / 8;
  if (inputBytes.length % bytesPerWord !== 0) {
    throw new Error(
      `shift-bits-left: input length ${inputBytes.length} is not a multiple of word size ${bytesPerWord} (wordBits=${wordBits})`,
    );
  }

  // SHL by ≥ wordBits is mathematically all-zero output. Short-circuit so the
  // per-width path can assume `bits ∈ [0, wordBits)` and rely on JS's
  // unconditional `<<` semantics.
  if (bits >= wordBits) {
    return new Map([["output", new Uint8Array(inputBytes.length)]]);
  }

  const out = new Uint8Array(inputBytes.length);

  // Dispatch on wordBits OUTSIDE the loop — picks the correct per-width codec
  // triple once. Same shape as shift-bits-right.ts's hoisted dispatch.
  if (wordBits === 64) {
    const bigN = BigInt(bits);
    for (let i = 0; i < inputBytes.length; i += 8) {
      encodeBE64(out, i, shl64(decodeBE64(inputBytes, i), bigN));
    }
  } else if (wordBits === 32) {
    for (let i = 0; i < inputBytes.length; i += 4) {
      encodeBE32(out, i, shl32(decodeBE32(inputBytes, i), bits));
    }
  } else if (wordBits === 16) {
    for (let i = 0; i < inputBytes.length; i += 2) {
      encodeBE16(out, i, shl16(decodeBE16(inputBytes, i), bits));
    }
  } else {
    // wordBits === 8
    for (let i = 0; i < inputBytes.length; i++) {
      encodeBE8(out, i, shl8(decodeBE8(inputBytes, i), bits));
    }
  }

  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const shiftBitsLeftDoc: StepDocumentation = {
  name: "Shift bits left",
  summary:
    "Shifts the bits of each word to the left, filling the bottom with zeros and dropping the bits that fall off the top.",
  detail: `# Shift bits left

Reads the input as one or more fixed-width words and shifts the bits of each
word to the left by \`bits\` positions. Unlike a rotation, a shift is not
circular: the bottom fills with zeros and the bits pushed off the top are
lost. This is the mirror of **Shift bits right**, and the close partner of
**Rotate bits left**.

## ROL vs SHL

| | ROL | SHL |
|---|---|---|
| Top \`n\` bits | wrap to bottom | drop |
| Bottom \`n\` bits | become old (B − n)..0 | zero-fill |
| Periodic | yes (period = wordBits) | no (SHL by ≥ wordBits = 0) |
| Reversible | yes (ROR by n) | no (information loss) |

A left shift by \`n\` multiplies the word by 2ⁿ, discarding anything that
overflows the word — which is why it is *not* reversible, and why it is the
operation a cipher reaches for when it wants to move bits upward and let the
top ones go.

## Where it fits

- **MT19937**: the tempering transform's middle two steps
  (Matsumoto & Nishimura 1998, §3):

\`\`\`
y ^= (y << 7)  & 0x9d2c5680
y ^= (y << 15) & 0xefc60000
\`\`\`

  The masks are what make tempering a *bijection* on 32-bit words — and
  therefore what make MT19937 predictable from its own output, since anything
  invertible can be undone.
- **General-purpose bit transforms**: any design whose definition writes
  "logical shift left" or "\`<<\`" rather than "rotate".

A note worth carrying: for MT19937's two constants specifically, a *rotation*
would produce the same answer, because each mask's low bits are exactly the
bits a rotation would wrap in. That is a coincidence of those published
constants, not a property of the operation — change a mask and the two
diverge immediately.

## Word-size guidance

| \`wordBits\` | Used by |
|---|---|
| 8  | Per-byte shift; rare in modern ciphers. |
| 16 | Bit-permutation gadgets; 16-bit ARX hybrids. |
| 32 | MT19937 tempering, ChaCha20/BLAKE2s-shaped mixing. |
| 64 | MT19937-64, SHA-512-shaped designs, BLAKE2b. |`,
  params: new Map([
    [
      "bits",
      "How many bit positions to shift left. A whole number (0 or more); shifting by a full word or more zeros the value out entirely.",
    ],
    ["wordBits", "The width of each word, in bits: 8, 16, 32, or 64."],
  ]),
  references: [
    "Matsumoto & Nishimura (1998), 'Mersenne twister: a 623-dimensionally equidistributed uniform pseudo-random number generator', ACM TOMACS 8(1), §3",
    "Knuth, TAOCP Vol. 2 §3.2 — shift-register and congruential generators",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead. Mirrors shift-bits-right@1's posture.
};
