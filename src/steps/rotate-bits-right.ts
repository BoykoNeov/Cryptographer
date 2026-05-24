/**
 * Rotate-bits-right — first port-native step type (universal-port plan
 * Phase 2 Slice 2.1a, 2026-05-24).
 *
 * Cyclic right-rotation of each big-endian word in the input by `params.bits`
 * positions, where `params.wordBits ∈ {8, 16, 32, 64}` selects the word size.
 * The input port carries a flat `Uint8Array` whose length must be a multiple
 * of `wordBits/8`; the output is the same length. No state, no aux — the
 * step is a pure `(inputs, params) → outputs` map, the universal-port
 * contract's minimum surface.
 *
 * **Why this is the FIRST port-native step.** Slice 2.1a's headline gate is
 * the contract widening that makes `StepRegistration.legacy` (and `meta`)
 * optional on the `kind: "ported"` variant; this file is the evidence the
 * widening is reachable. Rotate-bits-right is also load-bearing for SHA-256
 * (Slices 2.3/2.5 use it inside Σ0/Σ1/σ0/σ1 helpers and the message schedule
 * expansion) and for any future ARX cipher rebuild from medium primitives.
 *
 * **Authoring conventions.** Port-native (Phase 2+) steps deliberately OMIT
 * the legacy `StepDocumentation.shapeContract` — they have a richer
 * `PortContract` instead, and the legacy single-thread state shape doesn't
 * apply. The state-shape-contracts test was updated in Slice 2.1a to skip
 * port-native registrations for the same reason. The narration and
 * provenance contract tests gate only on step types with a `shapeContract`,
 * so omitting it also skips those gates until the step earns a richer UI
 * surface (Slice 2.6+ when it first wires into a real spec).
 *
 * **wordBits=64.** JavaScript's `>>>` / `<<` operators truncate to 32-bit
 * unsigned, so the 64-bit branch uses `BigInt`. The 8/16/32 branch uses
 * the plain-number `ror` helper — same pattern as `speck-round.ts`.
 *
 * **`bits` modulo `wordBits`.** Any non-negative integer is accepted and
 * reduced modulo the word size — `bits = 32, wordBits = 32` is the identity
 * just like `bits = 0`. This matches the textbook ROR definition and avoids
 * a footgun where a caller forgets to canonicalize.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type WordBits = 8 | 16 | 32 | 64;

type Params = {
  readonly bits: number;
  readonly wordBits: WordBits;
};

const VALID_WORD_BITS: ReadonlySet<number> = new Set([8, 16, 32, 64]);

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("rotate-bits-right: params must be an object");
  }
  const p = params as Record<string, Json>;
  const bits = p.bits;
  const wordBits = p.wordBits;
  if (typeof bits !== "number" || !Number.isInteger(bits) || bits < 0) {
    throw new Error("rotate-bits-right: params.bits must be a non-negative integer");
  }
  if (typeof wordBits !== "number" || !VALID_WORD_BITS.has(wordBits)) {
    throw new Error("rotate-bits-right: params.wordBits must be 8, 16, 32, or 64");
  }
  return { bits, wordBits: wordBits as WordBits };
};

// ─── Word codec + ROR helpers ─────────────────────────────────────────────
// Local copies; future Slice 2.2 may consolidate into a shared
// `core/word-codec.ts` per Open #N5. For now keeping them inline avoids a
// new module that would host only three trivial helpers.

const wordMask = (bits: number): number => (bits === 32 ? 0xffffffff : (1 << bits) - 1);

/** ROR for 8/16/32-bit words via plain-number bit ops. */
const ror32orSmaller = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  // n is already canonicalized to [0, bits); the (bits - n) path covers
  // n=0 too because JS `<<` truncates the shift amount mod 32 — so
  // `xm << 32` is `xm`, and the OR with `xm >>> 0 = xm` collapses cleanly.
  return ((xm >>> n) | (xm << (bits - n))) & mask;
};

const decodeBE = (bytes: Uint8Array, offset: number, byteCount: number): number => {
  let v = 0;
  for (let j = 0; j < byteCount; j++) {
    // Cast through Number — `bytes[i]` is `number | undefined` under
    // noUncheckedIndexedAccess, but the caller already bounds-checked.
    v = (v << 8) | (bytes[offset + j] as number);
  }
  // Force unsigned 32-bit view for 4-byte decode. `<< 0` would re-introduce
  // signed; `>>> 0` is the canonical "as unsigned" trick.
  return v >>> 0;
};

const encodeBE = (out: Uint8Array, offset: number, word: number, byteCount: number): void => {
  for (let j = 0; j < byteCount; j++) {
    out[offset + j] = (word >>> (8 * (byteCount - 1 - j))) & 0xff;
  }
};

/** 64-bit ROR via BigInt — JS number bitwise ops only cover 32 bits. */
const ror64 = (bytes: Uint8Array, offset: number, n: number, out: Uint8Array): void => {
  let word = 0n;
  for (let j = 0; j < 8; j++) {
    word = (word << 8n) | BigInt(bytes[offset + j] as number);
  }
  const mask = (1n << 64n) - 1n;
  const bigN = BigInt(n);
  // n is already canonicalized to [0, 64); BigInt has no shift-truncation
  // so `word << 64n` is enormous, but `& mask` collapses it. The n=0 case
  // works because `word << 64n & mask = 0n` and `word >> 0n | 0n = word`.
  const rotated = ((word >> bigN) | (word << (64n - bigN))) & mask;
  for (let j = 0; j < 8; j++) {
    out[offset + j] = Number((rotated >> BigInt(8 * (7 - j))) & 0xffn);
  }
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const rotateBitsRightPortContract: PortContract = {
  // Polymorphic byteLength on both ports — wiring at the consumer
  // determines the actual length, validated at execution time against the
  // word-size invariant. `layout: "raw"` until Slice 2.2 picks the
  // word-array encoding (Open #N5).
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const rotateBitsRight: PortedExecutor = (inputs, params, _ctx) => {
  const { bits, wordBits } = readParams(params);
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error("rotate-bits-right: missing required input port 'input'");
  }
  const bytesPerWord = wordBits / 8;
  if (inputBytes.length % bytesPerWord !== 0) {
    throw new Error(
      `rotate-bits-right: input length ${inputBytes.length} is not a multiple of word size ${bytesPerWord} (wordBits=${wordBits})`,
    );
  }

  // Canonicalize bits to [0, wordBits). `bits === 0` is identity; the loop
  // still runs but each word maps to itself.
  const n = bits % wordBits;
  const out = new Uint8Array(inputBytes.length);

  for (let i = 0; i < inputBytes.length; i += bytesPerWord) {
    if (wordBits === 64) {
      ror64(inputBytes, i, n, out);
    } else {
      const word = decodeBE(inputBytes, i, bytesPerWord);
      const rotated = ror32orSmaller(word, n, wordBits);
      encodeBE(out, i, rotated, bytesPerWord);
    }
  }

  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const rotateBitsRightDoc: StepDocumentation = {
  name: "Rotate bits right",
  summary:
    "Cyclic right-rotation of each big-endian word in the input by `bits` positions. Pure port-native primitive — no state, no aux.",
  detail: `# Rotate bits right

A foundational ARX-family primitive: split the input bytes into N
big-endian words of width \`wordBits\`, rotate each word's bits right by
\`bits\` positions (treating each word as a circular bit register), and
concatenate back to bytes. The output port carries the same number of
bytes as the input.

## Math

For each word \`w\` of width \`B\` bits, with a rotation amount \`n\`
(canonicalized to \`bits mod B\`):

\`\`\`
ROR(w, n, B) = ((w >> n) | (w << (B - n))) & (2^B - 1)
\`\`\`

The bottom \`n\` bits wrap to the top; the remaining \`B - n\` bits
shift right by \`n\`. \`n = 0\` (or any multiple of \`B\`) is the
identity.

## Where it fits

- **SHA-256**: building block of the Σ0, Σ1, σ0, σ1 helpers
  (FIPS 180-4 §4.1.2) and the message schedule's W_t recurrence.
- **ARX block ciphers**: Speck's round function and key schedule. The
  shipped \`speck.round@1\` step type inlines the rotation against
  Speck's wider 2-word state; this primitive isolates the rotation
  itself so future ARX rebuilds from medium primitives can compose it.
- **General-purpose bit transforms**: any time a cipher or hash treats
  a flat byte buffer as N parallel fixed-width words and rotates each.

## Word-size guidance

| \`wordBits\` | When |
|---|---|
| 8  | Per-byte rotation; rare in modern ciphers, occasionally in S-box construction. |
| 16 | Speck32/64. |
| 32 | SHA-256, Speck64/128, ChaCha20, BLAKE2s. |
| 64 | SHA-512, Speck128/256, BLAKE2b. |

## Implementation notes

The 8/16/32-bit path uses native JavaScript bit operators (\`>>> / << / |\`),
masked to the declared word width. The 64-bit path uses \`BigInt\` because
JS bit ops truncate to 32-bit unsigned. Both paths produce big-endian
encoded output, matching the typical hash-function convention.

## Phase status

Shipped in Slice 2.1a of the universal-port-dataflow plan as the first
port-native step type. Not yet wired into any cipher spec — Slice 2.6's
SHA-256 build is the first consumer.`,
  params: new Map([
    [
      "bits",
      "Number of bit positions to rotate right. Non-negative integer; reduced modulo `wordBits`.",
    ],
    [
      "wordBits",
      "Word width in bits. One of 8, 16, 32, 64. Input length must be a multiple of `wordBits / 8`.",
    ],
  ]),
  references: [
    "FIPS 180-4 §4.1.2 (SHA-256 helper functions Σ0, Σ1, σ0, σ1)",
    "Beaulieu et al. 2013, 'The SIMON and SPECK Families of Lightweight Block Ciphers'",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead. The state-shape-contracts test skips
  // `kind: "ported"` registrations that lack a `legacy` field (i.e.,
  // port-native ones).
};
