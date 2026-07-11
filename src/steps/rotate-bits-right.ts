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
 * **Slice 2.2 consolidation (2026-05-24):** the inline `decodeBE` /
 * `encodeBE` / `wordMask` / `ror32orSmaller` / `ror64` helpers that
 * shipped with Slice 2.1a moved to `src/core/word-codec.ts` so
 * `add-mod-32@1` (Slice 2.1b) and future SHA-256 helpers (Slice 2.3+)
 * can share them. The executor's `wordBits` dispatch now hoists out of
 * the per-word loop and uses per-width primitives directly, which is
 * tighter than the previous "one parameterized helper per call" form.
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
 * unsigned, so the 64-bit branch uses `BigInt` (via the shared `ror64`
 * helper which takes/returns `bigint`). The 8/16/32-bit branches stay on
 * plain numbers via the corresponding shared per-width helpers.
 *
 * **`bits` modulo `wordBits`.** Any non-negative integer is accepted and
 * reduced modulo the word size — `bits = 32, wordBits = 32` is the identity
 * just like `bits = 0`. This matches the textbook ROR definition and avoids
 * a footgun where a caller forgets to canonicalize.
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
  ror8,
  ror16,
  ror32,
  ror64,
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

// ─── Port contract + executor ─────────────────────────────────────────────

export const rotateBitsRightPortContract: PortContract = {
  // Polymorphic byteLength on both ports — wiring at the consumer
  // determines the actual length, validated at execution time against the
  // word-size invariant. `layout: "raw"` because no UI surface in Phase 2's
  // scope reads layout-as-data — adding a `word-array-be-32` tag would be
  // decoration today (see Slice 2.2 / Open #N5 rationale in
  // `src/core/word-codec.ts`).
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

  // Dispatch on wordBits OUTSIDE the loop — picks the correct per-width
  // codec triple once, then runs a tight loop calling only that triple.
  // Each branch is essentially the same three-statement compose
  // (decode → ror → encode) with width-specific primitives; the 64-bit
  // path uses BigInt because JS number bit ops truncate to 32-bit.
  if (wordBits === 64) {
    const bigN = BigInt(n);
    for (let i = 0; i < inputBytes.length; i += 8) {
      encodeBE64(out, i, ror64(decodeBE64(inputBytes, i), bigN));
    }
  } else if (wordBits === 32) {
    for (let i = 0; i < inputBytes.length; i += 4) {
      encodeBE32(out, i, ror32(decodeBE32(inputBytes, i), n));
    }
  } else if (wordBits === 16) {
    for (let i = 0; i < inputBytes.length; i += 2) {
      encodeBE16(out, i, ror16(decodeBE16(inputBytes, i), n));
    }
  } else {
    // wordBits === 8
    for (let i = 0; i < inputBytes.length; i++) {
      encodeBE8(out, i, ror8(decodeBE8(inputBytes, i), n));
    }
  }

  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const rotateBitsRightDoc: StepDocumentation = {
  name: "Rotate bits right",
  summary:
    "Rotates the bits of each word to the right, wrapping the bits that fall off the end back to the top.",
  detail: `# Rotate bits right

Reads the input as one or more fixed-width words and rotates the bits of each
word to the right by \`bits\` positions. A rotation is a circular shift: the
bits that fall off the right-hand end wrap around to the top, so no bits are
lost — only rearranged.

## Math

For each word \`w\` of width \`B\` bits, rotating right by \`n\`:

\`\`\`
ROR(w, n, B) = ((w >> n) | (w << (B - n)))   within B bits
\`\`\`

The bottom \`n\` bits wrap to the top; the rest move right by \`n\`. Rotating
by 0 (or a full word) leaves the value unchanged.

## Where it fits

Rotation is the **"R" in the ARX family** (Addition, Rotation, XOR). On its
own it just shuffles bits, but combined with addition and XOR it spreads each
bit's influence across the whole word, which is a large part of how these
ciphers and hashes mix their data:

- **SHA-256** builds its Σ0/Σ1/σ0/σ1 mixing functions from rotations.
- **Speck** rotates as part of every round and its key schedule.

## Word-size guidance

The word size sets how wide the "circle" of bits is — a rotation wraps within
one word, so it depends on the width the cipher uses:

| \`wordBits\` | Used by |
|---|---|
| 8  | Per-byte rotation; rare, occasionally in S-box construction. |
| 16 | Speck32/64. |
| 32 | SHA-256, Speck64/128, ChaCha20, BLAKE2s. |
| 64 | SHA-512, Speck128/256, BLAKE2b. |`,
  params: new Map([
    [
      "bits",
      "How many bit positions to rotate right. A whole number (0 or more); a rotation by the full word width brings you back to the start.",
    ],
    [
      "wordBits",
      "The width of each word, in bits: 8, 16, 32, or 64. The rotation wraps around within one word of this size.",
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
