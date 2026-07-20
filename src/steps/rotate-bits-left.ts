/**
 * Rotate-bits-left — the mirror of `rotate-bits-right@1`, added for ChaCha20
 * (RFC 8439, 2026-07-20).
 *
 * Cyclic LEFT-rotation of each big-endian word in the input by `params.bits`
 * positions, where `params.wordBits ∈ {8, 16, 32, 64}` selects the word size.
 * Same shape as its right-handed sibling in every other respect: the input
 * port carries a flat `Uint8Array` whose length must be a multiple of
 * `wordBits/8`, the output is the same length, and the step is a pure
 * `(inputs, params) → outputs` map with no state and no aux.
 *
 * **Why this exists when `rotate-bits-right@1` already does.** A left rotation
 * is arithmetically identical to a right rotation by the complement —
 * `ROL(w, n, B) === ROR(w, B - n, B)` — so this step type buys no new
 * *behaviour*. What it buys is **honest rendering**, which for this project is
 * the point. ChaCha20's quarter-round is defined in RFC 8439 §2.1 with the
 * rotations `<<< 16`, `<<< 12`, `<<< 8`, `<<< 7`. Expressing those as
 * `rotate-bits-right@1` with `bits` of 16/20/24/25 would run correctly and
 * trace *wrongly*: a learner scrubbing the quarter-round would read "ROR 20"
 * with the RFC open at "<<< 12" and have no way to reconcile the two. The
 * explorer exists so the trace and the specification say the same thing.
 *
 * The executor still DELEGATES to the shared `ror{8,16,32,64}` helpers rather
 * than growing a parallel set of `rol*` primitives. Those helpers are already
 * exercised by SHA-256, Speck and the port-provenance perturbation suite, and
 * a second implementation of the same bit math would be a second thing to get
 * wrong. The complement is an implementation detail confined to this file;
 * nothing above it ever sees a right-rotation.
 *
 * **Endianness.** Words are decoded big-endian, exactly as
 * `rotate-bits-right@1` does. This is not in tension with ChaCha20 being a
 * little-endian cipher: a rotation is defined on the 32-bit *value*, and how
 * that value is serialized to bytes is a separate question. ChaCha20's spec
 * builder travels the ports big-endian and localizes the LE↔BE crossing to
 * visible `permute@1` word-reversals at the endpoints — the convention Twofish
 * established (`src/ciphers/twofish-spec-builder.ts`).
 *
 * **`bits` modulo `wordBits`.** Any non-negative integer is accepted and
 * reduced modulo the word size, so `bits = 32, wordBits = 32` is the identity
 * just like `bits = 0` — matching the textbook ROL definition and its sibling's
 * behaviour.
 *
 * **Authoring conventions.** Port-native steps deliberately OMIT the legacy
 * `StepDocumentation.shapeContract` — they describe their surface via
 * `PortContract` instead.
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
    throw new Error("rotate-bits-left: params must be an object");
  }
  const p = params as Record<string, Json>;
  const bits = p.bits;
  const wordBits = p.wordBits;
  if (typeof bits !== "number" || !Number.isInteger(bits) || bits < 0) {
    throw new Error("rotate-bits-left: params.bits must be a non-negative integer");
  }
  if (typeof wordBits !== "number" || !VALID_WORD_BITS.has(wordBits)) {
    throw new Error("rotate-bits-left: params.wordBits must be 8, 16, 32, or 64");
  }
  return { bits, wordBits: wordBits as WordBits };
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const rotateBitsLeftPortContract: PortContract = {
  // Polymorphic byteLength on both ports — wiring at the consumer determines
  // the actual length, validated at execution time against the word-size
  // invariant. `layout: "raw"` for the same reason as every other port-native
  // primitive: no UI surface reads layout-as-data.
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const rotateBitsLeft: PortedExecutor = (inputs, params, _ctx) => {
  const { bits, wordBits } = readParams(params);
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error("rotate-bits-left: missing required input port 'input'");
  }
  const bytesPerWord = wordBits / 8;
  if (inputBytes.length % bytesPerWord !== 0) {
    throw new Error(
      `rotate-bits-left: input length ${inputBytes.length} is not a multiple of word size ${bytesPerWord} (wordBits=${wordBits})`,
    );
  }

  // ROL(w, n) === ROR(w, wordBits - n). Canonicalize `bits` into [0, wordBits)
  // FIRST, then take the complement and canonicalize again — the second
  // reduction is what keeps `bits = 0` (and any exact multiple of the word
  // width) at a right-rotation of 0 rather than a right-rotation of `wordBits`.
  const left = bits % wordBits;
  const right = (wordBits - left) % wordBits;
  const out = new Uint8Array(inputBytes.length);

  // Dispatch on wordBits OUTSIDE the loop, mirroring `rotate-bits-right@1`.
  // The 64-bit path uses BigInt because JS number bit ops truncate to 32-bit.
  if (wordBits === 64) {
    const bigRight = BigInt(right);
    for (let i = 0; i < inputBytes.length; i += 8) {
      encodeBE64(out, i, ror64(decodeBE64(inputBytes, i), bigRight));
    }
  } else if (wordBits === 32) {
    for (let i = 0; i < inputBytes.length; i += 4) {
      encodeBE32(out, i, ror32(decodeBE32(inputBytes, i), right));
    }
  } else if (wordBits === 16) {
    for (let i = 0; i < inputBytes.length; i += 2) {
      encodeBE16(out, i, ror16(decodeBE16(inputBytes, i), right));
    }
  } else {
    // wordBits === 8
    for (let i = 0; i < inputBytes.length; i++) {
      encodeBE8(out, i, ror8(decodeBE8(inputBytes, i), right));
    }
  }

  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const rotateBitsLeftDoc: StepDocumentation = {
  name: "Rotate bits left",
  summary:
    "Rotates the bits of each word to the left, wrapping the bits that fall off the top back around to the bottom.",
  detail: `# Rotate bits left

Reads the input as one or more fixed-width words and rotates the bits of each
word to the left by \`bits\` positions. A rotation is a circular shift: the bits
that fall off the left-hand end wrap around to the bottom, so no bits are lost
— only rearranged.

## Math

For each word \`w\` of width \`B\` bits, rotating left by \`n\`:

\`\`\`
ROL(w, n, B) = ((w << n) | (w >> (B - n)))   within B bits
\`\`\`

The top \`n\` bits wrap to the bottom; the rest move left by \`n\`. Rotating by
0 (or a full word) leaves the value unchanged.

## Left and right are the same operation

Rotating left by \`n\` is exactly rotating right by \`B - n\`. A 32-bit word
rotated left by 12 is the same word rotated right by 20 — the bits end up in
identical positions.

So why have both? Because **published specifications pick a direction, and the
trace should match the paper you are reading.** ChaCha20's quarter-round is
written with left rotations of 16, 12, 8 and 7. Rendering those as right
rotations of 16, 20, 24 and 25 would compute the right answer while showing you
numbers that appear nowhere in the specification. The two step types exist so
that whichever direction a cipher's designers chose, the trace can say it.

## Where it fits

Rotation is the **"R" in the ARX family** (Addition, Rotation, XOR). On its own
it just shuffles bits, but combined with addition and XOR it spreads each bit's
influence across the whole word — a large part of how these ciphers mix data:

- **ChaCha20** rotates left by 16, 12, 8 and 7 in every quarter-round.
- **Salsa20** rotates left by 7, 9, 13 and 18.
- **BLAKE2** inherits ChaCha's rotation structure.

Designs that write their rotations to the right — **SHA-256** and **Speck**
among them — use the sibling step, rotate bits right.

## Word-size guidance

The word size sets how wide the "circle" of bits is — a rotation wraps within
one word, so it depends on the width the cipher uses:

| \`wordBits\` | Used by |
|---|---|
| 8  | Per-byte rotation; rare, occasionally in S-box construction. |
| 16 | Speck32/64. |
| 32 | ChaCha20, Salsa20, BLAKE2s. |
| 64 | BLAKE2b. |`,
  params: new Map([
    [
      "bits",
      "How many bit positions to rotate left. A whole number (0 or more); a rotation by the full word width brings you back to the start.",
    ],
    [
      "wordBits",
      "The width of each word, in bits: 8, 16, 32, or 64. The rotation wraps around within one word of this size.",
    ],
  ]),
  references: [
    "RFC 8439 §2.1 (ChaCha20 quarter round)",
    "Bernstein 2008, 'ChaCha, a variant of Salsa20'",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
