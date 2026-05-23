/**
 * Serpent SubBytes — apply a 4-bit S-box to each of the 32 consecutive
 * nibbles of the 128-bit state.
 *
 * The 128-bit state has 32 nibbles when viewed as a bit-stream (LSB-first
 * within bytes): the low nibble of byte 0, then the high nibble of byte 0,
 * then the low nibble of byte 1, and so on. Nibble `i` lives at bit
 * positions `4i, 4i+1, 4i+2, 4i+3` of the state, with bit `4i` as its LSB.
 *
 * This is the "standard form" S-box layer (paired with the explicit IP at
 * the start of the cipher). The equivalent "bitslice form" applies the
 * S-box COLUMN-WISE across four 32-bit words and produces the same final
 * ciphertext WITHOUT needing IP/FP — but mixing the two forms (IP'd state
 * + column-wise S-box, or non-IP'd state + per-nibble S-box) gives garbage.
 *
 * Each Serpent round uses one of 8 different S-boxes. Round `i` (0-indexed)
 * uses `S_{i mod 8}` for forward encryption. The inverse cipher uses the
 * inverse table. Same executor for both directions — only the S-box param
 * differs at the leaf level.
 */

import type {
  BytesState,
  Json,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

export const serpentSubBytes: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("serpent.sub-bytes expects bytes state");
  }
  if (state.bytes.length !== 16) {
    throw new Error(`serpent.sub-bytes expects 16-byte state; got ${state.bytes.length} bytes`);
  }
  const sbox = readSbox(params);

  // Process each byte as two nibbles. Low nibble first (lower bit positions),
  // then high nibble — matching the LSB-first bitstream view.
  const next = new Uint8Array(16);
  for (let b = 0; b < 16; b++) {
    const input = state.bytes[b] ?? 0;
    const loIn = input & 0x0f;
    const hiIn = (input >> 4) & 0x0f;
    const loOut = sbox[loIn] ?? 0;
    const hiOut = sbox[hiIn] ?? 0;
    next[b] = (loOut & 0x0f) | ((hiOut & 0x0f) << 4);
  }

  const result: BytesState = { shape: "bytes", bytes: next };
  return { state: result };
};

export const serpentSubBytesDoc: StepDocumentation = {
  name: "SubBytes (Serpent)",
  summary: "Apply a 4-bit S-box to each of the 32 consecutive nibbles of the state.",
  detail: `## SubBytes (Serpent, standard form)

Serpent uses **eight** different 4-bit-to-4-bit S-boxes — \`S_0\` through
\`S_7\` — cycled across the rounds. Round \`i\` (0-indexed) uses
\`S_{i mod 8}\` for forward encryption. The inverse cipher uses the inverse
tables in reverse round order.

The 128-bit state is viewed as **32 consecutive 4-bit nibbles** (bitstream
LSB-first within bytes):

\`\`\`
nibble 0  = low nibble of byte 0     (bits 0..3)
nibble 1  = high nibble of byte 0    (bits 4..7)
nibble 2  = low nibble of byte 1     (bits 8..11)
nibble 3  = high nibble of byte 1    (bits 12..15)
...
nibble 31 = high nibble of byte 15   (bits 124..127)
\`\`\`

Each nibble is replaced independently with \`sbox[nibble]\`.

**Why eight S-boxes, not one?** Serpent's designers deliberately chose
distinct S-boxes per round-group as a defense against differential
attacks: a differential trail exploiting a property of one S-box can't
simply repeat across all 32 rounds.

**The IP makes this work.** Without the Initial Permutation, applying the
S-box "per consecutive nibble" would mix together bits that have no
algebraic reason to belong together. IP rearranges the bits of the
plaintext so that the right groups of 4 end up adjacent — bits that the
designers actually wanted the S-box to mix together. The exact equivalent
operation in the un-permuted "bitslice" domain is to apply the same
S-box **column-wise** across the four 32-bit words. Both forms compute
the same final ciphertext.

**Inverse.** The same executor is used for both directions; only the
\`sbox\` param changes (forward S-box for encrypt, inverse table for
decrypt).

**Editable per-leaf.** Each round's leaf carries its own copy of the
S-box table. The spec builder deep-copies the table per leaf so editing
one round's S-box doesn't bleed into any other.`,
  params: new Map([
    [
      "sbox",
      "16-entry 4-bit S-box: an array of 16 integers in 0..15 forming a permutation of {0,…,15}.",
    ],
    [
      "sboxIndex",
      "Display-only annotation: which of the 8 S-boxes this is (0..7). The executor ignores this; the param editor and trace renderer use it for context.",
    ],
  ]),
  references: [
    "Anderson, Biham, Knudsen 1998, §2 (Round function), Appendix (S-box tables)",
    "Serpent NIST submission, tstsubmtl/serpref.c (SHat() function)",
  ],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.7) ───────────────
// Pure bytes→bytes 16-byte fixed transform with no aux. The S-box table
// is per-leaf params (each round's leaf carries its own copy of the
// per-round S-box S_{i mod 8}), but the per-leaf table doesn't change
// the port surface — same shape as `serpent.bit-permutation@1`. The
// `sboxIndex` param is display-only; the executor ignores it.

export const serpentSubBytesMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

export const serpentSubBytesPortContract: PortContract = {
  inputs: new Map([["state", { byteLength: 16, layout: "raw" }]]),
  outputs: new Map([["state", { byteLength: 16, layout: "raw" }]]),
};

const readSbox = (params: Json): readonly number[] => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("serpent.sub-bytes requires params.sbox");
  }
  const p = params as { sbox?: unknown };
  if (!Array.isArray(p.sbox) || p.sbox.length !== 16) {
    throw new Error("serpent.sub-bytes: sbox must be a 16-entry array");
  }
  return p.sbox as readonly number[];
};
