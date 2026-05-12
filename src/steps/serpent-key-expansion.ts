/**
 * Serpent key expansion. Anderson/Biham/Knudsen 1998 §2.
 *
 * Generates 33 × 128-bit round keys (K_0 … K_32) from a 128-, 192-, or
 * 256-bit master key. The output is written to aux as `roundKey.0` …
 * `roundKey.32`, each a 16-byte Uint8Array.
 *
 * Algorithm:
 *
 *   1. Pad the master key to 256 bits if shorter. Padding: append a single
 *      "1" bit at the position immediately after the last key bit, then
 *      zeros to fill out to 256 bits. With LSB-first bit numbering inside
 *      each byte, this is just `padded[keyByteLength] = 0x01; rest = 0`.
 *
 *   2. View the padded key as eight 32-bit little-endian words:
 *      `w_{-8}, w_{-7}, …, w_{-1}` (the "prekeys").
 *
 *   3. Generate 132 more prekeys via the recurrence:
 *
 *        w_i = ROL(w_{i-8} XOR w_{i-5} XOR w_{i-3} XOR w_{i-1} XOR phi XOR i, 11)
 *
 *      with `phi = 0x9e3779b9` (fractional part of the golden ratio — the
 *      same Knuth-recommended constant Speck uses in its key schedule and
 *      TEA uses as its "delta" constant).
 *
 *   4. Apply S-boxes bitsliced to groups of four prekey words to produce
 *      33 raw 128-bit round keys. The S-box index for group `i` is
 *      `S_{(35 - i) mod 8}` — the index walks DOWN through the S-box list
 *      and wraps around, which is the trap noted in the plan:
 *
 *        Group 0 (K_0) uses S_3       Group 1 uses S_2
 *        Group 2     uses S_1         Group 3 uses S_0
 *        Group 4     uses S_7         Group 5 uses S_6
 *        ... (continues)
 *
 *   5. Apply IP to each raw round key so that the XOR with the IP'd state
 *      inside the round body aligns naturally. The round body never has
 *      to "permute then XOR then unpermute" — both operands are in the
 *      same permuted domain at all times.
 *
 * The same key schedule runs for both encrypt and decrypt; only the
 * order in which the round keys are consumed in the round body differs
 * (forward order for encrypt, reverse for decrypt).
 */

import { SERPENT_IP, SERPENT_PHI, SERPENT_SBOXES } from "../ciphers/serpent-constants";
import type { AuxValue, Json, StepDocumentation, StepExecutor } from "../core/types";
import {
  applyBitPermutation,
  readWordLE32,
  rotl32,
  sboxBitslice4,
  wordsToBytes4,
} from "./serpent-bit-ops";

export const serpentKeyExpansion: StepExecutor = (state, params, ctx) => {
  const p = readParams(params);
  const key = ctx.aux.get(p.keyAuxName);
  if (!(key instanceof Uint8Array)) {
    throw new Error(`serpent.key-expansion: aux '${p.keyAuxName}' must be a Uint8Array`);
  }
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`serpent.key-expansion: key must be 16, 24, or 32 bytes; got ${key.length}`);
  }
  if (key.length !== p.keyByteLength) {
    throw new Error(
      `serpent.key-expansion: spec declares keyByteLength=${p.keyByteLength} but aux key is ${key.length} bytes`,
    );
  }

  // ─── Step 1: pad to 256 bits / 32 bytes ─────────────────────────────────
  // LSB-first bit numbering within each byte makes this just "set byte at
  // index keyByteLength to 0x01" (which sets bit `8*keyByteLength` to 1).
  // For 32-byte keys, the padding is a no-op.
  const padded = new Uint8Array(32);
  padded.set(key);
  if (key.length < 32) {
    padded[key.length] = 0x01;
  }

  // ─── Step 2: decode as 8 LE 32-bit prekey words w_{-8}..w_{-1} ──────────
  // Stored in `prekey` at indices 0..7. Subsequent prekeys w_0..w_131 fill
  // indices 8..139.
  const TOTAL_PREKEYS = 140;
  const prekey = new Array<number>(TOTAL_PREKEYS);
  for (let j = 0; j < 8; j++) {
    prekey[j] = readWordLE32(padded, j * 4);
  }

  // ─── Step 3: generate w_0..w_131 ───────────────────────────────────────
  // The "+ j" in the XOR uses the round-counter `j` (not the array index)
  // — so j ranges over 0..131. The combined value is rotated left by 11.
  for (let j = 0; j < 132; j++) {
    const idx = j + 8;
    const x =
      (prekey[idx - 8] ?? 0) ^
      (prekey[idx - 5] ?? 0) ^
      (prekey[idx - 3] ?? 0) ^
      (prekey[idx - 1] ?? 0) ^
      SERPENT_PHI ^
      j;
    prekey[idx] = rotl32(x >>> 0, 11);
  }

  // ─── Steps 4 + 5: bitsliced S-box + IP per round key ───────────────────
  const auxWrites = new Map<string, AuxValue>();
  for (let i = 0; i < 33; i++) {
    // S-box index walks down through the table with wraparound: classic
    // off-by-one trap. (35 - i) % 8 for i in 0..32. Equivalently:
    // (32 + 3 - i) % 8.
    const sboxIdx = (((35 - i) % 8) + 8) % 8; // double-mod to handle negative remainders defensively
    const sbox = SERPENT_SBOXES[sboxIdx] ?? [];

    const base = 8 + 4 * i;
    const w0 = prekey[base] ?? 0;
    const w1 = prekey[base + 1] ?? 0;
    const w2 = prekey[base + 2] ?? 0;
    const w3 = prekey[base + 3] ?? 0;
    const [k0, k1, k2, k3] = sboxBitslice4(w0, w1, w2, w3, sbox);

    const rawRoundKey = wordsToBytes4(k0, k1, k2, k3);
    const permutedRoundKey = applyBitPermutation(rawRoundKey, SERPENT_IP);
    auxWrites.set(`${p.outputPrefix}.${i}`, permutedRoundKey);
  }

  return { state, auxReads: [p.keyAuxName], auxWrites };
};

export const serpentKeyExpansionDoc: StepDocumentation = {
  name: "Key Expansion (Serpent)",
  summary: "Derive 33 round keys from the 128/192/256-bit master key.",
  detail: `## Serpent Key Expansion

The master key is expanded into **33 round keys** of 128 bits each. The
Serpent round body uses 32 keys for the per-round AddRoundKey plus one
extra (\`K_32\`) for the final round's second AddRoundKey — hence 33
total, one more than the round count.

### Step 1: Pad to 256 bits

If the master key is shorter than 256 bits, append a single \`1\` bit
immediately after the last key bit, then zeros to fill out to 256 bits.
With LSB-first bit numbering inside each byte, that's just
\`padded[keyByteLength] = 0x01\` and the rest zero. A 256-bit key passes
through unchanged.

### Step 2: Eight prekey words from the padded key

View the 32-byte padded key as eight little-endian 32-bit words:
\`w_{-8}, w_{-7}, …, w_{-1}\`. These are the "prekeys."

### Step 3: Recurrence — 132 more prekey words

\`\`\`
w_i  =  ROL(w_{i-8} XOR w_{i-5} XOR w_{i-3} XOR w_{i-1} XOR phi XOR i, 11)
\`\`\`

for \`i = 0, 1, …, 131\`, where \`phi = 0x9e3779b9\` (fractional part of
the golden ratio — Knuth's recommended "random-looking" constant, also
used by Speck and TEA).

### Step 4: Bitsliced S-boxes produce raw round keys

Group the 132 new prekeys into 33 groups of 4 consecutive words. Apply a
bitsliced 4-bit S-box to each group, producing four output words per
group — the raw 128-bit round key for that group.

The S-box index walks **down** through the S-box list with wraparound:
group \`i\` uses \`S_{(35 - i) mod 8}\`. So group 0 uses \`S_3\`, group 1
uses \`S_2\`, …, group 4 uses \`S_7\`, group 5 uses \`S_6\`, and so on.
This indexing is a classic off-by-one trap.

### Step 5: Apply IP to each round key

The 33 raw round keys are passed through the Initial Permutation. This
makes them line up bit-for-bit with the IP'd state inside the round
body, so the AddRoundKey XOR works on two operands that are both in
the "permuted" domain.

### Why the same schedule for encrypt and decrypt

XOR is its own inverse, so AddRoundKey on encrypt and decrypt uses the
same round keys. The only difference is consumption order: encrypt
consumes \`K_0\` first, decrypt consumes \`K_32\` first.`,
  params: new Map([
    [
      "keyAuxName",
      "Aux entry holding the master key bytes. Length must equal the keyByteLength param.",
    ],
    [
      "outputPrefix",
      'Prefix for the round-key aux entries. With "roundKey", outputs are roundKey.0 … roundKey.32.',
    ],
    [
      "keyByteLength",
      "Expected key length in bytes: 16 (Serpent-128), 24 (Serpent-192), or 32 (Serpent-256). The executor cross-checks this against the actual aux key length.",
    ],
  ]),
  references: [
    "Anderson, Biham, Knudsen 1998, §2 (Key Schedule)",
    "Serpent NIST submission, tstsubmtl/serpref.c (makeKey() function)",
  ],
};

type Params = {
  keyAuxName: string;
  outputPrefix: string;
  keyByteLength: 16 | 24 | 32;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("serpent.key-expansion requires object params");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.keyAuxName !== "string" || p.keyAuxName.length === 0) {
    throw new Error("serpent.key-expansion: keyAuxName must be a non-empty string");
  }
  if (typeof p.outputPrefix !== "string" || p.outputPrefix.length === 0) {
    throw new Error("serpent.key-expansion: outputPrefix must be a non-empty string");
  }
  const klen = p.keyByteLength;
  if (klen !== 16 && klen !== 24 && klen !== 32) {
    throw new Error("serpent.key-expansion: keyByteLength must be 16, 24, or 32");
  }
  return {
    keyAuxName: p.keyAuxName,
    outputPrefix: p.outputPrefix,
    keyByteLength: klen,
  };
};
