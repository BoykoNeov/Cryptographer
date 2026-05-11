import type { AuxValue, Json, StepDocumentation, StepExecutor } from "../core/types";

/**
 * AES key expansion. FIPS-197 §5.2.
 *
 * Reads a 16-, 24-, or 32-byte key from aux (AES-128 / 192 / 256), writes
 * Nr+1 round keys (each Uint8Array(16)) to aux as `${outputPrefix}.0` …
 * `${outputPrefix}.Nr`. State is unchanged; the work product lives entirely
 * in aux.
 *
 * Nk (32-bit words in the key) is derived from the actual key length: 4 / 6 / 8
 * for AES-128 / 192 / 256. The standard relation Nr = Nk + 6 is asserted so a
 * mismatched spec (e.g. a 24-byte key paired with rounds=10) throws an explicit
 * error instead of silently deriving garbage round keys.
 *
 * AES-256 adds one extra subtlety: when Nk > 6, every word at index `i` where
 * `i % Nk === 4` passes through SubWord (forward S-box) WITHOUT RotWord and
 * WITHOUT an Rcon XOR. The branch only fires for Nk=8; AES-128 and AES-192
 * are unaffected.
 *
 * params: {
 *   keyAuxName: string,        // e.g. "key"
 *   outputPrefix: string,      // e.g. "roundKey"
 *   sbox: number[256],         // forward S-box used for SubWord
 *   rcon: number[],            // Rcon[i/Nk]; index 0 unused, 1..max(i/Nk)
 *   rounds: number,            // 10 / 12 / 14 for AES-128 / 192 / 256
 * }
 */
export const keyExpansion: StepExecutor = (state, params, ctx) => {
  const p = readParams(params);
  const key = ctx.aux.get(p.keyAuxName);
  if (
    !(key instanceof Uint8Array) ||
    (key.length !== 16 && key.length !== 24 && key.length !== 32)
  ) {
    throw new Error(`aux '${p.keyAuxName}' must be a 16-, 24-, or 32-byte Uint8Array`);
  }

  // Derive Nk from the key bytes themselves (the runtime gives us whatever the
  // user provided), then double-check against the spec-declared `rounds`.
  // Mismatched (key length, rounds) would silently produce wrong-shaped round
  // keys without this assertion.
  const Nk = key.length / 4; // 4, 6, or 8
  const Nb = 4; // AES block size in 32-bit words (always 16 bytes)
  if (p.rounds !== Nk + 6) {
    throw new Error(
      `rounds (${p.rounds}) must equal Nk+6 (${Nk + 6}) for a ${key.length}-byte key`,
    );
  }
  const totalWords = Nb * (p.rounds + 1);

  // Expanded key as words; each word is a Uint8Array(4).
  const w: Uint8Array[] = new Array(totalWords);
  for (let i = 0; i < Nk; i++) {
    w[i] = new Uint8Array([
      key[4 * i] ?? 0,
      key[4 * i + 1] ?? 0,
      key[4 * i + 2] ?? 0,
      key[4 * i + 3] ?? 0,
    ]);
  }

  for (let i = Nk; i < totalWords; i++) {
    let temp: Uint8Array = new Uint8Array(w[i - 1] as Uint8Array);
    if (i % Nk === 0) {
      temp = subWord(rotWord(temp), p.sbox);
      const rc = p.rcon[i / Nk] ?? 0;
      temp[0] = (temp[0] ?? 0) ^ rc;
    } else if (Nk > 6 && i % Nk === 4) {
      // AES-256-only branch (FIPS-197 §5.2): extra SubWord pass at the
      // mid-word position with no RotWord and no Rcon XOR. Fires solely
      // for Nk=8 — never reached for AES-128 or AES-192.
      temp = subWord(temp, p.sbox);
    }
    const prev = w[i - Nk] as Uint8Array;
    w[i] = new Uint8Array([
      (prev[0] ?? 0) ^ (temp[0] ?? 0),
      (prev[1] ?? 0) ^ (temp[1] ?? 0),
      (prev[2] ?? 0) ^ (temp[2] ?? 0),
      (prev[3] ?? 0) ^ (temp[3] ?? 0),
    ]);
  }

  // Pack words into 16-byte round keys.
  const auxWrites = new Map<string, AuxValue>();
  for (let r = 0; r <= p.rounds; r++) {
    const rk = new Uint8Array(16);
    for (let word = 0; word < 4; word++) {
      const src = w[r * 4 + word] as Uint8Array;
      rk[word * 4 + 0] = src[0] ?? 0;
      rk[word * 4 + 1] = src[1] ?? 0;
      rk[word * 4 + 2] = src[2] ?? 0;
      rk[word * 4 + 3] = src[3] ?? 0;
    }
    auxWrites.set(`${p.outputPrefix}.${r}`, rk);
  }

  return { state, auxReads: [p.keyAuxName], auxWrites };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const keyExpansionDoc: StepDocumentation = {
  name: "Key Expansion",
  summary: "Derive Nr+1 round keys (each 16 bytes) from the cipher key.",
  detail: `## Key Expansion (AES)

The cipher key is expanded into **Nr+1 round keys** of 16 bytes each — one
for the initial AddRoundKey, plus one per round. The number of rounds depends
on the key size:

| Variant  | Key bytes | Nk (words) | Rounds (Nr) | Round keys |
|----------|-----------|------------|-------------|------------|
| AES-128  | 16        | 4          | 10          | 11         |
| AES-192  | 24        | 6          | 12          | 13         |
| AES-256  | 32        | 8          | 14          | 15         |

Round keys are written to aux as \`roundKey.0\` through \`roundKey.Nr\`. The
state itself is unchanged by this step; the work product lives entirely in
the aux map.

The expansion is iterative. For most word indices \`i\`, the new word is
\`w[i] = w[i-Nk] XOR w[i-1]\`. Every Nk-th word receives extra processing:

1. **RotWord** — cyclic byte rotation of the previous word
2. **SubWord** — apply the (forward) S-box to each byte
3. **XOR with Rcon[i/Nk]** — round constant, defined as \`x^(i-1)\` in GF(2^8)

**AES-256 has one extra wrinkle.** When \`Nk > 6\`, every word at \`i % Nk == 4\`
gets an extra **SubWord** pass — no RotWord, no Rcon. This branch fires only
for AES-256; AES-128 and AES-192 are unaffected.

This guarantees the round keys differ from each other in nontrivial ways
even when the original key has structure (e.g. all zeros).

**Notable detail:** key expansion uses the **forward** S-box even when
we're decrypting. The inverse cipher consumes the same round keys in
reverse order, but it does *not* re-derive them with the inverse S-box.
That's why our forward and decryption specs share this step verbatim
across all three key sizes.`,
  params: new Map([
    [
      "keyAuxName",
      "Name of the aux entry containing the input cipher key. Length must be 16, 24, or 32 bytes (AES-128 / 192 / 256).",
    ],
    [
      "outputPrefix",
      'Prefix for the round-key aux entries. With prefix "roundKey", outputs are roundKey.0 … roundKey.Nr.',
    ],
    [
      "sbox",
      "Forward S-box used by the SubWord sub-step. Always the forward AES S-box, even when decrypting.",
    ],
    [
      "rcon",
      "Round-constant table. Index 0 is unused; indices 1..rounds carry the round constants.",
    ],
    [
      "rounds",
      "Number of cipher rounds: 10 (AES-128), 12 (AES-192), or 14 (AES-256). Must equal Nk+6.",
    ],
  ]),
  references: [
    "FIPS-197 §5.2 (Key Expansion)",
    "FIPS-197 Appendix A.1 (AES-128 example)",
    "FIPS-197 Appendix A.2 (AES-192 example)",
    "FIPS-197 Appendix A.3 (AES-256 example, illustrates the Nk>6 SubWord branch)",
  ],
};

const rotWord = (w: Uint8Array): Uint8Array =>
  new Uint8Array([w[1] ?? 0, w[2] ?? 0, w[3] ?? 0, w[0] ?? 0]);

const subWord = (w: Uint8Array, sbox: readonly number[]): Uint8Array =>
  new Uint8Array([
    sbox[w[0] ?? 0] ?? 0,
    sbox[w[1] ?? 0] ?? 0,
    sbox[w[2] ?? 0] ?? 0,
    sbox[w[3] ?? 0] ?? 0,
  ]);

type Params = {
  keyAuxName: string;
  outputPrefix: string;
  sbox: readonly number[];
  rcon: readonly number[];
  rounds: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("key-expansion requires object params");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.keyAuxName !== "string") throw new Error("keyAuxName must be string");
  if (typeof p.outputPrefix !== "string") throw new Error("outputPrefix must be string");
  if (!Array.isArray(p.sbox) || p.sbox.length !== 256) {
    throw new Error("sbox must be 256 numbers");
  }
  if (!Array.isArray(p.rcon)) throw new Error("rcon must be array");
  if (typeof p.rounds !== "number") throw new Error("rounds must be number");
  return {
    keyAuxName: p.keyAuxName,
    outputPrefix: p.outputPrefix,
    sbox: p.sbox as readonly number[],
    rcon: p.rcon as readonly number[],
    rounds: p.rounds,
  };
};
