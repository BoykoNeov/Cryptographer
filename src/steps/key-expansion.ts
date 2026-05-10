import type { AuxValue, Json, StepDocumentation, StepExecutor } from "../core/types";

/**
 * AES-128 key expansion. FIPS-197 §5.2.
 *
 * Reads a 16-byte key from aux, writes 11 round keys (each Uint8Array(16))
 * to aux as `${outputPrefix}.0` … `${outputPrefix}.10`. State is unchanged;
 * the work product lives entirely in aux.
 *
 * params: {
 *   keyAuxName: string,        // e.g. "key"
 *   outputPrefix: string,      // e.g. "roundKey"
 *   sbox: number[256],         // S-box used for SubWord
 *   rcon: number[],            // Rcon[i/Nk]; index 0 unused, 1..10 for AES-128
 *   rounds: number,            // number of rounds (10 for AES-128)
 * }
 */
export const keyExpansion: StepExecutor = (state, params, ctx) => {
  const p = readParams(params);
  const key = ctx.aux.get(p.keyAuxName);
  if (!(key instanceof Uint8Array) || key.length !== 16) {
    throw new Error(`aux '${p.keyAuxName}' must be a 16-byte Uint8Array`);
  }

  const Nk = 4; // 32-bit words in the key
  const Nb = 4; // block size in 32-bit words
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
  summary: "Derive 11 round keys (176 bytes total) from the 16-byte cipher key.",
  detail: `## Key Expansion (AES-128)

The 16-byte cipher key is expanded into **11 round keys** of 16 bytes
each — one for the initial AddRoundKey, plus one per round (10 for AES-128).
Total output: 176 bytes, written to aux as \`roundKey.0\` through
\`roundKey.10\`. The state itself is unchanged by this step; the work
product lives entirely in the aux map.

The expansion is iterative. For most word indices \`i\`, the new word is
\`w[i] = w[i-4] XOR w[i-1]\`. Every fourth word receives extra processing:

1. **RotWord** — cyclic byte rotation of the previous word
2. **SubWord** — apply the (forward) S-box to each byte
3. **XOR with Rcon[i/4]** — round constant, defined as \`x^(i-1)\` in GF(2^8)

This guarantees the round keys differ from each other in nontrivial ways
even when the original key has structure (e.g. all zeros).

**Notable detail:** key expansion uses the **forward** S-box even when
we're decrypting. The inverse cipher consumes the same round keys in
reverse order, but it does *not* re-derive them with the inverse S-box.
That's why our forward and decryption specs share this step verbatim.`,
  params: new Map([
    ["keyAuxName", "Name of the aux entry containing the input cipher key (16 bytes for AES-128)."],
    [
      "outputPrefix",
      'Prefix for the round-key aux entries. With prefix "roundKey", outputs are roundKey.0 … roundKey.10.',
    ],
    [
      "sbox",
      "Forward S-box used by the SubWord sub-step. Always the forward AES S-box, even when decrypting.",
    ],
    [
      "rcon",
      "Round-constant table. Index 0 is unused; indices 1..rounds carry the round constants.",
    ],
    ["rounds", "Number of cipher rounds. AES-128 uses 10."],
  ]),
  references: ["FIPS-197 §5.2 (Key Expansion)", "FIPS-197 Appendix A.1 (AES-128 example)"],
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
