/**
 * Speck round function — one ARX round of the forward cipher.
 *
 *     x ← (ROR(x, alpha) + y) mod 2^n
 *     x ← x XOR k_i
 *     y ← ROL(y, beta)
 *     y ← y XOR x
 *
 * Reads the round-key word from `aux[roundKeyAux]` (one word, byte-encoded
 * per the spec's `byteOrder`). Reads the state as a two-word block via
 * the codec, applies the ARX round, encodes the new state back to bytes.
 *
 * The same step file ships a sibling inverse (`speck-round-inverse.ts`).
 * Splitting forward and inverse into separate types mirrors how byte-substitution
 * params point at forward vs. inverse S-boxes for AES — keeping the math
 * direction visible at the step level.
 *
 * Generic across Speck variants. Speck32/64 plugs in `wordBits=16, alpha=7,
 * beta=2`; Speck64/128 would set `wordBits=32, alpha=8, beta=3`; etc.
 */

import type { BytesState, Json, StepDocumentation, StepExecutor } from "../core/types";
import {
  type SpeckByteOrder,
  decodeBlock,
  decodeWord,
  encodeBlock,
  readByteOrder,
} from "./speck-word-codec";

export const speckRound: StepExecutor = (state, params, ctx) => {
  if (state.shape !== "bytes") {
    throw new Error("speck.round expects bytes state");
  }
  const p = readParams(params);
  const expectedBytes = 2 * (p.wordBits / 8);
  if (state.bytes.length !== expectedBytes) {
    throw new Error(
      `speck.round: block must be ${expectedBytes} bytes for wordBits=${p.wordBits}; got ${state.bytes.length}`,
    );
  }

  const rkBytes = ctx.aux.get(p.roundKeyAux);
  if (!(rkBytes instanceof Uint8Array) || rkBytes.length !== p.wordBits / 8) {
    throw new Error(
      `speck.round: aux '${p.roundKeyAux}' must be a ${p.wordBits / 8}-byte Uint8Array`,
    );
  }
  const k = decodeWord(rkBytes, 0, p.wordBits, p.byteOrder);

  const [x0, y0] = decodeBlock(state.bytes, p.wordBits, p.byteOrder);
  const mask = wordMask(p.wordBits);
  const xNew = ((ror(x0, p.alpha, p.wordBits) + y0) & mask) ^ k;
  const yNew = rol(y0, p.beta, p.wordBits) ^ xNew;

  const out = encodeBlock(p.wordBits, p.byteOrder, xNew & mask, yNew & mask);
  const next: BytesState = { shape: "bytes", bytes: out };
  return { state: next, auxReads: [p.roundKeyAux] };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const speckRoundDoc: StepDocumentation = {
  name: "Speck Round",
  summary: "One ARX round: `x ← (ROR(x,α)+y) ⊕ k_i`, then `y ← ROL(y,β) ⊕ x`.",
  detail: `## Speck Round Function

Each Speck round is built from three operations — **modular addition,
rotation, and XOR** — collectively known as ARX. There is no S-box, no
Galois-field math, no large lookup tables; the entire cipher's
non-linearity comes from the carry chain in the modular addition.

Given the two-word block \`(x, y)\` and round key \`k_i\`:

\`\`\`
x  ←  (ROR(x, alpha) + y)  mod 2^n
x  ←  x  XOR  k_i
y  ←  ROL(y, beta)
y  ←  y  XOR  x
\`\`\`

\`n\` is the word width (16 for Speck32/64, 32 for Speck64/128, …). The
two rotation amounts \`(alpha, beta)\` are cipher-defining constants:
\`(7, 2)\` for Speck32/64 and \`(8, 3)\` for all larger variants.

**Why this is interesting pedagogically.** The round looks almost
Feistel-like — y feeds back into x via the addition, and x feeds into y
via the trailing XOR — but it isn't strictly a Feistel network. The
addition is the source of non-linearity (the carry bits propagate in a
key-dependent way), and the rotation prevents alignment attacks. With
those three primitives Speck achieves the same security goals as AES,
in roughly a quarter of the gate count.

**Byte order.** Plain state bytes and round-key bytes are interpreted
per the step's \`byteOrder\` param. Both BE-paper and LE-NSA conventions
share this same executor; only the codec at the boundary differs.

**Reference test vector (Speck32/64, BE-paper):** Key
\`1918111009080100\`, plaintext \`6574694c\`, ciphertext \`a86842f2\`
after 22 rounds.`,
  params: new Map([
    [
      "roundKeyAux",
      "Name of the aux entry holding this round's key word (e.g. roundKey.0). One word per round.",
    ],
    ["alpha", "Right-rotation amount on x. Speck32/64 = 7; Speck64/128 and above = 8."],
    ["beta", "Left-rotation amount on y. Speck32/64 = 2; Speck64/128 and above = 3."],
    ["wordBits", "Word width in bits. Speck32/64 = 16. The total block is 2*wordBits."],
    ["byteOrder", "Byte serialization convention: 'be-paper' or 'le-nsa'."],
  ]),
  references: [
    "Beaulieu et al. 2013, 'The SIMON and SPECK Families of Lightweight Block Ciphers', §3 (Speck Round Function)",
  ],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Helpers (duplicated from key-schedule deliberately — see note) ───────
// The same wordMask/rol/ror helpers exist in speck-key-schedule.ts. Keeping
// them per-file rather than centralising avoids a "speck-arithmetic.ts"
// utility module that would just be three trivial one-liners. Both copies
// are bit-identical and tested through the KAT.

const wordMask = (bits: number): number => (bits === 32 ? 0xffffffff : (1 << bits) - 1);

const rol = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  return ((xm << n) | (xm >>> (bits - n))) & mask;
};

const ror = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  return ((xm >>> n) | (xm << (bits - n))) & mask;
};

type Params = {
  roundKeyAux: string;
  alpha: number;
  beta: number;
  wordBits: number;
  byteOrder: SpeckByteOrder;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("speck.round requires object params");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.roundKeyAux !== "string") throw new Error("speck.round: roundKeyAux must be string");
  for (const k of ["alpha", "beta", "wordBits"] as const) {
    const v = p[k];
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1) {
      throw new Error(`speck.round: ${k} must be a positive integer`);
    }
  }
  return {
    roundKeyAux: p.roundKeyAux,
    alpha: p.alpha as number,
    beta: p.beta as number,
    wordBits: p.wordBits as number,
    byteOrder: readByteOrder(params, "speck.round"),
  };
};
