/**
 * Speck key schedule. Beaulieu et al. 2013 §3.
 *
 * Given an `m`-word master key `K = (l_{m-2}, l_{m-3}, …, l_0, k_0)`,
 * produces a sequence of `rounds` round-key words by iterating:
 *
 *     l_{i+m-1} = (k_i + ROR(l_i, alpha)) XOR i
 *     k_{i+1}   = ROL(k_i, beta) XOR l_{i+m-1}
 *
 * for `i = 0 … rounds-2`. The `k_i` sequence is the round-key stream
 * consumed by the round function. Note the key schedule shares the SAME
 * ARX kernel as the round function — that's the cipher's defining
 * elegance, and a major contrast with AES's S-box-driven schedule.
 *
 * The runtime aux map carries each round-key word as a `Uint8Array` of
 * length `wordBits/8`, byte-encoded per the spec's `byteOrder` so the
 * round step decodes it consistently. State is unchanged by this step;
 * the work product lives entirely in aux, just like AES key expansion.
 *
 * For Speck32/64: wordBits=16, m=4, rounds=22, alpha=7, beta=2. Larger
 * Speck variants tune these constants; the executor itself is generic.
 */

import type { AuxValue, Json, StepDocumentation, StepExecutor } from "../core/types";
import { type SpeckByteOrder, decodeKey, encodeWord, readByteOrder } from "./speck-word-codec";

export const speckKeySchedule: StepExecutor = (state, params, ctx) => {
  const p = readParams(params);
  const key = ctx.aux.get(p.keyAuxName);
  if (!(key instanceof Uint8Array)) {
    throw new Error(`speck.key-schedule: aux '${p.keyAuxName}' must be a Uint8Array`);
  }
  const expectedBytes = p.m * (p.wordBits / 8);
  if (key.length !== expectedBytes) {
    throw new Error(
      `speck.key-schedule: key must be ${expectedBytes} bytes for m=${p.m}, wordBits=${p.wordBits}; got ${key.length}`,
    );
  }

  // Decode the master key into m logical words `[k_0, l_0, …, l_{m-2}]`.
  // The codec absorbs byteOrder so the rest of the executor is convention-
  // agnostic.
  const logical = decodeKey(key, p.m, p.wordBits, p.byteOrder);
  const k = new Array<number>(p.rounds);
  // `l` indices 0..rounds+m-2 (we'll only write up to rounds+m-3, but
  // sizing for clarity).
  const l = new Array<number>(p.rounds + p.m - 1);
  k[0] = logical[0] ?? 0;
  for (let j = 0; j < p.m - 1; j++) {
    l[j] = logical[j + 1] ?? 0;
  }

  // Iterate the schedule. ROR/ROL operate on wordBits-wide values; we
  // mask back into range after each modular addition to keep JS's 32-bit
  // bitwise math from poisoning subsequent rotations.
  const mask = wordMask(p.wordBits);
  for (let i = 0; i < p.rounds - 1; i++) {
    const ki = k[i] ?? 0;
    const li = l[i] ?? 0;
    const rotLi = ror(li, p.alpha, p.wordBits);
    const newL = (((ki + rotLi) & mask) ^ i) & mask;
    l[i + p.m - 1] = newL;
    k[i + 1] = (rol(ki, p.beta, p.wordBits) ^ newL) & mask;
  }

  // Serialize the round keys back to bytes per the same byteOrder so the
  // round step decodes them as single words via decodeWord(.., 0, ..).
  const auxWrites = new Map<string, AuxValue>();
  const wb = p.wordBits / 8;
  for (let i = 0; i < p.rounds; i++) {
    const buf = new Uint8Array(wb);
    encodeWord(buf, 0, p.wordBits, p.byteOrder, k[i] ?? 0);
    auxWrites.set(`${p.outputPrefix}.${i}`, buf);
  }

  return { state, auxReads: [p.keyAuxName], auxWrites };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const speckKeyScheduleDoc: StepDocumentation = {
  name: "Speck Key Schedule",
  summary:
    "Derive `rounds` round-key words from the m-word master key using the cipher's own ARX kernel.",
  detail: `## Speck Key Schedule

The Speck key schedule reuses the cipher's own round function on the master
key, with the round counter \`i\` injected as the "constant" XOR. That's the
cipher's defining elegance — a single ARX kernel does double duty for both
encryption and key expansion, in stark contrast to AES which has an entirely
separate \`SubWord/RotWord/Rcon\` schedule.

**Master key.** \`m\` words wide: \`K = (l_{m-2}, l_{m-3}, …, l_0, k_0)\`.
For Speck32/64, \`m = 4\`.

**Iteration.** For \`i = 0, 1, …, rounds-2\`:

\`\`\`
l_{i+m-1}  =  (k_i + ROR(l_i, alpha)) XOR i
k_{i+1}    =  ROL(k_i, beta) XOR l_{i+m-1}
\`\`\`

The output is the sequence \`k_0, k_1, …, k_{rounds-1}\` — one round-key
word per round, stored in aux as \`outputPrefix.0\` … \`outputPrefix.rounds-1\`.

**Byte order.** The master key bytes and round-key bytes are encoded per
the step's \`byteOrder\` param. Two conventions are common:

- **BE-paper** — bytes left-to-right are the words \`(l_{m-2}, …, l_0, k_0)\`,
  each big-endian. Matches the visual display in the Beaulieu et al. paper.
- **LE-NSA**  — bytes left-to-right are \`(k_0, l_0, …, l_{m-2})\`, each
  little-endian. Matches the NSA reference C and SUPERCOP.

Both conventions compute the IDENTICAL word-level schedule; only the
serialization at the boundary differs.

**Speck32/64 constants** (verified against Beaulieu et al. Table 4.1):
\`wordBits = 16, m = 4, rounds = 22, alpha = 7, beta = 2\`.`,
  params: new Map([
    [
      "keyAuxName",
      "Name of the aux entry containing the master-key bytes. Length must be m * (wordBits/8).",
    ],
    [
      "outputPrefix",
      'Prefix for round-key aux entries. With "roundKey", outputs are roundKey.0 … roundKey.rounds-1.',
    ],
    ["rounds", "Number of rounds. Speck32/64 = 22; Speck64/128 = 27; etc."],
    [
      "wordBits",
      "Word width in bits. Speck32/64 = 16. Today only 16-bit words are tested; the executor allows up to 30.",
    ],
    ["m", "Number of words in the master key. Speck32/64 = 4."],
    ["alpha", "Right-rotation amount applied to l_i. Speck32/64 = 7; larger variants = 8."],
    ["beta", "Left-rotation amount applied to k_i. Speck32/64 = 2; larger variants = 3."],
    ["byteOrder", "How master-key and round-key bytes are serialized. 'be-paper' or 'le-nsa'."],
  ]),
  references: [
    "Beaulieu et al. 2013, 'The SIMON and SPECK Families of Lightweight Block Ciphers', §3 (Key Schedule)",
    "Beaulieu et al. 2013, Table 4.1 (Speck32/64 test vector)",
  ],
};

// ─── Helpers ──────────────────────────────────────────────────────────────

// Word-size-parameterized rotations. For wordBits ≤ 30 these stay in JS's
// safe-integer range. Speck32/64 uses 16-bit words, well inside the safe
// zone; larger Speck variants (24/32/48/64-bit words) would need BigInt
// support, deferred.
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
  keyAuxName: string;
  outputPrefix: string;
  rounds: number;
  wordBits: number;
  m: number;
  alpha: number;
  beta: number;
  byteOrder: SpeckByteOrder;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("speck.key-schedule requires object params");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.keyAuxName !== "string")
    throw new Error("speck.key-schedule: keyAuxName must be string");
  if (typeof p.outputPrefix !== "string")
    throw new Error("speck.key-schedule: outputPrefix must be string");
  for (const k of ["rounds", "wordBits", "m", "alpha", "beta"] as const) {
    const v = p[k];
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1) {
      throw new Error(`speck.key-schedule: ${k} must be a positive integer`);
    }
  }
  return {
    keyAuxName: p.keyAuxName,
    outputPrefix: p.outputPrefix,
    rounds: p.rounds as number,
    wordBits: p.wordBits as number,
    m: p.m as number,
    alpha: p.alpha as number,
    beta: p.beta as number,
    byteOrder: readByteOrder(params, "speck.key-schedule"),
  };
};
