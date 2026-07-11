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

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";
import {
  type SpeckByteOrder,
  decodeBlock,
  decodeWord,
  encodeBlock,
  readByteOrder,
} from "./speck-word-codec";

// Port-native executor (scaffolding-suppression Phase B, slice B2, 2026-05-30).
// Consumes and emits ONLY `Uint8Array` — no `State` wrapper, no lift adapter.
//   - `state`    — the carried 2-word block, projected by the runtime from the
//                  threaded state onto this port via `meta.stateInputPort`
//                  (the Speck spec is a flat pipeline; no `portInputs` wiring).
//   - `roundKey` — this round's key word, projected by the runtime from
//                  `aux[params.roundKeyAux]` via `meta.auxReadPorts` (the
//                  still-lifted `speck.key-schedule@1` writes those aux values).
// Returns the new block on the `state` output port; the runtime reconstructs
// the threaded `BytesState` from it via `meta.stateOutputPort`.
export const speckRound: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  const stateBytes = inputs.get("state");
  if (stateBytes === undefined) {
    throw new Error(
      "speck.round: 'state' input port is not wired (the runtime projects the carried block onto it via meta.stateInputPort)",
    );
  }
  const expectedBytes = 2 * (p.wordBits / 8);
  if (stateBytes.length !== expectedBytes) {
    throw new Error(
      `speck.round: block must be ${expectedBytes} bytes for wordBits=${p.wordBits}; got ${stateBytes.length}`,
    );
  }

  const rkBytes = inputs.get("roundKey");
  if (!(rkBytes instanceof Uint8Array) || rkBytes.length !== p.wordBits / 8) {
    throw new Error(
      `speck.round: 'roundKey' port must carry a ${p.wordBits / 8}-byte word (projected from aux['${p.roundKeyAux}'] via meta.auxReadPorts)`,
    );
  }
  const k = decodeWord(rkBytes, 0, p.wordBits, p.byteOrder);

  const [x0, y0] = decodeBlock(stateBytes, p.wordBits, p.byteOrder);
  const mask = wordMask(p.wordBits);
  const xNew = ((ror(x0, p.alpha, p.wordBits) + y0) & mask) ^ k;
  const yNew = rol(y0, p.beta, p.wordBits) ^ xNew;

  const out = encodeBlock(p.wordBits, p.byteOrder, xNew & mask, yNew & mask);
  return new Map([["state", out]]);
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

**Byte order.** The block and round-key bytes are read according to the
\`byteOrder\` setting — Speck has two published conventions (the original
paper's and the NSA's), which differ only in how the words are laid out as
bytes.

**Reference test vector (Speck32/64, BE-paper):** Key
\`1918111009080100\`, plaintext \`6574694c\`, ciphertext \`a86842f2\`
after 22 rounds.`,
  params: new Map([
    [
      "roundKeyAux",
      "The name of the slot holding this round's key word (e.g. roundKey.0) — one word per round.",
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

// ─── Universal port-dataflow metadata (port-native since slice B2) ──────
// State-bearing ARX round. The metadata is unchanged from the Slice 1.6
// lift — only the executor above went native (B2) — because the runtime's
// projection (`runtime.ts` Steps B/C) drives a native ported step the same
// way it drove the lift adapter: `stateInputPort`/`stateOutputPort` thread
// the carried block, `auxReadPorts` projects `aux[roundKeyAux]` onto the
// `roundKey` input port. Reads a single round-key word (a Uint8Array of
// `wordBits/8` bytes, byte-encoded per `byteOrder`) and transforms a 2-word
// `bytes`-shape state into a new 2-word block.
//
// **`stateLayout: "bytes"`** — Speck blocks are flat byte arrays (4 bytes
// for Speck32/64, 8 for Speck64/128, …). The runtime's `bytes`-layout
// state projection is identity, so the executor sees the block bytes
// directly on the `state` port.
//
// **byteLength absent on state + aux-read ports** — Speck variants vary
// the block size (`2 * wordBits / 8`) and the round-key size
// (`wordBits / 8`). Polymorphic byteLength (Slice 1.2 user pick) keeps
// the contract honest across variants without baking Speck32/64's
// specific numbers in. Same reasoning Slice 1.4 applied to AES
// key-expansion's `masterKey` port.
//
// **Aux read binding `roundKey`** — a per-leaf binding to whatever
// `params.roundKeyAux` names (e.g. `roundKey.5` for the 6th round).
// Function form because every leaf names a different round-key entry;
// the binding can only be resolved with `params` in hand. The runtime
// records it in `frame.auxRead`, preserving the key-schedule → round
// fan-out edge in the graph.

export const speckRoundMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  auxReadPorts: (params: Json) => {
    const { roundKeyAux } = readParams(params);
    return new Map([["roundKey", roundKeyAux]]);
  },
};

export const speckRoundPortContract: PortContract = {
  // byteLength absent on both state and aux ports — polymorphic across
  // Speck variants. layout "raw" on the aux input → the live aux value
  // is already a Uint8Array (written by speck.key-schedule); decode is
  // identity. The state ports carry the flat `bytes` shape.
  inputs: new Map([
    ["state", { layout: "raw" }],
    ["roundKey", { layout: "raw" }],
  ]),
  outputs: new Map([["state", { layout: "raw" }]]),
};
