/**
 * Byte-native AES round-body construction — scaffolding-suppression Phase B
 * Slices B1.1 (encrypt, 2026-05-29) + B1.2 (decrypt, 2026-05-29).
 *
 * The port-native replacement for `aes-round-builder.ts`. Where the legacy
 * builder threaded a `MatrixState` through `generic.{byte-substitution,
 * shift-rows,mix-columns,add-round-key}@1` (all `layout:"matrix-cm-4x4"`,
 * all on the A4 `NON_BYTES_ALLOWLIST`), this builder composes the round body
 * from byte-native primitives whose ports are all `layout:"raw"`:
 *
 *   SubBytes      → byte-substitute@1   (params.sbox)
 *   ShiftRows     → permute@1           (params.indices, column-major)
 *   MixColumns    → gf-matrix-multiply@1 (params.matrix)
 *   AddRoundKey   → aux-load-bytes@1 (roundKey.N) + xor@1 (2-way)
 *
 * Topology mirrors the byte-native SHA-256 spec (`sha-256.ts`): the 16-byte
 * working state carries port-to-port between round groups via the A3b
 * `StepGroup` `seedInput`/`bodyOutput` contract — no `state` thread, no
 * `state-to-bytes`/`bytes-to-state` bridges. The plaintext arrives on the
 * reserved `$input` source (A3a); each round group's `seedInput` reads the
 * previous round's published `out` port; round 1 reads the initial
 * AddRoundKey's xor output. The spec's `outputFrom` reads the final round's
 * `out` port.
 *
 * Round keys live in `aux["roundKey.0..N"]`, written by the untouched
 * monolithic `aes.key-expansion@1` (its forward S-box stays a param — see
 * `byte-substitute.ts` for why B1 does NOT move the S-box to
 * `cipherConstants`). Each AddRoundKey reads its key via `aux-load-bytes@1`
 * — the SHA-256 K/W fetch-then-combine pattern, since each `roundKey.N` has
 * exactly one consumer it would also be valid port-to-port, but key-
 * expansion publishes to aux today and stays untouched in B1.
 *
 * AES-variant agnostic: only the round count differs (10/12/14). The S-box,
 * mix matrix, and shift schedule are identical across variants (FIPS-197 §5).
 *
 * Single-block only (B1 core). ECB/CBC adopt the same body inside an
 * `iterate` with `seedInput`/`outputPorts` in Slice B1.4.
 */

import type { PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import {
  AES_INV_MIX_MATRIX,
  AES_INV_SBOX,
  AES_INV_SHIFT_ROWS,
  AES_MIX_MATRIX,
  AES_SBOX,
  AES_SHIFT_ROWS,
} from "./aes-constants";

const AES_BLOCK_BYTES = 16;

// ─── PortBinding helper ─────────────────────────────────────────────────────

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

// ─── Column-major ShiftRows index derivation (FIPS-197 §3.4 + §5.1.2) ───────
//
// AES state byte index i ↔ (row i mod 4, col ⌊i/4⌋). ShiftRows cyclically
// shifts row r LEFT by shift[r], which on the flat column-major byte array is
// the fixed gather:
//
//   out[r + 4·c] = in[r + 4·((c + shift[r]) mod 4)]
//   ⇒ indices[r + 4·c] = r + 4·((c + shift[r]) mod 4)
//
// Exported so the per-primitive test and any future inverse builder reuse
// exactly the same derivation (no hand-transcribed index array to drift).

export const shiftRowsIndices = (shifts: readonly number[]): number[] => {
  const indices = new Array<number>(AES_BLOCK_BYTES);
  for (let r = 0; r < 4; r++) {
    const shift = shifts[r] ?? 0;
    for (let c = 0; c < 4; c++) {
      indices[r + 4 * c] = r + 4 * ((c + shift) % 4);
    }
  }
  return indices;
};

// ─── narrationOverride docs (AES-specific friendly names + FIPS refs) ───────
//
// One static doc per round operation (the op is identical every round; the
// per-round specifics are the frame's byte values, not the prose). Renders
// as the leaf's name/summary/detail in the inspector, overriding the generic
// port-native primitive doc — same mechanism SHA-256's leaves use.

const NARR_SUB_BYTES: StepDocumentation = {
  name: "SubBytes",
  summary: "Substitute every state byte through the AES S-box (FIPS-197 §5.1.1).",
  detail: `## SubBytes

Each of the 16 state bytes \`b\` is replaced by \`sbox[b]\`, the AES S-box —
the non-linear layer. The S-box is the multiplicative inverse in GF(2⁸)
followed by an affine transform over GF(2); it is what gives AES its
resistance to differential and linear cryptanalysis.

Byte-local and position-preserving: the byte at column-major index \`i\` only
depends on the input byte at index \`i\`.`,
  references: ["FIPS-197 §5.1.1 (SubBytes)"],
};

const NARR_SHIFT_ROWS: StepDocumentation = {
  name: "ShiftRows",
  summary: "Cyclically shift state rows left by 0/1/2/3 (FIPS-197 §5.1.2).",
  detail: `## ShiftRows

Row \`r\` of the 4×4 state is cyclically shifted left by \`r\` bytes (row 0
unchanged, row 1 by 1, …). On the flat column-major byte array this is the
fixed permutation \`out[r+4c] = in[r + 4·((c+r) mod 4)]\`.

ShiftRows provides inter-column **diffusion**: it moves each row's bytes into
different columns so the subsequent MixColumns mixes bytes that started in
different columns.`,
  references: ["FIPS-197 §5.1.2 (ShiftRows)"],
};

const NARR_MIX_COLUMNS: StepDocumentation = {
  name: "MixColumns",
  summary: "Mix each column by the AES MDS matrix in GF(2⁸) (FIPS-197 §5.1.3).",
  detail: `## MixColumns

Each 4-byte column is multiplied by the fixed AES matrix over GF(2⁸):

\`\`\`
[2 3 1 1]
[1 2 3 1]
[1 1 2 3]
[3 1 1 2]
\`\`\`

This is intra-column diffusion: changing one input byte changes all four
output bytes of its column. Together with ShiftRows, two rounds achieve full
diffusion across the block. Omitted in the final round (FIPS-197 §5.1).`,
  references: ["FIPS-197 §5.1.3 (MixColumns)", "FIPS-197 §4.2 (GF(2⁸))"],
};

const NARR_FETCH_RK: StepDocumentation = {
  name: "Fetch round key",
  summary: "Read this round's 16-byte round key from aux (key schedule output).",
  detail: `## Fetch round key

Reads the round key \`roundKey.N\` from the aux map — the per-round 16-byte
subkey produced by the key schedule (\`aes.key-expansion@1\`). Exposed on a
port so AddRoundKey can XOR it into the state. Editing the key schedule's
output (or the master key) changes these bytes.`,
  references: ["FIPS-197 §5.2 (Key Expansion)"],
};

const NARR_ADD_ROUND_KEY: StepDocumentation = {
  name: "AddRoundKey",
  summary: "XOR the round key into the state (FIPS-197 §5.1.4).",
  detail: `## AddRoundKey

The state is XORed byte-for-byte with the round key. This is the only step
that depends on the secret key; every other round step is fixed and public.
XOR is its own inverse, which is why decryption re-applies the same round
keys in reverse order.`,
  references: ["FIPS-197 §5.1.4 (AddRoundKey)"],
};

const NARR_INITIAL_ARK: StepDocumentation = {
  name: "Initial AddRoundKey",
  summary: "XOR the plaintext with round key 0 before round 1 (FIPS-197 §5.1).",
  detail: `## Initial AddRoundKey

Before the first full round, the plaintext block is XORed with round key 0
(the master key itself for AES-128). This "whitening" ensures the first
SubBytes operates on key-dependent data.`,
  references: ["FIPS-197 §5.1 (Cipher)"],
};

// ─── Leaf factories ─────────────────────────────────────────────────────────
// Fresh params per call: the spec tree is `readonly`, but downstream mutators
// (editStepParams) replace nodes by id; sharing an `sbox`/`matrix`/`indices`
// array across rounds would let one edit leak into every round.

const subBytesLeaf = (p: string, inputBinding: PortBinding): StepNode => ({
  kind: "step",
  id: `${p}.sub-bytes`,
  type: "byte-substitute@1",
  params: { sbox: [...AES_SBOX] },
  portInputs: { input: inputBinding },
  narrationOverride: NARR_SUB_BYTES,
});

const shiftRowsLeaf = (p: string): StepNode => ({
  kind: "step",
  id: `${p}.shift-rows`,
  type: "permute@1",
  params: { indices: shiftRowsIndices(AES_SHIFT_ROWS) },
  portInputs: { input: port(`${p}.sub-bytes`, "output") },
  narrationOverride: NARR_SHIFT_ROWS,
});

const mixColumnsLeaf = (p: string): StepNode => ({
  kind: "step",
  id: `${p}.mix-columns`,
  type: "gf-matrix-multiply@1",
  params: { matrix: AES_MIX_MATRIX.map((row) => [...row]) },
  portInputs: { input: port(`${p}.shift-rows`, "output") },
  narrationOverride: NARR_MIX_COLUMNS,
});

const fetchRoundKeyLeaf = (p: string, roundIndex: number): StepNode => ({
  kind: "step",
  id: `${p}.fetch-rk`,
  type: "aux-load-bytes@1",
  params: { auxName: `roundKey.${roundIndex}`, byteLength: AES_BLOCK_BYTES },
  narrationOverride: NARR_FETCH_RK,
});

/** AddRoundKey xor: operand0 = the state from `stateBinding`, operand1 = the fetched round key. */
const addRoundKeyLeaf = (p: string, stateBinding: PortBinding): StepNode => ({
  kind: "step",
  id: `${p}.add-round-key`,
  type: "xor@1",
  params: { inputCount: 2 },
  portInputs: { operand0: stateBinding, operand1: port(`${p}.fetch-rk`, "output") },
  narrationOverride: NARR_ADD_ROUND_KEY,
});

// ─── Round groups ────────────────────────────────────────────────────────────

/** Full encrypt round: SubBytes → ShiftRows → MixColumns → AddRoundKey. */
const encryptRound = (n: number): StepNode => {
  const p = `round.${n}`;
  return {
    kind: "group",
    id: p,
    label: `Round ${n}`,
    children: [
      subBytesLeaf(p, port(p, "in")), // carried state injected on port(round.n,"in")
      shiftRowsLeaf(p),
      mixColumnsLeaf(p),
      fetchRoundKeyLeaf(p, n),
      addRoundKeyLeaf(p, port(`${p}.mix-columns`, "output")),
    ],
    // A3b group port contract: round 1 seeds from the initial AddRoundKey;
    // round n (>1) from round n-1's published exit. Port-to-port carry.
    seedInput: n === 1 ? port("initial.add-round-key", "output") : port(`round.${n - 1}`, "out"),
    bodyOutput: port(`${p}.add-round-key`, "output"),
  };
};

/** Final encrypt round (no MixColumns): SubBytes → ShiftRows → AddRoundKey. */
const encryptFinalRound = (rounds: number): StepNode => {
  const p = `round.${rounds}`;
  return {
    kind: "group",
    id: p,
    label: `Round ${rounds} (final, no MixColumns)`,
    children: [
      subBytesLeaf(p, port(p, "in")),
      shiftRowsLeaf(p),
      fetchRoundKeyLeaf(p, rounds),
      addRoundKeyLeaf(p, port(`${p}.shift-rows`, "output")),
    ],
    seedInput:
      rounds === 1 ? port("initial.add-round-key", "output") : port(`round.${rounds - 1}`, "out"),
    bodyOutput: port(`${p}.add-round-key`, "output"),
  };
};

/**
 * Build the byte-native forward (encrypt) AES body for the given round count.
 * `rounds = 10` → AES-128, `12` → AES-192, `14` → AES-256.
 *
 * Shape: `[ init.fetch-rk, initial.add-round-key, round.1, …, round.{rounds}(final) ]`.
 * The body reads the plaintext from `inputSource` (the reserved `$input`
 * source for single-block specs; `port(iterateId, "in")` for an ECB/CBC
 * iterate that injects the per-block bytes — Slice B1.4). The caller's spec
 * sets `outputFrom = aesNativeOutputFrom(rounds)` (single-block) or names the
 * iterate's `bodyOutput`/`outputPorts` (multi-block).
 */
export function buildAesEncryptBodyNative(
  rounds: number,
  inputSource: PortBinding = port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
): readonly StepNode[] {
  return [
    // Initial AddRoundKey (round key 0), at body scope — reads `inputSource`.
    fetchRoundKeyLeaf("init", 0),
    {
      kind: "step",
      id: "initial.add-round-key",
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: inputSource,
        operand1: port("init.fetch-rk", "output"),
      },
      narrationOverride: NARR_INITIAL_ARK,
    },
    ...Array.from({ length: rounds - 1 }, (_, i) => encryptRound(i + 1)),
    encryptFinalRound(rounds),
  ];
}

/** The cipher exit port: the final round's published `out`. */
export function aesNativeOutputFrom(rounds: number): PortBinding {
  return port(`round.${rounds}`, "out");
}

// ─── Inverse (decrypt) narrationOverride docs (FIPS-197 §5.3) ────────────────

const NARR_INV_SUB_BYTES: StepDocumentation = {
  name: "InvSubBytes",
  summary: "Substitute every state byte through the inverse AES S-box (FIPS-197 §5.3.2).",
  detail: `## InvSubBytes

Each of the 16 state bytes \`b\` is replaced by \`invSbox[b]\`, the inverse AES
S-box. It exactly undoes forward SubBytes: \`invSbox[sbox[x]] = x\`. The same
\`byte-substitute@1\` executor runs forward and inverse — only the table param
differs — which is the modularity claim the inverse cipher exists to prove.

Byte-local and position-preserving: output byte \`i\` depends only on input
byte \`i\`.`,
  references: ["FIPS-197 §5.3.2 (InvSubBytes)"],
};

const NARR_INV_SHIFT_ROWS: StepDocumentation = {
  name: "InvShiftRows",
  summary: "Cyclically shift state rows right by 0/1/2/3 (FIPS-197 §5.3.1).",
  detail: `## InvShiftRows

Row \`r\` of the 4×4 state is cyclically shifted **right** by \`r\` bytes —
the inverse of forward ShiftRows' left shift. Expressed on the flat
column-major byte array it is the fixed permutation
\`out[r+4c] = in[r + 4·((c + invShift[r]) mod 4)]\` with
\`invShift = [0,3,2,1]\` (a left shift by \`[0,3,2,1]\` equals a right shift
by \`[0,1,2,3]\`).`,
  references: ["FIPS-197 §5.3.1 (InvShiftRows)"],
};

const NARR_INV_MIX_COLUMNS: StepDocumentation = {
  name: "InvMixColumns",
  summary: "Mix each column by the inverse AES matrix in GF(2⁸) (FIPS-197 §5.3.3).",
  detail: `## InvMixColumns

Each 4-byte column is multiplied by the inverse of the forward MixColumns
matrix over GF(2⁸):

\`\`\`
[14 11 13  9]
[ 9 14 11 13]
[13  9 14 11]
[11 13  9 14]
\`\`\`

This is the GF(2⁸) inverse of the forward \`{2,3,1,1}\` matrix, so it undoes
MixColumns exactly. Omitted in the final inverse round (FIPS-197 §5.3).`,
  references: ["FIPS-197 §5.3.3 (InvMixColumns)", "FIPS-197 §4.2 (GF(2⁸))"],
};

const NARR_INV_INITIAL_ARK: StepDocumentation = {
  name: "Initial AddRoundKey (decrypt)",
  summary: "XOR the ciphertext with the LAST round key before the inverse rounds (FIPS-197 §5.3).",
  detail: `## Initial AddRoundKey (decrypt)

The inverse cipher consumes the round keys in reverse order, so it begins by
XORing the ciphertext with \`roundKey.{rounds}\` — the very key the forward
cipher applied last. Because XOR is its own inverse, this peels off the
forward cipher's final AddRoundKey and sets up the first inverse round.`,
  references: ["FIPS-197 §5.3 (Inverse Cipher)"],
};

// ─── Inverse (decrypt) leaf factories ────────────────────────────────────────
// Same three port-native primitives as the forward body, with the inverse
// tables and the FIPS-197 §5.3 leaf ids (`inv-sub-bytes`, `inv-shift-rows`,
// `inv-mix-columns`). The ids deliberately match the legacy matrix decrypt
// builder so the duplicate-round mirror (`round.N ↔ inv-round.N`) and the
// `inv-round.N` layout pins keep resolving. fetch-rk + AddRoundKey reuse the
// forward factories verbatim (the round-key fetch + 2-way xor are identical).

const invSubBytesLeaf = (p: string, inputBinding: PortBinding): StepNode => ({
  kind: "step",
  id: `${p}.inv-sub-bytes`,
  type: "byte-substitute@1",
  params: { sbox: [...AES_INV_SBOX] },
  portInputs: { input: inputBinding },
  narrationOverride: NARR_INV_SUB_BYTES,
});

const invShiftRowsLeaf = (p: string, inputBinding: PortBinding): StepNode => ({
  kind: "step",
  id: `${p}.inv-shift-rows`,
  type: "permute@1",
  params: { indices: shiftRowsIndices(AES_INV_SHIFT_ROWS) },
  portInputs: { input: inputBinding },
  narrationOverride: NARR_INV_SHIFT_ROWS,
});

const invMixColumnsLeaf = (p: string, inputBinding: PortBinding): StepNode => ({
  kind: "step",
  id: `${p}.inv-mix-columns`,
  type: "gf-matrix-multiply@1",
  params: { matrix: AES_INV_MIX_MATRIX.map((row) => [...row]) },
  portInputs: { input: inputBinding },
  narrationOverride: NARR_INV_MIX_COLUMNS,
});

// ─── Inverse round groups (FIPS-197 §5.3) ────────────────────────────────────
//
// Note the order: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns.
// AddRoundKey sits BEFORE InvMixColumns (unlike the forward body's
// SubBytes → ShiftRows → MixColumns → AddRoundKey). This is intrinsic to the
// inverse cipher and cannot be hidden behind a "reverse the order"
// abstraction. The descending seedInput chain (inv-round.{rounds-1} seeds
// from the initial AddRoundKey; each lower round from the next-HIGHER round's
// exit) mirrors the reverse round-key consumption order.

/** Full inverse round: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns. */
const decryptRound = (n: number, rounds: number): StepNode => {
  const p = `inv-round.${n}`;
  return {
    kind: "group",
    id: p,
    label: `Inverse Round ${n}`,
    children: [
      invShiftRowsLeaf(p, port(p, "in")), // carried state injected on port(inv-round.n,"in")
      invSubBytesLeaf(p, port(`${p}.inv-shift-rows`, "output")),
      fetchRoundKeyLeaf(p, n),
      addRoundKeyLeaf(p, port(`${p}.inv-sub-bytes`, "output")),
      invMixColumnsLeaf(p, port(`${p}.add-round-key`, "output")),
    ],
    // Descending chain: the highest inverse round seeds from the initial
    // AddRoundKey; every lower one from the next-higher round's exit.
    seedInput:
      n === rounds - 1
        ? port("inv-initial.add-round-key", "output")
        : port(`inv-round.${n + 1}`, "out"),
    bodyOutput: port(`${p}.inv-mix-columns`, "output"),
  };
};

/** Final inverse round (no InvMixColumns): InvShiftRows → InvSubBytes → AddRoundKey. */
const decryptFinalRound = (): StepNode => {
  const p = "inv-round.0";
  return {
    kind: "group",
    id: p,
    label: "Inverse Round 0 (final, no InvMixColumns)",
    children: [
      invShiftRowsLeaf(p, port(p, "in")),
      invSubBytesLeaf(p, port(`${p}.inv-shift-rows`, "output")),
      fetchRoundKeyLeaf(p, 0),
      addRoundKeyLeaf(p, port(`${p}.inv-sub-bytes`, "output")),
    ],
    seedInput: port("inv-round.1", "out"),
    bodyOutput: port(`${p}.add-round-key`, "output"),
  };
};

/**
 * Build the byte-native inverse (decrypt) AES body for the given round count.
 * `rounds = 10` → AES-128, `12` → AES-192, `14` → AES-256.
 *
 * Shape: `[ inv-initial.fetch-rk, inv-initial.add-round-key,
 *           inv-round.{rounds-1}, …, inv-round.1, inv-round.0(final) ]`.
 * Round keys are consumed in reverse: the initial AddRoundKey reads
 * `roundKey.{rounds}` and each inverse round `n` reads `roundKey.{n}` down to
 * `roundKey.0`. The ciphertext arrives on `inputSource` (`$input` single-block;
 * `port(iterateId, "in")` for an ECB iterate — Slice B1.4); the caller sets
 * `outputFrom = aesNativeDecryptOutputFrom()` (single-block) or names the
 * iterate's `bodyOutput`/`outputPorts` (multi-block).
 */
export function buildAesDecryptBodyNative(
  rounds: number,
  inputSource: PortBinding = port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
): readonly StepNode[] {
  return [
    // Initial AddRoundKey (the LAST round key), at body scope — reads `inputSource`.
    fetchRoundKeyLeaf("inv-initial", rounds),
    {
      kind: "step",
      id: "inv-initial.add-round-key",
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: inputSource,
        operand1: port("inv-initial.fetch-rk", "output"),
      },
      narrationOverride: NARR_INV_INITIAL_ARK,
    },
    ...Array.from({ length: rounds - 1 }, (_, i) => decryptRound(rounds - 1 - i, rounds)),
    decryptFinalRound(),
  ];
}

/** The inverse cipher exit port: the final inverse round's published `out`. */
export function aesNativeDecryptOutputFrom(): PortBinding {
  return port("inv-round.0", "out");
}
