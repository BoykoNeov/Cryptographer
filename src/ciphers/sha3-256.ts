/**
 * SHA3-256 cipher spec — the first sponge-based hash and the first SHA-3 /
 * Keccak function in the app (FIPS 202), 2026-07-13. Foundation slice for
 * future post-quantum work (ML-KEM / ML-DSA consume SHAKE, which reuses this
 * exact Keccak-f[1600] permutation).
 *
 * **Sponge, not Merkle–Damgård.** Where SHA-256 folds each block into a small
 * chaining value with a compression function, SHA-3 keeps a large 1600-bit
 * (200-byte) **state** and:
 *   - **absorbs** the padded message `rate` bytes (136 for SHA3-256) at a time,
 *     XORing each block into the first `rate` bytes of the state and then
 *     running the Keccak-f[1600] permutation;
 *   - **squeezes** the digest out of the state (for SHA3-256 the 32-byte digest
 *     fits in one `rate`-block, so a single squeeze = slice the first 32 bytes;
 *     no XOF loop — that is SHAKE's job in a later slice).
 *
 * **Reuses SHA-256's port-native machinery.** The absorb loop is the SAME
 * port-mode `iterate` fold SHA-256's multi-block hashing uses: the carried
 * chain is the full 200-byte state (`chainInput` bootstraps it to all-zeros,
 * `chainFeedback` advances it, `chainOutput` harvests the final state). Each
 * block arrives on `port("sponge","in")`, the running state on
 * `port("sponge","chain")`.
 *
 * **Keccak-f[1600] round = θ → ρ → π → χ → ι** (FIPS 202 §3.2), 24 rounds:
 *   θ (theta) → `keccak.theta@1`   — column parities mix whole columns
 *   ρ (rho)   → `rotate-lanes@1`   — per-lane left-rotate (25 distinct offsets)
 *   π (pi)    → `permute@1`        — lane transposition (a 200-byte gather)
 *   χ (chi)   → `permute`/`not`/`and`/`xor` — the sole NONLINEAR step, kept
 *               visible: A'[x] = A[x] ⊕ (¬A[x+1] ∧ A[x+2]) with the mod-5 row
 *               shifts done as whole-state permutes
 *   ι (iota)  → `keccak.iota@1`    — XOR RC[round] (from aux["RC"]) into lane 0
 *
 * **Little-endian state.** Keccak's state is a little-endian bit string. The
 * only endianness-sensitive operations (ρ and θ's internal rotate) do their
 * 64-bit math little-endian *inside* their step executors, so the 200-byte
 * state stays in standard LE byte-string form throughout — no boundary
 * byte-reversal, and `rotate-bits-right@1` (which assembles big-endian) is NOT
 * used here.
 *
 * **KAT.** The whole assembled sponge is byte-equal to `node:crypto`'s
 * `sha3-256` across all message lengths (`tests/sha3-256-kat.test.ts`),
 * including the empty message (`a7ffc6f8…f8434a`), the one-byte-short-of-a-block
 * pad-merge case, and multi-block messages. The decomposition + every constant
 * and index array below was validated against `node:crypto` before this spec
 * was authored.
 *
 * **References:**
 *   - FIPS 202 §3.1 — the state and its little-endian bit-string mapping
 *   - FIPS 202 §3.2 — the five step mappings θ, ρ, π, χ, ι
 *   - FIPS 202 §4    — the sponge construction
 *   - FIPS 202 §5.1  — pad10*1; §B.2 — domain separation (0x06 for SHA-3)
 *   - FIPS 202 §A.1  — SHA3-256 examples / KATs
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";

// ─── Keccak-f[1600] geometry + constants ────────────────────────────────────

const RATE = 136; // sponge rate in bytes (1088 bits); capacity = 64 bytes
const ROUNDS = 24;
const STATE_BYTES = 200;
const LANE_BYTES = 8;
const DIGEST_BYTES = 32;
const DOMAIN_SHA3 = 0x06;

/** Byte offset of lane (x,y) in the little-endian state (slot = x + 5y). */
const laneStart = (x: number, y: number): number => (x + 5 * y) * LANE_BYTES;

/**
 * ρ (rho) rotation offsets, indexed by lane slot (x + 5y). FIPS 202 Table 2,
 * flattened to slot order. Validated against `node:crypto` (the reference
 * script derived these from the triangular recurrence and confirmed the full
 * hash matches).
 */
const RHO_OFFSETS: readonly number[] = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/**
 * π (pi) lane transposition as a 200-byte gather: the new lane (x,y) is the old
 * lane ((x+3y) mod 5, x) — FIPS 202 §3.2.3. `output[i] = input[PI_INDICES[i]]`.
 */
const PI_INDICES: readonly number[] = (() => {
  const idx = new Array<number>(STATE_BYTES);
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      const dst = laneStart(x, y);
      const src = laneStart((x + 3 * y) % 5, x);
      for (let b = 0; b < LANE_BYTES; b++) idx[dst + b] = src + b;
    }
  }
  return idx;
})();

/**
 * χ (chi) row-shift gathers. χ is A'[x,y] = A[x,y] ⊕ (¬A[x+1,y] ∧ A[x+2,y])
 * (FIPS 202 §3.2.4). The x+1 / x+2 shifts wrap within each row (mod 5); as a
 * whole-state gather each is a fixed permutation: the lane in slot (x,y) is
 * replaced by the lane in slot ((x+k) mod 5, y).
 */
const chiShift = (k: number): readonly number[] => {
  const idx = new Array<number>(STATE_BYTES);
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      const dst = laneStart(x, y);
      const src = laneStart((x + k) % 5, y);
      for (let b = 0; b < LANE_BYTES; b++) idx[dst + b] = src + b;
    }
  }
  return idx;
};
const CHI_SHIFT1 = chiShift(1); // A[x+1]
const CHI_SHIFT2 = chiShift(2); // A[x+2]

/**
 * ι (iota) round constants RC[0..23], each a 64-bit value derived from the
 * FIPS 202 §3.2.5 LFSR. Stored as a 192-byte little-endian table in
 * `aux["RC"]`; `keccak.iota@1` slices lane `round` at offset 8·round.
 * Validated against `node:crypto`.
 */
const RC_VALUES: readonly bigint[] = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];

/** Encode the 24 round constants as a 192-byte little-endian lane table. */
const RC_BYTES: Uint8Array = (() => {
  const out = new Uint8Array(ROUNDS * LANE_BYTES);
  for (let i = 0; i < ROUNDS; i++) {
    const v = RC_VALUES[i] as bigint;
    for (let b = 0; b < LANE_BYTES; b++) {
      out[i * LANE_BYTES + b] = Number((v >> BigInt(8 * b)) & 0xffn);
    }
  }
  return out;
})();

/** The initial sponge state: 200 zero bytes (bootstraps the absorb fold). */
const S0_BYTES: Uint8Array = new Uint8Array(STATE_BYTES);

// ─── narrationOverride: Keccak-specific prose for the primary leaves ────────
//
// Port-native steps have no `shapeContract`, so they are exempt from the
// per-frame narration-coverage contract; these `narrationOverride` blocks are
// pedagogy, naming what each leaf does inside SHA-3. Leaves without an override
// fall back to the registry doc for their underlying primitive.

const NARR_PAD: StepDocumentation = {
  name: "Pad + domain-separate (pad10*1, FIPS 202 §5.1)",
  summary:
    "Append the SHA-3 domain byte 0x06 and pad with the 10*1 rule to a multiple of the 136-byte rate.",
  detail: `SHA-3 extends the message to a whole number of 136-byte sponge
blocks: append the domain byte \`0x06\` (which also carries the padding's
leading 1-bit), zero-fill, then set the top bit of the last byte. Unlike
SHA-256 there is **no length suffix** — the sponge's security comes from the
capacity, not from encoding the length. When the message is one byte short of a
block the two pad bits merge into a single \`0x86\` byte.`,
  references: ["FIPS 202 §5.1 (pad10*1)", "FIPS 202 §B.2 (domain separation)"],
};

const NARR_INIT_STATE: StepDocumentation = {
  name: "Initial sponge state (200 zero bytes)",
  summary: "Bootstrap the absorb fold with an all-zero 1600-bit state.",
  detail: `The sponge starts from the all-zero state (FIPS 202 §4). This leaf
loads the 200 zero bytes that seed the per-block fold's running state — the
Keccak analogue of SHA-256's initial hash values, but simpler: there are no
magic constants, the state just starts empty and every bit of structure comes
from absorbing the message and permuting.`,
  references: ["FIPS 202 §4 (sponge construction)"],
};

const NARR_ABSORB_SPLIT: StepDocumentation = {
  name: "Split state into rate (136) + capacity (64)",
  summary:
    "Separate the running state's absorbing part (first 136 bytes) from its hidden capacity (last 64).",
  detail: `The sponge only mixes the message into the **rate** portion — the
first 136 bytes. The remaining 64 bytes are the **capacity**, never touched
directly by the message; that hidden part is exactly what gives SHA-3 its
resistance to collision and preimage attacks. This split separates the two so
the next step XORs the block into the rate only.`,
  references: ["FIPS 202 §4 (rate and capacity)"],
};

const NARR_ABSORB_XOR: StepDocumentation = {
  name: "Absorb: XOR this block into the rate",
  summary: "XOR the 136-byte message block into the first 136 bytes of the state.",
  detail: `Absorbing a block means XORing it into the rate portion of the state
(FIPS 202 §4). This is the only place the message enters the sponge. After the
XOR the whole state is permuted, spreading the block's influence across all 1600
bits before the next block arrives.`,
  references: ["FIPS 202 §4 (absorbing)"],
};

const NARR_ABSORB_CONCAT: StepDocumentation = {
  name: "Reassemble the 200-byte state",
  summary: "Join the message-XORed rate back with the untouched capacity.",
  detail: `Rejoins the freshly-absorbed 136-byte rate with the 64-byte capacity
to form the full 200-byte state that the Keccak-f permutation will scramble.`,
  references: ["FIPS 202 §4 (sponge construction)"],
};

const NARR_THETA: StepDocumentation = {
  name: "θ (theta) — mix columns",
  summary:
    "XOR each lane with the parity of its two neighbouring columns — Keccak's main diffusion step.",
  detail: `θ mixes whole columns of the 5×5 lane grid: it computes each column's
parity, combines neighbouring columns (one with a 1-bit rotation), and folds the
result back into every lane. After θ each output bit depends on 11 input bits,
so a single flipped bit fans out quickly. FIPS 202 §3.2.1.`,
  references: ["FIPS 202 §3.2.1 (θ step)"],
};

const NARR_RHO: StepDocumentation = {
  name: "ρ (rho) — rotate each lane",
  summary: "Rotate each of the 25 lanes left by its own fixed offset (Keccak's rotation table).",
  detail: `ρ rotates lane (x,y) left by a fixed per-lane amount from Keccak's
rotation table (FIPS 202 §3.2.2, Table 2). It is the only step that moves bits
*within* the 64-bit lane direction, so together with θ (columns) and π (lane
positions) it diffuses changes across all three axes of the state. The lanes are
read little-endian — Keccak's convention.`,
  references: ["FIPS 202 §3.2.2 (ρ step)"],
};

const NARR_PI: StepDocumentation = {
  name: "π (pi) — permute lane positions",
  summary: "Move each lane to a new (x,y) position: lane (x,y) ← lane ((x+3y) mod 5, x).",
  detail: `π rearranges the 25 lanes without changing their contents — the new
lane (x,y) takes the old lane at ((x+3y) mod 5, x) (FIPS 202 §3.2.3). On the
flat 200-byte state this is a fixed gather of whole 8-byte lanes. π provides the
long-range mixing that keeps θ and ρ from settling into a small orbit.`,
  references: ["FIPS 202 §3.2.3 (π step)"],
};

const NARR_CHI_SHIFT1: StepDocumentation = {
  name: "χ helper: gather A[x+1] (row-shift by 1)",
  summary: "Line up each lane's right-hand neighbour within its row (mod 5).",
  detail: `The χ step reads, for each lane, its two right-hand neighbours in the
same row. This gather shifts every row by one lane so lane (x,y) is aligned with
the value A[(x+1) mod 5, y] — the \`¬…\` operand of χ. FIPS 202 §3.2.4.`,
  references: ["FIPS 202 §3.2.4 (χ step)"],
};

const NARR_CHI_SHIFT2: StepDocumentation = {
  name: "χ helper: gather A[x+2] (row-shift by 2)",
  summary: "Line up each lane's second right-hand neighbour within its row (mod 5).",
  detail: `Companion to the shift-by-1 gather: aligns lane (x,y) with A[(x+2) mod
5, y] — the second operand of χ's \`(¬A[x+1] ∧ A[x+2])\`. FIPS 202 §3.2.4.`,
  references: ["FIPS 202 §3.2.4 (χ step)"],
};

const NARR_CHI_NOT: StepDocumentation = {
  name: "χ helper: ¬A[x+1]",
  summary: "Complement the row-shifted lanes (the ¬ in χ's formula).",
  detail: `Bitwise NOT of the shift-by-1 gather, giving \`¬A[x+1]\` for every
lane — the negated operand of χ's AND. FIPS 202 §3.2.4.`,
  references: ["FIPS 202 §3.2.4 (χ step)"],
};

const NARR_CHI_AND: StepDocumentation = {
  name: "χ helper: ¬A[x+1] ∧ A[x+2]",
  summary: "AND the complemented neighbour with the second neighbour.",
  detail: `Computes \`¬A[x+1] ∧ A[x+2]\` for every lane — the nonlinear core of
χ. This AND is the ONLY nonlinear operation in all of Keccak-f; θ, ρ, π and ι
are linear. FIPS 202 §3.2.4.`,
  references: ["FIPS 202 §3.2.4 (χ step)"],
};

const NARR_CHI: StepDocumentation = {
  name: "χ (chi) — nonlinear combine",
  summary: "A'[x,y] = A[x,y] ⊕ (¬A[x+1,y] ∧ A[x+2,y]) — the one nonlinear step.",
  detail: `χ is Keccak's **confusion** step and its only source of
nonlinearity:

\`\`\`
A'[x,y] = A[x,y] ⊕ (¬A[x+1,y] ∧ A[x+2,y])
\`\`\`

Each lane is combined with its two right-hand neighbours in the same row (FIPS
202 §3.2.4). Because it is the sole nonlinear step, χ is what makes Keccak-f
resist linear and differential cryptanalysis; θ/ρ/π only move and add bits.`,
  references: ["FIPS 202 §3.2.4 (χ step)"],
};

const NARR_IOTA: StepDocumentation = {
  name: "ι (iota) — add round constant",
  summary: "XOR this round's constant RC[round] into lane (0,0) — the only per-round difference.",
  detail: `ι XORs a round-specific constant into lane (0,0) and nothing else
(FIPS 202 §3.2.5). Since θ, ρ, π and χ are identical every round, ι's changing
constant is what breaks the round-to-round symmetry that slide and rotational
attacks would otherwise exploit. The constants come from an LFSR — a
"nothing-up-my-sleeve" derivation — and live in the editable RC table.`,
  references: ["FIPS 202 §3.2.5 (ι step + round constants)"],
};

const NARR_SQUEEZE: StepDocumentation = {
  name: "Squeeze the 256-bit digest",
  summary: "Take the first 32 bytes of the final state as the SHA3-256 output.",
  detail: `After the last block is absorbed, SHA-3 **squeezes** the digest out of
the state. For SHA3-256 the 32-byte output fits inside the 136-byte rate, so a
single squeeze suffices: the digest is simply the first 32 bytes of the final
state (FIPS 202 §4). SHAKE, whose output can be arbitrarily long, repeats the
squeeze-and-permute loop — that is a later slice.`,
  references: ["FIPS 202 §4 (squeezing)", "FIPS 202 §A.1 (SHA3-256 examples)"],
};

// ─── Helpers ────────────────────────────────────────────────────────────────

const port = (node: string, port: string): { readonly node: string; readonly port: string } => ({
  node,
  port,
});

// ─── One Keccak-f round: θ → ρ → π → χ → ι (9 leaves) ───────────────────────

const buildKeccakRound = (r: number): StepNode => {
  const p = `round.${r}`;
  // Local ref helper — prefixes the round id so child ids stay globally unique.
  const rr = (node: string, portName: string) => port(`${p}.${node}`, portName);
  return {
    kind: "group",
    id: p,
    label: `Round ${r}`,
    // Default-collapse so the 24 rounds don't put ~216 chips on the canvas on
    // first render; the user expands any round via the chevron.
    defaultCollapsed: true,
    children: [
      // θ — reads the round's carried state off the group seed port.
      {
        kind: "step",
        id: `${p}.theta`,
        type: "keccak.theta@1",
        params: {},
        portInputs: { input: port(p, "in") },
        narrationOverride: NARR_THETA,
      },
      // ρ — per-lane left rotate, little-endian.
      {
        kind: "step",
        id: `${p}.rho`,
        type: "rotate-lanes@1",
        params: { wordBits: 64, offsets: [...RHO_OFFSETS], littleEndian: true },
        portInputs: { input: rr("theta", "output") },
        narrationOverride: NARR_RHO,
      },
      // π — lane transposition.
      {
        kind: "step",
        id: `${p}.pi`,
        type: "permute@1",
        params: { indices: [...PI_INDICES] },
        portInputs: { input: rr("rho", "output") },
        narrationOverride: NARR_PI,
      },
      // χ decomposed: two row-shift gathers + not + and + xor.
      {
        kind: "step",
        id: `${p}.chi-b`,
        type: "permute@1",
        params: { indices: [...CHI_SHIFT1] },
        portInputs: { input: rr("pi", "output") },
        narrationOverride: NARR_CHI_SHIFT1,
      },
      {
        kind: "step",
        id: `${p}.chi-c`,
        type: "permute@1",
        params: { indices: [...CHI_SHIFT2] },
        portInputs: { input: rr("pi", "output") },
        narrationOverride: NARR_CHI_SHIFT2,
      },
      {
        kind: "step",
        id: `${p}.chi-not`,
        type: "not@1",
        params: {},
        portInputs: { input: rr("chi-b", "output") },
        narrationOverride: NARR_CHI_NOT,
      },
      {
        kind: "step",
        id: `${p}.chi-and`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: { operand0: rr("chi-not", "output"), operand1: rr("chi-c", "output") },
        narrationOverride: NARR_CHI_AND,
      },
      {
        kind: "step",
        id: `${p}.chi`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: { operand0: rr("pi", "output"), operand1: rr("chi-and", "output") },
        narrationOverride: NARR_CHI,
      },
      // ι — XOR RC[round] (from aux["RC"], auto-projected) into lane (0,0).
      {
        kind: "step",
        id: `${p}.iota`,
        type: "keccak.iota@1",
        // auxName is explicit (not defaulted) so the constants panel's
        // static consumer scan attributes aux["RC"] to every ι leaf.
        params: { round: r, auxName: "RC" },
        portInputs: { input: rr("chi", "output") },
        narrationOverride: NARR_IOTA,
      },
    ],
    // The carried state enters on port("round.{r}","in"); round 0 seeds from
    // the absorbed state, later rounds from the previous round's exit. The
    // permuted state leaves on ι's output (the group's bodyOutput).
    seedInput: r === 0 ? port("absorb", "output") : port(`round.${r - 1}`, "out"),
    bodyOutput: rr("iota", "output"),
  };
};

// ─── Absorb leaves (inside the sponge iterate, before the rounds) ───────────
//
// XOR this block into the rate portion of the running state:
//   split the 200-byte chain into [136 rate][64 capacity], XOR the block into
//   the rate, concat back to 200 bytes. That 200-byte "absorb" output seeds
//   round 0; round 23's output is the fold's chainFeedback.

const buildAbsorbSteps = (): readonly StepNode[] => [
  {
    kind: "step",
    id: "absorb-split",
    type: "split-bytes@1",
    params: { widths: [RATE, STATE_BYTES - RATE] },
    portInputs: { input: port("sponge", "chain") },
    narrationOverride: NARR_ABSORB_SPLIT,
  },
  {
    kind: "step",
    id: "absorb-xor",
    type: "xor@1",
    params: { inputCount: 2 },
    portInputs: { operand0: port("absorb-split", "output0"), operand1: port("sponge", "in") },
    narrationOverride: NARR_ABSORB_XOR,
  },
  {
    kind: "step",
    id: "absorb",
    type: "concat@1",
    params: { inputCount: 2 },
    portInputs: { input0: port("absorb-xor", "output"), input1: port("absorb-split", "output1") },
    narrationOverride: NARR_ABSORB_CONCAT,
  },
];

// ─── Spec builder ────────────────────────────────────────────────────────────

/**
 * Build the SHA3-256 spec: pad → sponge-absorb fold (Keccak-f[1600] per block)
 * → squeeze the first 32 bytes.
 */
export const buildSha3256Spec = (): CipherSpec => ({
  id: "sha3-256@1",
  name: "SHA3-256",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 0 }, // hashes have no key
  },
  steps: [
    // ─── Padding (pad10*1 + domain byte 0x06) ────────────────────────────
    {
      kind: "step",
      id: "pad",
      type: "keccak.pad@1",
      params: { rate: RATE, domainByte: DOMAIN_SHA3 },
      portInputs: { input: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) },
      narrationOverride: NARR_PAD,
    },
    // ─── Initial all-zero sponge state (the fold's chainInput) ───────────
    {
      kind: "step",
      id: "init-state",
      type: "aux-load-bytes@1",
      params: { auxName: "S0", byteLength: STATE_BYTES },
      narrationOverride: NARR_INIT_STATE,
    },
    // ─── Sponge absorb fold (one Keccak-f[1600] per rate block) ──────────
    // Port-mode iterate: seedInput = padded message (split into 136-byte
    // blocks), chain = the running 200-byte state, chainOutput harvests the
    // final state for squeezing.
    {
      kind: "iterate",
      id: "sponge",
      label: "Sponge absorb (Keccak-f[1600] per block)",
      blockByteLength: RATE,
      seedInput: port("pad", "output"),
      chainInput: port("init-state", "output"),
      chainFeedback: port(`round.${ROUNDS - 1}`, "out"),
      bodyOutput: port(`round.${ROUNDS - 1}`, "out"),
      chainOutput: "state",
      children: [
        ...buildAbsorbSteps(),
        ...Array.from({ length: ROUNDS }, (_, r) => buildKeccakRound(r)),
      ],
    },
    // ─── Squeeze: first 32 bytes of the final state = the digest ─────────
    {
      kind: "step",
      id: "squeeze",
      type: "byte-slice@1",
      params: { sourceByteLength: STATE_BYTES, offset: 0, length: DIGEST_BYTES },
      portInputs: { input: port("sponge", "state") },
      narrationOverride: NARR_SQUEEZE,
    },
  ],
  // Published constants materialized into aux before the walk: RC (24-lane
  // round-constant table) + S0 (the all-zero initial state).
  cipherConstants: { RC: RC_BYTES, S0: S0_BYTES },
  outputFrom: port("squeeze", "output"),
});
