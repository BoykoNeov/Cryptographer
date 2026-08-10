/**
 * Keccak-f[1600] — the shared permutation + sponge-absorb machinery behind
 * every FIPS 202 function (SHA3-224/256/384/512 and SHAKE128/256), 2026-07-13.
 *
 * Extracted verbatim from `sha3-256.ts` when SHAKE landed: SHA-3 and SHAKE are
 * the SAME 24-round θ→ρ→π→χ→ι permutation over the SAME 200-byte little-endian
 * state, differing only in **rate** (how many bytes are absorbed/squeezed per
 * block), **domain byte** (0x06 vs 0x1F, handled by `keccak.pad@1`), and
 * **output length** (a fixed digest vs an extendable squeeze). So the geometry,
 * the round constants, the round builder, and the absorb XOR-fold all live here,
 * parameterized by rate; the per-function specs (`sha3-256.ts`, `shake.ts`)
 * supply the rate + domain + squeeze topology on top.
 *
 * **Little-endian state.** Keccak's state is a little-endian bit string. The
 * only endianness-sensitive operations (ρ and θ's internal rotate) do their
 * 64-bit math little-endian *inside* their step executors (`rotate-lanes@1`,
 * `keccak.theta@1`), so the 200-byte state stays in standard LE byte-string
 * form throughout — no boundary byte-reversal, and `rotate-bits-right@1` (which
 * assembles big-endian) is NOT used here.
 *
 * **Id stability.** `buildKeccakRound`/`buildKeccakRounds` take a `prefix`: an
 * EMPTY prefix reproduces SHA3-256's original ids (`round.0`…`round.23`) byte
 * for byte, so extracting this module left SHA3-256's spec tree (and thus its
 * saved-doc layout pins + URL-share hashes) unchanged. A non-empty prefix
 * (e.g. `squeeze.perm.1`) namespaces a second Keccak-f instance for SHAKE's
 * squeeze loop.
 *
 * **References:**
 *   - FIPS 202 §3.1 — the state and its little-endian bit-string mapping
 *   - FIPS 202 §3.2 — the five step mappings θ, ρ, π, χ, ι
 *   - FIPS 202 §4    — the sponge construction (absorb / squeeze)
 */

import type { PortBinding, StepDocumentation, StepNode } from "../core/types";

// ─── Keccak-f[1600] geometry + constants ────────────────────────────────────

export const ROUNDS = 24;
export const STATE_BYTES = 200;
export const LANE_BYTES = 8;

/** Byte offset of lane (x,y) in the little-endian state (slot = x + 5y). */
const laneStart = (x: number, y: number): number => (x + 5 * y) * LANE_BYTES;

/**
 * ρ (rho) rotation offsets, indexed by lane slot (x + 5y). FIPS 202 Table 2,
 * flattened to slot order. Validated against `node:crypto` (the reference
 * script derived these from the triangular recurrence and confirmed the full
 * hash matches).
 */
export const RHO_OFFSETS: readonly number[] = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/**
 * π (pi) lane transposition as a 200-byte gather: the new lane (x,y) is the old
 * lane ((x+3y) mod 5, x) — FIPS 202 §3.2.3. `output[i] = input[PI_INDICES[i]]`.
 */
export const PI_INDICES: readonly number[] = (() => {
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
export const CHI_SHIFT1 = chiShift(1); // A[x+1]
export const CHI_SHIFT2 = chiShift(2); // A[x+2]

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
export const RC_BYTES: Uint8Array = (() => {
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
export const S0_BYTES: Uint8Array = new Uint8Array(STATE_BYTES);

// ─── Port helper + id scheme ────────────────────────────────────────────────

/** Compact `{ node, port }` builder (mirrors the per-cipher local helpers). */
export const port = (node: string, portName: string): PortBinding => ({
  node,
  port: portName,
});

/**
 * The id of round `r` under `prefix`. An EMPTY prefix yields `round.{r}` —
 * byte-identical to SHA3-256's original ids so extraction stayed inert. A
 * non-empty prefix (a squeeze permutation) yields `{prefix}.round.{r}`.
 */
export const roundId = (prefix: string, r: number): string =>
  prefix ? `${prefix}.round.${r}` : `round.${r}`;

// ─── narrationOverride: Keccak-f round prose (rate/domain-independent) ───────
//
// These describe the five step mappings of the permutation itself — pure
// Keccak-f math with NO rate, domain byte, or function-family words — so they
// are shared verbatim by SHA-3 and SHAKE. (The rate/domain-specific pad +
// absorb prose is caller-supplied; see `buildAbsorbSteps` below.)

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

// ─── One Keccak-f round: θ → ρ → π → χ → ι (9 leaves) ───────────────────────

/**
 * Build one Keccak-f round as a port-mode group. `prefix` namespaces the round
 * (empty → SHA3-256's `round.{r}`); `seedInput` is the carried-state source
 * (round 0 seeds from the caller's absorbed/permuted state, later rounds from
 * the previous round's `"out"`). The permuted state leaves on ι's output
 * (the group's `bodyOutput`, published on `"out"`).
 */
export const buildKeccakRound = (prefix: string, r: number, seedInput: PortBinding): StepNode => {
  const p = roundId(prefix, r);
  // Round-local port helper — prefixes the round id so child ids stay globally
  // unique across every Keccak-f instance in the spec.
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
    // The carried state enters on port(p,"in"); the permuted state leaves on ι's
    // output (the group's bodyOutput).
    seedInput,
    bodyOutput: rr("iota", "output"),
  };
};

/**
 * Build all 24 Keccak-f rounds as a flat array of round groups, chained
 * round 0 → … → round 23. `seedRound0` feeds round 0; each later round reads
 * the previous round's published `"out"`. Used flat inside the absorb iterate
 * (prefix `""`, `seedRound0 = port("absorb","output")`).
 */
export const buildKeccakRounds = (prefix: string, seedRound0: PortBinding): StepNode[] =>
  Array.from({ length: ROUNDS }, (_, r) =>
    buildKeccakRound(prefix, r, r === 0 ? seedRound0 : port(roundId(prefix, r - 1), "out")),
  );

/**
 * Build a full Keccak-f[1600] permutation wrapped in a single collapsible
 * group — the form SHAKE's squeeze loop uses. The outer group seeds from
 * `seedInput` (the previous squeeze block's state), injects it on
 * `port(groupId,"in")` for round 0, and republishes round 23's output on
 * `port(groupId,"out")`. `defaultCollapsed` keeps the extra 24-round
 * permutations from flooding the canvas.
 */
export const buildKeccakPermGroup = (
  groupId: string,
  label: string,
  seedInput: PortBinding,
): StepNode => ({
  kind: "group",
  id: groupId,
  label,
  defaultCollapsed: true,
  seedInput,
  bodyOutput: port(roundId(groupId, ROUNDS - 1), "out"),
  children: buildKeccakRounds(groupId, port(groupId, "in")),
});

// ─── Absorb leaves (inside the sponge iterate, before the rounds) ───────────

/** Caller-supplied absorb narration (rate/family-specific prose). */
export type AbsorbNarration = {
  readonly split: StepDocumentation;
  readonly xor: StepDocumentation;
  readonly concat: StepDocumentation;
};

/**
 * XOR this block into the rate portion of the running state:
 *   split the 200-byte chain into [rate][capacity], XOR the block into the
 *   rate, concat back to 200 bytes. That 200-byte "absorb" output seeds
 *   round 0; round 23's output is the fold's chainFeedback.
 *
 * `rate` is a parameter (136 for SHA3-256, 168 for SHAKE128, 136 for
 * SHAKE256), so the split width + narration numbers are function-specific. The
 * narration is caller-supplied because its rate/family wording differs between
 * SHA-3 (a fixed digest) and SHAKE (an XOF); keeping it here would hardcode one
 * function's numbers onto the other's trace.
 */
export const buildAbsorbSteps = (rate: number, narration: AbsorbNarration): StepNode[] => [
  {
    kind: "step",
    id: "absorb-split",
    type: "split-bytes@1",
    params: { widths: [rate, STATE_BYTES - rate] },
    portInputs: { input: port("sponge", "chain") },
    narrationOverride: narration.split,
  },
  {
    kind: "step",
    id: "absorb-xor",
    type: "xor@1",
    params: { inputCount: 2 },
    portInputs: { operand0: port("absorb-split", "output0"), operand1: port("sponge", "in") },
    narrationOverride: narration.xor,
  },
  {
    kind: "step",
    id: "absorb",
    type: "concat@1",
    params: { inputCount: 2 },
    portInputs: { input0: port("absorb-xor", "output"), input1: port("absorb-split", "output1") },
    narrationOverride: narration.concat,
  },
];
