/**
 * Shared Keccak sponge tail — the `init-state → absorb fold → unrolled squeeze`
 * pipeline common to SHAKE, cSHAKE, and KMAC, 2026-07-13.
 *
 * SHAKE, cSHAKE, and KMAC differ only in how they build the **padded message**
 * that enters the sponge (SHAKE: `pad10*1` on the raw message; cSHAKE/KMAC:
 * an `encode_string`/`bytepad` prefix — and for KMAC a key block + a
 * `right_encode` suffix — before the same pad). Everything *after* the pad — the
 * all-zero initial state, the per-block Keccak-f[1600] absorb fold, and the
 * variable-length squeeze — is byte-for-byte identical across all three.
 *
 * This module owns that identical tail so the three spec builders share one
 * copy. Narration is **caller-supplied** (each function needs its own rate /
 * domain / XOF wording — hardcoding one family's numbers onto another's trace is
 * an unguarded defect the KAT can't see), following the same discipline as
 * `buildAbsorbSteps` in `keccak-f.ts`.
 *
 * **Reference:** FIPS 202 §4 (sponge: absorb + squeeze), Algorithm 8 (squeeze).
 */

import type { PortBinding, StepDocumentation, StepNode } from "../core/types";
import type { AbsorbNarration } from "./keccak-f";
import {
  ROUNDS,
  STATE_BYTES,
  buildAbsorbSteps,
  buildKeccakPermGroup,
  buildKeccakRounds,
  port,
} from "./keccak-f";

/** Caller-supplied narration for every leaf the sponge tail emits. */
export type SpongeNarration = {
  /** The `init-state` all-zero-state loader. */
  readonly initState: StepDocumentation;
  /** The per-block absorb (split / xor / concat) — rate-specific. */
  readonly absorb: AbsorbNarration;
  /** Squeeze block `j` of `numBlocks` (block 0 has no preceding permutation). */
  readonly extract: (j: number, numBlocks: number) => StepDocumentation;
  /** The concat that joins the squeezed blocks (only emitted when > 1 block). */
  readonly concat: (numBlocks: number) => StepDocumentation;
  /** The final truncate to the requested output length. */
  readonly truncate: StepDocumentation;
};

/**
 * A ready-made `SpongeNarration` for a named sponge function (cSHAKE, KMAC, …).
 * The absorb/squeeze mechanics are identical across every FIPS 202 / SP 800-185
 * function, so this supplies family-neutral prose keyed on a `displayName` and
 * the `rate`. (SHAKE keeps its own bundle in `shake.ts` — this one must not
 * touch that byte-stable output.)
 */
export const buildSpongeNarration = (
  displayName: string,
  rate: number,
  outputLength: number,
): SpongeNarration => {
  const capacity = STATE_BYTES - rate;
  return {
    initState: {
      name: "Initial sponge state (200 zero bytes)",
      summary: "Bootstrap the absorb fold with an all-zero 1600-bit state.",
      detail: `The sponge starts from the all-zero state (FIPS 202 §4). This leaf
loads the 200 zero bytes that seed the per-block fold's running state; every bit
of structure then comes from absorbing the (prefixed) message and permuting.`,
      references: ["FIPS 202 §4 (sponge construction)"],
    },
    absorb: {
      split: {
        name: `Split state into rate (${rate}) + capacity (${capacity})`,
        summary: `Separate the running state's absorbing part (first ${rate} bytes) from its hidden capacity (last ${capacity}).`,
        detail: `The sponge only mixes each block into the **rate** — the first
${rate} bytes. The remaining ${capacity} bytes are the **capacity**, never
touched by the message directly; that hidden part sets the ${(capacity * 8) / 2}-bit
security level. This split isolates the rate so the next step XORs the block in.`,
        references: ["FIPS 202 §4 (rate and capacity)"],
      },
      xor: {
        name: "Absorb: XOR this block into the rate",
        summary: `XOR the ${rate}-byte block into the first ${rate} bytes of the state.`,
        detail: `Absorbing a block XORs it into the rate portion of the state
(FIPS 202 §4) — the only place bytes enter the sponge. After the XOR the whole
state is permuted, spreading the block across all 1600 bits before the next.`,
        references: ["FIPS 202 §4 (absorbing)"],
      },
      concat: {
        name: "Reassemble the 200-byte state",
        summary: "Join the freshly-absorbed rate back with the untouched capacity.",
        detail: `Rejoins the ${rate}-byte rate with the ${capacity}-byte capacity
into the full 200-byte state the Keccak-f permutation will scramble.`,
        references: ["FIPS 202 §4 (sponge construction)"],
      },
    },
    extract: (j, _numBlocks) => ({
      name:
        j === 0 ? `Squeeze block 0 (first ${rate} bytes)` : `Squeeze block ${j} (${rate} bytes)`,
      summary: `Take ${rate} bytes off the ${j === 0 ? "absorbed" : "re-permuted"} state as output block ${j}.`,
      detail: `Squeezing extracts the first ${rate} bytes (the **rate**) of the
current state as a chunk of the ${displayName} output stream (FIPS 202 §4). ${
        j === 0
          ? "Block 0 comes straight off the state the absorb phase left — no permutation first."
          : `Block ${j} comes off the state after permutation ${j}.`
      } The hidden capacity is never emitted, which keeps the function one-way.`,
      references: ["FIPS 202 §4 (squeezing)"],
    }),
    concat: (numBlocks) => ({
      name: "Concatenate squeeze blocks",
      summary: `Join the ${numBlocks} squeezed ${rate}-byte blocks into one ${numBlocks * rate}-byte stream.`,
      detail: `The squeeze produced ${numBlocks} blocks of ${rate} bytes; this
joins them in order into the raw output stream, from which the final step keeps
only the requested number of bytes.`,
      references: ["FIPS 202 §4 (squeezing)", "FIPS 202 Algorithm 8"],
    }),
    truncate: {
      name: `Truncate to ${outputLength} bytes`,
      summary: `Keep the first ${outputLength} bytes of the squeeze stream as the ${displayName} output.`,
      detail: `The function emits a caller-chosen length. The squeeze produced
whole rate-sized blocks; this keeps exactly the first ${outputLength} bytes and
discards the rest (FIPS 202 §4, Algorithm 8 — \`Trunc_${outputLength * 8}\` of
the squeeze stream).`,
      references: ["FIPS 202 §4 (squeezing)", "NIST SP 800-185"],
    },
  };
};

/**
 * Build the unrolled squeeze (FIPS 202 Algorithm 8): `numBlocks =
 * ceil(outputLength / rate)` output blocks, each extracted from a state that has
 * been permuted once more than the last (block 0 straight off the absorbed
 * state). No permutation after the final extract. Returns the squeeze step nodes
 * and the port carrying the truncated output.
 */
const buildSqueeze = (
  rate: number,
  outputLength: number,
  narration: SpongeNarration,
): { readonly steps: StepNode[]; readonly output: PortBinding } => {
  const numBlocks = Math.ceil(outputLength / rate);
  const steps: StepNode[] = [];

  // Block 0: extract straight off the absorbed sponge state.
  steps.push({
    kind: "step",
    id: "squeeze.extract.0",
    type: "byte-slice@1",
    params: { sourceByteLength: STATE_BYTES, offset: 0, length: rate },
    portInputs: { input: port("sponge", "state") },
    narrationOverride: narration.extract(0, numBlocks),
  });

  // Blocks 1..numBlocks-1: permute once more, then extract.
  for (let j = 1; j < numBlocks; j++) {
    const permId = `squeeze.perm.${j}`;
    // perm.1 seeds from the absorbed state; perm.j (j>1) from perm.{j-1}'s exit.
    const seed = j === 1 ? port("sponge", "state") : port(`squeeze.perm.${j - 1}`, "out");
    // The perm group carries its pedagogy via its label; the family-neutral
    // Keccak-f rounds inside inherit the shared θρπχι narration.
    steps.push(buildKeccakPermGroup(permId, `Squeeze permutation ${j}`, seed));
    steps.push({
      kind: "step",
      id: `squeeze.extract.${j}`,
      type: "byte-slice@1",
      params: { sourceByteLength: STATE_BYTES, offset: 0, length: rate },
      portInputs: { input: port(permId, "out") },
      narrationOverride: narration.extract(j, numBlocks),
    });
  }

  // Join the blocks (only when there is more than one) and truncate to length.
  let sliceSource: PortBinding;
  let sliceSourceLen: number;
  if (numBlocks > 1) {
    const concatInputs: Record<string, PortBinding> = {};
    for (let j = 0; j < numBlocks; j++) {
      concatInputs[`input${j}`] = port(`squeeze.extract.${j}`, "output");
    }
    steps.push({
      kind: "step",
      id: "squeeze.concat",
      type: "concat@1",
      params: { inputCount: numBlocks },
      portInputs: concatInputs,
      narrationOverride: narration.concat(numBlocks),
    });
    sliceSource = port("squeeze.concat", "output");
    sliceSourceLen = numBlocks * rate;
  } else {
    sliceSource = port("squeeze.extract.0", "output");
    sliceSourceLen = rate;
  }

  steps.push({
    kind: "step",
    id: "squeeze.truncate",
    type: "byte-slice@1",
    params: { sourceByteLength: sliceSourceLen, offset: 0, length: outputLength },
    portInputs: { input: sliceSource },
    narrationOverride: narration.truncate,
  });

  return { steps, output: port("squeeze.truncate", "output") };
};

/**
 * Build the full sponge tail: an all-zero initial state, the per-block Keccak-f
 * absorb fold seeded from `padOutput`, and the unrolled squeeze producing
 * `outputLength` bytes. The caller supplies the padded-message port
 * (`padOutput`) and the constant `S0` (all-zero state) via `cipherConstants`.
 *
 * Returns the step nodes (in order: `init-state`, `sponge` iterate, squeeze) and
 * the port carrying the final output.
 */
export const buildSpongeSqueeze = (
  rate: number,
  outputLength: number,
  padOutput: PortBinding,
  narration: SpongeNarration,
): { readonly steps: StepNode[]; readonly outputFrom: PortBinding } => {
  const squeeze = buildSqueeze(rate, outputLength, narration);
  const steps: StepNode[] = [
    // ─── Initial all-zero sponge state (the fold's chainInput) ─────────────
    {
      kind: "step",
      id: "init-state",
      type: "aux-load-bytes@1",
      params: { auxName: "S0", byteLength: STATE_BYTES },
      narrationOverride: narration.initState,
    },
    // ─── Sponge absorb fold (one Keccak-f[1600] per rate block) ────────────
    {
      kind: "iterate",
      id: "sponge",
      label: "Sponge absorb (Keccak-f[1600] per block)",
      blockByteLength: rate,
      seedInput: padOutput,
      chainInput: port("init-state", "output"),
      chainFeedback: port(`round.${ROUNDS - 1}`, "out"),
      bodyOutput: port(`round.${ROUNDS - 1}`, "out"),
      chainOutput: "state",
      children: [
        ...buildAbsorbSteps(rate, narration.absorb),
        ...buildKeccakRounds("", port("absorb", "output")),
      ],
    },
    // ─── Squeeze (unrolled): extract → permute → extract → concat → trunc ───
    ...squeeze.steps,
  ];
  return { steps, outputFrom: squeeze.output };
};
