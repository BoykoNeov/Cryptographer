/**
 * SHAKE128 / SHAKE256 — the variable-length extendable-output functions (XOFs)
 * of FIPS 202, 2026-07-13. The app's first XOFs and the natural next slice
 * after SHA3-256: same Keccak-f[1600] permutation, same sponge absorb, but the
 * output is **arbitrarily long**.
 *
 * **What makes a SHAKE a SHAKE (vs SHA3-256):**
 *   - **Rate.** SHAKE128 absorbs/squeezes 168 bytes per block (capacity 256
 *     bits); SHAKE256 uses 136 bytes (capacity 512 bits — the same rate as
 *     SHA3-256, but a different function). Bigger rate ⇒ faster but a smaller
 *     security margin: SHAKE128 targets 128-bit, SHAKE256 256-bit strength.
 *   - **Domain byte 0x1F** (both), vs SHA-3's 0x06 — the two-bit XOF suffix
 *     `11` prepended to pad10*1. `keccak.pad@1` computes `0x1F ^ 0x80 = 0x9F`
 *     for the one-byte-short merge case generically (no hardcoded constant).
 *   - **Squeeze loop.** SHA3-256's 32-byte digest fits in one rate block, so it
 *     squeezes once. A SHAKE's output can exceed the rate, so it **squeezes r
 *     bytes, permutes, squeezes r more, …** until it has enough, then truncates
 *     to the requested length (FIPS 202 §4, Algorithm 8).
 *
 * **The squeeze is unrolled, not an `iterate`.** The port-mode iterate derives
 * its count from `seedInput.length / blockByteLength` — there is no
 * explicit-count path, and a squeeze's block count comes from the *desired
 * output length*, not from any input array. Unrolling is also more faithful to
 * Algorithm 8, which breaks the loop **before** the final permutation: for
 * `n = ceil(outputLength / rate)` output blocks there are exactly `n` extracts
 * and `n − 1` permutations — **no trailing wasted Keccak-f**. So:
 *
 * ```
 *   extract.0  ← Trunc_r(absorbed state)            # block 0, no permute first
 *   perm.1 = f(absorbed state) ;  extract.1 ← Trunc_r(perm.1)
 *   perm.2 = f(perm.1)         ;  extract.2 ← Trunc_r(perm.2)
 *   …
 *   concat(block 0 … block n−1)  →  truncate to outputLength
 * ```
 *
 * When `outputLength ≤ rate` (n = 1) the squeeze collapses to a single extract
 * + truncate — the same shape as SHA3-256.
 *
 * **Editable output length.** `outputLength` is a builder parameter, captured
 * structurally in the spec (the `squeeze.truncate` step's `length`), so it
 * travels through Save / Share. The UI resizes it by *rebuilding* the spec
 * (the block count is structural — it changes how many `squeeze.perm.{j}`
 * groups exist), bounded by a legibility cap in `stores/spec.ts`.
 *
 * **KAT.** Byte-equal to `node:crypto`'s `shake128` / `shake256` across message
 * lengths *and* output lengths (`tests/shake-kat.test.ts`), e.g. SHAKE128("abc",
 * 32) = `5881092d…`, SHAKE256("") @32 = `46b9dd2b…`.
 *
 * **References:**
 *   - FIPS 202 §4 (sponge: absorb + squeeze), §6.2 (SHAKE definitions)
 *   - FIPS 202 §B.2 (domain separation), Algorithm 8 (the squeeze loop)
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import type { AbsorbNarration } from "./keccak-f";
import {
  RC_BYTES,
  ROUNDS,
  S0_BYTES,
  STATE_BYTES,
  buildAbsorbSteps,
  buildKeccakPermGroup,
  buildKeccakRounds,
  port,
} from "./keccak-f";

// ─── SHAKE variants + parameters ────────────────────────────────────────────

export type ShakeVariant = "shake128" | "shake256";

/** Sponge rate in bytes per variant. Capacity = STATE_BYTES − rate. */
const RATE_BY_VARIANT: Record<ShakeVariant, number> = {
  shake128: 168, // capacity 256 bits → 128-bit security
  shake256: 136, // capacity 512 bits → 256-bit security
};

/** Domain-separation byte for every SHAKE (the XOF suffix `11` + pad start). */
const DOMAIN_SHAKE = 0x1f;

const DISPLAY_NAME: Record<ShakeVariant, string> = {
  shake128: "SHAKE128",
  shake256: "SHAKE256",
};

// ─── narrationOverride: SHAKE-specific prose ────────────────────────────────
//
// The Keccak-f round prose (θρπχι) is shared from `keccak-f.ts`. These blocks
// carry SHAKE's rate/domain/XOF wording — parameterized by rate because
// SHAKE128 (168/32) and SHAKE256 (136/64) split the state differently, and both
// differ from SHA3-256's fixed-digest framing.

const narrPad = (variant: ShakeVariant, rate: number): StepDocumentation => ({
  name: "Pad + domain-separate (pad10*1, FIPS 202 §5.1)",
  summary: `Append the SHAKE domain byte 0x1F and pad with the 10*1 rule to a multiple of the ${rate}-byte rate.`,
  detail: `${DISPLAY_NAME[variant]} extends the message to a whole number of
${rate}-byte sponge blocks: append the domain byte \`0x1F\` (the XOF
domain-separation suffix, which also carries the padding's leading 1-bit),
zero-fill, then set the top bit of the last byte. The \`0x1F\` is what keeps a
SHAKE's output distinct from SHA-3's (\`0x06\`) and from a raw Keccak sponge for
the same message. When the message is one byte short of a block the two pad bits
merge into a single \`0x9F\` byte (\`0x1F | 0x80\`).`,
  references: ["FIPS 202 §5.1 (pad10*1)", "FIPS 202 §B.2 (domain separation)"],
});

const narrInitState: StepDocumentation = {
  name: "Initial sponge state (200 zero bytes)",
  summary: "Bootstrap the absorb fold with an all-zero 1600-bit state.",
  detail: `The sponge starts from the all-zero state (FIPS 202 §4). This leaf
loads the 200 zero bytes that seed the per-block fold's running state; every bit
of structure then comes from absorbing the message and permuting.`,
  references: ["FIPS 202 §4 (sponge construction)"],
};

const narrAbsorb = (rate: number): AbsorbNarration => {
  const capacity = STATE_BYTES - rate;
  return {
    split: {
      name: `Split state into rate (${rate}) + capacity (${capacity})`,
      summary: `Separate the running state's absorbing part (first ${rate} bytes) from its hidden capacity (last ${capacity}).`,
      detail: `The sponge only mixes the message into the **rate** portion — the
first ${rate} bytes. The remaining ${capacity} bytes are the **capacity**, never
touched directly by the message; that hidden part is what sets the XOF's
security level (${capacity * 8} capacity bits ⇒ ${(capacity * 8) / 2}-bit
strength). This split separates the two so the next step XORs the block into the
rate only.`,
      references: ["FIPS 202 §4 (rate and capacity)"],
    },
    xor: {
      name: "Absorb: XOR this block into the rate",
      summary: `XOR the ${rate}-byte message block into the first ${rate} bytes of the state.`,
      detail: `Absorbing a block means XORing it into the rate portion of the
state (FIPS 202 §4). This is the only place the message enters the sponge. After
the XOR the whole state is permuted, spreading the block's influence across all
1600 bits before the next block arrives.`,
      references: ["FIPS 202 §4 (absorbing)"],
    },
    concat: {
      name: "Reassemble the 200-byte state",
      summary: "Join the message-XORed rate back with the untouched capacity.",
      detail: `Rejoins the freshly-absorbed ${rate}-byte rate with the
${capacity}-byte capacity to form the full 200-byte state that the Keccak-f
permutation will scramble.`,
      references: ["FIPS 202 §4 (sponge construction)"],
    },
  };
};

const narrExtract = (variant: ShakeVariant, j: number, rate: number): StepDocumentation => ({
  name: j === 0 ? `Squeeze block 0 (first ${rate} bytes)` : `Squeeze block ${j} (${rate} bytes)`,
  summary: `Take ${rate} bytes off the ${j === 0 ? "absorbed" : "re-permuted"} state as output block ${j}.`,
  detail: `Squeezing extracts the first ${rate} bytes (the **rate**) of the
current state as a chunk of the ${DISPLAY_NAME[variant]} output stream (FIPS 202
§4). ${
    j === 0
      ? "Block 0 comes straight off the state left by the absorb phase — no permutation first."
      : `Block ${j} comes off the state after permutation ${j}.`
  } The hidden capacity bytes are never emitted, which is what keeps the XOF
one-way.`,
  references: ["FIPS 202 §4 (squeezing)"],
});

const narrConcat = (numBlocks: number, rate: number): StepDocumentation => ({
  name: "Concatenate squeeze blocks",
  summary: `Join the ${numBlocks} squeezed ${rate}-byte blocks into one ${numBlocks * rate}-byte stream.`,
  detail: `The squeeze produced ${numBlocks} blocks of ${rate} bytes; this joins
them in order into the raw output stream, from which the final step keeps only as
many bytes as the requested output length.`,
  references: ["FIPS 202 §4 (squeezing)", "FIPS 202 Algorithm 8"],
});

const narrTruncate = (variant: ShakeVariant, outputLength: number): StepDocumentation => ({
  name: `Truncate to ${outputLength} bytes`,
  summary: `Keep the first ${outputLength} bytes of the squeeze stream as the ${DISPLAY_NAME[variant]} output.`,
  detail: `An XOF emits an output of a caller-chosen length. The squeeze produced
whole rate-sized blocks; this final step keeps exactly the first ${outputLength}
bytes and discards the rest (FIPS 202 §4, Algorithm 8 — the output is
\`Trunc_${outputLength * 8}\` of the squeeze stream). Change the output length in
the control above to see blocks appear or disappear.`,
  references: ["FIPS 202 §4 (squeezing)", "FIPS 202 §6.2 (SHAKE)"],
});

// ─── Squeeze (unrolled) ─────────────────────────────────────────────────────

/**
 * Build the unrolled squeeze: `numBlocks = ceil(outputLength / rate)` output
 * blocks, each extracted from a state that has been permuted once more than the
 * last (except block 0, straight off the absorbed state). No permutation after
 * the final extract. Returns the squeeze step nodes and the port carrying the
 * truncated output.
 */
const buildSqueeze = (
  variant: ShakeVariant,
  rate: number,
  outputLength: number,
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
    narrationOverride: narrExtract(variant, 0, rate),
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
      narrationOverride: narrExtract(variant, j, rate),
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
      narrationOverride: narrConcat(numBlocks, rate),
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
    narrationOverride: narrTruncate(variant, outputLength),
  });

  return { steps, output: port("squeeze.truncate", "output") };
};

// ─── Spec builder ────────────────────────────────────────────────────────────

/**
 * Build a SHAKE spec: pad → sponge-absorb fold (Keccak-f[1600] per block) →
 * unrolled squeeze producing `outputLength` bytes.
 *
 * `outputLength` is validated as a positive integer by the caller (the store
 * clamps it to `[1, MAX_SHAKE_OUTPUT]`); here it is trusted and drives the
 * squeeze block count structurally.
 */
export const buildShakeSpec = (variant: ShakeVariant, outputLength: number): CipherSpec => {
  const rate = RATE_BY_VARIANT[variant];
  const squeeze = buildSqueeze(variant, rate, outputLength);
  return {
    id: `${variant}@1`,
    name: DISPLAY_NAME[variant],
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 }, // XOFs have no key
    },
    steps: [
      // ─── Padding (pad10*1 + domain byte 0x1F) ────────────────────────────
      {
        kind: "step",
        id: "pad",
        type: "keccak.pad@1",
        params: { rate, domainByte: DOMAIN_SHAKE },
        portInputs: { input: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) },
        narrationOverride: narrPad(variant, rate),
      },
      // ─── Initial all-zero sponge state (the fold's chainInput) ───────────
      {
        kind: "step",
        id: "init-state",
        type: "aux-load-bytes@1",
        params: { auxName: "S0", byteLength: STATE_BYTES },
        narrationOverride: narrInitState,
      },
      // ─── Sponge absorb fold (one Keccak-f[1600] per rate block) ──────────
      {
        kind: "iterate",
        id: "sponge",
        label: "Sponge absorb (Keccak-f[1600] per block)",
        blockByteLength: rate,
        seedInput: port("pad", "output"),
        chainInput: port("init-state", "output"),
        chainFeedback: port(`round.${ROUNDS - 1}`, "out"),
        bodyOutput: port(`round.${ROUNDS - 1}`, "out"),
        chainOutput: "state",
        children: [
          ...buildAbsorbSteps(rate, narrAbsorb(rate)),
          ...buildKeccakRounds("", port("absorb", "output")),
        ],
      },
      // ─── Squeeze (unrolled): extract → permute → extract → concat → trunc ─
      ...squeeze.steps,
    ],
    // Published constants materialized into aux before the walk: RC (24-lane
    // round-constant table) + S0 (the all-zero initial state).
    cipherConstants: { RC: RC_BYTES, S0: S0_BYTES },
    outputFrom: squeeze.output,
  };
};

/** Read the output length back from a built SHAKE spec (the `squeeze.truncate`
 *  step's `length` param). Used by `applyDocument` to sync the output-length
 *  control after loading a saved / shared SHAKE document; returns `undefined`
 *  if the spec has no recognizable truncate step. */
export const readShakeOutputLength = (spec: CipherSpec): number | undefined => {
  for (const node of spec.steps) {
    if (node.kind === "step" && node.id === "squeeze.truncate") {
      const len = (node.params as Record<string, unknown>).length;
      if (typeof len === "number" && Number.isInteger(len) && len >= 1) return len;
    }
  }
  return undefined;
};

/** The variant's rate — exported so the UI stepper can step by whole blocks. */
export const shakeRate = (variant: ShakeVariant): number => RATE_BY_VARIANT[variant];
