/**
 * Speck32/64 spec factory. Emits a full CipherSpec for a chosen
 * `(byteOrder, direction)` pair. The four shipped Speck specs
 * (BE encrypt, BE decrypt, LE encrypt, LE decrypt) all route through
 * this one factory so they can't drift in step count, ids, or constants.
 *
 * Speck32/64 constants (Beaulieu et al. 2013 Table 4.1):
 *   wordBits = 16, m = 4, rounds = 22, alpha = 7, beta = 2, key bytes = 8.
 *
 * Each spec lays out as flat top-level leaves (no per-round group wrapper):
 *   key-schedule
 *   round.1  (consumes roundKey.0)
 *   round.2  (consumes roundKey.1)
 *   ...
 *   round.22 (consumes roundKey.21)
 *
 * The decrypt spec consumes round keys in REVERSE leaf order — round-inverse.1
 * uses roundKey.21, ..., round-inverse.22 uses roundKey.0. The forward
 * key-schedule step runs unchanged in both directions; only the leaf
 * ordering encodes the reversal.
 */

import type { CipherSpec, PortBinding, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import type { SpeckByteOrder } from "../steps/speck-word-codec";
import { buildSpeck32_64KeyScheduleNative } from "./speck-32-64-key-schedule-builder-native";

// Tiny binding helper — mirrors the per-file `port()` in the AES/DES/ECB
// builders (Phase 5 Slice 5.3b). `{ node, port }` is the sink-side edge a
// leaf's `portInputs[portName]` resolves against `nodeOutputs` at runtime.
const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

// Cipher constants — kept here so a future Speck64/128 builder can sit
// alongside this one with its own constants and the rest of the file is a
// near-identical clone.
const ROUNDS = 22;
const WORD_BITS = 16;
const M = 4;
const ALPHA = 7;
const BETA = 2;

/** Speck32/64's block is 32 bits — two 16-bit words. The `BlockCipherCore`. */
export const SPECK_32_64_BLOCK_BYTES = 4;
/** Speck32/64's key is 64 bits — m=4 words × 16 bits. */
export const SPECK_32_64_KEY_BYTES = M * (WORD_BITS / 8);

export type Speck32_64Direction = "encrypt" | "decrypt";

/**
 * The Speck32/64 round pipeline, seed-parameterized — the block-cipher *body*
 * a mode of operation drives.
 *
 * Split out from `buildSpeck32_64Spec` (2026-07-18) so the same 22-round leaf
 * chain feeds both surfaces: the single-block spec passes `$input`, while a
 * `BlockCipherCore` (`speck-32-64-core.ts`) passes the iterate's injected block
 * port. Only round 1's `state` binding varies with `seed`; every later round
 * and every param is identical, so the mode specs are byte-for-byte what the
 * single-block spec produces per block.
 *
 * `output` names the exit port explicitly (the last round's `state`) because a
 * mode iterate's `bodyOutput` cannot fall back to the runtime's implicit
 * last-leaf rule — see `BlockCipherCore` (`block-cipher-core.ts`).
 *
 * The round-key wiring stays as it was: encrypt's round.i consumes
 * roundKey.{i-1} (forward), decrypt's round-inverse.i consumes
 * roundKey.{ROUNDS-i} (reverse) — the leaf ORDER is what encodes the reversal,
 * and `roundKey` flows from `aux[roundKeyAux]` (unwired), which crosses an
 * iterate's scope boundary because aux is global.
 */
export const buildSpeck32_64Body = (
  byteOrder: SpeckByteOrder,
  direction: Speck32_64Direction,
  seed: PortBinding,
): { nodes: StepNode[]; output: PortBinding } => {
  const stepType = direction === "encrypt" ? "speck.round@1" : "speck.round-inverse@1";
  const idPrefix = direction === "encrypt" ? "round" : "round-inverse";

  const rounds: StepNode[] = [];
  for (let i = 1; i <= ROUNDS; i++) {
    const rkIndex = direction === "encrypt" ? i - 1 : ROUNDS - i;
    // Round 1 reads the injected block (`seed`: `$input` single-block, or the
    // iterate's "in" port under a mode); every later round reads its
    // predecessor's `state` output. Same shape as AES/Serpent.
    const stateBinding: PortBinding = i === 1 ? seed : port(`${idPrefix}.${i - 1}`, "state");
    rounds.push({
      kind: "step",
      id: `${idPrefix}.${i}`,
      type: stepType,
      params: {
        roundKeyAux: `roundKey.${rkIndex}`,
        alpha: ALPHA,
        beta: BETA,
        wordBits: WORD_BITS,
        byteOrder,
      },
      portInputs: { state: stateBinding },
    });
  }

  // The ciphertext (or plaintext, decrypting) block leaves on the last round's
  // `state` output — all rounds share `speck.round@1`, so all publish `state`.
  return { nodes: rounds, output: port(`${idPrefix}.${ROUNDS}`, "state") };
};

/** The Speck32/64 key schedule as one node — run once, outside a mode's loop. */
export const buildSpeck32_64KeySchedule = (byteOrder: SpeckByteOrder): StepNode =>
  buildSpeck32_64KeyScheduleNative(ROUNDS, M, WORD_BITS, ALPHA, BETA, byteOrder);

export const buildSpeck32_64Spec = (
  byteOrder: SpeckByteOrder,
  direction: Speck32_64Direction,
): CipherSpec => {
  const orderTag = byteOrder === "be-paper" ? "be" : "le";
  const dirTag = direction === "encrypt" ? "" : "-decrypt";
  const id = `speck-32-64-${orderTag}${dirTag}@1`;
  const name = `Speck 32/64 (${byteOrder === "be-paper" ? "BE, paper" : "LE, NSA"}${
    direction === "decrypt" ? ", decrypt" : ""
  })`;

  // The schedule is identical for both directions — it writes
  // roundKey.0 … roundKey.{ROUNDS-1} to aux regardless. K2a (2026-06-01)
  // decomposes the previously monolithic `speck.key-schedule@1` leaf into
  // a tree of port-native primitives (ROR/ADD/XOR/ROL/XOR per
  // Beaulieu et al. 2013 §3) plus byte-order codec leaves at the I/O
  // boundary, all wrapped in a default-collapsed `key-schedule` group.
  // Published aux entries are byte-identical to the monolith's output, so
  // the round-body consumers below are untouched. See
  // `speck-32-64-key-schedule-builder-native.ts` for the structure.
  const keySchedule: StepNode = buildSpeck32_64KeySchedule(byteOrder);

  // The 22-round body, seeded from the reserved `$input` source (the
  // single-block plaintext/ciphertext). `buildSpeck32_64Body` owns the
  // round-key ordering (forward for encrypt, reversed for decrypt) and the
  // `state`-spine wiring; a mode reuses the same builder with a different seed.
  const { nodes: rounds } = buildSpeck32_64Body(
    byteOrder,
    direction,
    port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
  );

  return {
    id,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: SPECK_32_64_KEY_BYTES }, // 8 bytes for Speck32/64
    },
    steps: [keySchedule, ...rounds],
  };
};
