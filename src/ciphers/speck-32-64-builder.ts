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

import type { CipherSpec, StepNode } from "../core/types";
import type { SpeckByteOrder } from "../steps/speck-word-codec";

// Cipher constants — kept here so a future Speck64/128 builder can sit
// alongside this one with its own constants and the rest of the file is a
// near-identical clone.
const ROUNDS = 22;
const WORD_BITS = 16;
const M = 4;
const ALPHA = 7;
const BETA = 2;

export type Speck32_64Direction = "encrypt" | "decrypt";

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

  // The schedule step is identical for both directions. It writes
  // roundKey.0 … roundKey.{ROUNDS-1} to aux.
  const keySchedule: StepNode = {
    kind: "step",
    id: "key-schedule",
    type: "speck.key-schedule@1",
    params: {
      keyAuxName: "key",
      outputPrefix: "roundKey",
      rounds: ROUNDS,
      wordBits: WORD_BITS,
      m: M,
      alpha: ALPHA,
      beta: BETA,
      byteOrder,
    },
  };

  // For encrypt, round.i consumes roundKey.{i-1} (forward order).
  // For decrypt, round-inverse.i consumes roundKey.{ROUNDS-i} (reverse order):
  //   decrypt leaf 1 → roundKey.21
  //   decrypt leaf 2 → roundKey.20
  //   …
  //   decrypt leaf 22 → roundKey.0
  const rounds: StepNode[] = [];
  for (let i = 1; i <= ROUNDS; i++) {
    const rkIndex = direction === "encrypt" ? i - 1 : ROUNDS - i;
    const stepType = direction === "encrypt" ? "speck.round@1" : "speck.round-inverse@1";
    const idPrefix = direction === "encrypt" ? "round" : "round-inverse";
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
    });
  }

  return {
    id,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: M * (WORD_BITS / 8) }, // 8 bytes for Speck32/64
    },
    steps: [keySchedule, ...rounds],
  };
};
