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
    // Explicit state-spine wiring (Phase 5 Slice 5.3b): declare the `state`
    // input port so `inferPortEdges` owns the round→round spine and the
    // `inferStateEdges` legacy fallback can be retired (5.3e). The first
    // round reads the reserved `$input` source (the plaintext/ciphertext
    // block); every later round reads its predecessor's `state` output port.
    //
    // Byte-equality (the 5.3b load-bearing spike): each round leaf is
    // hybrid-ported (`speckRoundMeta` present, `legacy === undefined`), so
    // declaring `portInputs.state` makes the runtime resolve the carried
    // block from `nodeOutputs` (Step A) and SKIP the `meta.stateInputPort`
    // projection (Step B). For `stateLayout: "bytes"` the projection is the
    // identity over the predecessor's recorded output bytes, so the trace
    // stays byte-identical to the implicit state-thread. `roundKey` is left
    // unwired — it keeps flowing from `aux[roundKeyAux]` via Step C, so the
    // key-schedule→round fan-out edges in `frame.auxRead` are preserved.
    const stateBinding: PortBinding =
      i === 1 ? port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) : port(`${idPrefix}.${i - 1}`, "state");
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
