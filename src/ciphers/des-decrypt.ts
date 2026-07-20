/**
 * DES decrypt spec. Inverse of `des.ts`.
 *
 * **Why a separate spec rather than reusing the encrypt spec with a flag?**
 * The project's two-spec store holds encrypt + decrypt simultaneously and
 * NEVER auto-syncs them — `[[feedback-cross-mode-no-auto-sync]]`. The user
 * sees both halves of the algorithm side-by-side and can edit either
 * independently to learn what breaks.
 *
 * **Algorithm.** Same body as encrypt — IP → 16 rounds → FP, with the
 * round-16 "no swap" exception. Only the per-round key consumption order
 * changes:
 *
 *     Encrypt round r ∈ 1..16 uses K_r           (aux roundKey.{r-1})
 *     Decrypt round r ∈ 1..16 uses K_{17-r}      (aux roundKey.{16-r})
 *
 * The "no swap" on the LAST round of *each* direction is what makes the
 * cipher self-inverse: with the swap on rounds 1..15 and no-swap on round
 * 16, running the same body backwards with reversed keys recovers the
 * plaintext. The key schedule runs the same way in both directions — it's
 * the per-round assignment that flips.
 *
 * Educational check the user can do: edit round 16's recombine to use the
 * swap order in either spec and watch the cipher stop round-tripping.
 *
 * **Port-native since B4 (universal-port Phase 4d).** Like `des.ts`, decrypt
 * no longer uses `feistel-round`: each round is a port-mode group wiring
 * split-bytes / des.expand-R / des.xor-with-K / des.s-boxes /
 * des.p-permutation / xor / concat, with the swap expressed as the concat
 * argument order. The round builder is duplicated here (rather than imported
 * from `des.ts`) to keep this spec self-contained — a user can read it
 * front-to-back without chasing.
 */

import type { CipherSpec, PortBinding, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { DES_E, DES_FP, DES_IP, DES_P, DES_SBOXES } from "./des-constants";
import { buildDesKeyScheduleNative } from "./des-key-schedule-builder-native";

/** Spell a port binding the way the runtime + the editor expect it. */
const port = (
  node: string,
  portName: string,
): { readonly node: string; readonly port: string } => ({
  node,
  port: portName,
});

/**
 * Build one DES round as a port-mode group. Same builder as encrypt's, but
 * the caller passes `auxIdx` so decrypt round r (1..16) reads
 * roundKey.{16 - r}. `swap` is `true` for rounds 1..15, `false` for round 16.
 * `seedInput` is caller-supplied (round 1 seeds across the outer group
 * boundary, later rounds from the previous round's output).
 */
const buildDesRound = (
  roundIdx: number,
  auxIdx: number,
  swap: boolean,
  seedInput: { readonly node: string; readonly port: string },
): StepNode => {
  const p = `round.${roundIdx}`;
  const r = (node: string, portName: string) => port(`${p}.${node}`, portName);
  // The recombine (concat) argument order IS the Feistel swap.
  const recombineInputs = swap
    ? { input0: r("split", "output1"), input1: r("fxor", "output") } // R || (L⊕F)
    : { input0: r("fxor", "output"), input1: r("split", "output1") }; // (L⊕F) || R
  return {
    kind: "group",
    id: p,
    label: `Round ${roundIdx}`,
    seedInput,
    bodyOutput: r("recombine", "output"),
    children: [
      {
        kind: "step",
        id: `${p}.split`,
        type: "split-bytes@1",
        params: { widths: [4, 4] },
        portInputs: { input: port(p, "in") },
      },
      {
        kind: "step",
        id: `${p}.expand-R`,
        type: "des.expand-R@1",
        params: { table: [...DES_E] },
        portInputs: { state: r("split", "output1") },
      },
      {
        kind: "step",
        id: `${p}.xor-K`,
        type: "des.xor-with-K@1",
        params: { roundKeyAux: `roundKey.${auxIdx}` },
        portInputs: { state: r("expand-R", "state") },
      },
      {
        kind: "step",
        id: `${p}.s-boxes`,
        type: "des.s-boxes@1",
        params: { sboxes: DES_SBOXES.map((box) => box.map((row) => [...row])) },
        portInputs: { state: r("xor-K", "state") },
      },
      {
        kind: "step",
        id: `${p}.p-permute`,
        type: "des.p-permutation@1",
        params: { table: [...DES_P] },
        portInputs: { state: r("s-boxes", "state") },
      },
      {
        kind: "step",
        id: `${p}.fxor`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("split", "output0"), operand1: r("p-permute", "state") },
      },
      {
        kind: "step",
        id: `${p}.recombine`,
        type: "concat@1",
        params: { inputCount: 2 },
        portInputs: recombineInputs,
      },
    ],
  };
};

/**
 * Build the 16-round body for decrypt. Decrypt round r ∈ 1..16 consumes
 * aux roundKey.{16 - r}:
 *   r = 1  → roundKey.15 (= K_16)
 *   r = 2  → roundKey.14 (= K_15)
 *   …
 *   r = 16 → roundKey.0  (= K_1)
 *
 * Round 16 (decrypt's last) is the no-swap exception, same as encrypt's
 * round 16. The "no swap on the last round" rule applies to each direction
 * independently. The outer "rounds" group is port-mode so round 1 can seed
 * from the Initial Permutation across the group boundary (see `des.ts`).
 */
const buildDesDecryptRounds = (): StepNode => ({
  kind: "group",
  id: "rounds",
  label: "Rounds",
  seedInput: port("initial-permutation", "state"),
  bodyOutput: port("round.16", "out"),
  children: [
    ...Array.from({ length: 15 }, (_, i) =>
      buildDesRound(
        i + 1,
        15 - i,
        true,
        i === 0 ? port("rounds", "in") : port(`round.${i}`, "out"),
      ),
    ),
    // Round 16 (decrypt's last) — no-swap, consuming K_1 (roundKey.0).
    buildDesRound(16, 0, false, port("round.15", "out")),
  ],
});

/**
 * The DES decrypt **body** — IP → 16 rounds (reversed key order) → FP —
 * reading its block from `seed`. Mirrors `buildDesEncryptBody` in `des.ts`,
 * duplicated here for the same self-containment reason as the round builder
 * above: a reader can follow decrypt front-to-back without chasing.
 *
 * Excludes the key schedule, which a mode of operation runs ONCE outside the
 * per-block loop. The seed is a parameter because a body inside a port-mode
 * `iterate` receives its block on the iterate's injected port — the runtime
 * seeds `$input` at top scope only. The single-block spec below passes
 * `$input`; `des-core.ts` passes the mode's block port.
 */
export const buildDesDecryptBody = (
  seed: PortBinding,
): { nodes: StepNode[]; output: PortBinding } => ({
  nodes: [
    {
      kind: "step",
      id: "initial-permutation",
      type: "des.initial-permutation@1",
      params: { table: [...DES_IP] },
      portInputs: { state: seed },
    },
    buildDesDecryptRounds(),
    {
      kind: "step",
      id: "final-permutation",
      type: "des.final-permutation@1",
      params: { table: [...DES_FP] },
      portInputs: { state: port("rounds", "out") },
    },
  ],
  output: port("final-permutation", "state"),
});

export const desDecryptSpec: CipherSpec = (() => {
  const { nodes, output } = buildDesDecryptBody(port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT));
  return {
    id: "des-decrypt@1",
    name: "DES (decrypt)",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 8 },
    },
    steps: [
      // Decomposed key schedule (key-schedule-decomposition K4a) — identical to
      // encrypt's. The schedule produces the SAME 16 round keys in BOTH
      // directions; only the per-round CONSUMPTION order flips (decrypt round r
      // reads roundKey.{16 - r}), which is handled above in the round wiring.
      buildDesKeyScheduleNative(),
      ...nodes,
    ],
    outputFrom: output,
  };
})();
