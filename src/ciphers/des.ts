/**
 * DES (Data Encryption Standard) encrypt spec. FIPS 46-3.
 *
 * Single-block: 64-bit plaintext, 64-bit key, 64-bit ciphertext. The same
 * algorithm decrypts when the round keys are consumed in reverse (see
 * `des-decrypt.ts`).
 *
 * **Port-native since B4 (universal-port Phase 4d).** DES no longer uses the
 * `feistel-round` branching primitive — the universal-port plan's thesis is
 * that Feistel needs no special primitive, and DES is the proof. Each round
 * is a port-mode `group` (SHA-256's compression-round template) whose body
 * wires the F function and the recombine from native primitives:
 *
 * ```
 * split-bytes widths=[4,4]   port("round.r","in")  → output0 = L, output1 = R
 * des.expand-R               state ← split.output1  → 48-bit E(R)
 * des.xor-with-K  roundKeyAux state ← expand-R;       → E ⊕ K_i
 *                            roundKey ← aux[roundKey.{auxIdx}]  (meta.auxReadPorts)
 * des.s-boxes                state ← xor-K           → 32-bit S(...)
 * des.p-permutation          state ← s-boxes         → F = P(S(...))
 * xor inputCount=2           operand0 = L, operand1 = F  → L ⊕ F
 * concat inputCount=2        → the round output (8 bytes)
 * ```
 *
 * **The Feistel swap IS the concat argument order** — no special combine:
 *   - Rounds 1..15 (textbook swap):  output = R || (L ⊕ F)  =
 *     `concat(split.output1, fxor.output)`. Matches the old
 *     `feistel-standard` combine (`new_L = R_in, new_R = L_in ⊕ R_out`).
 *   - Round 16 (the "no swap" last-round exception):  output = (L ⊕ F) || R =
 *     `concat(fxor.output, split.output1)`. Matches `feistel-no-swap`
 *     (`new_L = L_in ⊕ R_out, new_R = R_in`). The exception is what makes the
 *     cipher self-inverse under key-reversal, and it stays SPEC-VISIBLE: a
 *     user comparing round 16's recombine wiring to rounds 1..15 sees the
 *     halves enter the concat in the opposite order.
 *
 * **Wrapped between IP and FP.** The Initial Permutation runs once before
 * round 1 (reading the plaintext from the reserved `$input` source); the
 * Final Permutation runs once after round 16 and is the cipher's
 * `outputFrom`. Neither has cryptographic value (relics of bit-serial
 * hardware) — kept visible so the standard's structure is intact.
 *
 * **Key schedule stays lifted** (`des.key-schedule@1`), aux-only — it runs
 * first, expands the 64-bit master key into 16 × 48-bit round keys under
 * `roundKey.0..15`, mirroring `aes.key-expansion@1`. Each round's `xor-K`
 * reads its slot from aux.
 */

import type { CipherSpec, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import {
  DES_E,
  DES_FP,
  DES_IP,
  DES_P,
  DES_PC1,
  DES_PC2,
  DES_SBOXES,
  DES_SHIFTS,
} from "./des-constants";

/** Spell a port binding the way the runtime + the editor expect it. */
const port = (
  node: string,
  portName: string,
): { readonly node: string; readonly port: string } => ({
  node,
  port: portName,
});

/**
 * Build one DES round as a port-mode group. `roundIdx` is 1-based (FIPS
 * notation); `auxIdx` is the 0-based round-key slot consumed (encrypt passes
 * `roundIdx - 1`, decrypt passes the reverse). `swap` selects the recombine
 * order: `true` for the textbook rounds 1..15, `false` for the round-16
 * "no swap" exception.
 *
 * `seedInput` is supplied by the caller because round 1 seeds from the outer
 * "rounds" group's injected `"in"` port while later rounds seed from the
 * previous round's published `"out"` — a scope detail the round body itself
 * shouldn't know about.
 */
const buildDesRound = (
  roundIdx: number,
  auxIdx: number,
  swap: boolean,
  seedInput: { readonly node: string; readonly port: string },
): StepNode => {
  const p = `round.${roundIdx}`;
  // Round-local port helper: prefix a sibling leaf id with the round id.
  const r = (node: string, portName: string) => port(`${p}.${node}`, portName);
  // The recombine (concat) argument order IS the Feistel swap. See file header.
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
      // Split the 8-byte round input into L (bytes 0..3) and R (bytes 4..7).
      {
        kind: "step",
        id: `${p}.split`,
        type: "split-bytes@1",
        params: { widths: [4, 4] },
        portInputs: { input: port(p, "in") },
      },
      // F function on R: E → ⊕K_i → S-boxes → P.
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
      // L ⊕ F (the Feistel mix). operand0 = L (split.output0), operand1 = F.
      {
        kind: "step",
        id: `${p}.fxor`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("split", "output0"), operand1: r("p-permute", "state") },
      },
      // Recombine into the 8-byte round output. Argument order = the swap.
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
 * Build the 16-round body as a port-mode group. The outer "rounds" group
 * exists for graph-view collapse + the linear-view section header; making it
 * a PORT-MODE group (its own `seedInput`/`bodyOutput`) is what lets round 1
 * seed from the Initial Permutation across the group boundary: the runtime
 * injects the IP output on `port("rounds","in")`, round 1 reads it, and each
 * later round reads the previous round's `"out"` (same child scope). The
 * group republishes round 16's output on `port("rounds","out")` for FP.
 *
 * Rounds 1..15 use the swap; round 16 is the no-swap exception. For encrypt,
 * round r consumes `roundKey.{r-1}`.
 */
export const buildDesEncryptRounds = (): StepNode => ({
  kind: "group",
  id: "rounds",
  label: "Rounds",
  seedInput: port("initial-permutation", "state"),
  bodyOutput: port("round.16", "out"),
  children: [
    ...Array.from({ length: 15 }, (_, i) =>
      buildDesRound(i + 1, i, true, i === 0 ? port("rounds", "in") : port(`round.${i}`, "out")),
    ),
    // Round 16 — the no-swap exception, consuming K_16 (roundKey.15).
    buildDesRound(16, 15, false, port("round.15", "out")),
  ],
});

export const desSpec: CipherSpec = {
  id: "des@1",
  name: "DES",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 8 },
  },
  steps: [
    {
      kind: "step",
      id: "key-schedule",
      type: "des.key-schedule@1",
      params: {
        keyAuxName: "key",
        outputPrefix: "roundKey",
        pc1: [...DES_PC1],
        pc2: [...DES_PC2],
        shifts: [...DES_SHIFTS],
      },
    },
    {
      kind: "step",
      id: "initial-permutation",
      type: "des.initial-permutation@1",
      params: { table: [...DES_IP] },
      // The plaintext arrives on the reserved `$input` source (no state thread).
      portInputs: { state: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) },
    },
    buildDesEncryptRounds(),
    {
      kind: "step",
      id: "final-permutation",
      type: "des.final-permutation@1",
      params: { table: [...DES_FP] },
      portInputs: { state: port("rounds", "out") },
    },
  ],
  // The 8-byte ciphertext leaves the cipher straight off FP's `state` port.
  outputFrom: port("final-permutation", "state"),
};
