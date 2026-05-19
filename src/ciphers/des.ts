/**
 * DES (Data Encryption Standard) encrypt spec. FIPS 46-3.
 *
 * Single-block: 64-bit plaintext, 64-bit key, 64-bit ciphertext. The same
 * algorithm decrypts when the round keys are consumed in reverse (see
 * `des-decrypt.ts`).
 *
 * **The first cipher to use the `feistel-round` branching primitive.** The
 * round body is wrapped in a `feistel-round` node (Phase 2 of
 * `docs/plans/des-feistel.md`) with two tracks:
 *   - **L track** — passthrough, no children. Bytes [0..3] of the round's
 *     8-byte input slide through unchanged; the rejoin combine reads
 *     `L_in` to construct the next round's halves.
 *   - **R track** — runs the F function: E (expansion) → XOR with K_i →
 *     S-boxes → P (permutation). Bytes [4..7] of the round's input feed
 *     this track.
 *
 * Rounds 1..15 use `combineKind: "feistel-standard"` (textbook Feistel with
 * the post-round swap). Round 16 uses `combineKind: "feistel-no-swap"` —
 * the textbook "last round" exception that makes the cipher self-inverse
 * under key-reversal. The distinction is SPEC-VISIBLE rather than hidden in
 * the runtime: a user clicking round 16 in the linear view sees a different
 * combine kind from rounds 1..15 and can read its formula.
 *
 * **Wrapped between IP and FP.** The Initial Permutation runs once before
 * round 1; the Final Permutation runs once after round 16. Neither has
 * cryptographic value (relics of bit-serial hardware) — they're kept
 * visible in the spec so the standard's structure is intact.
 */

import type { CipherSpec, CombineKind, FeistelRoundGroup, StepNode } from "../core/types";
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

/**
 * Build one Feistel-round node for DES. `roundIdx` is 1-based to match
 * FIPS notation; `auxIdx` is the 0-based round-key index in aux (encrypt
 * passes `roundIdx - 1`, decrypt passes the reverse).
 *
 * Tracks declared as L = bytes [0..3], R = bytes [4..7]. Future ciphers
 * with non-contiguous halves (none planned today) could declare different
 * `inputBytes`; the runtime supports any disjoint covering.
 *
 * Round-key aux name is `roundKey.{auxIdx}` — the convention shared with
 * `aes.key-expansion@1`'s `outputPrefix: "roundKey"` and consumed by the
 * future linear-mode `RoundKeyPanel` (Phase 5d of the plan).
 */
const buildDesRound = (
  roundIdx: number,
  auxIdx: number,
  combineKind: CombineKind,
): FeistelRoundGroup => ({
  kind: "feistel-round",
  id: `round.${roundIdx}`,
  label: `Round ${roundIdx}`,
  tracks: [
    // L track: empty passthrough. The runtime emits zero frames for it
    // and routes L_in through to the combine as L_out unchanged.
    { name: "L", inputBytes: [0, 1, 2, 3], children: [] },
    // R track: runs F = P(S(E(R) ⊕ K_i)).
    {
      name: "R",
      inputBytes: [4, 5, 6, 7],
      children: [
        {
          kind: "step",
          id: `round.${roundIdx}.expand-R`,
          type: "des.expand-R@1",
          params: { table: [...DES_E] },
        },
        {
          kind: "step",
          id: `round.${roundIdx}.xor-K`,
          type: "des.xor-with-K@1",
          params: { roundKeyAux: `roundKey.${auxIdx}` },
        },
        {
          kind: "step",
          id: `round.${roundIdx}.s-boxes`,
          type: "des.s-boxes@1",
          params: { sboxes: DES_SBOXES.map((box) => box.map((row) => [...row])) },
        },
        {
          kind: "step",
          id: `round.${roundIdx}.p-permute`,
          type: "des.p-permutation@1",
          params: { table: [...DES_P] },
        },
      ],
    },
  ],
  combineKind,
});

/**
 * Build the body of the encrypt round sequence: 16 Feistel rounds wrapped
 * in a group for graph-view collapse + linear-view section header. Rounds
 * 1..15 use the standard combine; round 16 uses no-swap.
 *
 * Decrypt builds an equivalent sequence with `auxIdx` reversed and the
 * same combineKind layout (no-swap on the LAST round) — see
 * `buildDesDecryptRounds`.
 */
export const buildDesEncryptRounds = (): StepNode => ({
  kind: "group",
  id: "rounds",
  label: "Rounds",
  children: [
    // Rounds 1..15 — feistel-standard. roundIdx == auxIdx + 1 for encrypt.
    ...Array.from({ length: 15 }, (_, i) => buildDesRound(i + 1, i, "feistel-standard")),
    // Round 16 — feistel-no-swap (the textbook "last round" exception).
    buildDesRound(16, 15, "feistel-no-swap"),
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
    },
    buildDesEncryptRounds(),
    {
      kind: "step",
      id: "final-permutation",
      type: "des.final-permutation@1",
      params: { table: [...DES_FP] },
    },
  ],
};
