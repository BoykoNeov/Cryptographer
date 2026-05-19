/**
 * DES decrypt spec. Inverse of `des.ts`.
 *
 * **Why a separate spec rather than reusing the encrypt spec with a flag?**
 * The project's two-spec store holds encrypt + decrypt simultaneously and
 * NEVER auto-syncs them — `[[feedback-cross-mode-no-auto-sync]]`. The user
 * sees both halves of the algorithm side-by-side and can edit either
 * independently to learn what breaks.
 *
 * **Algorithm.** Same body as encrypt — IP → 16 Feistel rounds → FP, with
 * the round-16 "no swap" exception. Only the per-round key consumption
 * order changes:
 *
 *     Encrypt round r ∈ 1..16 uses K_r           (aux roundKey.{r-1})
 *     Decrypt round r ∈ 1..16 uses K_{17-r}      (aux roundKey.{16-r})
 *
 * The "no swap" on the LAST round of *each* direction is what makes the
 * cipher self-inverse: with the swap on rounds 1..15 and no-swap on
 * round 16, running the same body backwards with reversed keys recovers
 * the plaintext. The key schedule itself runs the same way in both
 * directions — it's the per-round assignment that flips.
 *
 * Educational check the user can do: edit a round-16 combine kind to
 * `feistel-standard` in either spec and watch the cipher stop round-tripping.
 */

import type { CipherSpec, FeistelRoundGroup, StepNode } from "../core/types";
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
 * Same builder as encrypt's, but takes `auxIdx` separately so callers can
 * map decrypt round r (1..16) to aux roundKey.{16 - r}. Duplicating rather
 * than importing keeps decrypt's spec self-contained (educational: a user
 * can read this file front-to-back without chasing).
 */
const buildDesRound = (
  roundIdx: number,
  auxIdx: number,
  combineKind: FeistelRoundGroup["combineKind"],
): FeistelRoundGroup => ({
  kind: "feistel-round",
  id: `round.${roundIdx}`,
  label: `Round ${roundIdx}`,
  tracks: [
    { name: "L", inputBytes: [0, 1, 2, 3], children: [] },
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
 * Build the 16-round body for decrypt. Decrypt round r ∈ 1..16 consumes
 * aux roundKey.{16 - r}:
 *   r = 1  → roundKey.15 (= K_16)
 *   r = 2  → roundKey.14 (= K_15)
 *   …
 *   r = 16 → roundKey.0  (= K_1)
 *
 * Round 16 (the LAST decrypt round) is feistel-no-swap, same as encrypt's
 * round 16. The "no swap on the last round" rule applies to each direction
 * independently.
 */
export const buildDesDecryptRounds = (): StepNode => ({
  kind: "group",
  id: "rounds",
  label: "Rounds",
  children: [
    ...Array.from({ length: 15 }, (_, i) => buildDesRound(i + 1, 15 - i, "feistel-standard")),
    // Round 16 (decrypt's last) — feistel-no-swap, consuming K_1 (roundKey.0).
    buildDesRound(16, 0, "feistel-no-swap"),
  ],
});

export const desDecryptSpec: CipherSpec = {
  id: "des-decrypt@1",
  name: "DES (decrypt)",
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
    buildDesDecryptRounds(),
    {
      kind: "step",
      id: "final-permutation",
      type: "des.final-permutation@1",
      params: { table: [...DES_FP] },
    },
  ],
};
