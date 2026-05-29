/**
 * Serpent round-body construction. Same shape as the AES round-body builders
 * (`aes-round-builder-native.ts`): a forward (encrypt) builder and an inverse
 * (decrypt) builder, each returning the flat StepNode list that sits between
 * the key-expansion step and the optional multi-block iterate wrapper.
 *
 * Forward (encrypt) body:
 *   IP
 *   round.1  group: [AK_0,  SubBytes(S_0), LT]
 *   round.2  group: [AK_1,  SubBytes(S_1), LT]
 *   ...
 *   round.31 group: [AK_30, SubBytes(S_6), LT]
 *   round.32 group (final, no LT): [AK_31, SubBytes(S_7), AK_32]
 *   FP
 *
 * Inverse (decrypt) body:
 *   IP   (= FP^-1; undoes encrypt's final FP)
 *   inv-round.32 group (first, undoes encrypt's final round): [AK_32, InvSubBytes(S_7), AK_31]
 *   inv-round.31 group: [InvLT, InvSubBytes(S_6), AK_30]
 *   inv-round.30 group: [InvLT, InvSubBytes(S_5), AK_29]
 *   ...
 *   inv-round.1  group: [InvLT, InvSubBytes(S_0), AK_0]
 *   FP   (= IP^-1; undoes encrypt's initial IP)
 *
 * Notes:
 *   - The inverse of `[AK, SB, LT]` is `[InvLT, InvSB, AK]` because XOR
 *     is self-inverse but the LT and SB are NOT — and the operations
 *     are composed `(LT ∘ SB ∘ AK)`, whose inverse is `(AK^-1 ∘ SB^-1 ∘ LT^-1)`
 *     = `(AK ∘ InvSB ∘ InvLT)`.
 *   - Each leaf gets a fresh-copied params object. The S-box arrays
 *     especially must be cloned per leaf so a UI edit to one round's
 *     S-box doesn't bleed into any other round that happens to cycle
 *     to the same S-box index.
 */

import type { StepNode } from "../core/types";
import {
  SERPENT_FP,
  SERPENT_INV_SBOXES,
  SERPENT_IP,
  SERPENT_ROUNDS,
  SERPENT_SBOXES,
} from "./serpent-constants";

// ─── Leaf factories — keep fresh per call ─────────────────────────────────

const ipLeaf = (id: string): StepNode => ({
  kind: "step",
  id,
  type: "serpent.bit-permutation@1",
  params: { table: [...SERPENT_IP], label: "IP" },
});

const fpLeaf = (id: string): StepNode => ({
  kind: "step",
  id,
  type: "serpent.bit-permutation@1",
  params: { table: [...SERPENT_FP], label: "FP" },
});

const addRoundKeyLeaf = (idPrefix: string, suffix: string, roundKeyIndex: number): StepNode => ({
  kind: "step",
  id: `${idPrefix}.${suffix}`,
  type: "serpent.add-round-key@1",
  params: { roundKeyAux: `roundKey.${roundKeyIndex}` },
});

const subBytesLeaf = (idPrefix: string, sboxIndex: number): StepNode => ({
  kind: "step",
  id: `${idPrefix}.sub-bytes`,
  type: "serpent.sub-bytes@1",
  // Deep-copy the S-box: each leaf must own its table so the UI's
  // per-leaf edits don't propagate via shared reference.
  params: {
    sbox: [...(SERPENT_SBOXES[sboxIndex] ?? [])],
    sboxIndex,
  },
});

const invSubBytesLeaf = (idPrefix: string, sboxIndex: number): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-sub-bytes`,
  type: "serpent.sub-bytes@1",
  // Same step type as forward SubBytes; only the S-box table differs.
  // sboxIndex still records which forward S-box this inverts (0..7) so
  // the param editor can show a coherent label.
  params: {
    sbox: [...(SERPENT_INV_SBOXES[sboxIndex] ?? [])],
    sboxIndex,
  },
});

const linearTransformLeaf = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.linear-transform`,
  type: "serpent.linear-transform@1",
  params: {},
});

const invLinearTransformLeaf = (idPrefix: string): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-linear-transform`,
  type: "serpent.inv-linear-transform@1",
  params: {},
});

// ─── Forward (encrypt) body ───────────────────────────────────────────────

const encryptNormalRound = (roundNumber: number): StepNode => {
  // roundNumber is 1-based. Round body: [AK(K_{r-1}), SubBytes(S_{(r-1)%8}), LT].
  const r = roundNumber;
  const idPrefix = `round.${r}`;
  return {
    kind: "group",
    id: idPrefix,
    label: `Round ${r}`,
    children: [
      addRoundKeyLeaf(idPrefix, "add-round-key", r - 1),
      subBytesLeaf(idPrefix, (r - 1) % 8),
      linearTransformLeaf(idPrefix),
    ],
  };
};

const encryptFinalRound = (): StepNode => {
  // Round 32 (final). Drops LT; replaces with a second AddRoundKey using K_32.
  const idPrefix = `round.${SERPENT_ROUNDS}`;
  return {
    kind: "group",
    id: idPrefix,
    label: `Round ${SERPENT_ROUNDS} (final, no LT)`,
    children: [
      addRoundKeyLeaf(idPrefix, "add-round-key", SERPENT_ROUNDS - 1),
      subBytesLeaf(idPrefix, (SERPENT_ROUNDS - 1) % 8),
      addRoundKeyLeaf(idPrefix, "add-final-round-key", SERPENT_ROUNDS),
    ],
  };
};

/**
 * Build the forward Serpent body: IP, 31 normal rounds, 1 final round, FP.
 * Total leaves: 1 (IP) + 31*3 + 1*3 + 1 (FP) = 98.
 */
export const buildSerpentEncryptBody = (): readonly StepNode[] => {
  const nodes: StepNode[] = [];
  nodes.push(ipLeaf("initial-permutation"));
  for (let r = 1; r <= SERPENT_ROUNDS - 1; r++) {
    nodes.push(encryptNormalRound(r));
  }
  nodes.push(encryptFinalRound());
  nodes.push(fpLeaf("final-permutation"));
  return nodes;
};

// ─── Inverse (decrypt) body ───────────────────────────────────────────────

const decryptFirstRound = (): StepNode => {
  // Inverts encrypt's final round (round 32). Encrypt's final was
  //   [AK(K_31), SB(S_7), AK(K_32)],
  // so its inverse (in reverse order, each piece inverted) is
  //   [AK(K_32), InvSB(S_7), AK(K_31)]
  // — AK is self-inverse.
  const idPrefix = `inv-round.${SERPENT_ROUNDS}`;
  return {
    kind: "group",
    id: idPrefix,
    label: `Inverse Round ${SERPENT_ROUNDS} (undoes encrypt's final round)`,
    children: [
      addRoundKeyLeaf(idPrefix, "add-round-key", SERPENT_ROUNDS),
      invSubBytesLeaf(idPrefix, (SERPENT_ROUNDS - 1) % 8),
      addRoundKeyLeaf(idPrefix, "add-prev-round-key", SERPENT_ROUNDS - 1),
    ],
  };
};

const decryptNormalRound = (roundNumber: number): StepNode => {
  // roundNumber is 1-based; this inverts encrypt's normal round `roundNumber`.
  // Encrypt's round r was [AK(K_{r-1}), SB(S_{(r-1)%8}), LT], so the inverse
  // (reverse order, each inverted) is [InvLT, InvSB(S_{(r-1)%8}), AK(K_{r-1})].
  const r = roundNumber;
  const idPrefix = `inv-round.${r}`;
  return {
    kind: "group",
    id: idPrefix,
    label: `Inverse Round ${r}`,
    children: [
      invLinearTransformLeaf(idPrefix),
      invSubBytesLeaf(idPrefix, (r - 1) % 8),
      addRoundKeyLeaf(idPrefix, "add-round-key", r - 1),
    ],
  };
};

/**
 * Build the inverse Serpent body: IP (which is FP^-1), inverse round 32
 * (no inv-LT, irregular), inverse rounds 31..1, FP (which is IP^-1).
 *
 * Total leaves: 1 + 1*3 + 31*3 + 1 = 98 — same shape as the encrypt body.
 */
export const buildSerpentDecryptBody = (): readonly StepNode[] => {
  const nodes: StepNode[] = [];
  // Encryption ended with FP; decryption starts by applying IP to undo it.
  nodes.push(ipLeaf("initial-permutation"));
  nodes.push(decryptFirstRound());
  for (let r = SERPENT_ROUNDS - 1; r >= 1; r--) {
    nodes.push(decryptNormalRound(r));
  }
  // Encryption started with IP; decryption ends with FP to undo it.
  nodes.push(fpLeaf("final-permutation"));
  return nodes;
};
