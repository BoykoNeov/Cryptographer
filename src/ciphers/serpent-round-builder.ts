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
 *
 * **Explicit state-spine wiring (Phase 5 Slice 5.3b).** Every leaf declares
 * its `state` input port via `portInputs`, and every round group declares
 * `seedInput`/`bodyOutput` — exactly mirroring the byte-native AES body
 * (`aes-round-builder-native.ts`). This hands the round→round spine to
 * `inferPortEdges` so the legacy `inferStateEdges` consecutive-siblings
 * inference can retire (5.3e). Because every Serpent leaf is
 * `stateLayout: "bytes"`, the runtime's Step-A port resolution is byte-equal
 * to the Step-B meta projection it overrides (runtime.ts:584-612), and the
 * group `seedInput`/`bodyOutput` plumbing only redirects the *read* + feeds
 * the next group's seed — the data still rides the shared threaded `state`
 * (runtime.ts:145/806). The full per-spec golden frame-stream checksum in
 * `runtime-ported-dispatch-serpent.test.ts` pins byte-equality across all six
 * shipped specs.
 *
 * Within a group the first leaf reads the carried block injected on
 * `port(groupId, "in")` (the runtime resolves the group's `seedInput` and
 * seeds the body scope with it); each later leaf reads its predecessor's
 * `state` output port. `seedInput` references the preceding top-level node's
 * exit: the IP leaf's `state` for round 1 (inv-round.32 for decrypt), or the
 * previous round group's published `"out"` port otherwise. The aux `roundKey`
 * ports stay UNWIRED — they keep flowing from `aux[roundKeyAux]` via the meta
 * projection, preserving the key-expansion→round fan-out edges.
 */

import type { PortBinding, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import {
  SERPENT_FP,
  SERPENT_INV_SBOXES,
  SERPENT_IP,
  SERPENT_ROUNDS,
  SERPENT_SBOXES,
} from "./serpent-constants";

// Tiny binding helper — mirrors the per-file `port()` in the AES/DES/ECB
// builders. `{ node, port }` is the sink-side edge a leaf's `portInputs`
// resolves against `nodeOutputs` at runtime.
const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

// ─── Leaf factories — keep fresh per call; take an explicit `state` binding ──

const ipLeaf = (id: string, stateBinding: PortBinding): StepNode => ({
  kind: "step",
  id,
  type: "serpent.bit-permutation@1",
  params: { table: [...SERPENT_IP], label: "IP" },
  portInputs: { state: stateBinding },
});

const fpLeaf = (id: string, stateBinding: PortBinding): StepNode => ({
  kind: "step",
  id,
  type: "serpent.bit-permutation@1",
  params: { table: [...SERPENT_FP], label: "FP" },
  portInputs: { state: stateBinding },
});

const addRoundKeyLeaf = (
  idPrefix: string,
  suffix: string,
  roundKeyIndex: number,
  stateBinding: PortBinding,
): StepNode => ({
  kind: "step",
  id: `${idPrefix}.${suffix}`,
  type: "serpent.add-round-key@1",
  params: { roundKeyAux: `roundKey.${roundKeyIndex}` },
  portInputs: { state: stateBinding },
});

const subBytesLeaf = (
  idPrefix: string,
  sboxIndex: number,
  stateBinding: PortBinding,
): StepNode => ({
  kind: "step",
  id: `${idPrefix}.sub-bytes`,
  type: "serpent.sub-bytes@1",
  // Deep-copy the S-box: each leaf must own its table so the UI's
  // per-leaf edits don't propagate via shared reference.
  params: {
    sbox: [...(SERPENT_SBOXES[sboxIndex] ?? [])],
    sboxIndex,
  },
  portInputs: { state: stateBinding },
});

const invSubBytesLeaf = (
  idPrefix: string,
  sboxIndex: number,
  stateBinding: PortBinding,
): StepNode => ({
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
  portInputs: { state: stateBinding },
});

const linearTransformLeaf = (idPrefix: string, stateBinding: PortBinding): StepNode => ({
  kind: "step",
  id: `${idPrefix}.linear-transform`,
  type: "serpent.linear-transform@1",
  params: {},
  portInputs: { state: stateBinding },
});

const invLinearTransformLeaf = (idPrefix: string, stateBinding: PortBinding): StepNode => ({
  kind: "step",
  id: `${idPrefix}.inv-linear-transform`,
  type: "serpent.inv-linear-transform@1",
  params: {},
  portInputs: { state: stateBinding },
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
      addRoundKeyLeaf(idPrefix, "add-round-key", r - 1, port(idPrefix, "in")),
      subBytesLeaf(idPrefix, (r - 1) % 8, port(`${idPrefix}.add-round-key`, "state")),
      linearTransformLeaf(idPrefix, port(`${idPrefix}.sub-bytes`, "state")),
    ],
    // Round 1 seeds from IP's exit; round r (>1) from round r-1's published exit.
    seedInput: r === 1 ? port("initial-permutation", "state") : port(`round.${r - 1}`, "out"),
    bodyOutput: port(`${idPrefix}.linear-transform`, "state"),
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
      addRoundKeyLeaf(idPrefix, "add-round-key", SERPENT_ROUNDS - 1, port(idPrefix, "in")),
      subBytesLeaf(idPrefix, (SERPENT_ROUNDS - 1) % 8, port(`${idPrefix}.add-round-key`, "state")),
      addRoundKeyLeaf(
        idPrefix,
        "add-final-round-key",
        SERPENT_ROUNDS,
        port(`${idPrefix}.sub-bytes`, "state"),
      ),
    ],
    seedInput: port(`round.${SERPENT_ROUNDS - 1}`, "out"),
    bodyOutput: port(`${idPrefix}.add-final-round-key`, "state"),
  };
};

/**
 * Build the forward Serpent body: IP, 31 normal rounds, 1 final round, FP.
 * Total leaves: 1 (IP) + 31*3 + 1*3 + 1 (FP) = 98.
 */
export const buildSerpentEncryptBody = (): readonly StepNode[] => {
  const nodes: StepNode[] = [];
  // IP reads the plaintext block from the reserved `$input` source.
  nodes.push(ipLeaf("initial-permutation", port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT)));
  for (let r = 1; r <= SERPENT_ROUNDS - 1; r++) {
    nodes.push(encryptNormalRound(r));
  }
  nodes.push(encryptFinalRound());
  // FP reads the final round group's published exit.
  nodes.push(fpLeaf("final-permutation", port(`round.${SERPENT_ROUNDS}`, "out")));
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
      addRoundKeyLeaf(idPrefix, "add-round-key", SERPENT_ROUNDS, port(idPrefix, "in")),
      invSubBytesLeaf(
        idPrefix,
        (SERPENT_ROUNDS - 1) % 8,
        port(`${idPrefix}.add-round-key`, "state"),
      ),
      addRoundKeyLeaf(
        idPrefix,
        "add-prev-round-key",
        SERPENT_ROUNDS - 1,
        port(`${idPrefix}.inv-sub-bytes`, "state"),
      ),
    ],
    // First inverse round seeds from IP's exit (IP undoes encrypt's FP).
    seedInput: port("initial-permutation", "state"),
    bodyOutput: port(`${idPrefix}.add-prev-round-key`, "state"),
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
      invLinearTransformLeaf(idPrefix, port(idPrefix, "in")),
      invSubBytesLeaf(idPrefix, (r - 1) % 8, port(`${idPrefix}.inv-linear-transform`, "state")),
      addRoundKeyLeaf(idPrefix, "add-round-key", r - 1, port(`${idPrefix}.inv-sub-bytes`, "state")),
    ],
    // The decrypt body runs inv-round.32 → inv-round.31 → … → inv-round.1, so
    // inv-round.r's predecessor in spec order is inv-round.{r+1} (DESCENDING).
    seedInput: port(`inv-round.${r + 1}`, "out"),
    bodyOutput: port(`${idPrefix}.add-round-key`, "state"),
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
  nodes.push(ipLeaf("initial-permutation", port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT)));
  nodes.push(decryptFirstRound());
  for (let r = SERPENT_ROUNDS - 1; r >= 1; r--) {
    nodes.push(decryptNormalRound(r));
  }
  // Encryption started with IP; decryption ends with FP to undo it. FP reads
  // the last inverse round group's (inv-round.1) published exit.
  nodes.push(fpLeaf("final-permutation", port("inv-round.1", "out")));
  return nodes;
};
