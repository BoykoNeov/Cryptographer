/**
 * Synthetic Feistel spec fixture — the shared stand-in for the OLD
 * `feistel-round`-shaped DES spec in B4-era tests (universal-port Phase 4d).
 *
 * After the DES rebuild, no shipped cipher uses `feistel-round`, but the
 * primitive + its track-mutation machinery (`transformParentArray` descent,
 * `prependChildToTrack`, `insertStepIntoSpec`'s `into-track-start` anchor)
 * survive until Phase 5. Tests that exercise that machinery need a spec that
 * actually uses the primitive — this fixture provides one shaped exactly like
 * the old DES: a `rounds` group of `feistel-round`s, each with a 4-leaf R
 * track (`expand-R`/`xor-K`/`s-boxes`/`p-permute` ids, so old assertions
 * stand) and an empty L track, plus a non-feistel `key-schedule` node.
 *
 * The leaves are inert `test.fixture@1` — these tests mutate the spec tree
 * structurally and never RUN it (the port-native DES leaves can't run inside
 * a track anyway; that's why DES left the primitive). Round 16, if present,
 * uses `feistel-no-swap` to mirror DES's last-round exception.
 */

import type { CipherSpec, FeistelRoundGroup, StepLeaf } from "@/core/types";

const leaf = (id: string): StepLeaf => ({ kind: "step", id, type: "test.fixture@1", params: {} });

const round = (i: number): FeistelRoundGroup => ({
  kind: "feistel-round",
  id: `round.${i}`,
  label: `Round ${i}`,
  tracks: [
    { name: "L", inputBytes: [0, 1, 2, 3], children: [] },
    {
      name: "R",
      inputBytes: [4, 5, 6, 7],
      children: [
        leaf(`round.${i}.expand-R`),
        leaf(`round.${i}.xor-K`),
        leaf(`round.${i}.s-boxes`),
        leaf(`round.${i}.p-permute`),
      ],
    },
  ],
  combineKind: i === 16 ? "feistel-no-swap" : "feistel-standard",
});

/**
 * Build a synthetic Feistel spec with `roundCount` rounds (default 5 — enough
 * for tests that need a middle round with both a predecessor and successor,
 * plus distinct round.1 / round.3 / round.5 anchors).
 */
export const buildSyntheticFeistelSpec = (roundCount = 5): CipherSpec => ({
  id: "synth-feistel@1",
  name: "Synthetic Feistel (test fixture)",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 8 } },
  steps: [
    leaf("key-schedule"),
    {
      kind: "group",
      id: "rounds",
      label: "Rounds",
      children: Array.from({ length: roundCount }, (_, i) => round(i + 1)),
    },
  ],
});
