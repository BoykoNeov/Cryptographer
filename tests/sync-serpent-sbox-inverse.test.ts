/**
 * Tests for `syncSboxInverseToCounterpartByIndex` in
 * `src/ui/stores/spec.ts` — the per-S-box-index variant of
 * `syncSboxInverseToCounterpart` that the Serpent SubBytes Sync button
 * uses.
 *
 * Serpent cycles **8 different 4-bit S-boxes** (`S_0`..`S_7`) across the
 * 32 rounds. The encrypt spec has 32 `serpent.sub-bytes@1` leaves, each
 * carrying its own `sboxIndex` (0..7) and `sbox` (16 entries). The
 * decrypt spec mirrors the structure with inverse tables. A Sync click
 * on a leaf editing S_3 must only update decrypt leaves whose
 * `sboxIndex === 3` — broadcasting one inverted table to all 32 decrypt
 * leaves would overwrite 28 of them with the wrong inverse.
 *
 * Properties pinned here:
 *   1. Writes the inverted table to every decrypt leaf with matching
 *      `sboxIndex`.
 *   2. Leaves decrypt leaves with OTHER `sboxIndex` values **byte-for-byte
 *      unchanged** (the non-regression assertion — a silent regression to
 *      broadcast mode would corrupt 7/8ths of the decrypt spec and the
 *      "matching index updated" assertion alone wouldn't catch it).
 *   3. Active slot is untouched (mutator only mirrors).
 *   4. Works in either direction (encrypt → decrypt and vice versa).
 *   5. Canonical round-trip: `syncByIndex(stepType, i, invertSbox(S_i))`
 *      against the canonical Serpent spec is a no-op (the decrypt slot
 *      already holds the inverse).
 */

import { SERPENT_INV_SBOXES, SERPENT_SBOXES } from "@/ciphers/serpent-constants";
import type { CipherSpec, StepNode } from "@/core/types";
import { invertSbox } from "@/ui/components/sbox-validation";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
// Import setCipher FROM stores/spec, NOT stores/cipher. The signal-only
// variant in `stores/cipher` flips the cipher signal but does NOT rebuild
// `specs` — it's the spec-store re-export that calls `buildCanonicalPair`
// and updates the active+counterpart specs. The UI uses the spec-store
// variant; matching that here keeps the test on the same boundary the
// real Sync button hits.
import {
  __resetSpecForTests,
  setCipher,
  setMode,
  syncSboxInverseToCounterpartByIndex,
  useCipherSpecsByMode,
} from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetLayoutsForTests();
};

// Selects Serpent-128 so the assertions below find serpent.sub-bytes@1
// leaves. The Serpent decrypt spec has the inverse round structure but
// the same `serpent.sub-bytes@1` step type — see
// `src/ciphers/serpent-round-builder.ts::invSubBytesLeaf`.
const selectSerpent128 = (): void => {
  setCipher("serpent-128");
};

// Collect (sboxIndex, sbox) pairs for every leaf of the given type. Lets
// us assert per-index without depending on the round count (32) or the
// specific leaf order.
type SboxLeafSnapshot = { readonly sboxIndex: number; readonly sbox: readonly number[] };
const collectSboxLeavesByIndex = (
  spec: CipherSpec,
  stepType: string,
): readonly SboxLeafSnapshot[] => {
  const out: SboxLeafSnapshot[] = [];
  const visit = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.type === stepType) {
        const params = n.params as { sbox?: readonly number[]; sboxIndex?: number };
        if (params.sbox && params.sboxIndex !== undefined) {
          out.push({ sboxIndex: params.sboxIndex, sbox: [...params.sbox] });
        }
      } else if (n.kind === "group" || n.kind === "iterate") {
        visit(n.children as readonly StepNode[]);
      }
    }
  };
  visit(spec.steps);
  return out;
};

describe("syncSboxInverseToCounterpartByIndex — Serpent per-index value mirror", () => {
  beforeEach(() => {
    resetAll();
    selectSerpent128();
  });
  afterEach(resetAll);

  it("writes the inverted table only to decrypt leaves whose sboxIndex matches", () => {
    // Pick a non-canonical permutation of 0..15 for S_3 so the test
    // would fail if the mutator silently no-op'd or wrote the canonical
    // inverse from somewhere else. Swap two entries of the canonical S_3.
    const editedS3 = [...(SERPENT_SBOXES[3] ?? [])];
    const a = editedS3[2];
    const b = editedS3[9];
    if (a !== undefined && b !== undefined) {
      editedS3[2] = b;
      editedS3[9] = a;
    }
    const expectedInverse = invertSbox(editedS3);

    // Snapshot the decrypt-side state BEFORE the mutator runs so we can
    // diff per-index. Each index 0..7 appears in ~4 leaves (32 rounds /
    // 8 S-boxes = 4 rounds per S-box).
    const before = collectSboxLeavesByIndex(
      useCipherSpecsByMode()().decrypt,
      "serpent.sub-bytes@1",
    );
    expect(before.length).toBeGreaterThan(0);

    syncSboxInverseToCounterpartByIndex("serpent.sub-bytes@1", 3, expectedInverse);

    const after = collectSboxLeavesByIndex(useCipherSpecsByMode()().decrypt, "serpent.sub-bytes@1");
    expect(after.length).toBe(before.length);

    // The matching-index leaves received `expectedInverse`...
    const matchingAfter = after.filter((leaf) => leaf.sboxIndex === 3);
    expect(matchingAfter.length).toBeGreaterThan(0);
    for (const leaf of matchingAfter) {
      expect(leaf.sbox).toEqual(expectedInverse);
    }

    // ...and EVERY other-index leaf is byte-for-byte identical to its
    // pre-mutation state. This is the non-regression assertion — without
    // it, a silent regression to broadcast mode would corrupt 28 of 32
    // decrypt leaves and the matching-index check alone wouldn't catch
    // it.
    const otherBefore = before.filter((leaf) => leaf.sboxIndex !== 3);
    const otherAfter = after.filter((leaf) => leaf.sboxIndex !== 3);
    expect(otherAfter.length).toBe(otherBefore.length);
    for (let i = 0; i < otherAfter.length; i++) {
      expect(otherAfter[i]?.sboxIndex).toBe(otherBefore[i]?.sboxIndex);
      expect(otherAfter[i]?.sbox).toEqual(otherBefore[i]?.sbox);
    }
  });

  it("writes to encrypt slot when active mode is decrypt", () => {
    setMode("decrypt");

    const editedInvS5 = [...(SERPENT_INV_SBOXES[5] ?? [])];
    const a = editedInvS5[0];
    const b = editedInvS5[14];
    if (a !== undefined && b !== undefined) {
      editedInvS5[0] = b;
      editedInvS5[14] = a;
    }
    const expectedWrite = invertSbox(editedInvS5);

    syncSboxInverseToCounterpartByIndex("serpent.sub-bytes@1", 5, expectedWrite);

    const encryptLeaves = collectSboxLeavesByIndex(
      useCipherSpecsByMode()().encrypt,
      "serpent.sub-bytes@1",
    );
    const matching = encryptLeaves.filter((leaf) => leaf.sboxIndex === 5);
    expect(matching.length).toBeGreaterThan(0);
    for (const leaf of matching) {
      expect(leaf.sbox).toEqual(expectedWrite);
    }
  });

  it("leaves the active slot untouched", () => {
    const inverse = invertSbox(SERPENT_SBOXES[2] ?? []);
    const beforeEncrypt = collectSboxLeavesByIndex(
      useCipherSpecsByMode()().encrypt,
      "serpent.sub-bytes@1",
    );

    syncSboxInverseToCounterpartByIndex("serpent.sub-bytes@1", 2, inverse);

    const afterEncrypt = collectSboxLeavesByIndex(
      useCipherSpecsByMode()().encrypt,
      "serpent.sub-bytes@1",
    );
    expect(afterEncrypt).toEqual(beforeEncrypt);
  });

  it("canonical round-trip: invertSbox(S_i) against the canonical Serpent spec is a no-op on decrypt's S_i leaves", () => {
    // The decrypt spec already holds SERPENT_INV_SBOXES[i] for every
    // leaf with sboxIndex i — so writing the inverse of SERPENT_SBOXES[i]
    // (which equals SERPENT_INV_SBOXES[i]) must produce a byte-identical
    // table. Pins the canonical/canonical relationship; if invertSbox
    // drifts or the spec factory changes its source tables, this catches
    // it.
    for (let i = 0; i < 8; i++) {
      const canonicalInverse = invertSbox(SERPENT_SBOXES[i] ?? []);
      syncSboxInverseToCounterpartByIndex("serpent.sub-bytes@1", i, canonicalInverse);
    }

    const decryptLeaves = collectSboxLeavesByIndex(
      useCipherSpecsByMode()().decrypt,
      "serpent.sub-bytes@1",
    );
    for (const leaf of decryptLeaves) {
      const expected = [...(SERPENT_INV_SBOXES[leaf.sboxIndex] ?? [])];
      expect(leaf.sbox).toEqual(expected);
    }
  });
});
