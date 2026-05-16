/**
 * Tests for `syncSboxInverseToCounterpart` in `src/ui/stores/spec.ts` —
 * the cross-slot value-mirror that the Sync-inverse button uses to
 * propagate a forward S-box edit into the matching decrypt slot (or
 * vice versa).
 *
 * What the mutator promises:
 *   1. Writes `invertedSbox` to every step of the named type in the
 *      counterpart slot.
 *   2. Leaves the ACTIVE slot untouched (the active edit is the
 *      caller's responsibility; we only mirror).
 *   3. Works in either direction — encrypt-side edit propagates to
 *      decrypt, decrypt-side edit propagates to encrypt — because the
 *      counterpart is computed from the active `useMode()`.
 *
 * Routes through the public store surface (no internals) so the test
 * exercises the same code path the UI button calls.
 */

import { AES_INV_SBOX, AES_SBOX } from "@/ciphers/aes-constants";
import type { CipherSpec, StepNode } from "@/core/types";
import { invertSbox } from "@/ui/components/sbox-validation";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  setMode,
  syncSboxInverseToCounterpart,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetLayoutsForTests();
};

// Visit every leaf with the given type and collect its `sbox` param.
// Used to assert "every matching step has table X" without depending on
// the AES round count (which varies across AES-128/192/256).
const collectSboxParams = (spec: CipherSpec, stepType: string): readonly number[][] => {
  const out: number[][] = [];
  const visit = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.type === stepType) {
        const params = n.params as { sbox?: readonly number[] };
        if (params.sbox) out.push([...params.sbox]);
      } else if (n.kind === "group" || n.kind === "iterate") {
        visit(n.children as readonly StepNode[]);
      }
    }
  };
  visit(spec.steps);
  return out;
};

describe("syncSboxInverseToCounterpart — cross-slot value mirror", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("writes the inverse to every matching step in the decrypt slot when active=encrypt", () => {
    // Active mode defaults to encrypt. The canonical AES-128 spec
    // ships with AES_SBOX in every byte-substitution step on the
    // encrypt side and AES_INV_SBOX on the decrypt side. We pick a
    // *non-canonical* forward table so the test would fail if the
    // mutator silently no-op'd or used the canonical defaults.
    const customForward = AES_SBOX.slice();
    customForward[0] = (customForward[0] ?? 0) ^ 0x01; // bit-flip
    customForward[1] = (customForward[1] ?? 0) ^ 0x01; // keep it a permutation? — no, this can produce dupes.

    // Use a proper permutation: a rotation.
    const rotated = AES_SBOX.slice();
    // Swap two values to get a fresh permutation that isn't AES_SBOX.
    const a = rotated[10];
    const b = rotated[20];
    if (a !== undefined && b !== undefined) {
      rotated[10] = b;
      rotated[20] = a;
    }
    const expectedInverse = invertSbox(rotated);

    syncSboxInverseToCounterpart("generic.byte-substitution@1", expectedInverse);

    const decryptSpec = useSpecsByMode()().decrypt;
    const decryptTables = collectSboxParams(decryptSpec, "generic.byte-substitution@1");

    expect(decryptTables.length).toBeGreaterThan(0); // AES has 10+ SubBytes steps
    for (const table of decryptTables) {
      expect(table).toEqual(expectedInverse);
    }
  });

  it("writes the inverse to every matching step in the encrypt slot when active=decrypt", () => {
    // Flip active mode first; the mutator should follow the active
    // signal and write to encrypt instead.
    setMode("decrypt");

    // Compute the inverse-of-something — doesn't matter what, as long
    // as it differs from the canonical default in the encrypt slot.
    const rotated = AES_INV_SBOX.slice();
    const a = rotated[5];
    const b = rotated[200];
    if (a !== undefined && b !== undefined) {
      rotated[5] = b;
      rotated[200] = a;
    }
    const expectedWrite = invertSbox(rotated);

    syncSboxInverseToCounterpart("generic.byte-substitution@1", expectedWrite);

    const encryptSpec = useSpecsByMode()().encrypt;
    const encryptTables = collectSboxParams(encryptSpec, "generic.byte-substitution@1");

    expect(encryptTables.length).toBeGreaterThan(0);
    for (const table of encryptTables) {
      expect(table).toEqual(expectedWrite);
    }
  });

  it("leaves the active slot untouched", () => {
    // Capture the active slot's tables before, mutate, compare after.
    const beforeEncrypt = collectSboxParams(
      useSpecsByMode()().encrypt,
      "generic.byte-substitution@1",
    );
    const inverse = invertSbox(AES_SBOX);
    syncSboxInverseToCounterpart("generic.byte-substitution@1", inverse);
    const afterEncrypt = collectSboxParams(
      useSpecsByMode()().encrypt,
      "generic.byte-substitution@1",
    );
    expect(afterEncrypt).toEqual(beforeEncrypt);
  });

  it("preserves canonical round-trip when called with invertSbox(AES_SBOX)", () => {
    // Property check: writing invertSbox(AES_SBOX) === AES_INV_SBOX into
    // the decrypt slot is a no-op against canonical. The test pins the
    // canonical/canonical relationship — if invertSbox or the spec
    // factory ever drifts, this catches it.
    const inverse = invertSbox(AES_SBOX);
    syncSboxInverseToCounterpart("generic.byte-substitution@1", inverse);

    const decryptTables = collectSboxParams(
      useSpecsByMode()().decrypt,
      "generic.byte-substitution@1",
    );
    for (const table of decryptTables) {
      expect(table).toEqual([...AES_INV_SBOX]);
    }
  });
});
