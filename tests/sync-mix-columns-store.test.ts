/**
 * Tests for `syncMixColumnsInverseToCounterpart` in `src/ui/stores/spec.ts` —
 * the cross-slot **inverse-matrix** mirror used by the MixColumns Sync
 * button.
 *
 * What this mutator promises (sibling to `syncSboxInverseToCounterpart`'s
 * shape, with `matrix` instead of `sbox` as the param key):
 *   1. Writes the supplied 4×4 matrix to every `generic.mix-columns@1`
 *      step in the COUNTERPART slot, by-value (a deep copy — caller
 *      mutating the input later doesn't bleed into the spec).
 *   2. Leaves the ACTIVE slot untouched.
 *   3. Works in either direction (active=encrypt → decrypt; active=
 *      decrypt → encrypt) because the counterpart is computed from
 *      `useMode()`.
 *   4. KAT integration: when the input matrix is computed by inverting
 *      the canonical `AES_MIX_MATRIX` via `gfMatInverse4x4`, the
 *      counterpart slot ends up holding `AES_INV_MIX_MATRIX` byte-for-
 *      byte (FIPS-197 §5.3.3). The full UI flow (edit matrix → click
 *      Sync → decrypt mirrors the inverse) is exercised at this
 *      mutator-plus-inverter boundary.
 *
 * Routes through the public store surface so we exercise the same code
 * path the UI's `SyncMixColumnsRow` button calls.
 */

import { AES_INV_MIX_MATRIX, AES_MIX_MATRIX } from "@/ciphers/aes-constants";
import { gfMatInverse4x4 } from "@/core/state/gf-matrix";
import type { CipherSpec, StepNode } from "@/core/types";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  setCipher,
  setMode,
  syncMixColumnsInverseToCounterpart,
  useCipherSpecsByMode,
} from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetLayoutsForTests();
  // Retarget to AES-192: the default AES-128 ENCRYPT spec is byte-native
  // (Slice B1) and no longer carries `generic.mix-columns@1` steps, so a
  // cross-slot mirror test on AES-128 would collect 0 matching steps in the
  // encrypt slot. AES-192 stays matrix on BOTH sides until B1.3 — keeping this
  // test exercising the still-live matrix mirror mutator. (Byte-native mirror
  // entries land in B1.2 when both modes share the byte-native type.)
  setCipher("aes-192");
};

// AES has one `generic.mix-columns@1` leaf per non-final round. We walk
// the tree rather than indexing by id because the spec shape isn't part
// of the mutator's contract — only "every leaf of this type is updated."
const collectMatrices = (spec: CipherSpec, stepType: string): readonly (readonly number[])[][] => {
  const out: (readonly number[])[][] = [];
  const visit = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.type === stepType) {
        const params = n.params as { matrix?: readonly (readonly number[])[] };
        if (params.matrix) out.push(params.matrix.map((row) => [...row]));
      } else if (n.kind === "group" || n.kind === "iterate") {
        visit(n.children as readonly StepNode[]);
      }
    }
  };
  visit(spec.steps);
  return out;
};

describe("syncMixColumnsInverseToCounterpart — cross-slot inverse-matrix mirror", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("writes the supplied matrix to every matching step in the counterpart (decrypt) slot when active=encrypt", () => {
    // Build a custom invertible 4×4 (NOT AES_INV_MIX_MATRIX) so a silent
    // no-op or canonical-fallback bug would surface. Lower-triangular,
    // pivots ∈ {1,2,3,4,5} — definitely nonsingular over GF(2^8).
    const customMatrix = [
      [1, 0, 0, 0],
      [7, 2, 0, 0],
      [3, 9, 4, 0],
      [5, 8, 0xb, 5],
    ];

    syncMixColumnsInverseToCounterpart("generic.mix-columns@1", customMatrix);

    const decryptMatrices = collectMatrices(
      useCipherSpecsByMode()().decrypt,
      "generic.mix-columns@1",
    );
    expect(decryptMatrices.length).toBeGreaterThan(0);
    for (const m of decryptMatrices) {
      expect(m).toEqual(customMatrix);
    }
  });

  it("writes to encrypt slot when active mode is decrypt (direction inference from useMode)", () => {
    setMode("decrypt");

    const customMatrix = [
      [2, 0, 0, 0],
      [0, 3, 0, 0],
      [0, 0, 4, 0],
      [0, 0, 0, 5],
    ];

    syncMixColumnsInverseToCounterpart("generic.mix-columns@1", customMatrix);

    const encryptMatrices = collectMatrices(
      useCipherSpecsByMode()().encrypt,
      "generic.mix-columns@1",
    );
    expect(encryptMatrices.length).toBeGreaterThan(0);
    for (const m of encryptMatrices) {
      expect(m).toEqual(customMatrix);
    }
  });

  it("leaves the active slot untouched", () => {
    const beforeEncrypt = collectMatrices(
      useCipherSpecsByMode()().encrypt,
      "generic.mix-columns@1",
    );
    syncMixColumnsInverseToCounterpart("generic.mix-columns@1", AES_INV_MIX_MATRIX);
    const afterEncrypt = collectMatrices(useCipherSpecsByMode()().encrypt, "generic.mix-columns@1");
    expect(afterEncrypt).toEqual(beforeEncrypt);
  });

  it("KAT integration — gfMatInverse4x4(AES_MIX_MATRIX) routed through the mutator lands AES_INV_MIX_MATRIX in decrypt", () => {
    // This is the end-to-end shape of what the UI's SyncMixColumnsRow does:
    //   1. read the active step's matrix (canonical AES_MIX_MATRIX),
    //   2. compute its inverse via gfMatInverse4x4,
    //   3. call the mutator with the inverse.
    // The decrypt slot should end up with AES_INV_MIX_MATRIX byte-for-byte.
    // Pinning this here gives the GF-inversion KAT (in tests/gf-matrix.test.ts)
    // an UI-flow-level second confirmation — the value actually ends up
    // in the spec.
    const inverse = gfMatInverse4x4(AES_MIX_MATRIX);
    syncMixColumnsInverseToCounterpart("generic.mix-columns@1", inverse);

    const decryptMatrices = collectMatrices(
      useCipherSpecsByMode()().decrypt,
      "generic.mix-columns@1",
    );
    expect(decryptMatrices.length).toBeGreaterThan(0);
    for (const m of decryptMatrices) {
      expect(m).toEqual(AES_INV_MIX_MATRIX.map((row) => [...row]));
    }
  });

  it("deep-copies the input — mutating the source array after calling does not bleed into the spec", () => {
    // The mutator is supposed to take ownership of the value (write
    // `matrix.map(row => [...row])`). A pass-by-reference bug would let
    // a subsequent caller-side mutation reach into stored params and
    // corrupt the spec — exactly the kind of footgun the .map([...row])
    // line exists to prevent.
    const source = AES_INV_MIX_MATRIX.map((row) => [...row]);
    syncMixColumnsInverseToCounterpart("generic.mix-columns@1", source);

    // Mutate the source AFTER the call.
    if (source[0]) source[0][0] = 0xff;

    const decryptMatrices = collectMatrices(
      useCipherSpecsByMode()().decrypt,
      "generic.mix-columns@1",
    );
    for (const m of decryptMatrices) {
      // The spec must still have the canonical value, NOT the post-mutation 0xff.
      expect(m[0]?.[0]).toBe(AES_INV_MIX_MATRIX[0]?.[0]);
    }
  });
});
