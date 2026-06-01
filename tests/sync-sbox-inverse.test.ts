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
import { isKeyScheduleLeafId, isRoundBodyLeafId } from "@/ui/components/cross-mode-mirror-registry";
import { invertSbox } from "@/ui/components/sbox-validation";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  setMode,
  syncSboxInverseToCounterpart,
  useCipherSpecsByMode,
} from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetLayoutsForTests();
  // Default AES-128 single-block (byte-native on BOTH modes since B1.1/B1.2).
  // Slice B1.4b made CBC byte-native too, so NO shipped spec carries the matrix
  // `generic.byte-substitution@1` type anymore — there is no selectable matrix
  // AES to mirror. This file therefore exercises the mutator against the
  // byte-native `byte-substitute@1` type, which is the live cross-mode-mirror
  // path. The mutator is stepType-agnostic (same function for matrix +
  // byte-native), so the both-directions / active-untouched / canonical
  // round-trip coverage below pins the mutator's full contract. The matrix
  // `generic.byte-substitution@1` mirror entry retires with Phase C.
};

// Visit every leaf with the given type and collect its (id, sbox). The id
// lets the role-scoped tests partition `byte-substitute@1` into round-body
// SubBytes vs key-schedule SubWord — both share the type since the
// key-schedule decomposition (2026-06-01), but only round-body takes the
// inverse mirror (the SubWord stays forward, FIPS-197 §5.2).
const collectSboxEntries = (
  spec: CipherSpec,
  stepType: string,
): readonly { id: string; sbox: readonly number[] }[] => {
  const out: { id: string; sbox: readonly number[] }[] = [];
  const visit = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.type === stepType) {
        const params = n.params as { sbox?: readonly number[] };
        if (params.sbox) out.push({ id: n.id, sbox: [...params.sbox] });
      } else if (n.kind === "group" || n.kind === "iterate") {
        visit(n.children as readonly StepNode[]);
      }
    }
  };
  visit(spec.steps);
  return out;
};

// Round-body SubBytes tables (the inverse-mirror role).
const roundBodyTables = (spec: CipherSpec): readonly (readonly number[])[] =>
  collectSboxEntries(spec, "byte-substitute@1")
    .filter((e) => isRoundBodyLeafId(e.id))
    .map((e) => e.sbox);

// Key-schedule SubWord tables (the identity/Copy role — must stay forward).
const keyScheduleTables = (spec: CipherSpec): readonly (readonly number[])[] =>
  collectSboxEntries(spec, "byte-substitute@1")
    .filter((e) => isKeyScheduleLeafId(e.id))
    .map((e) => e.sbox);

describe("syncSboxInverseToCounterpart — cross-slot value mirror", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("writes the inverse to every ROUND-BODY step in the decrypt slot when active=encrypt", () => {
    // Active mode defaults to encrypt. We pick a *non-canonical* forward
    // table (a swap of two AES_SBOX entries → still a permutation) so the
    // test would fail if the mutator silently no-op'd or used canonical
    // defaults. The UI path scopes the broadcast to round-body leaves via
    // `isRoundBodyLeafId` — that is the call shape under test.
    const rotated = AES_SBOX.slice();
    const a = rotated[10];
    const b = rotated[20];
    if (a !== undefined && b !== undefined) {
      rotated[10] = b;
      rotated[20] = a;
    }
    const expectedInverse = invertSbox(rotated);

    syncSboxInverseToCounterpart("byte-substitute@1", expectedInverse, isRoundBodyLeafId);

    const decryptSpec = useCipherSpecsByMode()().decrypt;
    const roundBody = roundBodyTables(decryptSpec);
    expect(roundBody.length).toBeGreaterThan(0); // AES has 10+ SubBytes steps
    for (const table of roundBody) {
      expect(table).toEqual(expectedInverse);
    }
  });

  // ── Corruption guard (key-schedule-decomposition K1c) ─────────────────
  // The SubWord leaves share the `byte-substitute@1` type but must hold the
  // FORWARD S-box even on the decrypt side (FIPS-197 §5.2). A type-wide
  // inverse broadcast would overwrite them with the inverse table and break
  // the decrypt key schedule — invisible to the ciphertext KATs (which run
  // the specs as-authored, not after a button click). This pins that the
  // role-scoped inverse leaves the SubWord leaves untouched.
  it("does NOT touch the decrypt key-schedule SubWord leaves (they stay forward)", () => {
    const rotated = AES_SBOX.slice();
    const a = rotated[10];
    const b = rotated[20];
    if (a !== undefined && b !== undefined) {
      rotated[10] = b;
      rotated[20] = a;
    }
    syncSboxInverseToCounterpart("byte-substitute@1", invertSbox(rotated), isRoundBodyLeafId);

    const subwordTables = keyScheduleTables(useCipherSpecsByMode()().decrypt);
    expect(subwordTables.length).toBeGreaterThan(0); // AES-128 has 10 SubWord leaves
    for (const table of subwordTables) {
      // Untouched → still the canonical forward S-box, NOT the inverse.
      expect(table).toEqual([...AES_SBOX]);
    }
  });

  it("writes the inverse to every ROUND-BODY step in the encrypt slot when active=decrypt", () => {
    // Flip active mode first; the mutator should follow the active
    // signal and write to encrypt instead.
    setMode("decrypt");

    const rotated = AES_INV_SBOX.slice();
    const a = rotated[5];
    const b = rotated[200];
    if (a !== undefined && b !== undefined) {
      rotated[5] = b;
      rotated[200] = a;
    }
    const expectedWrite = invertSbox(rotated);

    syncSboxInverseToCounterpart("byte-substitute@1", expectedWrite, isRoundBodyLeafId);

    const encryptSpec = useCipherSpecsByMode()().encrypt;
    const roundBody = roundBodyTables(encryptSpec);
    expect(roundBody.length).toBeGreaterThan(0);
    for (const table of roundBody) {
      expect(table).toEqual(expectedWrite);
    }
  });

  it("leaves the active slot untouched", () => {
    // Capture the active slot's tables before, mutate, compare after.
    const beforeEncrypt = roundBodyTables(useCipherSpecsByMode()().encrypt);
    const inverse = invertSbox(AES_SBOX);
    syncSboxInverseToCounterpart("byte-substitute@1", inverse, isRoundBodyLeafId);
    const afterEncrypt = roundBodyTables(useCipherSpecsByMode()().encrypt);
    expect(afterEncrypt).toEqual(beforeEncrypt);
  });

  it("preserves canonical round-trip when called with invertSbox(AES_SBOX)", () => {
    // Property check: writing invertSbox(AES_SBOX) === AES_INV_SBOX into
    // the decrypt slot is a no-op against canonical round-body leaves. The
    // test pins the canonical/canonical relationship — if invertSbox or the
    // spec factory ever drifts, this catches it.
    const inverse = invertSbox(AES_SBOX);
    syncSboxInverseToCounterpart("byte-substitute@1", inverse, isRoundBodyLeafId);

    const roundBody = roundBodyTables(useCipherSpecsByMode()().decrypt);
    for (const table of roundBody) {
      expect(table).toEqual([...AES_INV_SBOX]);
    }
  });
});
