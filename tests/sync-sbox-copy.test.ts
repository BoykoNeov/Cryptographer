/**
 * Tests for `syncSboxCopyToCounterpart` in `src/ui/stores/spec.ts` —
 * the cross-slot **identity** value-mirror used by the AES key-schedule
 * SubWord Copy-S-box button.
 *
 * Since the key-schedule decomposition (2026-06-01) the Copy affordance is
 * keyed on `byte-substitute@1` (the decomposed SubWord leaf), scoped to the
 * `key-schedule.*` leaves via `isKeyScheduleLeafId` — NOT the retired
 * monolithic `aes.key-expansion@1/@2` type. The round-body SubBytes leaves
 * share the type but take the *inverse* mirror, so the scope is load-bearing.
 *
 * What this mutator promises (mirrors `syncSboxInverseToCounterpart`'s
 * shape but with NO inversion, and now role-scoped):
 *   1. Writes `sboxValue` byte-for-byte to every key-schedule SubWord leaf
 *      in the COUNTERPART slot.
 *   2. Leaves the ACTIVE slot untouched.
 *   3. Leaves the round-body SubBytes leaves untouched (corruption guard).
 *   4. Works in either direction (encrypt↔decrypt) via `useMode()`.
 *
 * Routes through the public store surface so we exercise the same code
 * path the UI's `CopySboxRow` button calls.
 */

import { AES_SBOX } from "@/ciphers/aes-constants";
import type { CipherSpec, StepNode } from "@/core/types";
import { isKeyScheduleLeafId, isRoundBodyLeafId } from "@/ui/components/cross-mode-mirror-registry";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  setMode,
  syncSboxCopyToCounterpart,
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

// Walk the tree and collect (id, sbox) for every leaf of the type, so the
// tests can partition `byte-substitute@1` into key-schedule SubWord (the
// Copy role) vs round-body SubBytes (the inverse role, must stay untouched).
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

const keyScheduleTables = (spec: CipherSpec): readonly (readonly number[])[] =>
  collectSboxEntries(spec, "byte-substitute@1")
    .filter((e) => isKeyScheduleLeafId(e.id))
    .map((e) => e.sbox);

const roundBodyTables = (spec: CipherSpec): readonly (readonly number[])[] =>
  collectSboxEntries(spec, "byte-substitute@1")
    .filter((e) => isRoundBodyLeafId(e.id))
    .map((e) => e.sbox);

describe("syncSboxCopyToCounterpart — cross-slot identity mirror (key-schedule SubWord)", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("writes the input table verbatim to every SubWord leaf in the counterpart (decrypt) slot when active=encrypt", () => {
    // Build a non-canonical permutation so the test would fail if the
    // mutator silently no-op'd or used canonical defaults. Swap two
    // entries of AES_SBOX — still bijective, but distinct from canonical.
    const edited = [...AES_SBOX];
    const a = edited[10];
    const b = edited[200];
    if (a !== undefined && b !== undefined) {
      edited[10] = b;
      edited[200] = a;
    }

    syncSboxCopyToCounterpart("byte-substitute@1", edited, isKeyScheduleLeafId);

    const subwordTables = keyScheduleTables(useCipherSpecsByMode()().decrypt);
    expect(subwordTables.length).toBeGreaterThan(0); // AES-128: 10 SubWord leaves
    for (const table of subwordTables) {
      // The promise is **identity** — no inversion. The decrypt slot's
      // SubWord S-box now matches the input byte-for-byte.
      expect(table).toEqual(edited);
    }
  });

  // ── Corruption guard (key-schedule-decomposition K1c) ─────────────────
  // The Copy must NOT spill onto the round-body SubBytes leaves — those
  // hold AES_INV_SBOX on the decrypt side, and overwriting them with the
  // forward table would break decryption. The scope (`isKeyScheduleLeafId`)
  // confines the write to the SubWord leaves.
  it("does NOT touch the decrypt round-body SubBytes leaves", () => {
    const before = roundBodyTables(useCipherSpecsByMode()().decrypt);
    const edited = [...AES_SBOX];
    const a = edited[10];
    const b = edited[200];
    if (a !== undefined && b !== undefined) {
      edited[10] = b;
      edited[200] = a;
    }
    syncSboxCopyToCounterpart("byte-substitute@1", edited, isKeyScheduleLeafId);

    const after = roundBodyTables(useCipherSpecsByMode()().decrypt);
    expect(after.length).toBeGreaterThan(0);
    expect(after).toEqual(before); // round-body untouched
  });

  it("writes to encrypt slot when active mode is decrypt", () => {
    setMode("decrypt");

    const edited = [...AES_SBOX];
    const a = edited[5];
    const b = edited[100];
    if (a !== undefined && b !== undefined) {
      edited[5] = b;
      edited[100] = a;
    }

    syncSboxCopyToCounterpart("byte-substitute@1", edited, isKeyScheduleLeafId);

    const subwordTables = keyScheduleTables(useCipherSpecsByMode()().encrypt);
    expect(subwordTables.length).toBeGreaterThan(0);
    for (const table of subwordTables) {
      expect(table).toEqual(edited);
    }
  });

  it("leaves the active slot untouched", () => {
    const beforeEncrypt = keyScheduleTables(useCipherSpecsByMode()().encrypt);
    syncSboxCopyToCounterpart("byte-substitute@1", AES_SBOX, isKeyScheduleLeafId);
    const afterEncrypt = keyScheduleTables(useCipherSpecsByMode()().encrypt);
    expect(afterEncrypt).toEqual(beforeEncrypt);
  });

  it("canonical round-trip: copying AES_SBOX against the canonical AES-128 spec is a no-op on decrypt's SubWord leaves", () => {
    // Both sides ship with AES_SBOX in their SubWord leaves (FIPS-197 §5.2:
    // key expansion always uses the FORWARD S-box, even on the inverse
    // cipher). So a canonical-input Copy must leave the canonical decrypt
    // slot byte-identical.
    const beforeDecrypt = keyScheduleTables(useCipherSpecsByMode()().decrypt);
    syncSboxCopyToCounterpart("byte-substitute@1", AES_SBOX, isKeyScheduleLeafId);
    const afterDecrypt = keyScheduleTables(useCipherSpecsByMode()().decrypt);
    expect(afterDecrypt).toEqual(beforeDecrypt);
    // And the canonical table is what we expect: AES_SBOX verbatim.
    for (const table of afterDecrypt) {
      expect(table).toEqual([...AES_SBOX]);
    }
  });
});
