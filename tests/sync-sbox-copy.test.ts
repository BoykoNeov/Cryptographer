/**
 * Tests for `syncSboxCopyToCounterpart` in `src/ui/stores/spec.ts` —
 * the cross-slot **identity** value-mirror used by the AES key-expansion
 * Copy-S-box button.
 *
 * What this mutator promises (mirrors `syncSboxInverseToCounterpart`'s
 * shape but with NO inversion):
 *   1. Writes `sboxValue` byte-for-byte to every step of the named type
 *      in the COUNTERPART slot.
 *   2. Leaves the ACTIVE slot untouched.
 *   3. Works in either direction (active=encrypt → decrypt; active=
 *      decrypt → encrypt) because the counterpart is computed from
 *      `useMode()`.
 *   4. The semantic difference from the inverse case: a canonical-input
 *      Copy call leaves the canonical counterpart unchanged (both sides
 *      already hold the canonical AES_SBOX in their key-expansion step),
 *      whereas a canonical-input Inverse call would also produce a no-op
 *      but for the opposite reason (encrypt forward → decrypt's stored
 *      inverse).
 *
 * Routes through the public store surface so we exercise the same code
 * path the UI's `CopySboxRow` button calls.
 */

import { AES_SBOX } from "@/ciphers/aes-constants";
import type { CipherSpec, StepNode } from "@/core/types";
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

// AES key-expansion has exactly one leaf per spec (it lives outside any
// iterate/round group, at the top level). We still walk the tree rather
// than indexing into `spec.steps[0]` because the spec shape isn't part of
// this mutator's contract — only "every leaf of this type is updated."
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

describe("syncSboxCopyToCounterpart — cross-slot identity mirror", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("writes the input table verbatim to every matching step in the counterpart (decrypt) slot when active=encrypt", () => {
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

    syncSboxCopyToCounterpart("aes.key-expansion@1", edited);

    const decryptTables = collectSboxParams(
      useCipherSpecsByMode()().decrypt,
      "aes.key-expansion@1",
    );
    expect(decryptTables.length).toBeGreaterThan(0);
    for (const table of decryptTables) {
      // The promise is **identity** — no inversion. The decrypt slot's
      // key-expansion S-box now matches the input byte-for-byte.
      expect(table).toEqual(edited);
    }
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

    syncSboxCopyToCounterpart("aes.key-expansion@1", edited);

    const encryptTables = collectSboxParams(
      useCipherSpecsByMode()().encrypt,
      "aes.key-expansion@1",
    );
    expect(encryptTables.length).toBeGreaterThan(0);
    for (const table of encryptTables) {
      expect(table).toEqual(edited);
    }
  });

  it("leaves the active slot untouched", () => {
    const beforeEncrypt = collectSboxParams(
      useCipherSpecsByMode()().encrypt,
      "aes.key-expansion@1",
    );
    syncSboxCopyToCounterpart("aes.key-expansion@1", AES_SBOX);
    const afterEncrypt = collectSboxParams(useCipherSpecsByMode()().encrypt, "aes.key-expansion@1");
    expect(afterEncrypt).toEqual(beforeEncrypt);
  });

  it("canonical round-trip: copying AES_SBOX against the canonical AES-128 spec is a no-op on decrypt's key-expansion", () => {
    // Both sides ship with AES_SBOX in their key-expansion leaves
    // (FIPS-197 §5.2: key expansion always uses the FORWARD S-box,
    // even on the inverse cipher). So a canonical-input Copy must leave
    // the canonical decrypt slot byte-identical.
    const beforeDecrypt = collectSboxParams(
      useCipherSpecsByMode()().decrypt,
      "aes.key-expansion@1",
    );
    syncSboxCopyToCounterpart("aes.key-expansion@1", AES_SBOX);
    const afterDecrypt = collectSboxParams(useCipherSpecsByMode()().decrypt, "aes.key-expansion@1");
    expect(afterDecrypt).toEqual(beforeDecrypt);
    // And the canonical table is what we expect: AES_SBOX verbatim.
    for (const table of afterDecrypt) {
      expect(table).toEqual([...AES_SBOX]);
    }
  });
});
