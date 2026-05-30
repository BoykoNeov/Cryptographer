/**
 * Tests for `duplicateRoundInSpec` from `src/ui/stores/spec.ts` —
 * Phase 4 of docs/plans/duplicate-round.md. The store action wires the
 * pure mutator (already tested in `duplicate-round-mutator.test.ts`)
 * into the two-spec store, layouts, and the layered selector stores
 * (cipher / cipherMode / padding).
 *
 * Property bundles:
 *
 *   1. Active-side: the current mode's spec gets the duplicate.
 *   2. Auto-mirror: the counterpart mode's spec also gets a matching
 *      duplicate, by key index (round.N ↔ inv-round.N).
 *   3. Mode flip preserves both sides (two-spec store invariant).
 *   4. Stacking duplicates writes through the live counterpart slot,
 *      not a fresh canonical (regression guard from advisor).
 *   5. Edits don't clear the counterpart (regression guard from
 *      advisor — edits are mode-local).
 *   6. Cipher / cipherMode swap rebuilds both slots from canonical
 *      (loses the duplicate, as expected).
 *   7. Store-level end-to-end round-trip across a mode flip:
 *      duplicate → run encrypt → flip → run decrypt → assert recovered
 *      = plaintext.
 *   8. Layout pin migration: a pre-existing pin on a renumbered round
 *      follows the rename through the persisted layout.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { requiresPortedDispatch } from "@/core/dispatch";
import { runSpec } from "@/core/runtime";
import { findStep } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests, getLayoutForSpec, setNodePosition } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  duplicateRoundInSpec,
  editStepParams,
  isCustomSpec,
  setCipher,
  setMode,
  useCipherSpecsByMode,
  useSpec,
} from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetLayoutsForTests();
};

const findGroupIds = (spec: CipherSpec): string[] => {
  const out: string[] = [];
  const visit = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "group") out.push(n.id);
      if (n.kind === "step" || n.kind === "feistel-round") continue;
      visit(n.children);
    }
  };
  visit(spec.steps);
  return out;
};

const auxNameOf = (spec: CipherSpec, leafId: string): string | undefined => {
  const leaf = findStep(spec, leafId);
  if (!leaf) return undefined;
  const p = leaf.params as { auxName?: unknown };
  return typeof p.auxName === "string" ? p.auxName : undefined;
};

// ─── 1. Active-side mutation ─────────────────────────────────────────────

describe("duplicateRoundInSpec — active-side mutation", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("forward: duplicating round.2 on encrypt grows encrypt to 11 rounds", () => {
    const spec = useSpec();
    expect(findGroupIds(spec()).filter((id) => id.startsWith("round."))).toHaveLength(10);

    duplicateRoundInSpec("round.2");

    const after = spec();
    const roundIds = findGroupIds(after).filter((id) => id.startsWith("round."));
    expect(roundIds).toHaveLength(11);
    expect(roundIds).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map((n) => `round.${n}`));
    // Byte-native encrypt (Slice B1; merged in Finding F3): the round-key
    // index lives on the single `xor-with-aux@1` AddRoundKey leaf's auxName.
    expect(auxNameOf(after, "round.3.add-round-key")).toBe("roundKey.3");
  });

  it("reverse: duplicating inv-round.2 on decrypt grows decrypt to 11 inverse rounds", () => {
    setMode("decrypt");
    const spec = useSpec();
    expect(findGroupIds(spec()).filter((id) => id.startsWith("inv-round."))).toHaveLength(10);

    duplicateRoundInSpec("inv-round.2");

    const after = spec();
    const invIds = findGroupIds(after).filter((id) => id.startsWith("inv-round."));
    expect(invIds).toHaveLength(11);
    // Byte-native decrypt (Slice B1.2; merged in F3): the LAST round key's
    // index lives on `inv-initial.add-round-key` (`xor-with-aux@1`).
    expect(auxNameOf(after, "inv-initial.add-round-key")).toBe("roundKey.11");
  });
});

// ─── 2. Auto-mirror to counterpart ────────────────────────────────────────

describe("duplicateRoundInSpec — auto-mirror to counterpart", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("forward duplicate on encrypt mirrors to decrypt's inv-round.N", () => {
    const all = useCipherSpecsByMode();
    expect(findGroupIds(all().decrypt).filter((id) => id.startsWith("inv-round."))).toHaveLength(
      10,
    );

    duplicateRoundInSpec("round.2");

    const after = all();
    // Encrypt got the forward duplicate.
    expect(findGroupIds(after.encrypt).filter((id) => id.startsWith("round."))).toHaveLength(11);
    // Decrypt got the reverse-mirror.
    expect(findGroupIds(after.decrypt).filter((id) => id.startsWith("inv-round."))).toHaveLength(
      11,
    );
    // Key index alignment: clone reads key.3 on BOTH sides. Both directions
    // are byte-native (Slice B1.1 encrypt / B1.2 decrypt; merged in F3), so
    // the round key index lives on the `*.add-round-key` (`xor-with-aux@1`)
    // leaf on each side.
    expect(auxNameOf(after.encrypt, "round.3.add-round-key")).toBe("roundKey.3");
    expect(auxNameOf(after.decrypt, "inv-round.3.add-round-key")).toBe("roundKey.3");
    expect(auxNameOf(after.decrypt, "inv-initial.add-round-key")).toBe("roundKey.11");
  });

  it("reverse duplicate on decrypt mirrors to encrypt's round.N", () => {
    setMode("decrypt");
    const all = useCipherSpecsByMode();
    duplicateRoundInSpec("inv-round.4");

    const after = all();
    expect(findGroupIds(after.encrypt).filter((id) => id.startsWith("round."))).toHaveLength(11);
    expect(findGroupIds(after.decrypt).filter((id) => id.startsWith("inv-round."))).toHaveLength(
      11,
    );
    // Clone reads key.5 (source was round 4, clone is N+1). Both directions
    // byte-native (B1.1/B1.2; merged in F3) → round key index on the
    // `*.add-round-key` (`xor-with-aux@1`) leaf.
    expect(auxNameOf(after.encrypt, "round.5.add-round-key")).toBe("roundKey.5");
    expect(auxNameOf(after.decrypt, "inv-round.5.add-round-key")).toBe("roundKey.5");
  });
});

// ─── 3. Mode flip preserves both sides ───────────────────────────────────

describe("duplicateRoundInSpec — mode flip preserves both sides (two-spec store)", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("ping-pong encrypt → decrypt → encrypt keeps the duplicate visible", () => {
    duplicateRoundInSpec("round.2");
    const spec = useSpec();

    // We're still on encrypt; verify the duplicate is there.
    expect(findGroupIds(spec()).filter((id) => id.startsWith("round."))).toHaveLength(11);

    // Flip to decrypt — should show the mirrored decrypt.
    setMode("decrypt");
    expect(findGroupIds(spec()).filter((id) => id.startsWith("inv-round."))).toHaveLength(11);

    // Flip back — encrypt's duplicate must still be there (the prior
    // single-spec store would have reset to canonical here).
    setMode("encrypt");
    expect(findGroupIds(spec()).filter((id) => id.startsWith("round."))).toHaveLength(11);
  });
});

// ─── 4. Stacking duplicates ───────────────────────────────────────────────

describe("duplicateRoundInSpec — stacking duplicates", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("a second duplicate composes onto the live counterpart, not canonical", () => {
    duplicateRoundInSpec("round.2"); // encrypt: 11 rounds; decrypt: 11 inv-rounds
    duplicateRoundInSpec("round.5"); // both sides should grow to 12

    const all = useCipherSpecsByMode();
    expect(findGroupIds(all().encrypt).filter((id) => id.startsWith("round."))).toHaveLength(12);
    expect(findGroupIds(all().decrypt).filter((id) => id.startsWith("inv-round."))).toHaveLength(
      12,
    );
  });
});

// ─── 5. Edits don't clear the counterpart ─────────────────────────────────

describe("duplicateRoundInSpec — edits are mode-local, don't invalidate counterpart", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("editing encrypt's round.4 params doesn't reset decrypt's mirrored duplicate", () => {
    duplicateRoundInSpec("round.2");
    const all = useCipherSpecsByMode();
    expect(findGroupIds(all().decrypt).filter((id) => id.startsWith("inv-round."))).toHaveLength(
      11,
    );

    // Edit an arbitrary param on encrypt. Today's editStepParams writes
    // to the active mode's slot only — decrypt should be unchanged.
    const encryptLeaf = findStep(all().encrypt, "round.4.add-round-key");
    expect(encryptLeaf).not.toBeNull();
    editStepParams("round.4.add-round-key", { auxName: "roundKey.4-custom" });

    // Decrypt's mirror is still intact. Byte-native (B1.2): the round key
    // index lives on `inv-round.4.add-round-key`.
    expect(findGroupIds(all().decrypt).filter((id) => id.startsWith("inv-round."))).toHaveLength(
      11,
    );
    expect(auxNameOf(all().decrypt, "inv-round.4.add-round-key")).toBe("roundKey.4");
  });
});

// ─── 6. Cipher swap rebuilds both ─────────────────────────────────────────

describe("duplicateRoundInSpec — cipher swap discards the duplicate (clean break)", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("setCipher rebuilds BOTH slots from canonical", () => {
    duplicateRoundInSpec("round.2");
    const all = useCipherSpecsByMode();
    expect(findGroupIds(all().encrypt).filter((id) => id.startsWith("round."))).toHaveLength(11);

    // AES-256 has 14 rounds canonical. A cipher swap should fully
    // replace both slots with the new canonical pair.
    setCipher("aes-256");
    expect(findGroupIds(all().encrypt).filter((id) => id.startsWith("round."))).toHaveLength(14);
    expect(findGroupIds(all().decrypt).filter((id) => id.startsWith("inv-round."))).toHaveLength(
      14,
    );
    expect(isCustomSpec()).toBe(false);
  });
});

// ─── 7. Store-level end-to-end round-trip across a mode flip ─────────────

describe("duplicateRoundInSpec — end-to-end round-trip via the store boundary", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("duplicate → run encrypt → flip mode → run decrypt → plaintext recovers", () => {
    // FIPS-197 §A.1 (plaintext, key). Modified spec produces non-
    // canonical ciphertext; we just verify the round-trip.
    const plaintextHex = "00112233445566778899aabbccddeeff";
    const keyHex = "000102030405060708090a0b0c0d0e0f";

    const spec = useSpec();

    // Active = encrypt. Duplicate round.2 — mirror lands on decrypt.
    duplicateRoundInSpec("round.2");

    const registry = buildDefaultRegistry();
    // Encrypt is byte-native (Slice B1.1): flat BytesState in/out, ported
    // dispatch required. Byte-equal to the legacy matrix encrypt, so it
    // inverts under the mirrored byte-native decrypt below.
    const encryptSpec = spec();
    const encryptTrace = runSpec(encryptSpec, registry, {
      initialState: makeBytesState(bytesFromHex(plaintextHex)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
      portedDispatchEnabled: requiresPortedDispatch(encryptSpec, registry),
    });
    if (encryptTrace.finalState.shape !== "bytes") throw new Error("expected bytes");
    const ciphertextBytes = encryptTrace.finalState.bytes;

    // Flip to decrypt — store returns the mirrored spec without
    // rebuilding from canonical.
    setMode("decrypt");

    // Decrypt is byte-native too (Slice B1.2): flat BytesState in/out, ported
    // dispatch required, descending seedInput chain through the mirrored
    // inverse rounds.
    const decryptSpec = spec();
    const decryptTrace = runSpec(decryptSpec, registry, {
      initialState: makeBytesState(ciphertextBytes),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
      portedDispatchEnabled: requiresPortedDispatch(decryptSpec, registry),
    });
    if (decryptTrace.finalState.shape !== "bytes") throw new Error("expected bytes");
    expect(hexFromBytes(decryptTrace.finalState.bytes)).toBe(plaintextHex);
  });
});

// ─── 8. Layout pin migration ──────────────────────────────────────────────

describe("duplicateRoundInSpec — layout pin migration", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("a pin on round.5 follows the rename to round.6 after a forward duplicate of round.2", () => {
    // Set up a pin on round.5 BEFORE the duplicate.
    setNodePosition("aes-128@1", "round.5", 200, 100);
    expect(getLayoutForSpec("aes-128@1")?.positions["round.5"]).toEqual({ x: 200, y: 100 });

    duplicateRoundInSpec("round.2");

    // round.5 became round.6 (subsequent siblings shift up). The
    // pin should follow.
    const layoutAfter = getLayoutForSpec("aes-128@1");
    expect(layoutAfter?.positions["round.6"]).toEqual({ x: 200, y: 100 });
    expect(layoutAfter?.positions["round.5"]).toBeUndefined();
  });

  it("pins on un-renamed nodes (round.1, key-expansion) pass through unchanged", () => {
    setNodePosition("aes-128@1", "round.1", 50, 50);
    setNodePosition("aes-128@1", "key-expansion", 0, 0);

    duplicateRoundInSpec("round.5"); // affects round.6..round.10

    const layoutAfter = getLayoutForSpec("aes-128@1");
    expect(layoutAfter?.positions["round.1"]).toEqual({ x: 50, y: 50 });
    expect(layoutAfter?.positions["key-expansion"]).toEqual({ x: 0, y: 0 });
  });
});
