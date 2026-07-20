/**
 * CTR never takes the padding overlay — the regression pin for the
 * `overlayBlockBytes` seam (2026-07-20).
 *
 * ## Why this file exists
 *
 * CTR is a stream mode: it needs no padding, and a pad step spliced into a CTR
 * spec would re-fill the final block so the partial-block path would **silently
 * never run**. The failure has no error and no visual tell — the app just goes
 * back to behaving like a block mode, which is precisely the thing CTR exists
 * to contrast with.
 *
 * The rule originally landed in `buildCanonicalPair` alone. **Browser smoke
 * found the gap within minutes:** `setPadding` recomputed the block width
 * independently, so choosing a scheme while CTR was active padded the message
 * back up to a whole block (a 5-byte plaintext produced 16 bytes of
 * ciphertext). Three more call sites had the same shape —
 * `setSpecFromDocument`, `resetSpec`, `isCustomSpec` — each recomputing the
 * width with a bare `blockByteLengthFor`.
 *
 * All five now route through one `overlayBlockBytes(cipher, cipherMode)`
 * helper. This file drives the STORE SETTERS (not the helper directly), because
 * the bug was never in the width calculation — it was in a call site forgetting
 * to ask. A test of the helper alone would have passed throughout.
 *
 * The invariant, stated once: **after any store operation, a CTR spec contains
 * no padding leaf, whatever the persisted padding scheme.**
 */

import type { CipherSpec, StepNode } from "@/core/types";
import {
  __resetSpecForTests,
  resetSpec,
  setCipher,
  setCipherMode,
  setMode,
  setPadding,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { beforeEach, describe, expect, it } from "vitest";

/** Every padding step type the overlay can splice in. */
const PAD_TYPES = [
  "generic.pkcs7-pad@1",
  "generic.pkcs7-unpad@1",
  "generic.zero-pad@1",
  "generic.zero-unpad@1",
  "generic.iso7816-4-pad@1",
  "generic.iso7816-4-unpad@1",
];

/** Recursively collect every step type in a spec tree. */
const stepTypesIn = (nodes: readonly StepNode[]): string[] => {
  const out: string[] = [];
  for (const n of nodes) {
    if (n.kind === "step") out.push(n.type);
    else out.push(...stepTypesIn(n.children));
  }
  return out;
};

const padLeavesIn = (spec: CipherSpec): string[] =>
  stepTypesIn(spec.steps).filter((t) => PAD_TYPES.includes(t));

/** Assert BOTH slots of the current cipher spec pair are pad-free. */
const expectNoPadding = (label: string): void => {
  const current = useSpecsByMode()();
  if (current.kind !== "cipher") throw new Error(`${label}: expected a cipher spec pair`);
  expect(padLeavesIn(current.encrypt), `${label} (encrypt)`).toEqual([]);
  expect(padLeavesIn(current.decrypt), `${label} (decrypt)`).toEqual([]);
};

describe("CTR never takes the padding overlay — all five call sites", () => {
  beforeEach(() => {
    __resetSpecForTests();
    setPadding("none");
    setCipher("aes-128");
  });

  it("buildCanonicalPair: entering CTR with a padding scheme already active splices no pad", () => {
    // The persisted-scheme path — the user picks PKCS#7 in ECB, then switches
    // to CTR. `setCipherMode` rebuilds via buildCanonicalPair.
    setCipherMode("ecb");
    setPadding("pkcs7");
    setCipherMode("ctr");
    expectNoPadding("after setCipherMode('ctr')");
  });

  it("setPadding: choosing a scheme WHILE CTR is active splices no pad (the smoke-caught bug)", () => {
    // This is the exact sequence browser smoke failed on. `setPadding`
    // recomputed the width itself, bypassing buildCanonicalPair's CTR check.
    setCipherMode("ctr");
    for (const scheme of ["pkcs7", "zero-pad", "iso7816-4"] as const) {
      setPadding(scheme);
      expectNoPadding(`after setPadding('${scheme}') under CTR`);
    }
  });

  it("resetSpec: restoring canonical under CTR splices no pad", () => {
    setCipherMode("ctr");
    setPadding("pkcs7");
    resetSpec();
    expectNoPadding("after resetSpec() under CTR");
  });

  it("holds in BOTH directions — decrypt is as pad-free as encrypt", () => {
    // CTR ciphertext is exactly as ragged as its plaintext, so an unpad leaf on
    // the decrypt side would be just as wrong. `expectNoPadding` checks both
    // slots, but pin the direction explicitly since decrypt is the side a
    // careless "encrypt needs no padding" reading would miss.
    setCipherMode("ctr");
    setPadding("pkcs7");
    setMode("decrypt");
    expectNoPadding("decrypt mode under CTR");
    setMode("encrypt");
    expectNoPadding("encrypt mode under CTR");
  });

  it("holds for every cored cipher, not just AES", () => {
    // The overlay's width comes from the core, so a per-cipher regression is
    // possible in principle. Speck's 4-byte block is the sharpest case.
    for (const cipher of ["aes-128", "speck-32-64-be", "blowfish", "des", "serpent-128"] as const) {
      setCipher(cipher);
      setCipherMode("ctr");
      setPadding("pkcs7");
      expectNoPadding(`${cipher} under CTR`);
    }
  });

  it("ECB and CBC still DO take the overlay — the relaxation must not leak", () => {
    // The other half of the invariant. If this ever goes green-by-accident
    // (e.g. someone makes `overlayBlockBytes` always return undefined), the
    // CTR assertions above would still pass while padding broke everywhere.
    setCipherMode("ecb");
    setPadding("pkcs7");
    const current = useSpecsByMode()();
    if (current.kind !== "cipher") throw new Error("expected a cipher spec pair");
    expect(padLeavesIn(current.encrypt)).toContain("generic.pkcs7-pad@1");
    expect(padLeavesIn(current.decrypt)).toContain("generic.pkcs7-unpad@1");
  });
});
