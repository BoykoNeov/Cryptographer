/**
 * The IV must be exactly one block of the ACTIVE cipher — regression pins for
 * `reconcileIvWidth`.
 *
 * ## The bug this guards, and why the whole test suite missed it
 *
 * Phase C's browser smoke landed on Blowfish + CBC and screenshotted a **16-byte**
 * IV (`000102…0f`, the AES default) sitting in the field of a cipher whose block
 * is 8. `IvInput` passes Blowfish's 8 to `setIvBytes`, which THROWS on a
 * mismatch — so the field was displaying a value it would have rejected had the
 * user typed it back. Phase B made the IV width a parameter but never re-defaulted
 * the STORED value, which is persisted and module-scope while `cipher` /
 * `cipherMode` are session-only.
 *
 * ## Why none of this asserts a ciphertext
 *
 * It cannot. The 16-byte default truncated to 8 by the runtime's port-length
 * coercion is `0001020304050607` — byte-identical to the correct 8-byte default.
 * Blowfish CBC therefore produces the SAME ciphertext broken and fixed, and a KAT
 * cannot tell them apart. The defect is the stored/displayed VALUE, so that is
 * what these assert.
 */

import {
  __resetIvForTests,
  defaultIvOfWidth,
  reconcileIvWidth,
  setIvBytes,
  useIvBytes,
} from "@/ui/stores/iv";
import { beforeEach, describe, expect, it } from "vitest";

const ivBytes = useIvBytes();

describe("defaultIvOfWidth", () => {
  it("reproduces the published SP 800-38A §F IV at AES's width", () => {
    // The generated default must stay byte-identical to the spelled-out vector
    // it replaced, or AES-128 CBC stops reproducing the published §F.2.1
    // ciphertext on first impression.
    expect([...defaultIvOfWidth(16)]).toEqual([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
      0x0f,
    ]);
  });

  it("extends the same rule to a non-16 block", () => {
    expect([...defaultIvOfWidth(8)]).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect([...defaultIvOfWidth(4)]).toEqual([0, 1, 2, 3]);
  });
});

describe("reconcileIvWidth", () => {
  beforeEach(() => {
    __resetIvForTests();
  });

  it("narrows the AES-width default to 8 for an 8-byte-block cipher", () => {
    expect(ivBytes().length).toBe(16);
    reconcileIvWidth(8);
    expect(ivBytes().length).toBe(8);
  });

  it("widens back to 16 when returning to AES", () => {
    // The bug is bidirectional: the IV persists across reloads while `cipher`
    // and `cipherMode` are session-only, so an 8-byte IV left over from a
    // Blowfish session would otherwise be handed to AES-128 on the next CBC run.
    reconcileIvWidth(8);
    reconcileIvWidth(16);
    expect(ivBytes().length).toBe(16);
  });

  it("leaves a user's hand-typed IV alone when the width already agrees", () => {
    // Reconcile fires on every cipher/mode change, so a no-op on agreement is
    // what keeps it from stomping a deliberate IV mid-experiment.
    const custom = Uint8Array.from({ length: 16 }, () => 0xab);
    setIvBytes(custom, 16);
    reconcileIvWidth(16);
    expect([...ivBytes()]).toEqual([...custom]);
  });

  it("leaves the IV alone when there is no block cipher at all", () => {
    // A hash / RSA / coreless cipher has no block, so the IV is inert rather
    // than wrong — nothing to reconcile it against.
    const custom = Uint8Array.from({ length: 16 }, () => 0xcd);
    setIvBytes(custom, 16);
    reconcileIvWidth(undefined);
    expect([...ivBytes()]).toEqual([...custom]);
  });

  it("leaves an IV the active cipher would ACCEPT — the actual defect", () => {
    // The sharpest statement of the bug: whatever the store holds after a
    // reconcile must be a value `setIvBytes` accepts at that same width. Before
    // the fix this threw — the field displayed 16 bytes while validating at 8.
    reconcileIvWidth(8);
    expect(() => setIvBytes(ivBytes(), 8)).not.toThrow();
  });
});
