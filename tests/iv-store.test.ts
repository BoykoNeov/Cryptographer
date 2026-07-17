/**
 * Tests for `src/ui/stores/iv.ts` — the IV signal that the App seeds
 * under `aux["iv"]` when CBC is active.
 *
 * Three properties to pin:
 *
 *   1. **Default.** Fresh sessions start at the NIST §F.2 standard test
 *      IV, so the first-impression CBC run against the §F sample
 *      plaintext matches the published §F.2.1 ciphertext.
 *   2. **Randomize produces 16 fresh bytes** with overwhelming
 *      probability of two consecutive calls differing.
 *   3. **Defensive copy on write.** Mutating the input after setIvBytes
 *      must not leak into the stored signal — aux entries survive
 *      across many frames and aliased Uint8Arrays would corrupt them
 *      from a distance.
 *
 * Length contract: the IV is exactly one cipher block wide (it XORs with a
 * block), so `setIvBytes` throws when the bytes don't match the width the
 * caller names. The width is a PARAMETER rather than a fixed 16 — an
 * 8-byte-block cipher in CBC needs an 8-byte IV, and the old fixed check made
 * that unrepresentable. See `docs/plans/foamy-prancing-wren.md` Phase B.
 *
 * localStorage persistence is tested separately at the App level (via
 * the document round-trip test); the node env vitest is running under
 * doesn't provide localStorage, so this file stays focused on the
 * in-memory signal contract.
 */

import { __resetIvForTests, randomizeIv, setIvBytes, useIvBytes } from "@/ui/stores/iv";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const NIST_IV = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

describe("iv store", () => {
  beforeEach(() => {
    __resetIvForTests();
  });

  afterEach(() => {
    __resetIvForTests();
  });

  it("default IV is the NIST SP 800-38A §F.2 standard test vector", () => {
    expect(Array.from(useIvBytes()())).toEqual(Array.from(NIST_IV));
  });

  it("setIvBytes updates the signal", () => {
    const fresh = new Uint8Array(16).fill(0xab);
    setIvBytes(fresh, 16);
    expect(Array.from(useIvBytes()())).toEqual(Array.from(fresh));
  });

  it("setIvBytes makes a defensive copy (caller mutation does not leak)", () => {
    const fresh = new Uint8Array(16).fill(0xab);
    setIvBytes(fresh, 16);
    fresh[0] = 0x00;
    expect(useIvBytes()()[0]).toBe(0xab);
  });

  it("setIvBytes throws when the bytes don't match the named block width", () => {
    expect(() => setIvBytes(new Uint8Array(15), 16)).toThrow(/must be 16 bytes, got 15/);
    expect(() => setIvBytes(new Uint8Array(32), 16)).toThrow(/must be 16 bytes, got 32/);
    expect(() => setIvBytes(new Uint8Array(0), 16)).toThrow(/must be 16 bytes, got 0/);
  });

  it("setIvBytes accepts a non-16 IV when that IS the cipher's block width", () => {
    // The property the old fixed-16 check made unrepresentable: an
    // 8-byte-block cipher (DES/Blowfish) in CBC needs an 8-byte IV. No
    // shipped cipher exercises this until Phase C, so it is pinned here.
    const eight = new Uint8Array(8).fill(0xcd);
    setIvBytes(eight, 8);
    expect(Array.from(useIvBytes()())).toEqual(Array.from(eight));
    // ...and 16 is now the WRONG length for that cipher, not the right one.
    expect(() => setIvBytes(new Uint8Array(16), 8)).toThrow(/must be 8 bytes, got 16/);
  });

  it("setIvBytes skips the length check when the caller names no width", () => {
    // The document-restore path: the schema already validated the length and
    // there's no cipher context to check against.
    const odd = new Uint8Array(8).fill(0x11);
    setIvBytes(odd, undefined);
    expect(Array.from(useIvBytes()())).toEqual(Array.from(odd));
  });

  it("randomizeIv produces one block of bytes that differ across two calls", () => {
    randomizeIv();
    const first = new Uint8Array(useIvBytes()());
    expect(first.length).toBe(16);

    randomizeIv();
    const second = new Uint8Array(useIvBytes()());
    expect(second.length).toBe(16);

    // The chance of two 16-byte crypto-random sequences being equal is
    // ~2^-128 — well below the bar for "this test will be flaky."
    expect(Array.from(first)).not.toEqual(Array.from(second));
  });

  it("randomizeIv fills the width it's given", () => {
    randomizeIv(8);
    expect(useIvBytes()().length).toBe(8);
  });

  it("__resetIvForTests returns to the NIST default", () => {
    randomizeIv();
    __resetIvForTests();
    expect(Array.from(useIvBytes()())).toEqual(Array.from(NIST_IV));
  });
});
