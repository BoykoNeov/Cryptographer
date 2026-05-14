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
 * Length contract: setIvBytes throws on non-16-byte input.
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
    setIvBytes(fresh);
    expect(Array.from(useIvBytes()())).toEqual(Array.from(fresh));
  });

  it("setIvBytes makes a defensive copy (caller mutation does not leak)", () => {
    const fresh = new Uint8Array(16).fill(0xab);
    setIvBytes(fresh);
    fresh[0] = 0x00;
    expect(useIvBytes()()[0]).toBe(0xab);
  });

  it("setIvBytes throws on wrong length", () => {
    expect(() => setIvBytes(new Uint8Array(15))).toThrow(/must be 16 bytes, got 15/);
    expect(() => setIvBytes(new Uint8Array(32))).toThrow(/must be 16 bytes, got 32/);
    expect(() => setIvBytes(new Uint8Array(0))).toThrow(/must be 16 bytes, got 0/);
  });

  it("randomizeIv produces 16 bytes that differ across two calls", () => {
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

  it("__resetIvForTests returns to the NIST default", () => {
    randomizeIv();
    __resetIvForTests();
    expect(Array.from(useIvBytes()())).toEqual(Array.from(NIST_IV));
  });
});
