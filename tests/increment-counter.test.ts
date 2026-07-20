/**
 * `increment-counter@1` unit tests — the arithmetic CTR mode rests on.
 *
 * The step is three lines of carry ripple, but its correctness is load-bearing
 * in a way that hides well: a wrong carry produces a *plausible* keystream, so
 * the cipher still "works" (encrypt/decrypt round-trip fine, because both sides
 * make the same mistake) and only an external oracle catches it. These tests
 * pin the arithmetic directly, so a failure here names the bug instead of
 * surfacing as an unexplained AES-CTR mismatch three files away.
 *
 * The properties that matter:
 *   • big-endian — the carry travels right-to-left (SP 800-38A Appendix B.1)
 *   • width-free — the modulus is the input's byte length, whatever it is
 *   • total — all-ones wraps to zero rather than throwing
 *
 * References: NIST SP 800-38A Appendix B.1.
 */

import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { incrementCounter } from "@/steps/increment-counter";
import { describe, expect, it } from "vitest";

/** Run the executor on a hex counter, return the hex result. */
const inc = (hex: string): string => {
  const out = incrementCounter(new Map([["counter", bytesFromHex(hex)]]), {}, undefined as never);
  const bytes = out.get("output");
  if (bytes === undefined) throw new Error("increment-counter produced no 'output' port");
  return hexFromBytes(bytes);
};

describe("increment-counter@1 — the +1 inside CTR's loop", () => {
  it("adds one to the least-significant (rightmost) byte", () => {
    // Big-endian: the LAST byte is the ones place. If this step were
    // little-endian the first byte would move instead, and every CTR vector
    // would disagree with node:crypto.
    expect(inc("00000000000000000000000000000001")).toBe("00000000000000000000000000000002");
  });

  it("ripples a carry leftward when a byte overflows 0xFF", () => {
    expect(inc("000000ff")).toBe("00000100");
  });

  it("ripples a carry across many consecutive 0xFF bytes", () => {
    // The carry has to survive the whole run of FFs and stop at the first byte
    // that doesn't overflow. A `break` placed one statement early would leave
    // the trailing FFs untouched.
    expect(inc("07ffffff")).toBe("08000000");
  });

  it("wraps all-ones to all-zero rather than throwing (mod 2^(8·len))", () => {
    // Total, not partial: a counter that has exhausted its space wraps. Real
    // CTR must never get here under one key, but that is a key-management
    // property this leaf cannot police — it sees one block, not the message.
    expect(inc("ffffffffffffffff")).toBe("0000000000000000");
  });

  it("stops the ripple at the first byte that does not overflow", () => {
    // Byte 1 (0x00) absorbs the carry; byte 0 must be left alone.
    expect(inc("4200ff")).toBe("420100");
  });

  it("derives its width from the input — the same step serves every block size", () => {
    // This is the property that makes CTR cipher-agnostic: 4 bytes for
    // Speck32/64, 8 for DES/Blowfish, 16 for AES/Serpent, one step type.
    expect(inc("ffffffff")).toBe("00000000"); // Speck's 4-byte block
    expect(inc("00000000000000ff")).toBe("0000000000000100"); // DES/Blowfish
    expect(inc("000000000000000000000000000000ff")).toBe(
      "00000000000000000000000000000100", // AES/Serpent
    );
  });

  it("leaves the input buffer untouched (outputs are freshly owned)", () => {
    // The CTR loop reads the incoming counter for BOTH the cipher body and
    // this step; mutating in place would corrupt the keystream branch.
    const input = bytesFromHex("000000ff");
    incrementCounter(new Map([["counter", input]]), {}, undefined as never);
    expect(hexFromBytes(input)).toBe("000000ff");
  });

  it("rejects a missing port by name so the editor can flag the unwired arrow", () => {
    expect(() => incrementCounter(new Map(), {}, undefined as never)).toThrow(
      /missing required input port 'counter'/,
    );
  });

  it("rejects a zero-width counter rather than emitting an empty block", () => {
    // An empty output would surface downstream as a confusing xor@1
    // length-mismatch; fail where the cause is.
    expect(() =>
      incrementCounter(new Map([["counter", new Uint8Array(0)]]), {}, undefined as never),
    ).toThrow(/at least 1 byte/);
  });
});
