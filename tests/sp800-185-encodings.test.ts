/**
 * NIST SP 800-185 §2.3 encodings — `left_encode` / `right_encode` (core) and
 * the `encode-string@1` / `bytepad@1` / `right-encode@1` port-native steps.
 *
 * These byte encodings are the whole cSHAKE/KMAC prefix machinery, and the
 * bit-vs-byte length in `encode_string` is the single most common
 * implementation bug — so the properties are pinned directly against the
 * §2.3 formulas and the values cross-checked in the independent reference
 * (`M:\claud_projects\temp\cshake-kmac-ref\ref.py`, which agrees with
 * pycryptodome + the NIST published samples).
 */

import { leftEncode, rightEncode } from "@/core/sp800-185";
import type { Json, StepContext } from "@/core/types";
import { bytepad } from "@/steps/bytepad";
import { encodeString } from "@/steps/encode-string";
import { rightEncodeStep } from "@/steps/right-encode";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };
const bytes = (...b: number[]) => new Uint8Array(b);

// ─── core: left_encode / right_encode ──────────────────────────────────────

describe("left_encode (SP 800-185 §2.3.1)", () => {
  it("encodes 0 as 01 00 (n=1, single zero byte)", () => {
    expect(Array.from(leftEncode(0))).toEqual([0x01, 0x00]);
  });
  it("encodes a one-byte value with the count first", () => {
    expect(Array.from(leftEncode(168))).toEqual([0x01, 0xa8]);
    expect(Array.from(leftEncode(136))).toEqual([0x01, 0x88]);
  });
  it("uses the minimal number of big-endian bytes", () => {
    expect(Array.from(leftEncode(255))).toEqual([0x01, 0xff]);
    expect(Array.from(leftEncode(256))).toEqual([0x02, 0x01, 0x00]);
    expect(Array.from(leftEncode(65536))).toEqual([0x03, 0x01, 0x00, 0x00]);
  });
  it("rejects negative and non-integer values", () => {
    expect(() => leftEncode(-1)).toThrow(/non-negative integer/);
    expect(() => leftEncode(1.5)).toThrow(/non-negative integer/);
  });
});

describe("right_encode (SP 800-185 §2.3.1)", () => {
  it("encodes 0 as 00 01 (count last) — the KMACXOF suffix", () => {
    expect(Array.from(rightEncode(0))).toEqual([0x00, 0x01]);
  });
  it("puts the byte count last", () => {
    expect(Array.from(rightEncode(256))).toEqual([0x01, 0x00, 0x02]);
    expect(Array.from(rightEncode(512))).toEqual([0x02, 0x00, 0x02]);
  });
});

// ─── encode-string@1 ────────────────────────────────────────────────────────

describe("encode-string@1 (SP 800-185 §2.3.2)", () => {
  const run = (s: Uint8Array) =>
    encodeString(new Map([["input", s]]), {} as Json, CTX).get("output") as Uint8Array;

  it("prefixes with the BIT length, not the byte length (the #1 footgun)", () => {
    // "Email Signature" is 15 bytes ⇒ 120 bits ⇒ left_encode(120) = 01 78.
    const s = new TextEncoder().encode("Email Signature");
    const out = run(s);
    expect(Array.from(out.subarray(0, 2))).toEqual([0x01, 0x78]);
    expect(Array.from(out.subarray(2))).toEqual(Array.from(s));
  });

  it("encodes the empty string as 01 00 (left_encode(0))", () => {
    expect(Array.from(run(bytes()))).toEqual([0x01, 0x00]);
  });

  it("encodes the fixed KMAC name string", () => {
    // "KMAC" = 4 bytes = 32 bits ⇒ left_encode(32) = 01 20, then 4B 4D 41 43.
    const out = run(new TextEncoder().encode("KMAC"));
    expect(Array.from(out)).toEqual([0x01, 0x20, 0x4b, 0x4d, 0x41, 0x43]);
  });

  it("throws on a missing input port", () => {
    expect(() => encodeString(new Map(), {} as Json, CTX)).toThrow(/missing required input port/);
  });
});

// ─── bytepad@1 ──────────────────────────────────────────────────────────────

describe("bytepad@1 (SP 800-185 §2.3.3)", () => {
  const run = (x: Uint8Array, w: number) =>
    bytepad(new Map([["input", x]]), { w } as Json, CTX).get("output") as Uint8Array;

  it("prefixes left_encode(w) and zero-pads up to a multiple of w", () => {
    const out = run(bytes(0xaa, 0xbb), 8);
    // left_encode(8) = 01 08, then AA BB, then zero-pad to 8 bytes.
    expect(Array.from(out)).toEqual([0x01, 0x08, 0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00]);
    expect(out.length % 8).toBe(0);
  });

  it("adds a whole extra block only when needed, none when already aligned", () => {
    // body = left_encode(4)=01 04 + 2 bytes = 4 bytes = exactly one w=4 block.
    const out = run(bytes(0xaa, 0xbb), 4);
    expect(Array.from(out)).toEqual([0x01, 0x04, 0xaa, 0xbb]);
    expect(out.length).toBe(4);
  });

  it("always lands on a rate boundary for the real sponge rates", () => {
    for (const w of [168, 136]) {
      const out = run(new Uint8Array(300), w);
      expect(out.length % w).toBe(0);
      expect(out.length).toBeGreaterThanOrEqual(300);
    }
  });

  it("throws on a bad w", () => {
    expect(() => run(bytes(1), 0)).toThrow(/params.w must be a positive integer/);
  });
});

// ─── right-encode@1 ─────────────────────────────────────────────────────────

describe("right-encode@1 (SP 800-185 §2.3.1)", () => {
  const run = (value: number) =>
    rightEncodeStep(new Map(), { value } as Json, CTX).get("output") as Uint8Array;

  it("emits right_encode(L·8) for a KMAC output-length commitment", () => {
    // 32 bytes ⇒ 256 bits ⇒ right_encode(256) = 01 00 02.
    expect(Array.from(run(256))).toEqual([0x01, 0x00, 0x02]);
  });

  it("emits right_encode(0) = 00 01 for the KMACXOF variant", () => {
    expect(Array.from(run(0))).toEqual([0x00, 0x01]);
  });

  it("throws on a negative value", () => {
    expect(() => run(-8)).toThrow(/non-negative integer/);
  });
});
