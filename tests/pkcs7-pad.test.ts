import type { BytesState, StepContext } from "@/core/types";
import { pkcs7Pad } from "@/steps/pkcs7-pad";
import { pkcs7Unpad } from "@/steps/pkcs7-unpad";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };

const bytes = (...vals: number[]): BytesState => ({
  shape: "bytes",
  bytes: new Uint8Array(vals),
});

describe("pkcs7-pad", () => {
  it("pads a 5-byte input ('apple') with eleven 0x0b bytes", () => {
    const input = bytes(0x61, 0x70, 0x70, 0x6c, 0x65); // "apple"
    const result = pkcs7Pad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    // Original 5 bytes intact.
    expect(Array.from(result.state.bytes.slice(0, 5))).toEqual([0x61, 0x70, 0x70, 0x6c, 0x65]);
    // Trailing 11 bytes are all 0x0b (= 11).
    for (let i = 5; i < 16; i++) {
      expect(result.state.bytes[i]).toBe(0x0b);
    }
  });

  it("pads an empty input with a full block of 0x10", () => {
    const result = pkcs7Pad(bytes(), { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    for (let i = 0; i < 16; i++) {
      expect(result.state.bytes[i]).toBe(0x10);
    }
  });

  it("pads a 15-byte input with a single 0x01", () => {
    const input = bytes(...new Array(15).fill(0xaa));
    const result = pkcs7Pad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    expect(result.state.bytes[15]).toBe(0x01);
  });

  it("pads a 16-byte input by adding a FULL extra block of 0x10", () => {
    // PKCS#7 always adds at least one byte. When input is already a block
    // multiple, that means appending a whole extra block. The UI clamps
    // this at 15 bytes in single-block scope, but the step itself must
    // implement the canonical behavior.
    const input = bytes(...new Array(16).fill(0x42));
    const result = pkcs7Pad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(32);
    for (let i = 16; i < 32; i++) {
      expect(result.state.bytes[i]).toBe(0x10);
    }
  });

  it("supports non-AES block sizes (DES blockSize=8)", () => {
    const input = bytes(0x01, 0x02, 0x03); // 3 bytes
    const result = pkcs7Pad(input, { blockSize: 8 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(8);
    // 5 bytes of padding, each = 5.
    for (let i = 3; i < 8; i++) {
      expect(result.state.bytes[i]).toBe(0x05);
    }
  });

  it("rejects bad params shapes", () => {
    expect(() => pkcs7Pad(bytes(), {}, ctx)).toThrow(/blockSize/);
    expect(() => pkcs7Pad(bytes(), { blockSize: 0 }, ctx)).toThrow(/blockSize/);
    expect(() => pkcs7Pad(bytes(), { blockSize: 256 }, ctx)).toThrow(/blockSize/);
    expect(() => pkcs7Pad(bytes(), { blockSize: 1.5 }, ctx)).toThrow(/blockSize/);
  });

  // The "rejects non-bytes state" guard test was retired in Phase 5
  // Slice 5.1 (2026-05-30) with the MatrixState shape (see zero-pad.test.ts).
});

describe("pkcs7-unpad", () => {
  it("round-trips pad → unpad across all lengths 0..15", () => {
    for (let len = 0; len <= 15; len++) {
      const original = new Uint8Array(len);
      for (let i = 0; i < len; i++) original[i] = (i * 7 + 1) & 0xff; // arbitrary pattern
      const padded = pkcs7Pad({ shape: "bytes", bytes: original }, { blockSize: 16 }, ctx);
      const unpadded = pkcs7Unpad(padded.state, { blockSize: 16 }, ctx);
      expect(unpadded.state.shape).toBe("bytes");
      if (unpadded.state.shape !== "bytes") return;
      expect(unpadded.state.bytes.length).toBe(len);
      expect(Array.from(unpadded.state.bytes)).toEqual(Array.from(original));
    }
  });

  it("strips eleven 0x0b bytes from a padded 'apple'", () => {
    const padded = bytes(
      0x61,
      0x70,
      0x70,
      0x6c,
      0x65,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
      0x0b,
    );
    const result = pkcs7Unpad(padded, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(Array.from(result.state.bytes)).toEqual([0x61, 0x70, 0x70, 0x6c, 0x65]);
  });

  it("throws on empty input", () => {
    expect(() => pkcs7Unpad(bytes(), { blockSize: 16 }, ctx)).toThrow(/empty/);
  });

  it("throws when input length isn't a multiple of blockSize", () => {
    expect(() => pkcs7Unpad(bytes(1, 2, 3), { blockSize: 16 }, ctx)).toThrow(
      /multiple of blockSize/,
    );
  });

  it("throws when pad length is 0 (out of range)", () => {
    // Last byte is 0x00 — never a valid PKCS#7 pad length.
    const bad = bytes(...new Array(15).fill(0xaa), 0x00);
    expect(() => pkcs7Unpad(bad, { blockSize: 16 }, ctx)).toThrow(/out of range/);
  });

  it("throws when pad length exceeds blockSize", () => {
    // Last byte claims pad length 0x11 (17) — impossible for blockSize 16.
    const bad = bytes(...new Array(15).fill(0xaa), 0x11);
    expect(() => pkcs7Unpad(bad, { blockSize: 16 }, ctx)).toThrow(/out of range/);
  });

  it("throws when trailing bytes don't all match the pad length", () => {
    // padLen says 4, but only 3 of the trailing bytes are 0x04.
    const bad = bytes(
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xaa,
      0xff, // <-- should be 0x04 too
      0x04,
      0x04,
      0x04,
    );
    expect(() => pkcs7Unpad(bad, { blockSize: 16 }, ctx)).toThrow(/padding byte at offset/);
  });
});
