import type { BytesState, StepContext } from "@/core/types";
import { zeroPad } from "@/steps/zero-pad";
import { zeroUnpad } from "@/steps/zero-unpad";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };

const bytes = (...vals: number[]): BytesState => ({
  shape: "bytes",
  bytes: new Uint8Array(vals),
});

describe("zero-pad", () => {
  it("pads a 5-byte input ('apple') with eleven 0x00 bytes", () => {
    const input = bytes(0x61, 0x70, 0x70, 0x6c, 0x65); // "apple"
    const result = zeroPad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    expect(Array.from(result.state.bytes.slice(0, 5))).toEqual([0x61, 0x70, 0x70, 0x6c, 0x65]);
    for (let i = 5; i < 16; i++) {
      expect(result.state.bytes[i]).toBe(0x00);
    }
  });

  it("is a NO-OP when input is already a clean block multiple", () => {
    // This is the distinguishing property vs. PKCS#7: zero-pad doesn't
    // append a full extra block when input.length % blockSize == 0. It
    // returns the input unchanged in length (and byte content).
    const input = bytes(...new Array(16).fill(0x42));
    const result = zeroPad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    for (let i = 0; i < 16; i++) {
      expect(result.state.bytes[i]).toBe(0x42);
    }
  });

  it("pads a 15-byte input with a single 0x00", () => {
    const input = bytes(...new Array(15).fill(0xaa));
    const result = zeroPad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    expect(result.state.bytes[15]).toBe(0x00);
  });

  it("supports non-AES block sizes (DES blockSize=8)", () => {
    const input = bytes(0x01, 0x02, 0x03); // 3 bytes
    const result = zeroPad(input, { blockSize: 8 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(8);
    for (let i = 3; i < 8; i++) {
      expect(result.state.bytes[i]).toBe(0x00);
    }
  });

  it("rejects bad params shapes", () => {
    expect(() => zeroPad(bytes(), {}, ctx)).toThrow(/blockSize/);
    expect(() => zeroPad(bytes(), { blockSize: 0 }, ctx)).toThrow(/blockSize/);
    expect(() => zeroPad(bytes(), { blockSize: 256 }, ctx)).toThrow(/blockSize/);
    expect(() => zeroPad(bytes(), { blockSize: 1.5 }, ctx)).toThrow(/blockSize/);
  });

  it("rejects non-bytes state", () => {
    const matrixState = { shape: "matrix4x4-bytes" as const, bytes: new Uint8Array(16) };
    expect(() => zeroPad(matrixState, { blockSize: 16 }, ctx)).toThrow(/bytes state/);
  });
});

describe("zero-unpad", () => {
  it("round-trips pad → unpad LOSSILY across lengths 1..15 (no trailing zeros)", () => {
    // Use a non-zero terminator on the original so the inverse is non-lossy
    // for this case. Bytes 1..length-1 are arbitrary nonzero values.
    for (let len = 1; len <= 15; len++) {
      const original = new Uint8Array(len);
      for (let i = 0; i < len; i++) original[i] = (i * 7 + 1) & 0xff || 1; // never 0
      const padded = zeroPad({ shape: "bytes", bytes: original }, { blockSize: 16 }, ctx);
      const unpadded = zeroUnpad(padded.state, { blockSize: 16 }, ctx);
      expect(unpadded.state.shape).toBe("bytes");
      if (unpadded.state.shape !== "bytes") return;
      expect(unpadded.state.bytes.length).toBe(len);
      expect(Array.from(unpadded.state.bytes)).toEqual(Array.from(original));
    }
  });

  it("DEMONSTRATES THE LOSSINESS: trailing 0x00 in original is eaten", () => {
    // Original = "hi\x00\x00" (4 bytes, last two are intentional NULs).
    // zero-pad adds 12 more zeros → 16 bytes total. zero-unpad strips ALL
    // trailing zeros → "hi" (2 bytes). The original NULs are gone.
    // This is the canonical zero-pad weakness — make it visible in tests.
    const original = bytes(0x68, 0x69, 0x00, 0x00);
    const padded = zeroPad(original, { blockSize: 16 }, ctx);
    const unpadded = zeroUnpad(padded.state, { blockSize: 16 }, ctx);
    expect(unpadded.state.shape).toBe("bytes");
    if (unpadded.state.shape !== "bytes") return;
    expect(Array.from(unpadded.state.bytes)).toEqual([0x68, 0x69]);
  });

  it("strips eleven 0x00 bytes from a padded 'apple'", () => {
    const padded = bytes(
      0x61,
      0x70,
      0x70,
      0x6c,
      0x65,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
    );
    const result = zeroUnpad(padded, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(Array.from(result.state.bytes)).toEqual([0x61, 0x70, 0x70, 0x6c, 0x65]);
  });

  it("returns empty bytes when the entire block is 0x00", () => {
    // No malformed-padding error here — an all-zeros block is valid zero-
    // padding of an empty input (or of itself when blockSize-aligned).
    const padded = bytes(...new Array(16).fill(0x00));
    const result = zeroUnpad(padded, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(0);
  });

  it("throws on empty input", () => {
    expect(() => zeroUnpad(bytes(), { blockSize: 16 }, ctx)).toThrow(/empty/);
  });

  it("throws when input length isn't a multiple of blockSize", () => {
    expect(() => zeroUnpad(bytes(1, 2, 3), { blockSize: 16 }, ctx)).toThrow(
      /multiple of blockSize/,
    );
  });
});
