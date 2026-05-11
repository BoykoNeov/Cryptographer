import type { BytesState, MatrixState, StepContext } from "@/core/types";
import { loadBlock } from "@/steps/load-block";
import { storeBlock } from "@/steps/store-block";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };

describe("load-block", () => {
  it("packs 16 bytes into a column-major 4x4 matrix (FIPS-197 layout)", () => {
    // Use the FIPS-197 Appendix C.1 plaintext so we know exactly where each
    // byte should land. Column-major: bytes 0..3 → column 0, etc.
    const input: BytesState = {
      shape: "bytes",
      bytes: new Uint8Array([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
      ]),
    };
    const result = loadBlock(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("matrix4x4-bytes");
    if (result.state.shape !== "matrix4x4-bytes") return;
    // The bytes array should be a copy of the input — load-block doesn't
    // change byte values, only the shape tag.
    expect(Array.from(result.state.bytes)).toEqual(Array.from(input.bytes));
  });

  it("allocates a fresh buffer (does not alias the input)", () => {
    const input: BytesState = { shape: "bytes", bytes: new Uint8Array(16) };
    const result = loadBlock(input, { blockSize: 16 }, ctx);
    if (result.state.shape !== "matrix4x4-bytes") return;
    expect(result.state.bytes).not.toBe(input.bytes);
  });

  it("throws when input length doesn't match blockSize", () => {
    const input: BytesState = { shape: "bytes", bytes: new Uint8Array(15) };
    expect(() => loadBlock(input, { blockSize: 16 }, ctx)).toThrow(/expected exactly 16 bytes/);
  });

  it("throws on non-AES blockSize (only 16 supported today)", () => {
    const input: BytesState = { shape: "bytes", bytes: new Uint8Array(8) };
    expect(() => loadBlock(input, { blockSize: 8 }, ctx)).toThrow(/only blockSize=16/);
  });

  it("rejects non-bytes state", () => {
    const matrixState: MatrixState = { shape: "matrix4x4-bytes", bytes: new Uint8Array(16) };
    expect(() => loadBlock(matrixState, { blockSize: 16 }, ctx)).toThrow(/bytes state/);
  });
});

describe("store-block", () => {
  it("unpacks a 4x4 matrix back into 16 bytes (identity on values)", () => {
    const input: MatrixState = {
      shape: "matrix4x4-bytes",
      bytes: new Uint8Array([
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
      ]),
    };
    const result = storeBlock(input, {}, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(Array.from(result.state.bytes)).toEqual(Array.from(input.bytes));
  });

  it("allocates a fresh buffer (does not alias the input)", () => {
    const input: MatrixState = { shape: "matrix4x4-bytes", bytes: new Uint8Array(16) };
    const result = storeBlock(input, {}, ctx);
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes).not.toBe(input.bytes);
  });

  it("rejects non-matrix state", () => {
    const bytesState: BytesState = { shape: "bytes", bytes: new Uint8Array(16) };
    expect(() => storeBlock(bytesState, {}, ctx)).toThrow(/matrix4x4-bytes/);
  });
});

describe("load-block / store-block round-trip", () => {
  it("16 bytes → matrix → 16 bytes is byte-identical", () => {
    const original = new Uint8Array([
      0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33,
      0x44,
    ]);
    const loaded = loadBlock({ shape: "bytes", bytes: original }, { blockSize: 16 }, ctx);
    if (loaded.state.shape !== "matrix4x4-bytes") return;
    const stored = storeBlock(loaded.state, {}, ctx);
    if (stored.state.shape !== "bytes") return;
    expect(Array.from(stored.state.bytes)).toEqual(Array.from(original));
  });
});
