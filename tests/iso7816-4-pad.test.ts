import type { BytesState, Json, StepContext } from "@/core/types";
import { iso78164Pad as iso78164PadExec } from "@/steps/iso7816-4-pad";
import { iso78164Unpad as iso78164UnpadExec } from "@/steps/iso7816-4-unpad";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };

const bytes = (...vals: number[]): BytesState => ({
  shape: "bytes",
  bytes: new Uint8Array(vals),
});

// Slice 5.2: iso7816-4-pad / -unpad are now PortedExecutors — bytes flow on the
// `state` port. These thin adapters drive the port signature and re-wrap the
// `state` output as { state: BytesState } so the assertions below stay
// unchanged. The ignored third arg lets the existing 3-arg call sites compile.
const iso78164Pad = (
  input: BytesState,
  params: Json,
  _ctx?: StepContext,
): { state: BytesState } => {
  const out = iso78164PadExec(new Map([["state", input.bytes]]), params, ctx);
  const s = out.get("state");
  if (s === undefined) throw new Error("iso7816-4-pad emitted no state output");
  return { state: { shape: "bytes", bytes: s } };
};
const iso78164Unpad = (
  input: BytesState,
  params: Json,
  _ctx?: StepContext,
): { state: BytesState } => {
  const out = iso78164UnpadExec(new Map([["state", input.bytes]]), params, ctx);
  const s = out.get("state");
  if (s === undefined) throw new Error("iso7816-4-unpad emitted no state output");
  return { state: { shape: "bytes", bytes: s } };
};

describe("iso7816-4-pad", () => {
  it("pads a 5-byte input ('apple') with 0x80 followed by ten 0x00", () => {
    const input = bytes(0x61, 0x70, 0x70, 0x6c, 0x65); // "apple"
    const result = iso78164Pad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    expect(Array.from(result.state.bytes.slice(0, 5))).toEqual([0x61, 0x70, 0x70, 0x6c, 0x65]);
    expect(result.state.bytes[5]).toBe(0x80); // sentinel
    for (let i = 6; i < 16; i++) {
      expect(result.state.bytes[i]).toBe(0x00);
    }
  });

  it("pads an empty input with 0x80 + fifteen 0x00", () => {
    const result = iso78164Pad(bytes(), { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    expect(result.state.bytes[0]).toBe(0x80);
    for (let i = 1; i < 16; i++) {
      expect(result.state.bytes[i]).toBe(0x00);
    }
  });

  it("pads a 15-byte input with a single 0x80 (no trailing zeros)", () => {
    const input = bytes(...new Array(15).fill(0xaa));
    const result = iso78164Pad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(16);
    expect(result.state.bytes[15]).toBe(0x80);
  });

  it("pads a 16-byte input by adding a FULL extra block (0x80 + 15 zeros)", () => {
    // Same "always adds at least one byte" property as PKCS#7. The UI's
    // single-block scope caps input at 15 to avoid this case, but the step
    // itself must implement the canonical behavior.
    const input = bytes(...new Array(16).fill(0x42));
    const result = iso78164Pad(input, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(32);
    expect(result.state.bytes[16]).toBe(0x80);
    for (let i = 17; i < 32; i++) {
      expect(result.state.bytes[i]).toBe(0x00);
    }
  });

  it("supports non-AES block sizes (DES blockSize=8)", () => {
    const input = bytes(0x01, 0x02, 0x03); // 3 bytes
    const result = iso78164Pad(input, { blockSize: 8 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(result.state.bytes.length).toBe(8);
    expect(result.state.bytes[3]).toBe(0x80);
    for (let i = 4; i < 8; i++) {
      expect(result.state.bytes[i]).toBe(0x00);
    }
  });

  it("rejects bad params shapes", () => {
    expect(() => iso78164Pad(bytes(), {}, ctx)).toThrow(/blockSize/);
    expect(() => iso78164Pad(bytes(), { blockSize: 0 }, ctx)).toThrow(/blockSize/);
    expect(() => iso78164Pad(bytes(), { blockSize: 256 }, ctx)).toThrow(/blockSize/);
  });

  // The "rejects non-bytes state" guard test was retired in Phase 5
  // Slice 5.1 (2026-05-30) with the MatrixState shape (see zero-pad.test.ts).
});

describe("iso7816-4-unpad", () => {
  it("round-trips pad → unpad across all lengths 0..15 (including trailing zeros in original)", () => {
    // Crucially, unlike zero-unpad, ISO 7816-4 unpad is NOT lossy on
    // trailing zeros in the original — the 0x80 sentinel marks the
    // boundary unambiguously. Test that explicitly by setting at least
    // one trailing byte to 0x00.
    for (let len = 0; len <= 15; len++) {
      const original = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        // Set last byte to 0x00 if len > 0; arbitrary nonzero pattern otherwise.
        original[i] = i === len - 1 ? 0x00 : (i * 7 + 1) & 0xff || 1;
      }
      const padded = iso78164Pad({ shape: "bytes", bytes: original }, { blockSize: 16 }, ctx);
      const unpadded = iso78164Unpad(padded.state, { blockSize: 16 }, ctx);
      expect(unpadded.state.shape).toBe("bytes");
      if (unpadded.state.shape !== "bytes") return;
      expect(unpadded.state.bytes.length).toBe(len);
      expect(Array.from(unpadded.state.bytes)).toEqual(Array.from(original));
    }
  });

  it("preserves original trailing 0x00 bytes (vs. zero-pad which would eat them)", () => {
    const original = bytes(0x68, 0x69, 0x00, 0x00); // "hi\x00\x00"
    const padded = iso78164Pad(original, { blockSize: 16 }, ctx);
    const unpadded = iso78164Unpad(padded.state, { blockSize: 16 }, ctx);
    expect(unpadded.state.shape).toBe("bytes");
    if (unpadded.state.shape !== "bytes") return;
    expect(Array.from(unpadded.state.bytes)).toEqual([0x68, 0x69, 0x00, 0x00]);
  });

  it("strips 0x80 + trailing zeros from a padded 'apple'", () => {
    const padded = bytes(
      0x61,
      0x70,
      0x70,
      0x6c,
      0x65,
      0x80, // sentinel
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
    const result = iso78164Unpad(padded, { blockSize: 16 }, ctx);
    expect(result.state.shape).toBe("bytes");
    if (result.state.shape !== "bytes") return;
    expect(Array.from(result.state.bytes)).toEqual([0x61, 0x70, 0x70, 0x6c, 0x65]);
  });

  it("throws on empty input", () => {
    expect(() => iso78164Unpad(bytes(), { blockSize: 16 }, ctx)).toThrow(/empty/);
  });

  it("throws when input length isn't a multiple of blockSize", () => {
    expect(() => iso78164Unpad(bytes(1, 2, 3), { blockSize: 16 }, ctx)).toThrow(
      /multiple of blockSize/,
    );
  });

  it("throws when there's no 0x80 sentinel in the trailing block", () => {
    // All zeros: no sentinel anywhere.
    const allZero = bytes(...new Array(16).fill(0x00));
    expect(() => iso78164Unpad(allZero, { blockSize: 16 }, ctx)).toThrow(/no 0x80 sentinel/);
  });

  it("throws when the first non-zero byte from the end isn't 0x80", () => {
    // Trailing bytes are 00, 00, ..., 00, 0xff. 0xff is not 0x80, so the
    // padding is malformed.
    const bad = bytes(...new Array(11).fill(0xaa), 0xff, 0x00, 0x00, 0x00, 0x00);
    expect(() => iso78164Unpad(bad, { blockSize: 16 }, ctx)).toThrow(/no 0x80 sentinel/);
  });
});
