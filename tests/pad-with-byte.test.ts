/**
 * Tests for `pad-with-byte@1` — port-native padding primitive shipped in
 * universal-port plan Phase 2 Slice 2.4 (2026-05-24).
 *
 * Two principal test buckets:
 *
 *  (1) **SHA-256 padding KAT.** "abc" padded to 56 bytes ending with the
 *      0x80 sentinel followed by 52 zeros, per FIPS 180-4 §A.1.
 *  (2) **Length-formula edge cases.** Empty input, input exactly at
 *      `padTarget`, input one byte short of `padTarget`, input at full
 *      block boundary (forces a full-block wrap), input at `blockSize -
 *      1` (just before wrap).
 *
 * Plus param validation throws and dispatch-path guards (same posture as
 * `xor.test.ts` and the rest of the Phase 2 port-native tests).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { padWithByte, padWithBytePortContract } from "@/steps/pad-with-byte";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callDirectly = (input: Uint8Array, params: Json): Uint8Array => {
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const out = padWithByte(new Map([["input", input]]), params, ctx);
  const result = out.get("output");
  if (result === undefined) {
    throw new Error("test helper: executor did not produce 'output' port");
  }
  return result;
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

const bytesOf = (...nums: number[]): Uint8Array => new Uint8Array(nums);

const SHA256_PAD_PARAMS = { padByte: 0x80, blockSize: 64, padTarget: 56 };

// ─── (1) SHA-256 padding KAT ──────────────────────────────────────────────

describe("pad-with-byte@1 SHA-256 KAT", () => {
  it("pads 'abc' to 56 bytes ending in 0x80 + 52 zeros (FIPS 180-4 §A.1)", () => {
    const abc = bytesOf(0x61, 0x62, 0x63);
    const padded = callDirectly(abc, SHA256_PAD_PARAMS);

    expect(padded.length).toBe(56);
    expect(padded[0]).toBe(0x61);
    expect(padded[1]).toBe(0x62);
    expect(padded[2]).toBe(0x63);
    expect(padded[3]).toBe(0x80);
    // Bytes [4, 56) must all be 0x00.
    for (let i = 4; i < 56; i++) {
      expect(padded[i]).toBe(0x00);
    }
  });

  it("pads empty input to 56 bytes (sentinel + 55 zeros)", () => {
    const empty = new Uint8Array(0);
    const padded = callDirectly(empty, SHA256_PAD_PARAMS);

    expect(padded.length).toBe(56);
    expect(padded[0]).toBe(0x80);
    for (let i = 1; i < 56; i++) {
      expect(padded[i]).toBe(0x00);
    }
  });

  it("pads 55-byte input by exactly the sentinel byte (no zero fill)", () => {
    const input = new Uint8Array(55).fill(0xaa);
    const padded = callDirectly(input, SHA256_PAD_PARAMS);

    expect(padded.length).toBe(56);
    // Original bytes preserved.
    for (let i = 0; i < 55; i++) {
      expect(padded[i]).toBe(0xaa);
    }
    expect(padded[55]).toBe(0x80);
  });

  it("pads 56-byte input by appending a full new block (sentinel + 63 zeros)", () => {
    const input = new Uint8Array(56).fill(0xbb);
    const padded = callDirectly(input, SHA256_PAD_PARAMS);

    // Input is already at padTarget, so we must wrap to the next
    // (padTarget mod blockSize) position, adding a FULL blockSize of
    // padding (sentinel + 63 zeros).
    expect(padded.length).toBe(120); // 56 + 64
    expect(padded[56]).toBe(0x80);
    for (let i = 57; i < 120; i++) {
      expect(padded[i]).toBe(0x00);
    }
  });

  it("pads 63-byte input (one byte before block boundary) to 120 bytes", () => {
    const input = new Uint8Array(63).fill(0xcc);
    const padded = callDirectly(input, SHA256_PAD_PARAMS);

    // pos = 63; padLen = ((56 - 63 - 1) mod 64) + 1 = ((-8 mod 64)) + 1
    //                  = 56 + 1 = 57. outLen = 120.
    expect(padded.length).toBe(120);
    expect(padded[63]).toBe(0x80);
    for (let i = 64; i < 120; i++) {
      expect(padded[i]).toBe(0x00);
    }
  });

  it("pads 64-byte input (exactly one block) to 120 bytes", () => {
    const input = new Uint8Array(64).fill(0xdd);
    const padded = callDirectly(input, SHA256_PAD_PARAMS);

    // pos = 0; padLen = ((56 - 0 - 1) mod 64) + 1 = 55 + 1 = 56.
    // outLen = 120.
    expect(padded.length).toBe(120);
    expect(padded[64]).toBe(0x80);
    for (let i = 65; i < 120; i++) {
      expect(padded[i]).toBe(0x00);
    }
  });

  it("pads 120-byte input (already at next padTarget) by a full block", () => {
    const input = new Uint8Array(120).fill(0xee);
    const padded = callDirectly(input, SHA256_PAD_PARAMS);

    // pos = 120 mod 64 = 56 (= padTarget). padLen = 64 (full wrap).
    expect(padded.length).toBe(184);
    expect(padded[120]).toBe(0x80);
  });
});

// ─── (2) Other padTarget variants ─────────────────────────────────────────

describe("pad-with-byte@1 with non-SHA-256 parameters", () => {
  it("ISO 7816-4 (padTarget=0, blockSize=16): pads to next full block", () => {
    const input = bytesOf(0x61, 0x70, 0x70, 0x6c, 0x65); // "apple" — 5 bytes
    const padded = callDirectly(input, { padByte: 0x80, blockSize: 16, padTarget: 0 });

    // pos = 5; padLen = ((0 - 5 - 1) mod 16) + 1 = ((-6 mod 16)) + 1
    //                 = 10 + 1 = 11. outLen = 16.
    expect(padded.length).toBe(16);
    expect(padded[5]).toBe(0x80);
    for (let i = 6; i < 16; i++) {
      expect(padded[i]).toBe(0x00);
    }
  });

  it("ISO 7816-4 with block-aligned input adds a full new block", () => {
    const input = new Uint8Array(16).fill(0x11);
    const padded = callDirectly(input, { padByte: 0x80, blockSize: 16, padTarget: 0 });

    // pos = 0 = padTarget; padLen = blockSize = 16.
    expect(padded.length).toBe(32);
    expect(padded[16]).toBe(0x80);
  });

  it("SHA-512 padding (padTarget=112, blockSize=128) of 100-byte input", () => {
    const input = new Uint8Array(100).fill(0x55);
    const padded = callDirectly(input, { padByte: 0x80, blockSize: 128, padTarget: 112 });

    // pos = 100; padLen = ((112 - 100 - 1) mod 128) + 1 = 11 + 1 = 12.
    expect(padded.length).toBe(112);
    expect(padded[100]).toBe(0x80);
    for (let i = 101; i < 112; i++) {
      expect(padded[i]).toBe(0x00);
    }
  });

  it("supports non-0x80 sentinel byte (e.g., 0x01 for theoretical 1-bit variant)", () => {
    const input = bytesOf(0xff, 0xff);
    const padded = callDirectly(input, { padByte: 0x01, blockSize: 8, padTarget: 0 });

    expect(padded.length).toBe(8);
    expect(padded[0]).toBe(0xff);
    expect(padded[1]).toBe(0xff);
    expect(padded[2]).toBe(0x01);
    for (let i = 3; i < 8; i++) {
      expect(padded[i]).toBe(0x00);
    }
  });
});

// ─── (3) Output buffer freshness ──────────────────────────────────────────

describe("pad-with-byte@1 output is a fresh buffer", () => {
  it("output is not aliased to input — mutating output does not affect input", () => {
    const input = bytesOf(0x01, 0x02, 0x03);
    const padded = callDirectly(input, SHA256_PAD_PARAMS);

    padded[0] = 0xff;
    expect(input[0]).toBe(0x01);
  });

  it("output's input-prefix is a copy — mutating input does not affect output", () => {
    const input = bytesOf(0xaa, 0xbb, 0xcc);
    const padded = callDirectly(input, SHA256_PAD_PARAMS);

    input[0] = 0x00;
    expect(padded[0]).toBe(0xaa);
  });
});

// ─── (4) Param validation ─────────────────────────────────────────────────

describe("pad-with-byte@1 param validation", () => {
  const ANY_INPUT = bytesOf(0x01);

  it("throws if padByte is missing", () => {
    expect(() => callDirectly(ANY_INPUT, { blockSize: 64, padTarget: 56 } as Json)).toThrow(
      /padByte must be an integer in \[0, 255\]/,
    );
  });

  it("throws if padByte is out of range", () => {
    expect(() =>
      callDirectly(ANY_INPUT, { padByte: 256, blockSize: 64, padTarget: 56 } as Json),
    ).toThrow(/padByte must be an integer in \[0, 255\]/);
  });

  it("throws if blockSize is missing", () => {
    expect(() => callDirectly(ANY_INPUT, { padByte: 0x80, padTarget: 56 } as Json)).toThrow(
      /blockSize must be a positive integer/,
    );
  });

  it("throws if blockSize is zero or negative", () => {
    expect(() =>
      callDirectly(ANY_INPUT, { padByte: 0x80, blockSize: 0, padTarget: 0 } as Json),
    ).toThrow(/blockSize must be a positive integer/);
  });

  it("throws if padTarget is out of range (≥ blockSize)", () => {
    expect(() =>
      callDirectly(ANY_INPUT, { padByte: 0x80, blockSize: 64, padTarget: 64 } as Json),
    ).toThrow(/padTarget must be an integer in \[0, blockSize\)/);
  });

  it("throws if padTarget is negative", () => {
    expect(() =>
      callDirectly(ANY_INPUT, { padByte: 0x80, blockSize: 64, padTarget: -1 } as Json),
    ).toThrow(/padTarget must be an integer in \[0, blockSize\)/);
  });

  it("throws if params is not an object", () => {
    expect(() => callDirectly(ANY_INPUT, 42 as Json)).toThrow(/params must be an object/);
  });

  it("throws if input port is missing", () => {
    const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
    expect(() => padWithByte(new Map(), SHA256_PAD_PARAMS as Json, ctx)).toThrow(
      /missing required input port 'input'/,
    );
  });
});

// ─── (5) PortContract shape ───────────────────────────────────────────────

describe("pad-with-byte@1 PortContract shape", () => {
  it("input + output ports are static, polymorphic byteLength, raw layout", () => {
    if (typeof padWithBytePortContract.inputs === "function") {
      throw new Error("pad-with-byte's PortContract.inputs should be static, not function form");
    }
    if (typeof padWithBytePortContract.outputs === "function") {
      throw new Error("pad-with-byte's PortContract.outputs should be static, not function form");
    }
    expect([...padWithBytePortContract.inputs.keys()]).toEqual(["input"]);
    expect([...padWithBytePortContract.outputs.keys()]).toEqual(["output"]);
    const inputShape = padWithBytePortContract.inputs.get("input");
    const outputShape = padWithBytePortContract.outputs.get("output");
    expect(inputShape?.layout).toBe("raw");
    expect(outputShape?.layout).toBe("raw");
    expect(inputShape?.byteLength).toBeUndefined();
    expect(outputShape?.byteLength).toBeUndefined();
  });
});

// ─── (6) Dispatch-path guards (mirrors Slice 2.1+ posture) ────────────────

describe("pad-with-byte@1 — runtime dispatch guards", () => {
  // Single-leaf spec wiring the port-native step. Until Slice 2.6 lands
  // spec edge-wiring, this spec is unreachable via either dispatch path
  // without explicit error — matches rotate-bits-right's posture.
  const buildSpec = (): CipherSpec => ({
    id: "test-pad-with-byte@1",
    name: "test pad-with-byte",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "p",
        type: "pad-with-byte@1",
        params: SHA256_PAD_PARAMS,
      },
    ],
  });

  it("off-flag dispatch throws 'port-native; requires portedDispatchEnabled: true'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), { initialState: emptyBytes() }),
    ).toThrow('step type "pad-with-byte@1" is port-native; requires portedDispatchEnabled: true');
  });

  it("on-flag dispatch with no portInputs throws 'input port input is not wired' (Slice 2.6a)", () => {
    // Post-Slice-2.6a: edge-wiring landed; unwired ports surface
    // per-port via the dispatch-path guard. End-to-end wired specs
    // live in `runtime-port-edge-wiring-toy.test.ts`.
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
        portedDispatchEnabled: true,
      }),
    ).toThrow(/input port 'input' is not wired/);
  });
});
