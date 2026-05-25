/**
 * byte-slice@1 — port-native byte-range extraction primitive tests
 * (universal-port plan Phase 2 Slice 2.6d, 2026-05-25).
 *
 * Two layers, mirroring the port-native primitive test pattern:
 *
 *  1. **Executor unit tests** — direct invocation against `inputs` Map.
 *     The executor extracts the sub-range and emits it on `output`.
 *
 *  2. **Runtime integration tests** — full-spec round-trip through the
 *     runtime to verify the PortContract's declared byteLengths and the
 *     port-native dispatch path work together.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { CipherSpec, Json, StepContext } from "@/core/types";
import { byteSlice } from "@/steps/byte-slice";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const callExecutor = (input: Uint8Array, params: Json): Uint8Array => {
  const out = byteSlice(new Map([["input", input]]), params, CTX);
  return out.get("output") as Uint8Array;
};

// ─── Executor unit tests ──────────────────────────────────────────────────

describe("byte-slice@1 — executor sub-range extraction", () => {
  it("extracts a contiguous range from the middle", () => {
    const input = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    const out = callExecutor(input, { sourceByteLength: 8, offset: 2, length: 4 });
    expect(Array.from(out)).toEqual([0x02, 0x03, 0x04, 0x05]);
  });

  it("extracts from the start (offset = 0)", () => {
    const input = new Uint8Array([0xa, 0xb, 0xc, 0xd]);
    const out = callExecutor(input, { sourceByteLength: 4, offset: 0, length: 2 });
    expect(Array.from(out)).toEqual([0xa, 0xb]);
  });

  it("extracts to the end (offset + length = sourceByteLength)", () => {
    const input = new Uint8Array([0xa, 0xb, 0xc, 0xd]);
    const out = callExecutor(input, { sourceByteLength: 4, offset: 2, length: 2 });
    expect(Array.from(out)).toEqual([0xc, 0xd]);
  });

  it("identity slice (offset = 0, length = sourceByteLength)", () => {
    const input = new Uint8Array([0xa, 0xb, 0xc, 0xd]);
    const out = callExecutor(input, { sourceByteLength: 4, offset: 0, length: 4 });
    expect(Array.from(out)).toEqual([0xa, 0xb, 0xc, 0xd]);
  });

  it("single-byte slice (length = 1)", () => {
    const input = new Uint8Array([0xa, 0xb, 0xc, 0xd]);
    const out = callExecutor(input, { sourceByteLength: 4, offset: 1, length: 1 });
    expect(Array.from(out)).toEqual([0xb]);
  });

  it("SHA-256 K_t extraction — K_5 from a 256-byte K-table", () => {
    // K_0..K_63 each are 4 bytes; K_5 lives at offset 20.
    const k = new Uint8Array(256);
    for (let i = 0; i < 256; i++) k[i] = i;
    const out = callExecutor(k, { sourceByteLength: 256, offset: 20, length: 4 });
    expect(Array.from(out)).toEqual([20, 21, 22, 23]);
  });

  it("output is a fresh buffer — mutating it does not affect the input", () => {
    const input = new Uint8Array([0xa, 0xb, 0xc, 0xd]);
    const out = callExecutor(input, { sourceByteLength: 4, offset: 0, length: 2 });
    out[0] = 0xff;
    expect(input[0]).toBe(0xa);
  });

  it("throws when input port is missing", () => {
    expect(() => byteSlice(new Map(), { sourceByteLength: 4, offset: 0, length: 2 }, CTX)).toThrow(
      /missing required input port 'input'/,
    );
  });
});

// ─── Param validation ──────────────────────────────────────────────────────

describe("byte-slice@1 — param validation throws on misuse", () => {
  it("throws when params is null", () => {
    expect(() => callExecutor(new Uint8Array(4), null)).toThrow(/params must be an object/);
  });

  it("throws when sourceByteLength is zero", () => {
    expect(() =>
      callExecutor(new Uint8Array(4), { sourceByteLength: 0, offset: 0, length: 1 }),
    ).toThrow(/params.sourceByteLength must be a positive integer/);
  });

  it("throws when offset is negative", () => {
    expect(() =>
      callExecutor(new Uint8Array(4), { sourceByteLength: 4, offset: -1, length: 2 }),
    ).toThrow(/params.offset must be a non-negative integer/);
  });

  it("throws when length is zero", () => {
    expect(() =>
      callExecutor(new Uint8Array(4), { sourceByteLength: 4, offset: 0, length: 0 }),
    ).toThrow(/params.length must be a positive integer/);
  });

  it("throws when offset + length exceeds sourceByteLength", () => {
    expect(() =>
      callExecutor(new Uint8Array(4), { sourceByteLength: 4, offset: 2, length: 3 }),
    ).toThrow(/offset \+ length \(2 \+ 3 = 5\) exceeds sourceByteLength \(4\)/);
  });

  it("throws when offset is not an integer", () => {
    expect(() =>
      callExecutor(new Uint8Array(4), { sourceByteLength: 4, offset: 1.5, length: 1 }),
    ).toThrow(/params.offset must be a non-negative integer/);
  });
});

// ─── Runtime integration ───────────────────────────────────────────────────

describe("byte-slice@1 — runtime integration via port wiring", () => {
  /**
   * Wire state-to-bytes → byte-slice → bytes-to-state. Extract a 4-byte
   * range from a 16-byte plaintext; finalState should carry exactly those
   * 4 bytes.
   */
  it("extracts a sub-range from a plaintext via the port-native chain", () => {
    const plaintext = new Uint8Array([
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
      0x1f,
    ]);
    const spec: CipherSpec = {
      id: "toy-byte-slice-roundtrip",
      name: "byte-slice round-trip (Slice 2.6d)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "src",
          type: "state-to-bytes@1",
          params: {},
        },
        {
          kind: "step",
          id: "extract",
          type: "byte-slice@1",
          params: { sourceByteLength: 16, offset: 4, length: 4 },
          portInputs: { input: { node: "src", port: "output" } },
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: { input: { node: "extract", port: "output" } },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: plaintext },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([0x14, 0x15, 0x16, 0x17]);
  });

  /**
   * Two byte-slice leaves extracting different ranges from the same source.
   * Concat the two outputs to verify both extractions resolved independently.
   */
  it("two independent extractions can fan out from one source", () => {
    const plaintext = new Uint8Array([
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
      0x1f,
    ]);
    const spec: CipherSpec = {
      id: "toy-byte-slice-fanout",
      name: "byte-slice fan-out (Slice 2.6d)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "src", type: "state-to-bytes@1", params: {} },
        {
          kind: "step",
          id: "head",
          type: "byte-slice@1",
          params: { sourceByteLength: 16, offset: 0, length: 4 },
          portInputs: { input: { node: "src", port: "output" } },
        },
        {
          kind: "step",
          id: "tail",
          type: "byte-slice@1",
          params: { sourceByteLength: 16, offset: 12, length: 4 },
          portInputs: { input: { node: "src", port: "output" } },
        },
        {
          kind: "step",
          id: "rejoin",
          type: "concat@1",
          params: { inputCount: 2 },
          portInputs: {
            input0: { node: "head", port: "output" },
            input1: { node: "tail", port: "output" },
          },
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: { input: { node: "rejoin", port: "output" } },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: plaintext },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([
      0x10, 0x11, 0x12, 0x13, 0x1c, 0x1d, 0x1e, 0x1f,
    ]);
  });

  it("off-flag dispatch throws (port-native, no legacy executor)", () => {
    const spec: CipherSpec = {
      id: "toy-byte-slice-offflag",
      name: "off-flag throw",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "src", type: "state-to-bytes@1", params: {} },
        {
          kind: "step",
          id: "extract",
          type: "byte-slice@1",
          params: { sourceByteLength: 4, offset: 0, length: 2 },
          portInputs: { input: { node: "src", port: "output" } },
        },
      ],
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array([0x01, 0x02, 0x03, 0x04]) },
      }),
    ).toThrow(/port-native; requires portedDispatchEnabled: true/);
  });
});
