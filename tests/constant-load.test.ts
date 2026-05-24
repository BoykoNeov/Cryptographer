/**
 * Tests for `constant-load@1` — port-native constant emitter shipped in
 * universal-port plan Phase 2 Slice 2.4 (2026-05-24).
 *
 * Coverage buckets:
 *  (1) **SHA-256 initial hash values H_0..H_7** (FIPS 180-4 §5.3.3) —
 *      byte-equal round-trip through the executor.
 *  (2) **SHA-256 round constants K_0..K_63** (FIPS 180-4 §4.2.2) —
 *      spot-check 4 representative leaves (K_0, K_15, K_47, K_63).
 *  (3) **Edge cases**: empty array (0-byte output), 1-byte output.
 *  (4) **Output buffer freshness** (mutation cannot leak back).
 *  (5) **Param validation throws**: missing / non-array / non-integer /
 *      out-of-range byte.
 *  (6) **PortContract shape**: empty input map; function-form output
 *      with EXACT byteLength derived from params.
 *  (7) **Dispatch-path guards**: off-flag + on-flag.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { constantLoad, constantLoadPortContract } from "@/steps/constant-load";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callDirectly = (params: Json): Uint8Array => {
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const out = constantLoad(new Map(), params, ctx);
  const result = out.get("output");
  if (result === undefined) {
    throw new Error("test helper: executor did not produce 'output' port");
  }
  return result;
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// ─── (1) SHA-256 H_0..H_7 (FIPS 180-4 §5.3.3) ────────────────────────────

describe("constant-load@1 — SHA-256 initial hash values (FIPS 180-4 §5.3.3)", () => {
  // Reference: FIPS 180-4 §5.3.3 — first 32 bits of the fractional parts
  // of the square roots of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).
  const H = [
    [0x6a, 0x09, 0xe6, 0x67], // H_0
    [0xbb, 0x67, 0xae, 0x85], // H_1
    [0x3c, 0x6e, 0xf3, 0x72], // H_2
    [0xa5, 0x4f, 0xf5, 0x3a], // H_3
    [0x51, 0x0e, 0x52, 0x7f], // H_4
    [0x9b, 0x05, 0x68, 0x8c], // H_5
    [0x1f, 0x83, 0xd9, 0xab], // H_6
    [0x5b, 0xe0, 0xcd, 0x19], // H_7
  ];

  for (let i = 0; i < H.length; i++) {
    const expected = H[i] as number[];
    it(`emits H_${i} = ${expected.map((b) => b.toString(16).padStart(2, "0")).join(" ")}`, () => {
      const out = callDirectly({ bytes: expected });
      expect(out.length).toBe(4);
      expect(Array.from(out)).toEqual(expected);
    });
  }
});

// ─── (2) SHA-256 K_0..K_63 spot checks (FIPS 180-4 §4.2.2) ───────────────

describe("constant-load@1 — SHA-256 round constants (FIPS 180-4 §4.2.2)", () => {
  // Reference: FIPS 180-4 §4.2.2 — first 32 bits of the fractional parts
  // of the cube roots of the first 64 primes. Spot-check the boundaries
  // and a couple of mid-range values.
  const cases: ReadonlyArray<{ index: number; bytes: readonly number[] }> = [
    { index: 0, bytes: [0x42, 0x8a, 0x2f, 0x98] }, // K_0
    { index: 15, bytes: [0xc1, 0x9b, 0xf1, 0x74] }, // K_15
    { index: 47, bytes: [0x10, 0x6a, 0xa0, 0x70] }, // K_47
    { index: 63, bytes: [0xc6, 0x71, 0x78, 0xf2] }, // K_63
  ];

  for (const { index, bytes } of cases) {
    it(`emits K_${index} = ${bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ")}`, () => {
      const out = callDirectly({ bytes: bytes as number[] });
      expect(out.length).toBe(4);
      expect(Array.from(out)).toEqual(bytes);
    });
  }
});

// ─── (3) Edge cases ───────────────────────────────────────────────────────

describe("constant-load@1 — edge cases", () => {
  it("empty array → 0-byte output", () => {
    const out = callDirectly({ bytes: [] });
    expect(out.length).toBe(0);
  });

  it("1-byte output (e.g., AES-128 Rcon[0] = 0x01)", () => {
    const out = callDirectly({ bytes: [0x01] });
    expect(out.length).toBe(1);
    expect(out[0]).toBe(0x01);
  });

  it("256-byte output (e.g., AES S-box full table)", () => {
    // Synthesize a 256-byte ramp.
    const bytes = Array.from({ length: 256 }, (_, i) => i);
    const out = callDirectly({ bytes });
    expect(out.length).toBe(256);
    expect(out[0]).toBe(0);
    expect(out[255]).toBe(255);
  });

  it("boundary byte values (0 and 255)", () => {
    const out = callDirectly({ bytes: [0x00, 0xff, 0x00, 0xff] });
    expect(Array.from(out)).toEqual([0x00, 0xff, 0x00, 0xff]);
  });
});

// ─── (4) Output buffer freshness ──────────────────────────────────────────

describe("constant-load@1 — output buffer freshness", () => {
  it("output is a fresh buffer — mutating it cannot leak back into params", () => {
    const paramsBytes = [0xaa, 0xbb, 0xcc];
    const out = callDirectly({ bytes: paramsBytes });
    out[0] = 0xff;
    expect(paramsBytes[0]).toBe(0xaa);
  });

  it("two successive calls produce independent buffers", () => {
    const params = { bytes: [0x11, 0x22] };
    const out1 = callDirectly(params);
    const out2 = callDirectly(params);
    out1[0] = 0xff;
    expect(out2[0]).toBe(0x11);
  });
});

// ─── (5) Param validation throws ──────────────────────────────────────────

describe("constant-load@1 — param validation", () => {
  it("throws if params is not an object", () => {
    expect(() => callDirectly(42 as Json)).toThrow(/params must be an object/);
  });

  it("throws if params.bytes is missing", () => {
    expect(() => callDirectly({} as Json)).toThrow(/params.bytes must be an array/);
  });

  it("throws if params.bytes is not an array", () => {
    expect(() => callDirectly({ bytes: "deadbeef" } as Json)).toThrow(
      /params.bytes must be an array/,
    );
  });

  it("throws if a byte is out of range (negative)", () => {
    expect(() => callDirectly({ bytes: [0x00, -1, 0x00] } as Json)).toThrow(
      /params.bytes\[1\] must be an integer in \[0, 255\]/,
    );
  });

  it("throws if a byte is out of range (≥ 256)", () => {
    expect(() => callDirectly({ bytes: [256] } as Json)).toThrow(
      /params.bytes\[0\] must be an integer in \[0, 255\]/,
    );
  });

  it("throws if a byte is a non-integer number", () => {
    expect(() => callDirectly({ bytes: [0.5] } as Json)).toThrow(
      /params.bytes\[0\] must be an integer in \[0, 255\]/,
    );
  });

  it("throws if a byte is a string", () => {
    expect(() => callDirectly({ bytes: ["0xff"] } as Json)).toThrow(
      /params.bytes\[0\] must be an integer in \[0, 255\]/,
    );
  });
});

// ─── (6) PortContract shape ───────────────────────────────────────────────

describe("constant-load@1 — PortContract shape", () => {
  it("input map is empty (zero inputs)", () => {
    if (typeof constantLoadPortContract.inputs === "function") {
      throw new Error("input should be static");
    }
    expect(constantLoadPortContract.inputs.size).toBe(0);
  });

  it("output is function-form (byteLength varies with params)", () => {
    if (typeof constantLoadPortContract.outputs !== "function") {
      throw new Error("output should be function-form");
    }
  });

  it("output declares EXACT byteLength derived from params.bytes.length", () => {
    if (typeof constantLoadPortContract.outputs !== "function") {
      throw new Error("output should be function-form");
    }
    const fn = constantLoadPortContract.outputs;
    const at4 = fn({ bytes: [1, 2, 3, 4] });
    const at8 = fn({ bytes: [1, 2, 3, 4, 5, 6, 7, 8] });
    const at0 = fn({ bytes: [] });
    expect(at4.get("output")?.byteLength).toBe(4);
    expect(at8.get("output")?.byteLength).toBe(8);
    expect(at0.get("output")?.byteLength).toBe(0);
  });

  it("output port carries layout=raw", () => {
    if (typeof constantLoadPortContract.outputs !== "function") {
      throw new Error("output should be function-form");
    }
    const shape = constantLoadPortContract.outputs({ bytes: [0] }).get("output");
    expect(shape?.layout).toBe("raw");
  });
});

// ─── (7) Dispatch-path guards ─────────────────────────────────────────────

describe("constant-load@1 — runtime dispatch guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "test-constant-load@1",
    name: "test constant-load",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "c",
        type: "constant-load@1",
        params: { bytes: [0x6a, 0x09, 0xe6, 0x67] },
      },
    ],
  });

  it("off-flag dispatch throws 'port-native; requires portedDispatchEnabled: true'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), { initialState: emptyBytes() }),
    ).toThrow('step type "constant-load@1" is port-native; requires portedDispatchEnabled: true');
  });

  it("on-flag dispatch throws 'requires spec edge-wiring (Slice 2.6+)'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
        portedDispatchEnabled: true,
      }),
    ).toThrow(/port-native and requires spec edge-wiring/);
  });
});
