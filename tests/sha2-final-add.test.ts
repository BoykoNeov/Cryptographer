/**
 * sha2.final-add@1 — lifted-legacy SHA-256 final-add tests
 * (universal-port plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * The final-add step takes the post-compression 288-byte state, adds
 * H_0..H_7 (mod 2^32) to the eight working-variable words, and emits a
 * 32-byte hash. This file pins:
 *
 *  - **Executor invariants**: state shape/length, aux['H'] shape/length,
 *    asymmetric state byteLength transformation (288 → 32).
 *  - **Math correctness via TS oracle**: hand-coded `(a + H_0) mod 2^32`
 *    per word, cross-checked against the executor.
 *  - **FIPS 180-4 §A.1 KAT for 'abc'**: the canonical reference. After 64
 *    rounds applied to H_init + W('abc'), the working vars are a known
 *    sequence; adding H back produces `ba7816bf 8f01cfea 4141 40de ...`.
 *    The full end-to-end KAT runs in `tests/sha-256.test.ts`; here we
 *    pin the final-add output given hand-computed post-compression vars.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { AuxValue, BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { decodeBE32, encodeBE32 } from "@/core/word-codec";
import { sha2FinalAdd } from "@/steps/sha2-final-add";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const H_WORDS: readonly number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const buildHBytes = (): Uint8Array => {
  const h = new Uint8Array(32);
  for (let i = 0; i < 8; i++) encodeBE32(h, 4 * i, H_WORDS[i] as number);
  return h;
};

const buildStateBytes = (workingVars: readonly number[]): Uint8Array => {
  if (workingVars.length !== 8) throw new Error("expected 8 working vars");
  const out = new Uint8Array(288);
  for (let i = 0; i < 8; i++) encodeBE32(out, 4 * i, workingVars[i] as number);
  // W tail (bytes 32..288) — irrelevant for final-add but must be present.
  return out;
};

const callExecutorDirect = (workingVars: readonly number[], hBytes: Uint8Array): Uint8Array => {
  const aux = new Map<string, AuxValue>([["H", hBytes]]);
  const ctx: StepContext = { stepId: "test", path: [], aux };
  const initial: BytesState = { shape: "bytes", bytes: buildStateBytes(workingVars) };
  const result = sha2FinalAdd(initial, {} as Json, ctx);
  if (result.state.shape !== "bytes") throw new Error("expected bytes state");
  return result.state.bytes;
};

// ─── Executor invariants ──────────────────────────────────────────────────

describe("sha2.final-add@1 — executor invariants", () => {
  it("output is 32 bytes (NOT 288 — state shape transforms from compression layout to hash)", () => {
    const out = callExecutorDirect(H_WORDS, buildHBytes());
    expect(out.length).toBe(32);
  });

  it("throws when state is not 288 bytes", () => {
    const aux = new Map<string, AuxValue>([["H", buildHBytes()]]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const state: BytesState = { shape: "bytes", bytes: new Uint8Array(287) };
    expect(() => sha2FinalAdd(state, {} as Json, ctx)).toThrow(/state\.bytes\.length must be 288/);
  });

  it("throws when aux['H'] is missing", () => {
    const aux = new Map<string, AuxValue>();
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const state: BytesState = { shape: "bytes", bytes: buildStateBytes(H_WORDS) };
    expect(() => sha2FinalAdd(state, {} as Json, ctx)).toThrow(/aux\['H'\] must be a Uint8Array/);
  });

  it("throws when aux['H'] is not 32 bytes", () => {
    const aux = new Map<string, AuxValue>([["H", new Uint8Array(31)]]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const state: BytesState = { shape: "bytes", bytes: buildStateBytes(H_WORDS) };
    expect(() => sha2FinalAdd(state, {} as Json, ctx)).toThrow(/aux\['H'\]\.length must be 32/);
  });

  it("auxReads declares 'H'", () => {
    const aux = new Map<string, AuxValue>([["H", buildHBytes()]]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const state: BytesState = { shape: "bytes", bytes: buildStateBytes(H_WORDS) };
    const result = sha2FinalAdd(state, {} as Json, ctx);
    expect(result.auxReads).toEqual(["H"]);
  });
});

// ─── Math correctness via TS oracle ──────────────────────────────────────

describe("sha2.final-add@1 — TS oracle parity", () => {
  it("doubles H (vars=H + H=H) — sanity check on the add", () => {
    // vars = H_WORDS; H = H_WORDS. Output = vars + H = 2*H_i mod 2^32.
    const out = callExecutorDirect(H_WORDS, buildHBytes());
    for (let i = 0; i < 8; i++) {
      const expected = ((H_WORDS[i] as number) + (H_WORDS[i] as number)) >>> 0;
      expect(decodeBE32(out, 4 * i)).toBe(expected);
    }
  });

  it("identity when vars=0: output = H", () => {
    const out = callExecutorDirect([0, 0, 0, 0, 0, 0, 0, 0], buildHBytes());
    expect(Array.from(out)).toEqual(Array.from(buildHBytes()));
  });

  it("wraps at 2^32 (modular addition, not int saturation)", () => {
    // vars[0] = 0xFFFFFFFF, H_0 = 1 → sum mod 2^32 = 0
    const h = new Uint8Array(32);
    encodeBE32(h, 0, 0x00000001);
    // H_1..H_7 stay zero (filled by `new Uint8Array(32)` default)
    const out = callExecutorDirect([0xffffffff, 0, 0, 0, 0, 0, 0, 0], h);
    expect(decodeBE32(out, 0)).toBe(0);
  });

  it("64 pseudo-random tuples match oracle", () => {
    let state = 0xfafafafa;
    const next = (): number => {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state;
    };
    for (let trial = 0; trial < 64; trial++) {
      const vars: number[] = [];
      const h = new Uint8Array(32);
      for (let i = 0; i < 8; i++) {
        const v = next();
        const hi = next();
        vars.push(v);
        encodeBE32(h, 4 * i, hi);
      }
      const out = callExecutorDirect(vars, h);
      for (let i = 0; i < 8; i++) {
        const expected = ((vars[i] as number) + decodeBE32(h, 4 * i)) >>> 0;
        expect(decodeBE32(out, 4 * i)).toBe(expected);
      }
    }
  });
});

// ─── FIPS 180-4 §A.1 KAT for 'abc' ────────────────────────────────────────

describe("sha2.final-add@1 — FIPS 180-4 §A.1 'abc' KAT", () => {
  // FIPS 180-4 §A.1 tabulates the final working variables after all 64
  // rounds applied to H_init + W('abc'):
  //
  //   a = 506e3058  b = d39a2165  c = 04d24d6c  d = b85e2ce9
  //   e = 5ef50f24  f = fb121210  g = 948d25b6  h = 961f4894
  //
  // Adding H_0..H_7 to these gives the §A.1 expected hash:
  //   ba7816bf 8f01cfea 4141 40de 5dae 2223 b00361a3 96177a9c b410ff61 f20015ad
  //
  // (Computed:
  //    a + H_0 = 506e3058 + 6a09e667 = ba7816bf   ✓
  //    b + H_1 = d39a2165 + bb67ae85 = 8f01cfea   ✓
  //    ...)
  it("final hash for 'abc' matches FIPS 180-4 §A.1: ba7816bf...20015ad", () => {
    const finalVars = [
      0x506e3058, 0xd39a2165, 0x04d24d6c, 0xb85e2ce9, 0x5ef50f24, 0xfb121210, 0x948d25b6,
      0x961f4894,
    ];
    const out = callExecutorDirect(finalVars, buildHBytes());

    const expectedHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const hex = Array.from(out)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(expectedHex);
  });
});

// ─── Runtime dispatch ─────────────────────────────────────────────────────

describe("sha2.final-add@1 — runtime dispatch via runSpec", () => {
  it("dispatches as a port-native leaf under portedDispatchEnabled: true", () => {
    const initialState: BytesState = {
      shape: "bytes",
      bytes: buildStateBytes([
        0x506e3058, 0xd39a2165, 0x04d24d6c, 0xb85e2ce9, 0x5ef50f24, 0xfb121210, 0x948d25b6,
        0x961f4894,
      ]),
    };
    const spec: CipherSpec = {
      id: "toy-final-add",
      name: "final-add dispatch (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "h-load",
          type: "generic.aux-load@1",
          params: { auxName: "H", value: Array.from(buildHBytes()) },
        },
        {
          kind: "step",
          id: "final-add",
          type: "sha2.final-add@1",
          params: {},
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState,
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
    expect(trace.finalState.bytes.length).toBe(32);
    const hex = Array.from(trace.finalState.bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("off-flag dispatch (legacy path) produces byte-equal output", () => {
    const initialState: BytesState = {
      shape: "bytes",
      bytes: buildStateBytes([
        0x506e3058, 0xd39a2165, 0x04d24d6c, 0xb85e2ce9, 0x5ef50f24, 0xfb121210, 0x948d25b6,
        0x961f4894,
      ]),
    };
    const spec: CipherSpec = {
      id: "toy-final-add-offflag",
      name: "final-add off-flag (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "h-load",
          type: "generic.aux-load@1",
          params: { auxName: "H", value: Array.from(buildHBytes()) },
        },
        {
          kind: "step",
          id: "final-add",
          type: "sha2.final-add@1",
          params: {},
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState,
      // portedDispatchEnabled omitted
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
    const hex = Array.from(trace.finalState.bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});
