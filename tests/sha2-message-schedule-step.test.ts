/**
 * sha2.message-schedule-step@1 — lifted-legacy body leaf tests
 * (universal-port plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * Two layers:
 *
 *  1. **Executor unit tests** — direct invocation against a hand-built
 *     `ctx.aux` Map populated with prior-2 / prior-7 / prior-15 / prior-16
 *     Uint8Array values. Pins hand-derived KATs and oracle parity.
 *
 *  2. **Runtime integration tests** — exercise the step inside a real
 *     `for-each-subgraph-with-history` body. Validates that:
 *       (a) The runtime correctly populates aux["prior-N"] per iteration.
 *       (b) The executor reads them and emits the right W_t.
 *       (c) The FES-with-history's exit state = W_0..W_63 concat.
 *
 * Reuses the Slice 2.5 oracle (TS-direct recurrence) to verify each W_t
 * across the full schedule for the FIPS 180-4 §A.1 "abc" example.
 *
 * **Cross-pin with Slice 2.5.** `tests/sha256-message-schedule.test.ts`
 * already pins the composition form (rotate-bits-right + shift-bits-right
 * + xor + add-mod-32) byte-identical to the same recurrence via the same
 * oracle. This file pins the SHA-256-specific helper form (sha2.message-
 * schedule-step@1's atomic executor). Both forms produce the same bytes
 * — Slice 2.6d's decomposition will replace the helper with the
 * composition without changing the trace's byte output.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { AuxValue, BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { appendBe64Length } from "@/steps/append-be64-length";
import { padWithByte } from "@/steps/pad-with-byte";
import { sha2MessageScheduleStep } from "@/steps/sha2-message-schedule-step";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const u32ToBytes = (w: number): Uint8Array =>
  new Uint8Array([(w >>> 24) & 0xff, (w >>> 16) & 0xff, (w >>> 8) & 0xff, w & 0xff]);

const beU32 = (bytes: Uint8Array, off: number): number =>
  (((bytes[off] as number) << 24) |
    ((bytes[off + 1] as number) << 16) |
    ((bytes[off + 2] as number) << 8) |
    (bytes[off + 3] as number)) >>>
  0;

const rorU32 = (w: number, n: number): number => {
  const k = n & 31;
  return k === 0 ? w >>> 0 : ((w >>> k) | (w << (32 - k))) >>> 0;
};
const shrU32 = (w: number, n: number): number => (w >>> 0) >>> n;
const oracleSmallSigma0 = (x: number): number =>
  (rorU32(x, 7) ^ rorU32(x, 18) ^ shrU32(x, 3)) >>> 0;
const oracleSmallSigma1 = (x: number): number =>
  (rorU32(x, 17) ^ rorU32(x, 19) ^ shrU32(x, 10)) >>> 0;

// Build aux with the four required priors set to the given 32-bit words.
const buildCtxAux = (
  p2: number,
  p7: number,
  p15: number,
  p16: number,
): ReadonlyMap<string, AuxValue> =>
  new Map<string, AuxValue>([
    ["prior-2", u32ToBytes(p2)],
    ["prior-7", u32ToBytes(p7)],
    ["prior-15", u32ToBytes(p15)],
    ["prior-16", u32ToBytes(p16)],
  ]);

const callExecutor = (p2: number, p7: number, p15: number, p16: number): Uint8Array => {
  const aux = buildCtxAux(p2, p7, p15, p16);
  const ctx: StepContext = { stepId: "test", path: [], aux };
  const initialState: BytesState = { shape: "bytes", bytes: new Uint8Array(4) };
  const result = sha2MessageScheduleStep(initialState, {} as Json, ctx);
  if (result.state.shape !== "bytes") throw new Error("expected bytes state");
  return result.state.bytes;
};

// ─── Executor unit tests ──────────────────────────────────────────────────

describe("sha2.message-schedule-step@1 — executor unit tests", () => {
  it("W_16 for 'abc': all-zeros + W_0=0x61626380 = 0x61626380 (only non-zero operand)", () => {
    // The recurrence at t=16 for the "abc" padded block:
    //   W_t-2 = W_14 = 0
    //   W_t-7 = W_9  = 0
    //   W_t-15= W_1  = 0
    //   W_t-16= W_0  = 0x61626380
    // → W_16 = σ1(0) + 0 + σ0(0) + 0x61626380 = 0x61626380
    const out = callExecutor(0, 0, 0, 0x61626380);
    expect(beU32(out, 0)).toBe(0x61626380);
  });

  it("W_17 for 'abc': σ1(0x18) is the only contribution = 0x000F0000", () => {
    // The recurrence at t=17:
    //   W_t-2 = W_15 = 0x18 (low 32 bits of length-suffix 0x...0018)
    //   W_t-7 = W_10 = 0
    //   W_t-15= W_2  = 0
    //   W_t-16= W_1  = 0
    // → W_17 = σ1(0x18) + 0 + σ0(0) + 0 = 0x000F0000 (pre-pinned Slice 2.5).
    const out = callExecutor(0x18, 0, 0, 0);
    expect(beU32(out, 0)).toBe(0x000f0000);
  });

  it("all-zero priors produce all-zero W_t", () => {
    const out = callExecutor(0, 0, 0, 0);
    expect(beU32(out, 0)).toBe(0);
  });

  it("matches TS-direct oracle across 64 pseudo-random prior tuples", () => {
    // LCG with a fresh seed (avoiding Slice 2.3/2.5's seeds so a shared
    // latent bug doesn't pass all three suites).
    const seed = 0xfeedface;
    let state = seed >>> 0;
    const next = (): number => {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state;
    };
    for (let trial = 0; trial < 64; trial++) {
      const p2 = next();
      const p7 = next();
      const p15 = next();
      const p16 = next();
      const expected =
        (((oracleSmallSigma1(p2) + p7) >>> 0) + ((oracleSmallSigma0(p15) + p16) >>> 0)) >>> 0;
      const got = beU32(callExecutor(p2, p7, p15, p16), 0);
      expect(got).toBe(expected);
    }
  });

  it("throws when aux['prior-2'] is missing", () => {
    const aux = new Map<string, AuxValue>([
      ["prior-7", u32ToBytes(0)],
      ["prior-15", u32ToBytes(0)],
      ["prior-16", u32ToBytes(0)],
    ]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const initialState: BytesState = { shape: "bytes", bytes: new Uint8Array(4) };
    expect(() => sha2MessageScheduleStep(initialState, {} as Json, ctx)).toThrow(
      /aux\["prior-2"\] must be a Uint8Array/,
    );
  });

  it("throws when an aux prior has wrong byte length", () => {
    const aux = new Map<string, AuxValue>([
      ["prior-2", new Uint8Array([0x01, 0x02])], // wrong length: 2 instead of 4
      ["prior-7", u32ToBytes(0)],
      ["prior-15", u32ToBytes(0)],
      ["prior-16", u32ToBytes(0)],
    ]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const initialState: BytesState = { shape: "bytes", bytes: new Uint8Array(4) };
    expect(() => sha2MessageScheduleStep(initialState, {} as Json, ctx)).toThrow(
      /aux\["prior-2"\] must be 4 bytes/,
    );
  });

  it("declares auxReads for all four prior keys", () => {
    const aux = buildCtxAux(0, 0, 0, 0);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const initialState: BytesState = { shape: "bytes", bytes: new Uint8Array(4) };
    const result = sha2MessageScheduleStep(initialState, {} as Json, ctx);
    expect(result.auxReads).toEqual(["prior-2", "prior-7", "prior-15", "prior-16"]);
  });
});

// ─── Runtime integration: full message schedule for "abc" ─────────────────

describe("sha2.message-schedule-step@1 — integration via FES-with-history", () => {
  // Build the FIPS 180-4 §A.1 padded block via the shipped Slice 2.4
  // primitives. Same pattern as the Slice 2.5 emulation test — keeps the
  // input honest.
  const buildPaddedBlock = (): Uint8Array => {
    const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };
    const message = new Uint8Array([0x61, 0x62, 0x63]);
    const padded = padWithByte(
      new Map([["input", message]]),
      { padByte: 0x80, blockSize: 64, padTarget: 56 } as unknown as Json,
      CTX,
    ).get("output") as Uint8Array;
    return appendBe64Length(
      new Map([
        ["data", padded],
        ["length-source", message],
      ]),
      {} as Json,
      CTX,
    ).get("output") as Uint8Array;
  };

  // TS-direct oracle that reproduces W_0..W_63 byte-equal to FIPS §6.2.2.
  const computeScheduleOracle = (paddedBlock: Uint8Array): readonly number[] => {
    const W: number[] = [];
    for (let t = 0; t < 16; t++) W.push(beU32(paddedBlock, t * 4));
    for (let t = 16; t < 64; t++) {
      const a = oracleSmallSigma1(W[t - 2] as number);
      const b = W[t - 7] as number;
      const c = oracleSmallSigma0(W[t - 15] as number);
      const d = W[t - 16] as number;
      W.push((((a + b) >>> 0) + ((c + d) >>> 0)) >>> 0);
    }
    return W;
  };

  it("FES-with-history wrapping the step produces W_0..W_63 byte-equal to the oracle for 'abc'", () => {
    const block = buildPaddedBlock();
    const oracle = computeScheduleOracle(block);

    // Construct a minimal spec: FES-with-history body = our step.
    // Parent state seeded with the padded block (64 bytes = 16 × 4-byte
    // entries). After 48 iterations, exit state = 256-byte W concat.
    const spec: CipherSpec = {
      id: "toy-schedule-integration",
      name: "sha2-message-schedule-step integration (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "for-each-subgraph-with-history",
          id: "schedule",
          iterationCount: 48,
          lookbackOffsets: [2, 7, 15, 16],
          historyEntryByteLength: 4,
          children: [
            {
              kind: "step",
              id: "expand",
              type: "sha2.message-schedule-step@1",
              params: {},
            },
          ],
        },
      ],
    };

    // Run with the padded block as initial state.
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: block },
      portedDispatchEnabled: true,
    });

    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
    // 64 entries × 4 bytes = 256 bytes.
    expect(trace.finalState.bytes.length).toBe(256);
    for (let t = 0; t < 64; t++) {
      expect(beU32(trace.finalState.bytes, t * 4)).toBe(oracle[t]);
    }
  });

  it("body emits 48 frames with :r{t} suffixes (one per iteration)", () => {
    const block = buildPaddedBlock();
    const spec: CipherSpec = {
      id: "toy-schedule-frame-suffix",
      name: "frame suffix gate (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "for-each-subgraph-with-history",
          id: "schedule",
          iterationCount: 48,
          lookbackOffsets: [2, 7, 15, 16],
          historyEntryByteLength: 4,
          children: [
            {
              kind: "step",
              id: "expand",
              type: "sha2.message-schedule-step@1",
              params: {},
            },
          ],
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: block },
      portedDispatchEnabled: true,
    });
    expect(trace.frames).toHaveLength(48);
    for (let t = 0; t < 48; t++) {
      const frame = trace.frames[t];
      if (frame === undefined) throw new Error(`frame ${t} undefined`);
      expect(frame.stepId).toBe(`expand:r${t}`);
    }
  });
});
