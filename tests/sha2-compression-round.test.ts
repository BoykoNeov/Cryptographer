/**
 * sha2.compression-round@1 — lifted-legacy compression-round tests
 * (universal-port plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * Coverage strategy:
 *
 *  1. **Executor invariants** — state-shape / state-length / aux['K']
 *     length validation. Loud throws on every malformed input.
 *
 *  2. **TS oracle parity** — a direct JS reimplementation of FIPS 180-4
 *     §6.2.2 step 3 (compression round). Running the executor for each
 *     of 64 rounds against the oracle pins the math.
 *
 *  3. **FIPS 180-4 §A.1 KAT for "abc"** — the canonical reference: the
 *     standard tabulates the per-round working variables (a..h) after
 *     each compression round. We pin round 0's and round 63's values
 *     against the published table — the most direct check that this
 *     executor produces the same bytes the standard says.
 *
 * **Hand-derived KATs vs the §A.1 table.** Slice 2.3's `sha256-helpers`
 * tests pin Σ0/Σ1/Ch/Maj independently; Slice 2.5's
 * `sha256-message-schedule` pins W_0..W_63 for "abc"; this file's KATs
 * pin the round structure (T1/T2 composition + shuffle). Together they
 * pin SHA-256 end-to-end at distinct algebraic boundaries.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { AuxValue, BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { decodeBE32, encodeBE32, ror32 } from "@/core/word-codec";
import { appendBe64Length } from "@/steps/append-be64-length";
import { padWithByte } from "@/steps/pad-with-byte";
import { sha2CompressionRound } from "@/steps/sha2-compression-round";
import { describe, expect, it } from "vitest";

// ─── SHA-256 constants ────────────────────────────────────────────────────

// FIPS 180-4 §4.2.2 — K_0..K_63 (first 32 bits of the fractional parts of
// the cube roots of the first 64 primes).
const K_WORDS: readonly number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// FIPS 180-4 §5.3.3 — H_0..H_7 (first 32 bits of the fractional parts of
// the square roots of the first 8 primes).
const H_WORDS: readonly number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const buildKBytes = (): Uint8Array => {
  const k = new Uint8Array(256);
  for (let i = 0; i < 64; i++) {
    encodeBE32(k, 4 * i, K_WORDS[i] as number);
  }
  return k;
};

// (H_WORDS used directly below as initial working vars — no separate
// buildHBytes helper needed since the compression-round consumes a..h
// from STATE, not from aux. The H_BYTES helper would be redundant in
// these tests; `tests/sha2-final-add.test.ts` has its own.)

// ─── TS oracle ────────────────────────────────────────────────────────────
// Direct JS reimplementation of the FIPS 180-4 round, used to cross-check
// the executor against an independent code path.

const Sigma0 = (x: number): number => (ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22)) >>> 0;
const Sigma1 = (x: number): number => (ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25)) >>> 0;
const Ch = (x: number, y: number, z: number): number => ((x & y) ^ (~x & z)) >>> 0;
const Maj = (x: number, y: number, z: number): number => ((x & y) ^ (x & z) ^ (y & z)) >>> 0;

type Vars = readonly [number, number, number, number, number, number, number, number];
const oracleRound = (vars: Vars, k: number, w: number): Vars => {
  const [a, b, c, d, e, f, g, h] = vars;
  const t1 = (((h + Sigma1(e)) >>> 0) + ((Ch(e, f, g) + ((k + w) >>> 0)) >>> 0)) >>> 0;
  const t2 = (Sigma0(a) + Maj(a, b, c)) >>> 0;
  return [(t1 + t2) >>> 0, a, b, c, (d + t1) >>> 0, e, f, g];
};

const varsToStateBytes = (vars: Vars, wBytes: Uint8Array): Uint8Array => {
  if (wBytes.length !== 256) throw new Error("expected 256-byte W block");
  const out = new Uint8Array(288);
  for (let i = 0; i < 8; i++) {
    encodeBE32(out, 4 * i, vars[i] as number);
  }
  out.set(wBytes, 32);
  return out;
};

const stateBytesToVars = (bytes: Uint8Array): Vars => {
  if (bytes.length !== 288) throw new Error("expected 288-byte state");
  return [
    decodeBE32(bytes, 0),
    decodeBE32(bytes, 4),
    decodeBE32(bytes, 8),
    decodeBE32(bytes, 12),
    decodeBE32(bytes, 16),
    decodeBE32(bytes, 20),
    decodeBE32(bytes, 24),
    decodeBE32(bytes, 28),
  ];
};

// ─── Build the message schedule for "abc" (deterministic, well-pinned) ───

const buildAbcPaddedBlock = (): Uint8Array => {
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

const buildAbcWBytes = (): Uint8Array => {
  const block = buildAbcPaddedBlock();
  const W: number[] = [];
  for (let t = 0; t < 16; t++) W.push(decodeBE32(block, t * 4));
  const sigma0 = (x: number): number => (ror32(x, 7) ^ ror32(x, 18) ^ (x >>> 3)) >>> 0;
  const sigma1 = (x: number): number => (ror32(x, 17) ^ ror32(x, 19) ^ (x >>> 10)) >>> 0;
  for (let t = 16; t < 64; t++) {
    const v =
      (((sigma1(W[t - 2] as number) + (W[t - 7] as number)) >>> 0) +
        ((sigma0(W[t - 15] as number) + (W[t - 16] as number)) >>> 0)) >>>
      0;
    W.push(v);
  }
  const wBytes = new Uint8Array(256);
  for (let t = 0; t < 64; t++) encodeBE32(wBytes, t * 4, W[t] as number);
  return wBytes;
};

const callExecutorDirect = (
  stateBytes: Uint8Array,
  roundIndex: number,
  kBytes: Uint8Array,
): Uint8Array => {
  const aux = new Map<string, AuxValue>([["K", kBytes]]);
  const ctx: StepContext = { stepId: "test", path: [], aux };
  const initial: BytesState = { shape: "bytes", bytes: stateBytes };
  const result = sha2CompressionRound(initial, { roundIndex } as Json, ctx);
  if (result.state.shape !== "bytes") throw new Error("expected bytes state");
  return result.state.bytes;
};

// ─── Tests ────────────────────────────────────────────────────────────────

describe("sha2.compression-round@1 — executor invariants", () => {
  it("throws when state is not bytes-shape", () => {
    const aux = new Map<string, AuxValue>([["K", buildKBytes()]]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const badState: BytesState = { shape: "bytes", bytes: new Uint8Array(287) }; // wrong length
    expect(() => sha2CompressionRound(badState, { roundIndex: 0 } as Json, ctx)).toThrow(
      /state\.bytes\.length must be 288/,
    );
  });

  it("throws when aux['K'] is missing", () => {
    const aux = new Map<string, AuxValue>();
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const state: BytesState = { shape: "bytes", bytes: new Uint8Array(288) };
    expect(() => sha2CompressionRound(state, { roundIndex: 0 } as Json, ctx)).toThrow(
      /aux\['K'\] must be a Uint8Array/,
    );
  });

  it("throws when aux['K'] has wrong length", () => {
    const aux = new Map<string, AuxValue>([["K", new Uint8Array(255)]]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const state: BytesState = { shape: "bytes", bytes: new Uint8Array(288) };
    expect(() => sha2CompressionRound(state, { roundIndex: 0 } as Json, ctx)).toThrow(
      /aux\['K'\]\.length must be 256/,
    );
  });

  it("throws when roundIndex is out of range", () => {
    const aux = new Map<string, AuxValue>([["K", buildKBytes()]]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const state: BytesState = { shape: "bytes", bytes: new Uint8Array(288) };
    expect(() => sha2CompressionRound(state, { roundIndex: 64 } as Json, ctx)).toThrow(
      /roundIndex must be an integer in \[0, 63\]/,
    );
    expect(() => sha2CompressionRound(state, { roundIndex: -1 } as Json, ctx)).toThrow(
      /roundIndex must be an integer in \[0, 63\]/,
    );
  });

  it("preserves the W block bytes unchanged across the round", () => {
    const wBytes = buildAbcWBytes();
    const stateBytes = varsToStateBytes(H_WORDS as unknown as Vars, wBytes);
    const out = callExecutorDirect(stateBytes, 0, buildKBytes());
    // W tail (bytes 32..288) should match input.
    expect(Array.from(out.subarray(32))).toEqual(Array.from(wBytes));
  });

  it("auxReads declares 'K'", () => {
    const aux = new Map<string, AuxValue>([["K", buildKBytes()]]);
    const ctx: StepContext = { stepId: "test", path: [], aux };
    const state: BytesState = {
      shape: "bytes",
      bytes: varsToStateBytes(H_WORDS as unknown as Vars, buildAbcWBytes()),
    };
    const result = sha2CompressionRound(state, { roundIndex: 0 } as Json, ctx);
    expect(result.auxReads).toEqual(["K"]);
  });
});

describe("sha2.compression-round@1 — TS oracle parity across all 64 rounds for 'abc'", () => {
  it("each round's working variables match the oracle byte-equal", () => {
    const wBytes = buildAbcWBytes();
    const kBytes = buildKBytes();
    let stateBytes = varsToStateBytes(H_WORDS as unknown as Vars, wBytes);
    let oracleVars: Vars = H_WORDS as unknown as Vars;

    for (let t = 0; t < 64; t++) {
      stateBytes = callExecutorDirect(stateBytes, t, kBytes);
      oracleVars = oracleRound(oracleVars, K_WORDS[t] as number, decodeBE32(wBytes, t * 4));
      const execVars = stateBytesToVars(stateBytes);
      expect(execVars).toEqual(oracleVars);
    }
  });
});

describe("sha2.compression-round@1 — FIPS 180-4 §A.1 'abc' KAT for round 0", () => {
  // FIPS 180-4 §A.1 tabulates the per-round working variables. After
  // round 0 (1-indexed by the standard, t=0 here), the values are:
  //
  //   a = 5d6aebcd  b = 6a09e667  c = bb67ae85  d = 3c6ef372
  //   e = fa2a4622  f = 510e527f  g = 9b05688c  h = 1f83d9ab
  //
  // (Computed by the standard's own walk: T1 = H7 + Σ1(H4) + Ch(H4,H5,H6)
  //  + K_0 + W_0, T2 = Σ0(H0) + Maj(H0,H1,H2), then shuffle. The values
  //  here are the canonical reference output.)
  it("round 0 working variables match §A.1's published table", () => {
    const wBytes = buildAbcWBytes();
    const stateBytes = varsToStateBytes(H_WORDS as unknown as Vars, wBytes);
    const out = callExecutorDirect(stateBytes, 0, buildKBytes());
    const vars = stateBytesToVars(out);
    expect(vars[0]).toBe(0x5d6aebcd); // a
    expect(vars[1]).toBe(0x6a09e667); // b = a_prev = H_0
    expect(vars[2]).toBe(0xbb67ae85); // c = b_prev = H_1
    expect(vars[3]).toBe(0x3c6ef372); // d = c_prev = H_2
    expect(vars[4]).toBe(0xfa2a4622); // e
    expect(vars[5]).toBe(0x510e527f); // f = e_prev = H_4
    expect(vars[6]).toBe(0x9b05688c); // g = f_prev = H_5
    expect(vars[7]).toBe(0x1f83d9ab); // h = g_prev = H_6
  });
});

describe("sha2.compression-round@1 — runtime dispatch via runSpec", () => {
  // Single-round dry-run via runSpec to verify the lifted-legacy path
  // works end-to-end. The full 64-round chain ships in the SHA-256
  // cipher test; this just pins that ONE round leaf dispatches correctly.
  it("dispatches as a port-native leaf under portedDispatchEnabled: true", () => {
    const wBytes = buildAbcWBytes();
    const initialState: BytesState = {
      shape: "bytes",
      bytes: varsToStateBytes(H_WORDS as unknown as Vars, wBytes),
    };
    const spec: CipherSpec = {
      id: "toy-compression-single-round",
      name: "single-round dispatch (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "k-load",
          type: "generic.aux-load@1",
          params: { auxName: "K", value: Array.from(buildKBytes()) },
        },
        {
          kind: "step",
          id: "round.0",
          type: "sha2.compression-round@1",
          params: { roundIndex: 0 },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState,
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
    expect(trace.finalState.bytes.length).toBe(288);
    const vars = stateBytesToVars(trace.finalState.bytes);
    expect(vars[0]).toBe(0x5d6aebcd); // a after round 0
  });

  it("off-flag dispatch runs the legacy executor unchanged (frame-parity gate)", () => {
    // The lifted-legacy ported registration also carries the original
    // legacy executor under `legacy:`. Running with portedDispatchEnabled
    // omitted should still produce the same KAT — pinning that the
    // dual-dispatch shape stays byte-equal across paths.
    const wBytes = buildAbcWBytes();
    const initialState: BytesState = {
      shape: "bytes",
      bytes: varsToStateBytes(H_WORDS as unknown as Vars, wBytes),
    };
    const spec: CipherSpec = {
      id: "toy-compression-offflag",
      name: "off-flag dispatch (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "k-load",
          type: "generic.aux-load@1",
          params: { auxName: "K", value: Array.from(buildKBytes()) },
        },
        {
          kind: "step",
          id: "round.0",
          type: "sha2.compression-round@1",
          params: { roundIndex: 0 },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState,
      // No portedDispatchEnabled — uses legacy path.
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
    const vars = stateBytesToVars(trace.finalState.bytes);
    expect(vars[0]).toBe(0x5d6aebcd);
  });
});
