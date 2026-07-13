/**
 * Per-step unit tests for the four SHA-3 / Keccak port-native step types
 * (2026-07-13): `rotate-lanes@1` (ρ), `keccak.theta@1` (θ),
 * `keccak.iota@1` (ι), and `keccak.pad@1` (sponge padding).
 *
 * These are hand-derived KATs straight from the FIPS 202 step formulas —
 * independent of the end-to-end SHA3-256 oracle in
 * `tests/sha3-256-kat.test.ts` (which cross-checks the whole assembled sponge
 * against `node:crypto`). Testing each executor in isolation localizes a
 * regression to the exact step.
 */

import type { Json, PortedExecutor, StepContext } from "@/core/types";
import { keccakIota } from "@/steps/keccak-iota";
import { keccakPad } from "@/steps/keccak-pad";
import { keccakTheta } from "@/steps/keccak-theta";
import { rotateLanes } from "@/steps/rotate-lanes";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const call = (
  executor: PortedExecutor,
  ports: Record<string, readonly number[]>,
  params: Json,
): number[] => {
  const inputs = new Map(Object.entries(ports).map(([k, v]) => [k, new Uint8Array(v)]));
  const out = executor(inputs, params, CTX).get("output");
  if (!out) throw new Error("no output port");
  return Array.from(out);
};

// ─── rotate-lanes@1 (ρ) ─────────────────────────────────────────────────────

describe("rotate-lanes@1 — per-lane left rotate, little-endian", () => {
  const lane = (v: readonly number[]) => v; // 8 LE bytes

  it("rotl 1 of value 1 → value 2 (LE)", () => {
    expect(
      call(
        rotateLanes,
        { input: lane([1, 0, 0, 0, 0, 0, 0, 0]) },
        {
          wordBits: 64,
          offsets: [1],
          littleEndian: true,
        },
      ),
    ).toEqual([2, 0, 0, 0, 0, 0, 0, 0]);
  });

  it("rotl 8 of value 1 → value 256 (byte 1 = 0x01, LE)", () => {
    expect(
      call(
        rotateLanes,
        { input: lane([1, 0, 0, 0, 0, 0, 0, 0]) },
        {
          wordBits: 64,
          offsets: [8],
          littleEndian: true,
        },
      ),
    ).toEqual([0, 1, 0, 0, 0, 0, 0, 0]);
  });

  it("rotl 63 of value 1 → 0x8000000000000000 (top bit, LE byte 7 = 0x80)", () => {
    expect(
      call(
        rotateLanes,
        { input: lane([1, 0, 0, 0, 0, 0, 0, 0]) },
        {
          wordBits: 64,
          offsets: [63],
          littleEndian: true,
        },
      ),
    ).toEqual([0, 0, 0, 0, 0, 0, 0, 0x80]);
  });

  it("distinct per-lane offsets: [1, 4] rotate each lane independently", () => {
    // lane0 = 1 rotl 1 = 2; lane1 = 1 rotl 4 = 16
    expect(
      call(
        rotateLanes,
        { input: [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0] },
        {
          wordBits: 64,
          offsets: [1, 4],
          littleEndian: true,
        },
      ),
    ).toEqual([2, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0]);
  });

  it("offset 0 is identity", () => {
    const bytes = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    expect(
      call(rotateLanes, { input: bytes }, { wordBits: 64, offsets: [0], littleEndian: true }),
    ).toEqual(bytes);
  });

  it("little-endian and big-endian give different results (endianness is load-bearing)", () => {
    const bytes = [1, 0, 0, 0, 0, 0, 0, 0];
    const le = call(
      rotateLanes,
      { input: bytes },
      { wordBits: 64, offsets: [8], littleEndian: true },
    );
    const be = call(
      rotateLanes,
      { input: bytes },
      { wordBits: 64, offsets: [8], littleEndian: false },
    );
    expect(le).not.toEqual(be);
  });

  it("throws when the offsets count does not match the lane count", () => {
    expect(() =>
      call(
        rotateLanes,
        { input: [0, 0, 0, 0, 0, 0, 0, 0] },
        { wordBits: 64, offsets: [1, 2], littleEndian: true },
      ),
    ).toThrow(/offsets/);
  });
});

// ─── keccak.theta@1 (θ) ─────────────────────────────────────────────────────

describe("keccak.theta@1 — column-mixing step", () => {
  const laneStart = (x: number, y: number) => (x + 5 * y) * 8;

  it("θ of the all-zero state is all-zero", () => {
    expect(call(keccakTheta, { input: new Array(200).fill(0) }, {})).toEqual(
      new Array(200).fill(0),
    );
  });

  it("θ with only lane (0,0) bit 0 set matches the hand-derived FIPS 202 formula", () => {
    // Input: A[0,0] = 1, everything else 0.
    const input = new Array(200).fill(0);
    input[0] = 1;
    // C[0]=1, C[1..4]=0.  D[1]=C[0]=1, D[4]=ROTL(C[0],1)=2, D[0]=D[2]=D[3]=0.
    // A'[x,y] = A[x,y] ⊕ D[x]:
    //   column 0 (D=0): unchanged → lane(0,0)=1
    //   column 1 (D=1): all 5 lanes' byte 0 become 1
    //   column 4 (D=2): all 5 lanes' byte 0 become 2
    const expected = new Array(200).fill(0);
    expected[0] = 1; // lane (0,0)
    for (let y = 0; y < 5; y++) expected[laneStart(1, y)] = 1;
    for (let y = 0; y < 5; y++) expected[laneStart(4, y)] = 2;
    expect(call(keccakTheta, { input }, {})).toEqual(expected);
  });

  it("throws on a non-200-byte state", () => {
    expect(() => call(keccakTheta, { input: new Array(100).fill(0) }, {})).toThrow(/200 bytes/);
  });
});

// ─── keccak.iota@1 (ι) ──────────────────────────────────────────────────────

describe("keccak.iota@1 — round-constant XOR into lane (0,0)", () => {
  const rcTable = (): number[] => {
    // 24 lanes × 8 bytes; lane i filled with byte value (i+1) so each is distinct.
    const t = new Array(24 * 8).fill(0);
    for (let i = 0; i < 24; i++) for (let b = 0; b < 8; b++) t[i * 8 + b] = i + 1;
    return t;
  };

  it("round 3 XORs RC lane 3 into lane (0,0), leaving the rest untouched", () => {
    const state = new Array(200).fill(0);
    const out = call(keccakIota, { input: state, rc: rcTable() }, { round: 3 });
    const expected = new Array(200).fill(0);
    for (let b = 0; b < 8; b++) expected[b] = 4; // lane 3 filled with value 4
    expect(out).toEqual(expected);
  });

  it("round 0 selects RC lane 0", () => {
    const state = new Array(200).fill(0);
    const out = call(keccakIota, { input: state, rc: rcTable() }, { round: 0 });
    expect(out.slice(0, 8)).toEqual([1, 1, 1, 1, 1, 1, 1, 1]);
    expect(out.slice(8)).toEqual(new Array(192).fill(0));
  });

  it("XOR is against existing lane-0 bytes, not an overwrite", () => {
    const state = new Array(200).fill(0);
    for (let b = 0; b < 8; b++) state[b] = 0xf0;
    const out = call(keccakIota, { input: state, rc: rcTable() }, { round: 0 }); // lane 0 = 0x01
    expect(out.slice(0, 8)).toEqual(new Array(8).fill(0xf1));
  });

  it("throws when round is out of range", () => {
    expect(() =>
      call(keccakIota, { input: new Array(200).fill(0), rc: rcTable() }, { round: 24 }),
    ).toThrow(/round/);
  });
});

// ─── keccak.pad@1 (pad10*1 + domain) ────────────────────────────────────────

describe("keccak.pad@1 — sponge padding", () => {
  it("empty message pads to one full block: [domain, 0.., 0x80]", () => {
    expect(call(keccakPad, { input: [] }, { rate: 4, domainByte: 0x06 })).toEqual([
      0x06, 0, 0, 0x80,
    ]);
  });

  it("merge case (one byte short of a block): domain and 0x80 collapse to 0x86", () => {
    expect(call(keccakPad, { input: [0xaa, 0xbb, 0xcc] }, { rate: 4, domainByte: 0x06 })).toEqual([
      0xaa, 0xbb, 0xcc, 0x86,
    ]);
  });

  it("exact multiple of rate gains a full extra padding block", () => {
    expect(
      call(keccakPad, { input: [0xaa, 0xbb, 0xcc, 0xdd] }, { rate: 4, domainByte: 0x06 }),
    ).toEqual([0xaa, 0xbb, 0xcc, 0xdd, 0x06, 0, 0, 0x80]);
  });

  it("SHAKE domain byte 0x1F merges to 0x9F in the one-byte case", () => {
    expect(call(keccakPad, { input: [0xaa, 0xbb, 0xcc] }, { rate: 4, domainByte: 0x1f })).toEqual([
      0xaa, 0xbb, 0xcc, 0x9f,
    ]);
  });

  it("output length is always a multiple of rate", () => {
    for (let len = 0; len < 40; len++) {
      const out = call(
        keccakPad,
        { input: new Array(len).fill(0xaa) },
        { rate: 8, domainByte: 0x06 },
      );
      expect(out.length % 8).toBe(0);
      expect(out.length).toBeGreaterThan(len);
    }
  });
});
