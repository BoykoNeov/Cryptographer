/**
 * Tests for `gf-matrix-multiply@1` — port-native GF(2⁸) column-mixing
 * primitive (scaffolding-suppression plan Phase B Slice B1.1, 2026-05-29).
 *
 * The byte-native replacement for the matrix-shaped `generic.mix-columns@1`.
 * Coverage:
 *   1. Executor KAT against the canonical AES MixColumns column vector
 *      ({db,13,53,45} → {8e,4d,a1,bc}, FIPS-197 / textbook).
 *   2. Forward∘inverse round-trip with the AES matrices.
 *   3. Byte-equal PARITY against the existing, already-tested legacy
 *      `mixColumns` executor (in-repo oracle — the safest check that the
 *      flat-byte arithmetic matches the matrix implementation it replaces).
 *   4. Multi-column (>4 bytes) + non-multiple-of-4 rejection.
 *   5. PortContract static raw (A4-clean) + dispatch guards.
 */

import { AES_INV_MIX_MATRIX, AES_MIX_MATRIX } from "@/ciphers/aes-constants";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, MatrixState, StepContext } from "@/core/types";
import { gfMatrixMultiply, gfMatrixMultiplyPortContract } from "@/steps/gf-matrix-multiply";
import { mixColumns } from "@/steps/mix-columns";
import { describe, expect, it } from "vitest";

const mat = (m: readonly (readonly number[])[]): number[][] => m.map((row) => [...row]);

const callGf = (input: readonly number[], matrix: readonly (readonly number[])[]): number[] => {
  const inputs = new Map([["input", new Uint8Array(input)]]);
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = gfMatrixMultiply(inputs, { matrix: mat(matrix) } as unknown as Json, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("gf-matrix-multiply: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

describe("gf-matrix-multiply@1 — executor (direct invocation)", () => {
  it("canonical AES MixColumns column {db,13,53,45} → {8e,4d,a1,bc}", () => {
    expect(callGf([0xdb, 0x13, 0x53, 0x45], AES_MIX_MATRIX)).toEqual([0x8e, 0x4d, 0xa1, 0xbc]);
  });

  it("InvMixColumns undoes MixColumns (round trip on the canonical column)", () => {
    const mixed = callGf([0xdb, 0x13, 0x53, 0x45], AES_MIX_MATRIX);
    expect(callGf(mixed, AES_INV_MIX_MATRIX)).toEqual([0xdb, 0x13, 0x53, 0x45]);
  });

  it("identity matrix is a passthrough", () => {
    const identity = [
      [1, 0, 0, 0],
      [0, 1, 0, 0],
      [0, 0, 1, 0],
      [0, 0, 0, 1],
    ];
    expect(callGf([0xaa, 0xbb, 0xcc, 0xdd], identity)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
  });

  it("byte-equal parity with the legacy mixColumns executor (16-byte AES block)", () => {
    // The legacy executor is matrix-shaped + already KAT-tested; use it as
    // an in-repo oracle. A fixed pseudo-random 16-byte block exercises all
    // four columns.
    const block = Array.from({ length: 16 }, (_, i) => (i * 53 + 7) & 0xff);
    const legacy: MatrixState = { shape: "matrix4x4-bytes", bytes: new Uint8Array(block) };
    const legacyOut = Array.from(
      (
        mixColumns(legacy, { matrix: mat(AES_MIX_MATRIX) } as unknown as Json, {
          stepId: "t",
          path: [],
          aux: new Map(),
        }).state as MatrixState
      ).bytes,
    );
    expect(callGf(block, AES_MIX_MATRIX)).toEqual(legacyOut);
  });

  it("processes multiple 4-byte columns independently (8 bytes = 2 columns)", () => {
    const col = callGf([0xdb, 0x13, 0x53, 0x45], AES_MIX_MATRIX);
    expect(callGf([0xdb, 0x13, 0x53, 0x45, 0xdb, 0x13, 0x53, 0x45], AES_MIX_MATRIX)).toEqual([
      ...col,
      ...col,
    ]);
  });

  describe("validation", () => {
    const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
    it("throws when matrix is not 4×4", () => {
      expect(() =>
        gfMatrixMultiply(
          new Map([["input", new Uint8Array(4)]]),
          { matrix: [[1, 2]] } as unknown as Json,
          ctx,
        ),
      ).toThrow(/4×4/);
    });
    it("throws when input is not wired", () => {
      expect(() =>
        gfMatrixMultiply(new Map(), { matrix: mat(AES_MIX_MATRIX) } as unknown as Json, ctx),
      ).toThrow(/input port "input" is not wired/);
    });
    it("throws when input length is not a multiple of 4", () => {
      expect(() =>
        gfMatrixMultiply(
          new Map([["input", new Uint8Array(6)]]),
          { matrix: mat(AES_MIX_MATRIX) } as unknown as Json,
          ctx,
        ),
      ).toThrow(/not a multiple of 4/);
    });
  });
});

describe("gf-matrix-multiply@1 — PortContract is A4-clean (static raw)", () => {
  it("input + output are static raw maps", () => {
    if (typeof gfMatrixMultiplyPortContract.inputs === "function") throw new Error("inputs static");
    if (typeof gfMatrixMultiplyPortContract.outputs === "function")
      throw new Error("outputs static");
    expect(gfMatrixMultiplyPortContract.inputs.get("input")?.layout).toBe("raw");
    expect(gfMatrixMultiplyPortContract.outputs.get("output")?.layout).toBe("raw");
  });
});

describe("gf-matrix-multiply@1 — runtime dispatch guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "test-gf-matrix-multiply@1",
    name: "test gf-matrix-multiply",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "s",
        type: "gf-matrix-multiply@1",
        params: { matrix: mat(AES_MIX_MATRIX) },
      },
    ],
  });

  it("off-flag dispatch throws 'requires portedDispatchEnabled: true'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), { initialState: emptyBytes() }),
    ).toThrow(
      'step type "gf-matrix-multiply@1" is port-native; requires portedDispatchEnabled: true',
    );
  });

  it("on-flag dispatch with no portInputs throws 'input port input is not wired'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
        portedDispatchEnabled: true,
      }),
    ).toThrow(/input port 'input' is not wired/);
  });
});
