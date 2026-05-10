import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

describe("AES-128 (FIPS-197 Appendix C.1)", () => {
  const plaintextHex = "00112233445566778899aabbccddeeff";
  const keyHex = "000102030405060708090a0b0c0d0e0f";
  const expectedHex = "69c4e0d86a7b0430d8cdb78070b4c55a";

  it("encrypts the canonical test vector", () => {
    const plaintext = matrixFromBytes(bytesFromHex(plaintextHex));
    const key = bytesFromHex(keyHex);
    const initialAux = new Map<string, AuxValue>([["key", key]]);

    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    expect(trace.finalState.shape).toBe("matrix4x4-bytes");
    if (trace.finalState.shape !== "matrix4x4-bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(expectedHex);
  });

  it("emits a frame for every leaf step", () => {
    const plaintext = matrixFromBytes(bytesFromHex(plaintextHex));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);

    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    // Expected frames:
    //   key-expansion (1)
    //   initial AddRoundKey (1)
    //   rounds 1..9 × 4 sub-steps = 36
    //   final round × 3 sub-steps = 3
    //   = 41 frames
    expect(trace.frames.length).toBe(41);
  });

  it("produces all 11 round keys in aux", () => {
    const plaintext = matrixFromBytes(bytesFromHex(plaintextHex));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    for (let r = 0; r <= 10; r++) {
      const rk = trace.finalAux.get(`roundKey.${r}`);
      expect(rk).toBeInstanceOf(Uint8Array);
      expect((rk as Uint8Array).length).toBe(16);
    }

    // FIPS-197 §A.1: w[0..3] is the original key, so roundKey.0 must equal it.
    const rk0 = trace.finalAux.get("roundKey.0") as Uint8Array;
    expect(hexFromBytes(rk0)).toBe(keyHex);

    // FIPS-197 §C.1 expanded key for the all-sequential key:
    //   round 10 key = 13 11 1d 7f e3 94 4a 17 f3 07 a7 8b 4d 2b 30 c5
    expect(hexFromBytes(trace.finalAux.get("roundKey.10") as Uint8Array)).toBe(
      "13111d7fe3944a17f307a78b4d2b30c5",
    );
  });

  it("intermediate state after initial AddRoundKey matches FIPS-197 Appendix B", () => {
    // Appendix B uses plaintext 3243f6a8...e0370734 with key 2b7e1516...3c4f3c09c.
    const plaintext = matrixFromBytes(bytesFromHex("3243f6a8885a308d313198a2e0370734"));
    const key = bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c");
    const initialAux = new Map<string, AuxValue>([["key", key]]);

    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    // Appendix B: state after the initial round key add (start of round 1):
    //   col 0: 19 a0 9a e9
    //   col 1: 3d f4 c6 f8
    //   col 2: e3 e2 8d 48
    //   col 3: be 2b 2a 08
    const initialAddFrame = trace.frames.find((f) => f.stepId === "initial.add-round-key");
    expect(initialAddFrame).toBeDefined();
    if (!initialAddFrame) return;
    if (initialAddFrame.stateAfter.shape !== "matrix4x4-bytes") return;
    expect(hexFromBytes(initialAddFrame.stateAfter.bytes)).toBe("193de3bea0f4e22b9ac68d2ae9f84808");
  });

  it("changes ciphertext when ShiftRows and MixColumns are reordered", () => {
    // Note: SubBytes and ShiftRows actually *commute* — both are byte-wise
    // permutations, so swapping them gives identical output. ShiftRows and
    // MixColumns do NOT commute, because MixColumns mixes within columns
    // and ShiftRows changes which bytes occupy each column.
    const plaintext = matrixFromBytes(bytesFromHex(plaintextHex));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);

    const swapped = structuredClone(aes128Spec) as typeof aes128Spec;
    const round1 = swapped.steps[2];
    if (!round1 || round1.kind !== "group") throw new Error("expected round 1 group");
    // children layout: [sub-bytes, shift-rows, mix-columns, add-round-key]
    const children = round1.children as StepNode[];
    const sr = children[1];
    const mc = children[2];
    if (!sr || !mc) throw new Error("missing children");
    children[1] = mc;
    children[2] = sr;

    const trace = runSpec(swapped, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    if (trace.finalState.shape !== "matrix4x4-bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).not.toBe(expectedHex);
  });
});
