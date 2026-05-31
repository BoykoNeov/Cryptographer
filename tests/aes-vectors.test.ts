import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

/**
 * Known-answer test for byte-native AES-128 (scaffolding-suppression Slice B1,
 * 2026-05-29; AddRoundKey merged to one leaf in Finding F3, 2026-05-30). The
 * spec is built from port-native primitives (`byte-substitute@1` / `permute@1`
 * / `gf-matrix-multiply@1` / `xor-with-aux@1`) with no legacy executor, so it
 * runs ONLY under `portedDispatchEnabled: true` and produces a `bytes`
 * finalState.
 *
 * After the ported-dispatch parity tests dropped their byte-native AES-128
 * rows (no legacy path to compare against), THIS file is the primary pin on
 * the byte-native AES-128 frame stream: 41 frames, all 11 round keys, and the
 * FIPS-197 Appendix B intermediate after the initial AddRoundKey. Keep these
 * as frame-stream assertions, not a KAT-only check.
 */
describe("AES-128 (FIPS-197 Appendix C.1)", () => {
  const plaintextHex = "00112233445566778899aabbccddeeff";
  const keyHex = "000102030405060708090a0b0c0d0e0f";
  const expectedHex = "69c4e0d86a7b0430d8cdb78070b4c55a";

  it("encrypts the canonical test vector", () => {
    const plaintext = makeBytesState(bytesFromHex(plaintextHex));
    const key = bytesFromHex(keyHex);
    const initialAux = new Map<string, AuxValue>([["key", key]]);

    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(expectedHex);
  });

  it("emits a frame for every leaf step", () => {
    const plaintext = makeBytesState(bytesFromHex(plaintextHex));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);

    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    // Byte-native AES-128 leaves (one frame each), after Finding F3 merged
    // AddRoundKey's fetch-rk + xor pair into the single `xor-with-aux@1` leaf:
    //   key-expansion (1)
    //   initial.add-round-key (1)
    //   rounds 1..9 × 4 sub-steps (sub-bytes, shift-rows, mix-columns,
    //     add-round-key) = 36
    //   final round.10 × 3 sub-steps (no mix-columns) = 3
    //   = 41 frames
    expect(trace.frames.length).toBe(41);
  });

  it("produces all 11 round keys in aux", () => {
    const plaintext = makeBytesState(bytesFromHex(plaintextHex));
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
    const plaintext = makeBytesState(bytesFromHex("3243f6a8885a308d313198a2e0370734"));
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
    // Byte-native: the initial AddRoundKey is an `xor@1` leaf; its 16-byte
    // output (plaintext ⊕ roundKey.0, in input/column-major byte order) is
    // read from the frame's `portOutputs` "output" port, not `stateAfter`.
    const initialAddFrame = trace.frames.find((f) => f.stepId === "initial.add-round-key");
    expect(initialAddFrame).toBeDefined();
    if (!initialAddFrame) return;
    const out = initialAddFrame.portOutputs?.get("output");
    expect(out).toBeInstanceOf(Uint8Array);
    if (!out) return;
    expect(hexFromBytes(out)).toBe("193de3bea0f4e22b9ac68d2ae9f84808");
  });

  // The legacy "changes ciphertext when ShiftRows and MixColumns are reordered"
  // test (which swapped two entries of the round's children ARRAY) is moot
  // under byte-native port wiring: execution dataflow is determined by each
  // leaf's explicit `portInputs` bindings (sub-bytes → shift-rows → mix-columns
  // → add-round-key), not by array position. Swapping array entries without
  // rewiring the bindings would only break dataflow (a later leaf reading a
  // not-yet-computed output), not faithfully reorder the operations — a
  // misleading "differs" for the wrong reason. The ShiftRows/MixColumns
  // non-commutativity it demonstrated is preserved by the unchanged §C.1 KAT
  // above (any reorder of the published spec breaks that exact ciphertext). A
  // faithful port-era reorder test would rewire all three bindings AND the
  // children array; deferred — not a frame-stream pin.
});
