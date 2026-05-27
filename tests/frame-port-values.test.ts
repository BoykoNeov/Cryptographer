/**
 * Slice 2.9a of the universal-port-dataflow plan
 * (`docs/plans/slice-2-9-port-aware-provenance.md`).
 *
 * Pin TraceFrame's new `portInputs` / `portOutputs` fields:
 *
 *  - POSITIVE: a pure port-native frame (SHA-256's 5-operand T1
 *    `add-mod-32@1` reads h + Σ1(e) + Ch(e,f,g) + K_t + W_t) carries
 *    `portInputs` with 5 entries of 4 bytes each AND `portOutputs` with
 *    a single `output` entry whose bytes equal the manual modular sum
 *    of the inputs.
 *
 *  - NEGATIVE (advisor flag, 2026-05-27): a lifted-legacy ported frame
 *    (AES `generic.byte-substitution@1` — `kind: "ported"` WITH `legacy`
 *    defined) leaves BOTH port fields undefined even when
 *    `portedDispatchEnabled: true`. This is the gate that protects 2.9b's
 *    predicate (`portInputs !== undefined || portOutputs !== undefined`)
 *    from dispatching AES SubBytes through PortFlowView; lifted-legacy
 *    frames must continue rendering through the existing matrix viewer.
 *
 *  - LEGACY-PATH: every step type, run with `portedDispatchEnabled: false`
 *    (default), leaves both port fields undefined.
 *
 *  - HELPER: `framePortBytes` returns `null` on a legacy frame, `null` on
 *    a port-native frame asked for an unknown port name, and the
 *    Uint8Array reference for a valid (port-native frame, known port)
 *    lookup on each side.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { framePortBytes } from "@/core/port-projection";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const runSha256AbcTrace = () =>
  runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    portedDispatchEnabled: true,
  });

const findFrameByStepType = (
  frames: readonly TraceFrame[],
  stepType: string,
  predicate?: (f: TraceFrame) => boolean,
): TraceFrame => {
  for (const f of frames) {
    if (f.stepType !== stepType) continue;
    if (predicate && !predicate(f)) continue;
    return f;
  }
  throw new Error(`no frame with stepType=${stepType} matched predicate`);
};

const decodeBE32 = (bytes: Uint8Array, offset: number): number => {
  // Read 4 BE bytes as an unsigned 32-bit word. `>>> 0` keeps the result
  // unsigned (avoids the sign bit when bit 31 is set).
  return (
    (((bytes[offset] ?? 0) << 24) |
      ((bytes[offset + 1] ?? 0) << 16) |
      ((bytes[offset + 2] ?? 0) << 8) |
      (bytes[offset + 3] ?? 0)) >>>
    0
  );
};

// ─── Positive: pure port-native frame carries portInputs / portOutputs ────

describe("TraceFrame port-fields — pure port-native (SHA-256 add-mod-32@1)", () => {
  it("a 5-operand add-mod-32 frame carries 5 operand input ports of 4 bytes each", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );

    expect(t1.portInputs).toBeDefined();
    expect(t1.portOutputs).toBeDefined();

    const inputs = t1.portInputs;
    if (inputs === undefined) throw new Error("portInputs was undefined");
    expect(inputs.size).toBe(5);
    for (let i = 0; i < 5; i++) {
      const bytes = inputs.get(`operand${i}`);
      expect(bytes, `operand${i}`).toBeInstanceOf(Uint8Array);
      expect(bytes?.length, `operand${i} length`).toBe(4);
    }
  });

  it("portOutputs has a single `output` port of 4 bytes equal to the manual modular sum", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );

    const inputs = t1.portInputs;
    const outputs = t1.portOutputs;
    if (inputs === undefined || outputs === undefined) throw new Error("port fields undefined");

    expect(outputs.size).toBe(1);
    const out = outputs.get("output");
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out?.length).toBe(4);
    if (out === undefined) throw new Error("output port absent");

    // Manual modular sum of the five 4-byte operands' BE32 words.
    let sum = 0;
    for (let i = 0; i < 5; i++) {
      const op = inputs.get(`operand${i}`);
      if (op === undefined) throw new Error(`operand${i} absent`);
      sum = (sum + decodeBE32(op, 0)) >>> 0;
    }
    const expected = new Uint8Array(4);
    expected[0] = (sum >>> 24) & 0xff;
    expected[1] = (sum >>> 16) & 0xff;
    expected[2] = (sum >>> 8) & 0xff;
    expected[3] = sum & 0xff;
    expect(Array.from(out)).toEqual(Array.from(expected));
  });
});

// ─── Negative: lifted-legacy ported frame leaves port fields undefined ────

describe("TraceFrame port-fields — lifted-legacy ported (AES byte-substitution)", () => {
  it("AES SubBytes frame under portedDispatchEnabled:true has portInputs and portOutputs both undefined", () => {
    // FIPS-197 §C.1 AES-128 KAT vectors. Direct AES boot mirrors the per-
    // cipher dispatch test files; key in aux, plaintext as initial state.
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: matrixFromBytes(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map([["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")]]),
      portedDispatchEnabled: true,
    });

    // Lifted-legacy: `kind: "ported"` with `legacy` defined. The runtime
    // executes through the ported path, but Slice 2.9a's gate
    // (`meta === undefined`) skips port-field capture.
    const subBytes = findFrameByStepType(trace.frames, "generic.byte-substitution@1");
    expect(subBytes.portInputs).toBeUndefined();
    expect(subBytes.portOutputs).toBeUndefined();
  });

  it("AES key-expansion frame (lifted-legacy with auxWritePorts) also leaves port fields undefined", () => {
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: matrixFromBytes(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map([["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")]]),
      portedDispatchEnabled: true,
    });
    const keyExpansion = findFrameByStepType(trace.frames, "aes.key-expansion@1");
    expect(keyExpansion.portInputs).toBeUndefined();
    expect(keyExpansion.portOutputs).toBeUndefined();
  });
});

// ─── Legacy path: flag-off leaves port fields undefined everywhere ────────

describe("TraceFrame port-fields — legacy dispatch path", () => {
  it("portedDispatchEnabled:false (default) leaves port fields undefined on every AES frame", () => {
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: matrixFromBytes(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map([["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")]]),
      // portedDispatchEnabled omitted — default false.
    });
    for (const f of trace.frames) {
      expect(f.portInputs, `frame ${f.index} (${f.stepType})`).toBeUndefined();
      expect(f.portOutputs, `frame ${f.index} (${f.stepType})`).toBeUndefined();
    }
  });
});

// ─── framePortBytes helper ────────────────────────────────────────────────

describe("framePortBytes helper", () => {
  it("returns the operand bytes for a port-native frame on the input side", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const op0 = framePortBytes(t1, "operand0", "input");
    expect(op0).toBeInstanceOf(Uint8Array);
    expect(op0?.length).toBe(4);
  });

  it("returns the output bytes for a port-native frame on the output side", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const out = framePortBytes(t1, "output", "output");
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out?.length).toBe(4);
  });

  it("returns null when the named port is absent on the chosen side", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    // `output` is the OUTPUT port, not an input — asking for it on the
    // input side returns null.
    expect(framePortBytes(t1, "output", "input")).toBeNull();
    expect(framePortBytes(t1, "operand0", "output")).toBeNull();
    expect(framePortBytes(t1, "no-such-port", "input")).toBeNull();
  });

  it("returns null for a legacy-path frame (port fields undefined)", () => {
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: matrixFromBytes(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map([["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")]]),
    });
    const subBytes = findFrameByStepType(trace.frames, "generic.byte-substitution@1");
    expect(framePortBytes(subBytes, "state", "input")).toBeNull();
    expect(framePortBytes(subBytes, "state", "output")).toBeNull();
  });
});
