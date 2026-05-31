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
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
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

// ─── Port-field capture on a meta-bearing port-native frame ───────────────
// (The lifted-legacy negative case — the Feistel toy's frames leaving port
// fields undefined — was retired in Phase 5 Slice 5.3e with the toy, the
// last `legacy`-bearing ported step. No lifted-legacy step remains.)

describe("TraceFrame port-fields — meta-bearing port-native (AES key-expansion)", () => {
  it("AES key-expansion frame (port-native since Slice 5.2) carries portInputs + portOutputs", () => {
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map([["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")]]),
      portedDispatchEnabled: true,
    });
    const keyExpansion = findFrameByStepType(trace.frames, "aes.key-expansion@1");
    // Slice 5.2 dropped the `legacy` lift, so the runtime now captures the
    // projected port I/O: the master key on `masterKey`, the 11 round keys
    // (AES-128, rounds=10) on `key0` … `key10`. (KeyScheduleExplorer still
    // intercepts this frame by stepType, so the inspector view is unchanged
    // — but the captured port maps now exist, like every other port-native
    // leaf.)
    expect(keyExpansion.portInputs).toBeDefined();
    expect(keyExpansion.portOutputs).toBeDefined();
    expect([...(keyExpansion.portInputs?.keys() ?? [])]).toContain("masterKey");
    expect(keyExpansion.portOutputs?.size).toBe(11);
    for (let r = 0; r <= 10; r++) {
      expect([...(keyExpansion.portOutputs?.keys() ?? [])]).toContain(`key${r}`);
    }
  });
});

// (The "legacy dispatch path leaves port fields undefined" describe was
// retired in Phase 5 Slice 5.3e: it ran the Feistel toy under
// `portedDispatchEnabled:false`, but no `legacy`-bearing step survives — and
// every shipped port-native step THROWS under flag-off, so there is nothing
// left to exercise the legacy path with.)

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
});
