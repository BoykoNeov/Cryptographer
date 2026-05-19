/**
 * Phase 2 of the DES + branching primitive plan (`docs/plans/des-feistel.md`).
 * Pins the branching primitive's runtime semantics against a toy spec —
 * BEFORE any DES code lands.
 *
 * Why a toy fixture: DES has 16 rounds + bit permutations + key schedule
 * that take ~hundreds of lines of code. The primitive's job (run two
 * parallel tracks, stamp `branchPath`, apply a 4-arg combine, emit a
 * synthetic rejoin frame) doesn't depend on any of that — exercising it
 * against a minimal `(R + k) mod 256` F-function isolates primitive bugs
 * from cipher bugs and keeps the test diagnostic when something fails.
 *
 * The F is intentionally NOT self-inverse so a buggy combine produces a
 * different ciphertext (a self-inverse F like XOR would round-trip even
 * if `combineKind` were mis-applied) — see the toy spec doc-comment.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { FEISTEL_TOY_KAT, FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { REJOIN_STEP_TYPE } from "@/core/combine-kinds";
import { runSpec } from "@/core/runtime";
import { hexFromBytes } from "@/core/state/bytes";
import { canonicalStepId } from "@/core/step-id";
import { describe, expect, it } from "vitest";

describe("feistel-round primitive (toy spec)", () => {
  it("matches the hand-computed KAT", () => {
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
    });
    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(hexFromBytes(FEISTEL_TOY_KAT.ciphertext));
  });

  it("emits exactly one frame per non-empty track leaf plus one rejoin per round", () => {
    // Each round has: ZERO frames for empty L track, ONE frame for the
    // single R-track step (add-k), ONE rejoin frame. 2 rounds × 2 = 4 frames.
    // If a future change to the runtime accidentally emitted a passthrough
    // frame for the empty L track, this assertion catches it.
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
    });
    expect(trace.frames.length).toBe(4);
  });

  it("stamps branchPath on every R-track frame and on rejoin frames", () => {
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
    });
    // R-track frames carry branchPath: ["R"]. Rejoin frames inherit the
    // ENCLOSING branchPath — toy is at root scope, so rejoin's branchPath
    // is empty/undefined (NOT ["R"]).
    const trackFrames = trace.frames.filter((f) => f.stepType === "feistel.toy-add-k@1");
    expect(trackFrames).toHaveLength(2);
    for (const f of trackFrames) {
      expect(f.branchPath).toEqual(["R"]);
    }
    const rejoinFrames = trace.frames.filter((f) => f.stepType === REJOIN_STEP_TYPE);
    expect(rejoinFrames).toHaveLength(2);
    for (const f of rejoinFrames) {
      // Rejoin frames at root-scope rounds have NO enclosing track, so
      // branchPath must be absent (the runtime omits the field rather
      // than emitting an empty array).
      expect(f.branchPath).toBeUndefined();
    }
  });

  it("appends :t{name} suffix to in-track frame stepIds, canonicalizable back to spec id", () => {
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
    });
    const addK1 = trace.frames.find((f) => f.stepId === "round.1.add-k:tR");
    expect(addK1).toBeDefined();
    expect(canonicalStepId("round.1.add-k:tR")).toBe("round.1.add-k");
    const addK2 = trace.frames.find((f) => f.stepId === "round.2.add-k:tR");
    expect(addK2).toBeDefined();
  });

  it("emits rejoin frames with deterministic synthetic ids and combineKind params", () => {
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
    });
    const r1 = trace.frames.find((f) => f.stepId === "round.1:rejoin");
    const r2 = trace.frames.find((f) => f.stepId === "round.2:rejoin");
    expect(r1).toBeDefined();
    expect(r2).toBeDefined();
    expect(r1?.stepType).toBe(REJOIN_STEP_TYPE);
    expect(r2?.stepType).toBe(REJOIN_STEP_TYPE);
    expect(r1?.params).toEqual({ combineKind: "feistel-standard" });
    expect(r2?.params).toEqual({ combineKind: "feistel-no-swap" });
    // The rejoin frame's stepId canonicalizes to the round id — that's
    // what makes "click the rejoin chip" scrub to the round's location
    // in the spec tree.
    expect(canonicalStepId("round.1:rejoin")).toBe("round.1");
    expect(canonicalStepId("round.2:rejoin")).toBe("round.2");
  });

  it("rejoin frame's stateBefore concatenates L_out|R_out; stateAfter is the combined state", () => {
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
    });
    // Round 1: L_out = L_in = [0x01, 0x02], R_out = R_in + 0x11 = [0x14, 0x15].
    // stateBefore = L_out || R_out = [0x01, 0x02, 0x14, 0x15].
    // After feistel-standard combine: new_L = R_in = [0x03, 0x04],
    // new_R = L_in XOR R_out = [0x15, 0x17]. stateAfter = [0x03, 0x04, 0x15, 0x17].
    const r1 = trace.frames.find((f) => f.stepId === "round.1:rejoin");
    expect(r1).toBeDefined();
    if (!r1 || r1.stateBefore.shape !== "bytes" || r1.stateAfter.shape !== "bytes") return;
    expect(hexFromBytes(r1.stateBefore.bytes)).toBe("01021415");
    expect(hexFromBytes(r1.stateAfter.bytes)).toBe("03041517");
  });

  it("throws when the input state is not bytes-shape", () => {
    expect(() =>
      runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
        initialState: { shape: "matrix4x4-bytes", bytes: new Uint8Array(16) },
      }),
    ).toThrow(/requires bytes-shape state/);
  });

  it("throws when a track's inputBytes index is out of range", () => {
    const badSpec = {
      ...FEISTEL_TOY_SPEC,
      steps: [
        {
          kind: "feistel-round" as const,
          id: "round.bad",
          tracks: [
            { name: "L", inputBytes: [0, 1], children: [] },
            // R declares index 99, which is past the 4-byte input.
            { name: "R", inputBytes: [2, 99], children: [] },
          ],
          combineKind: "feistel-standard" as const,
        },
      ],
    };
    expect(() =>
      runSpec(badSpec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
      }),
    ).toThrow(/out of range/);
  });

  it("throws when two tracks reuse the same byte index", () => {
    const overlapSpec = {
      ...FEISTEL_TOY_SPEC,
      steps: [
        {
          kind: "feistel-round" as const,
          id: "round.overlap",
          tracks: [
            { name: "L", inputBytes: [0, 1], children: [] },
            // R reuses byte 1.
            { name: "R", inputBytes: [1, 2], children: [] },
          ],
          combineKind: "feistel-standard" as const,
        },
      ],
    };
    expect(() =>
      runSpec(overlapSpec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
      }),
    ).toThrow(/reuses byte index/);
  });
});
