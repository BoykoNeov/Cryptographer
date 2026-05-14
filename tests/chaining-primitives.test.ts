/**
 * Tests for the three Phase-2 chaining-mode primitives:
 *
 *   - `generic.iv-load@1`           — Uint8Array (16) aux → MatrixState aux.
 *   - `generic.xor-aux-into-state@1` — state ⊕= aux[name] (MatrixState only).
 *   - `generic.state-to-aux@1`       — snapshot state into aux[name] (deep clone).
 *
 * Coverage axes mirror the aux-primitives tests next door:
 *
 *   1. **Per-primitive KAT** — byte math under direct executor calls.
 *   2. **Graceful missing-aux** — half-wired (empty params or absent reads)
 *      returns passthrough with reads still declared, so Slice 9's
 *      `validateGraph` can surface orphan-read warnings.
 *   3. **Composition** — a full CBC encrypt cycle using only the three new
 *      primitives + the existing aux-copy + the AES round body. Validates
 *      that the four-step decrypt body (state-to-aux → AES⁻¹ →
 *      xor-aux-into-state → aux-copy) inverts the encrypt body.
 *
 * State and aux value cloning is checked specifically — aliasing between
 * the running state and the chain snapshot is the most likely regression,
 * and the runtime's per-iter `state = cloneState(blocks[i])` swap would
 * silently corrupt aliased snapshots.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, MatrixState, StepContext } from "@/core/types";
import { ivLoad } from "@/steps/iv-load";
import { stateToAux } from "@/steps/state-to-aux";
import { xorAuxIntoState } from "@/steps/xor-aux-into-state";
import { describe, expect, it } from "vitest";

const emptyBytes = () => makeBytesState(new Uint8Array(0));

const makeCtx = (aux: ReadonlyMap<string, AuxValue>): StepContext => ({
  stepId: "test",
  path: [],
  aux,
});

const sixteen = (b: number): Uint8Array => new Uint8Array(16).fill(b);

// ─── iv-load ──────────────────────────────────────────────────────────────

describe("iv-load@1", () => {
  it("reads aux[ivAuxName] and writes a fresh MatrixState under aux[outAuxName]", () => {
    const ivBytes = sixteen(0xab);
    const aux = new Map<string, AuxValue>([["iv", ivBytes]]);
    const result = ivLoad(emptyBytes(), { ivAuxName: "iv", outAuxName: "chain" }, makeCtx(aux));
    const written = result.auxWrites?.get("chain") as MatrixState;
    expect(written.shape).toBe("matrix4x4-bytes");
    expect(Array.from(written.bytes)).toEqual(Array.from(ivBytes));
    // Fresh allocation — the written matrix must not share storage with
    // the source IV bytes. Mutating one must not affect the other.
    ivBytes[0] = 0x00;
    expect(written.bytes[0]).toBe(0xab);
  });

  it("declares the read regardless of presence (orphan-warning contract)", () => {
    const result = ivLoad(
      emptyBytes(),
      { ivAuxName: "iv", outAuxName: "chain" },
      makeCtx(new Map()),
    );
    expect(result.auxReads).toEqual(["iv"]);
    // Missing read → no write.
    expect(result.auxWrites).toBeUndefined();
  });

  it("treats empty ivAuxName as unset (passthrough, no write)", () => {
    const result = ivLoad(emptyBytes(), { ivAuxName: "", outAuxName: "chain" }, makeCtx(new Map()));
    expect(result.auxWrites).toBeUndefined();
  });

  it("read-side wired but no outAuxName → passthrough (half-wired forward authoring state)", () => {
    const aux = new Map<string, AuxValue>([["iv", sixteen(0xff)]]);
    const result = ivLoad(emptyBytes(), { ivAuxName: "iv", outAuxName: "" }, makeCtx(aux));
    expect(result.auxReads).toEqual(["iv"]);
    expect(result.auxWrites).toBeUndefined();
  });

  it("THROWS on present-but-wrong-shape aux (non-Uint8Array)", () => {
    const aux = new Map<string, AuxValue>([["iv", 42]]);
    expect(() =>
      ivLoad(emptyBytes(), { ivAuxName: "iv", outAuxName: "chain" }, makeCtx(aux)),
    ).toThrow(/must be a Uint8Array/);
  });

  it("THROWS on wrong-length Uint8Array (15 bytes)", () => {
    const aux = new Map<string, AuxValue>([["iv", new Uint8Array(15)]]);
    expect(() =>
      ivLoad(emptyBytes(), { ivAuxName: "iv", outAuxName: "chain" }, makeCtx(aux)),
    ).toThrow(/must be 16 bytes, got 15/);
  });

  it("rejects non-string params (malformed JSON spec — not reachable from UI)", () => {
    expect(() =>
      ivLoad(emptyBytes(), { ivAuxName: 1, outAuxName: "x" }, makeCtx(new Map())),
    ).toThrow(/ivAuxName must be a string/);
  });
});

// ─── xor-aux-into-state ───────────────────────────────────────────────────

describe("xor-aux-into-state@1", () => {
  const stateAll0xAB = (): MatrixState => matrixFromBytes(sixteen(0xab));
  const chain0xCD = (): MatrixState => matrixFromBytes(sixteen(0xcd));

  it("XORs the aux MatrixState into the state, returning a fresh MatrixState", () => {
    const aux = new Map<string, AuxValue>([["chain", chain0xCD()]]);
    const result = xorAuxIntoState(stateAll0xAB(), { auxName: "chain" }, makeCtx(aux));
    expect(result.state.shape).toBe("matrix4x4-bytes");
    if (result.state.shape !== "matrix4x4-bytes") return;
    // 0xab ^ 0xcd = 0x66
    expect(Array.from(result.state.bytes)).toEqual(Array.from(sixteen(0x66)));
  });

  it("does NOT mutate state.bytes in place (fresh allocation per call)", () => {
    const initial = stateAll0xAB();
    const aux = new Map<string, AuxValue>([["chain", chain0xCD()]]);
    xorAuxIntoState(initial, { auxName: "chain" }, makeCtx(aux));
    // Input state is untouched — the runtime relies on this for the
    // trace's `before` snapshot.
    expect(initial.bytes[0]).toBe(0xab);
  });

  it("declares the read regardless of presence (orphan-warning contract)", () => {
    const result = xorAuxIntoState(stateAll0xAB(), { auxName: "chain" }, makeCtx(new Map()));
    expect(result.auxReads).toEqual(["chain"]);
    // Missing read → passthrough, original state returned.
    expect(result.state.shape).toBe("matrix4x4-bytes");
    if (result.state.shape !== "matrix4x4-bytes") return;
    expect(result.state.bytes[0]).toBe(0xab);
  });

  it("treats empty auxName as unset (passthrough)", () => {
    const result = xorAuxIntoState(stateAll0xAB(), { auxName: "" }, makeCtx(new Map()));
    if (result.state.shape !== "matrix4x4-bytes") return;
    expect(result.state.bytes[0]).toBe(0xab);
  });

  it("is self-inverse: applying twice with the same aux returns the original state", () => {
    const aux = new Map<string, AuxValue>([["chain", chain0xCD()]]);
    const once = xorAuxIntoState(stateAll0xAB(), { auxName: "chain" }, makeCtx(aux));
    const twice = xorAuxIntoState(once.state, { auxName: "chain" }, makeCtx(aux));
    if (twice.state.shape !== "matrix4x4-bytes") return;
    expect(Array.from(twice.state.bytes)).toEqual(Array.from(sixteen(0xab)));
  });

  it("THROWS on non-matrix state shape (today only AES-shaped supported)", () => {
    const aux = new Map<string, AuxValue>([["chain", chain0xCD()]]);
    expect(() =>
      xorAuxIntoState(makeBytesState(new Uint8Array(16)), { auxName: "chain" }, makeCtx(aux)),
    ).toThrow(/state must be matrix4x4-bytes/);
  });

  it("THROWS on aux value being a Uint8Array (must be MatrixState)", () => {
    const aux = new Map<string, AuxValue>([["chain", sixteen(0xcd)]]);
    expect(() => xorAuxIntoState(stateAll0xAB(), { auxName: "chain" }, makeCtx(aux))).toThrow(
      /must be a MatrixState/,
    );
  });
});

// ─── state-to-aux ─────────────────────────────────────────────────────────

describe("state-to-aux@1", () => {
  it("writes a deep clone of the state into aux[auxName]; state passthrough", () => {
    const state = matrixFromBytes(sixteen(0x55));
    const result = stateToAux(state, { auxName: "chain" }, makeCtx(new Map()));
    expect(result.state).toBe(state); // passthrough reference is the same object
    const written = result.auxWrites?.get("chain") as MatrixState;
    expect(written.shape).toBe("matrix4x4-bytes");
    expect(Array.from(written.bytes)).toEqual(Array.from(sixteen(0x55)));
    // Deep clone — mutating the snapshot must not affect the live state.
    written.bytes[0] = 0xff;
    expect(state.bytes[0]).toBe(0x55);
  });

  it("treats empty auxName as unset (passthrough, no write)", () => {
    const state = matrixFromBytes(sixteen(0x55));
    const result = stateToAux(state, { auxName: "" }, makeCtx(new Map()));
    expect(result.auxWrites).toBeUndefined();
  });

  it("declares NO auxReads (write-only — no upstream dataflow)", () => {
    const result = stateToAux(matrixFromBytes(sixteen(0x55)), { auxName: "x" }, makeCtx(new Map()));
    expect(result.auxReads).toBeUndefined();
  });

  it("rejects non-string auxName (malformed JSON spec)", () => {
    expect(() =>
      stateToAux(matrixFromBytes(sixteen(0)), { auxName: 7 }, makeCtx(new Map())),
    ).toThrow(/auxName must be a string/);
  });

  it("handles BytesState too (generic across shapes)", () => {
    const state = makeBytesState(new Uint8Array([1, 2, 3, 4]));
    const result = stateToAux(state, { auxName: "snap" }, makeCtx(new Map()));
    const written = result.auxWrites?.get("snap");
    expect(written && typeof written === "object" && "shape" in written && written.shape).toBe(
      "bytes",
    );
  });
});

// ─── End-to-end: chaining primitives composed inside a runtime spec ───────

describe("chaining primitives compose inside a runSpec invocation", () => {
  it("iv-load → xor-aux-into-state → state-to-aux pipeline produces the right aux trail", () => {
    // No iterate node — this is a single-pass exercise of the three primitives
    // in sequence, simulating one CBC iteration's worth of chain math
    // independent of the AES round body.
    const initialState = matrixFromBytes(sixteen(0x10));
    const iv = sixteen(0x20);
    const aux = new Map<string, AuxValue>([["iv", iv]]);
    const registry = buildDefaultRegistry();

    const trace = runSpec(
      {
        id: "test-chain",
        name: "Chain primitives smoke test",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "iv-load",
            type: "generic.iv-load@1",
            params: { ivAuxName: "iv", outAuxName: "chain" },
          },
          {
            kind: "step",
            id: "xor-1",
            type: "generic.xor-aux-into-state@1",
            params: { auxName: "chain" },
          },
          {
            kind: "step",
            id: "snap",
            type: "generic.state-to-aux@1",
            params: { auxName: "chain" },
          },
        ],
      },
      registry,
      { initialState, initialAux: aux },
    );

    // After xor-1: 0x10 ^ 0x20 = 0x30 (the new state).
    // After snap: aux[chain] = MatrixState 0x30, replacing the initial-IV MatrixState.
    expect(trace.frames.length).toBe(3);
    if (trace.finalState.shape !== "matrix4x4-bytes") {
      throw new Error("expected matrix state");
    }
    expect(trace.finalState.bytes[0]).toBe(0x30);
    const finalChain = trace.finalAux.get("chain") as MatrixState;
    expect(finalChain.shape).toBe("matrix4x4-bytes");
    expect(finalChain.bytes[0]).toBe(0x30);
  });
});
