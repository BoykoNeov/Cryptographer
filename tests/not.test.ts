/**
 * Tests for `not@1` — port-native bitwise NOT primitive (universal-
 * port plan Phase 2 Slice 2.3, 2026-05-24).
 *
 * Simpler test surface than `and`/`xor`/`add-mod-32`: no params, no
 * arity variation. Coverage focuses on the algebraic identities that
 * justify a dedicated step type over `xor` against all-ones:
 *   - involution: NOT(NOT(x)) = x for any x
 *   - byte-wise bit flip: each byte's bits invert independently
 *   - length-polymorphic: any input length, output length = input
 *   - PortContract is fully static (both sides one fixed port)
 *   - dispatch-path guards parallel rotate-bits-right / xor / and
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { not, notPortContract } from "@/steps/not";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callNot = (inputBytes: readonly number[]): number[] => {
  const inputs = new Map([["input", new Uint8Array(inputBytes)]]);
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = not(inputs, {} as Json, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("not: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// ─── Direct executor — KATs + algebraic properties ───────────────────────

describe("not@1 — executor (direct invocation)", () => {
  describe("byte-wise bit flip KATs", () => {
    it("¬0x00 = 0xFF", () => {
      expect(callNot([0x00])).toEqual([0xff]);
    });

    it("¬0xFF = 0x00", () => {
      expect(callNot([0xff])).toEqual([0x00]);
    });

    it("¬0xAA = 0x55 (alternating bits)", () => {
      // 0xAA = 10101010 ; ¬0xAA = 01010101 = 0x55
      expect(callNot([0xaa])).toEqual([0x55]);
    });

    it("¬0x55 = 0xAA (alternating bits, opposite phase)", () => {
      expect(callNot([0x55])).toEqual([0xaa]);
    });

    it("flips bits byte-by-byte across a multi-byte payload", () => {
      // Each output byte = 0xFF - input byte.
      expect(callNot([0x12, 0x34, 0x56, 0x78])).toEqual([0xed, 0xcb, 0xa9, 0x87]);
    });

    it("¬H_0 (SHA-256 IV) of length 4", () => {
      // 0x6A09E667 → ¬ = 0x95F61998. Used in SHA-256 Ch's ¬x branch
      // when x = H_0 = a_init at round 0.
      expect(callNot([0x6a, 0x09, 0xe6, 0x67])).toEqual([0x95, 0xf6, 0x19, 0x98]);
    });
  });

  describe("algebraic properties", () => {
    it("involution: ¬¬x = x for any x", () => {
      // The defining property — justifies the dedicated step type
      // over `xor` against all-ones (both implementations satisfy
      // this, but a named NOT makes the property surface in narration).
      const samples = [
        [0x00, 0x01, 0x10, 0xff],
        [0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85],
        [0x55, 0xaa, 0xa5, 0x5a],
      ];
      for (const x of samples) {
        expect(callNot(callNot(x))).toEqual(x);
      }
    });

    it("¬x ⊕ x = 0xFF…FF (NOT and XOR-against-all-ones are bit-identical)", () => {
      // Algebraically why a dedicated NOT step type isn't strictly
      // necessary, only desirable. Pin the bit-identity here.
      const x = [0x12, 0x34, 0x56, 0x78];
      const notX = callNot(x);
      const xored = x.map((b, i) => b ^ (notX[i] as number));
      expect(xored).toEqual([0xff, 0xff, 0xff, 0xff]);
    });
  });

  describe("length polymorphism", () => {
    it("empty input → empty output", () => {
      expect(callNot([])).toEqual([]);
    });

    it("single-byte input → single-byte output", () => {
      expect(callNot([0x42]).length).toBe(1);
    });

    it("8-byte input → 8-byte output (SHA-256 word pair)", () => {
      expect(callNot([0, 0, 0, 0, 0, 0, 0, 0]).length).toBe(8);
    });

    it("16-byte input → 16-byte output (block cipher block)", () => {
      const input = Array.from({ length: 16 }, (_, i) => i);
      expect(callNot(input).length).toBe(16);
    });
  });

  describe("fresh-buffer invariant", () => {
    it("returns a fresh buffer (downstream mutation must not leak back)", () => {
      const inputBytes = new Uint8Array([0xaa, 0xbb]);
      const inputs = new Map([["input", inputBytes]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      const outputs = not(inputs, {} as Json, ctx);
      const out = outputs.get("output") as Uint8Array;
      out[0] = 0xff;
      expect(inputBytes[0]).toBe(0xaa);
    });
  });

  describe("wiring validation", () => {
    it("throws on missing input port", () => {
      const inputs = new Map<string, Uint8Array>();
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => not(inputs, {} as Json, ctx)).toThrow(/missing required input port 'input'/);
    });
  });
});

// ─── PortContract static-form exercise ──────────────────────────────────

describe("not@1 — PortContract (static both sides)", () => {
  it("input side is one 'input' port, polymorphic byteLength", () => {
    if (typeof notPortContract.inputs === "function") {
      throw new Error("not's PortContract.inputs should be static, not function form");
    }
    expect([...notPortContract.inputs.keys()]).toEqual(["input"]);
    const inputShape = notPortContract.inputs.get("input");
    expect(inputShape?.layout).toBe("raw");
    expect(inputShape?.byteLength).toBeUndefined();
  });

  it("output side is one 'output' port, polymorphic byteLength", () => {
    if (typeof notPortContract.outputs === "function") {
      throw new Error("not's PortContract.outputs should be static, not function form");
    }
    expect([...notPortContract.outputs.keys()]).toEqual(["output"]);
    const outputShape = notPortContract.outputs.get("output");
    expect(outputShape?.layout).toBe("raw");
    expect(outputShape?.byteLength).toBeUndefined();
  });
});

// ─── Dispatch-path guards ────────────────────────────────────────────────

describe("not@1 — runtime dispatch guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "test-not@1",
    name: "test not",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "n",
        type: "not@1",
        params: {},
      },
    ],
  });

  it("on-flag dispatch with no portInputs throws 'input port input is not wired' (Slice 2.6a)", () => {
    // Post-Slice-2.6a: edge-wiring landed; unwired ports surface
    // per-port via the dispatch-path guard. End-to-end wired specs
    // live in `runtime-port-edge-wiring-toy.test.ts`.
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
      }),
    ).toThrow(/input port 'input' is not wired/);
  });
});
