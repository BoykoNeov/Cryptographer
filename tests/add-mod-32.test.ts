/**
 * Tests for `add-mod-32@1` — port-native N-way modular addition over
 * 32-bit BE word arrays (universal-port plan Phase 2 Slice 2.1b,
 * 2026-05-24).
 *
 * Coverage:
 *   1. Executor unit tests (direct invocation): zero identity; basic
 *      addition; carry-wrap (0xFFFFFFFF + 1 = 0); 3-way carry pile-up;
 *      5-way (SHA-256 T1 outer arity); multi-word independence
 *      (carries do NOT cross word boundaries).
 *   2. PortContract function-form exercise at inputCount = 2, 3, 5.
 *   3. Param + wiring validation: inputCount < 2; non-mod-4 length;
 *      missing operand port; mismatched operand lengths.
 *   4. Dispatch-path guards: off-flag + on-flag explicit errors.
 *
 * Direct executor calls for the KAT suite — same posture as
 * rotate-bits-right's + xor's test files.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { addMod32, addMod32OperandPortName, addMod32PortContract } from "@/steps/add-mod-32";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callAdd = (operands: readonly (readonly number[])[]): number[] => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(addMod32OperandPortName(i), new Uint8Array(op)));
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = addMod32(inputs, { inputCount: operands.length } as unknown as Json, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("add-mod-32: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// ─── Direct executor — KATs ──────────────────────────────────────────────

describe("add-mod-32@1 — executor (direct invocation)", () => {
  describe("identity (zero is additive identity)", () => {
    it("x + 0 = x", () => {
      expect(
        callAdd([
          [0x12, 0x34, 0x56, 0x78],
          [0x00, 0x00, 0x00, 0x00],
        ]),
      ).toEqual([0x12, 0x34, 0x56, 0x78]);
    });

    it("0 + 0 + 0 = 0 (3-way zero)", () => {
      expect(
        callAdd([
          [0, 0, 0, 0],
          [0, 0, 0, 0],
          [0, 0, 0, 0],
        ]),
      ).toEqual([0, 0, 0, 0]);
    });
  });

  describe("2-way basic addition (no carry)", () => {
    it("[0x00 00 00 01] + [0x00 00 00 02] = [0x00 00 00 03]", () => {
      expect(
        callAdd([
          [0x00, 0x00, 0x00, 0x01],
          [0x00, 0x00, 0x00, 0x02],
        ]),
      ).toEqual([0x00, 0x00, 0x00, 0x03]);
    });

    it("commutative: a + b = b + a", () => {
      const a = [0x12, 0x34, 0x56, 0x78];
      const b = [0xfe, 0xdc, 0xba, 0x98];
      expect(callAdd([a, b])).toEqual(callAdd([b, a]));
    });

    it("BE word: [0x00 00 01 00] + [0x00 00 00 FF] = [0x00 00 01 FF] (no carry across bytes inside word)", () => {
      expect(
        callAdd([
          [0x00, 0x00, 0x01, 0x00],
          [0x00, 0x00, 0x00, 0xff],
        ]),
      ).toEqual([0x00, 0x00, 0x01, 0xff]);
    });

    it("byte-level carry: [0x00 00 00 FF] + [0x00 00 00 01] = [0x00 00 01 00]", () => {
      // Single-word addition; carry from byte 3 into byte 2 lives inside
      // the 32-bit word and re-encodes naturally.
      expect(
        callAdd([
          [0x00, 0x00, 0x00, 0xff],
          [0x00, 0x00, 0x00, 0x01],
        ]),
      ).toEqual([0x00, 0x00, 0x01, 0x00]);
    });
  });

  describe("carry-wrap (the core mod-2³² semantic)", () => {
    it("[0xFFFFFFFF] + [0x00000001] = [0x00000000]", () => {
      // The defining test for mod-2³² addition: max + 1 wraps to 0.
      expect(
        callAdd([
          [0xff, 0xff, 0xff, 0xff],
          [0x00, 0x00, 0x00, 0x01],
        ]),
      ).toEqual([0x00, 0x00, 0x00, 0x00]);
    });

    it("[0x80000000] + [0x80000000] = [0x00000000] (high bit sum wraps)", () => {
      // 2^31 + 2^31 = 2^32 ≡ 0 (mod 2^32). Catches sign-extension bugs
      // where the JS `+` accidentally treats the operand as signed.
      expect(
        callAdd([
          [0x80, 0x00, 0x00, 0x00],
          [0x80, 0x00, 0x00, 0x00],
        ]),
      ).toEqual([0x00, 0x00, 0x00, 0x00]);
    });

    it("[0xFFFFFFFF] + [0xFFFFFFFF] = [0xFFFFFFFE] (2-way max)", () => {
      // (2^32 - 1) + (2^32 - 1) = 2^33 - 2 ≡ 2^32 - 2 = 0xFFFFFFFE.
      expect(
        callAdd([
          [0xff, 0xff, 0xff, 0xff],
          [0xff, 0xff, 0xff, 0xff],
        ]),
      ).toEqual([0xff, 0xff, 0xff, 0xfe]);
    });
  });

  describe("3-way carry pile-up", () => {
    it("[0xFFFFFFFF] + [0xFFFFFFFF] + [0x00000002] = [0x00000000] (double wrap)", () => {
      // 2 × (2^32 - 1) + 2 = 2^33 ≡ 0 (mod 2^32). Validates that the
      // accumulator can pile up carries past one wrap without losing
      // bits — the IEEE-double accumulator is safe up to ~2^21 operands.
      expect(
        callAdd([
          [0xff, 0xff, 0xff, 0xff],
          [0xff, 0xff, 0xff, 0xff],
          [0x00, 0x00, 0x00, 0x02],
        ]),
      ).toEqual([0x00, 0x00, 0x00, 0x00]);
    });
  });

  describe("5-way (SHA-256 T1 = h + Σ1(e) + Ch + K[i] + W[i] outer arity)", () => {
    it("sums five distinct single-word operands", () => {
      // 1 + 2 + 3 + 4 + 5 = 15 in the low byte.
      expect(
        callAdd([
          [0x00, 0x00, 0x00, 0x01],
          [0x00, 0x00, 0x00, 0x02],
          [0x00, 0x00, 0x00, 0x03],
          [0x00, 0x00, 0x00, 0x04],
          [0x00, 0x00, 0x00, 0x05],
        ]),
      ).toEqual([0x00, 0x00, 0x00, 0x0f]);
    });
  });

  describe("multi-word independence (carries do NOT cross word boundaries)", () => {
    it("two 32-bit words: [0xFFFFFFFF | 0x00000000] + [0x00000001 | 0x00000005] = [0x00000000 | 0x00000005]", () => {
      // Word 0 wraps to zero — its carry MUST NOT bleed into word 1.
      // Word 1 simply sums to 5. This is the single most important
      // sanity check on the per-word loop boundary.
      expect(
        callAdd([
          [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
          [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05],
        ]),
      ).toEqual([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]);
    });

    it("eight 32-bit words (SHA-256 state width): per-word add", () => {
      // SHA-256 hash state is 8 × 32 bits = 32 bytes. Validate the
      // executor produces the right result at that width.
      const a = [
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
        0x00, 0x08,
      ];
      const b = [
        0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x11,
      ];
      const sum = [
        0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x11, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
        0x00, 0x19,
      ];
      expect(callAdd([a, b])).toEqual(sum);
    });
  });

  describe("output buffer is fresh (no aliasing to operand0)", () => {
    it("mutating output does not leak back into operand0", () => {
      const operand0 = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
      const operand1 = new Uint8Array([0x00, 0x00, 0x00, 0x01]);
      const inputs = new Map([
        ["operand0", operand0],
        ["operand1", operand1],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      const outputs = addMod32(inputs, { inputCount: 2 } as unknown as Json, ctx);
      const out = outputs.get("output") as Uint8Array;
      out[0] = 0xff;
      expect(operand0[0]).toBe(0x12);
    });
  });

  describe("param validation", () => {
    it("throws when inputCount is missing", () => {
      const inputs = new Map([["operand0", new Uint8Array([0, 0, 0, 1])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod32(inputs, {} as Json, ctx)).toThrow(/inputCount.*≥ 2/);
    });

    it("throws when inputCount < 2 (no 1-operand identity case)", () => {
      const inputs = new Map([["operand0", new Uint8Array([0, 0, 0, 1])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod32(inputs, { inputCount: 1 } as unknown as Json, ctx)).toThrow(/≥ 2/);
    });

    it("throws when inputCount is non-integer", () => {
      const inputs = new Map([
        ["operand0", new Uint8Array([0, 0, 0, 1])],
        ["operand1", new Uint8Array([0, 0, 0, 2])],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod32(inputs, { inputCount: 2.5 } as unknown as Json, ctx)).toThrow(/≥ 2/);
    });

    it("throws when params is not an object", () => {
      const inputs = new Map<string, Uint8Array>();
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod32(inputs, null as unknown as Json, ctx)).toThrow(
        /params must be an object/,
      );
    });
  });

  describe("wiring + shape validation", () => {
    it("throws on missing operand port", () => {
      const inputs = new Map([["operand0", new Uint8Array([0, 0, 0, 1])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod32(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /missing required input port "operand1"/,
      );
    });

    it("throws when operand length is not a multiple of 4", () => {
      const inputs = new Map([
        ["operand0", new Uint8Array([0x12, 0x34, 0x56])],
        ["operand1", new Uint8Array([0x00, 0x00, 0x00])],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod32(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /byteLength 3 is not a multiple of 4/,
      );
    });

    it("throws on mismatched operand lengths", () => {
      const inputs = new Map([
        ["operand0", new Uint8Array([0x00, 0x00, 0x00, 0x01])],
        ["operand1", new Uint8Array([0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03])],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod32(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /operand1 length 8 does not match operand0 length 4/,
      );
    });
  });
});

// ─── PortContract function-form exercise ─────────────────────────────────

describe("add-mod-32@1 — PortContract.inputs function form", () => {
  if (typeof addMod32PortContract.inputs !== "function") {
    throw new Error("add-mod-32's PortContract.inputs must be function form");
  }
  const fn = addMod32PortContract.inputs;

  it("resolves to 2 ports at inputCount=2", () => {
    expect([...fn({ inputCount: 2 }).keys()]).toEqual(["operand0", "operand1"]);
  });

  it("resolves to 3 ports at inputCount=3", () => {
    expect([...fn({ inputCount: 3 }).keys()]).toEqual(["operand0", "operand1", "operand2"]);
  });

  it("resolves to 5 ports at inputCount=5 (SHA-256 T1 arity sanity)", () => {
    expect([...fn({ inputCount: 5 }).keys()]).toEqual([
      "operand0",
      "operand1",
      "operand2",
      "operand3",
      "operand4",
    ]);
  });

  it("every input port carries layout=raw, byteLength absent (polymorphic)", () => {
    const map = fn({ inputCount: 3 });
    for (const [, shape] of map) {
      expect(shape.layout).toBe("raw");
      expect(shape.byteLength).toBeUndefined();
    }
  });

  it("output side is static (one 'output' port; matches rotate-bits-right precedent)", () => {
    // Per Slice 2.1b advisor pick (2026-05-24): function form only when N
    // varies on THAT side. Output side is fixed at one port, so static.
    if (typeof addMod32PortContract.outputs === "function") {
      throw new Error("add-mod-32's PortContract.outputs should be static, not function form");
    }
    expect([...addMod32PortContract.outputs.keys()]).toEqual(["output"]);
  });
});

// ─── Dispatch-path guards ────────────────────────────────────────────────

describe("add-mod-32@1 — runtime dispatch guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "test-add-mod-32@1",
    name: "test add-mod-32",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "a",
        type: "add-mod-32@1",
        params: { inputCount: 2 },
      },
    ],
  });

  it("off-flag dispatch throws 'port-native; requires portedDispatchEnabled: true'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), { initialState: emptyBytes() }),
    ).toThrow('step type "add-mod-32@1" is port-native; requires portedDispatchEnabled: true');
  });

  it("on-flag dispatch throws 'requires spec edge-wiring (Slice 2.6+)'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
        portedDispatchEnabled: true,
      }),
    ).toThrow(/port-native and requires spec edge-wiring/);
  });
});
