/**
 * Tests for `add-mod-16@1` — port-native N-way modular addition over
 * 16-bit BE word arrays (key-schedule-decomposition K2a, 2026-06-01).
 *
 * Coverage parallels `tests/add-mod-32.test.ts` (the K2a sibling):
 *   1. Executor unit tests: zero identity; basic addition; carry-wrap
 *      (0xFFFF + 1 = 0); 3-way carry pile-up; 4-way (Speck-schedule
 *      arity sanity); multi-word independence (carries do NOT cross
 *      16-bit word boundaries — the most important invariant since
 *      Speck32/64 operates on 2-word state buffers).
 *   2. PortContract function-form exercise at inputCount = 2, 3, 4.
 *   3. Param + wiring validation: inputCount < 2; non-mod-2 length;
 *      missing operand port; mismatched operand lengths.
 *   4. Dispatch-path guards: on-flag explicit unwired-port error.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { addMod16, addMod16OperandPortName, addMod16PortContract } from "@/steps/add-mod-16";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callAdd = (operands: readonly (readonly number[])[]): number[] => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(addMod16OperandPortName(i), new Uint8Array(op)));
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = addMod16(inputs, { inputCount: operands.length } as unknown as Json, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("add-mod-16: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// ─── Direct executor — KATs ──────────────────────────────────────────────

describe("add-mod-16@1 — executor (direct invocation)", () => {
  describe("identity (zero is additive identity)", () => {
    it("x + 0 = x", () => {
      expect(callAdd([[0x12, 0x34], [0x00, 0x00]])).toEqual([0x12, 0x34]);
    });

    it("0 + 0 + 0 = 0 (3-way zero)", () => {
      expect(callAdd([[0, 0], [0, 0], [0, 0]])).toEqual([0, 0]);
    });
  });

  describe("2-way basic addition (no carry)", () => {
    it("[0x00 01] + [0x00 02] = [0x00 03]", () => {
      expect(callAdd([[0x00, 0x01], [0x00, 0x02]])).toEqual([0x00, 0x03]);
    });

    it("commutative: a + b = b + a", () => {
      const a = [0x12, 0x34];
      const b = [0xfe, 0xdc];
      expect(callAdd([a, b])).toEqual(callAdd([b, a]));
    });

    it("byte-level carry within word: [0x00 FF] + [0x00 01] = [0x01 00]", () => {
      // Single-word addition; carry from byte 1 into byte 0 lives inside
      // the 16-bit word and re-encodes naturally as BE.
      expect(callAdd([[0x00, 0xff], [0x00, 0x01]])).toEqual([0x01, 0x00]);
    });

    it("high-byte add (no carry): [0x12 00] + [0x34 00] = [0x46 00]", () => {
      expect(callAdd([[0x12, 0x00], [0x34, 0x00]])).toEqual([0x46, 0x00]);
    });
  });

  describe("carry-wrap (the core mod-2¹⁶ semantic)", () => {
    it("[0xFFFF] + [0x0001] = [0x0000]", () => {
      // The defining test for mod-2¹⁶ addition: max + 1 wraps to 0.
      expect(callAdd([[0xff, 0xff], [0x00, 0x01]])).toEqual([0x00, 0x00]);
    });

    it("[0x8000] + [0x8000] = [0x0000] (high bit sum wraps)", () => {
      // 2^15 + 2^15 = 2^16 ≡ 0 (mod 2^16). Sign-extension trap check —
      // would fail if `decodeBE16` produced a negative number via the JS
      // signed-OR semantics. The `>>> 0` in `decodeBE16` prevents that.
      expect(callAdd([[0x80, 0x00], [0x80, 0x00]])).toEqual([0x00, 0x00]);
    });

    it("[0xFFFF] + [0xFFFF] = [0xFFFE] (2-way max)", () => {
      // (2^16 - 1) + (2^16 - 1) = 2^17 - 2 ≡ 2^16 - 2 = 0xFFFE.
      expect(callAdd([[0xff, 0xff], [0xff, 0xff]])).toEqual([0xff, 0xfe]);
    });
  });

  describe("3-way carry pile-up", () => {
    it("[0xFFFF] + [0xFFFF] + [0x0002] = [0x0000] (double wrap)", () => {
      // 2 × (2^16 - 1) + 2 = 2^17 ≡ 0 (mod 2^16). Validates that the
      // accumulator can pile up carries past one wrap without losing
      // bits.
      expect(
        callAdd([
          [0xff, 0xff],
          [0xff, 0xff],
          [0x00, 0x02],
        ]),
      ).toEqual([0x00, 0x00]);
    });
  });

  describe("4-way (Speck schedule m=4 master-key arity sanity)", () => {
    it("sums four distinct single-word operands", () => {
      // 1 + 2 + 3 + 4 = 10 in the low byte.
      expect(
        callAdd([
          [0x00, 0x01],
          [0x00, 0x02],
          [0x00, 0x03],
          [0x00, 0x04],
        ]),
      ).toEqual([0x00, 0x0a]);
    });
  });

  describe("multi-word independence (carries do NOT cross word boundaries)", () => {
    it("two 16-bit words: [0xFFFF | 0x0000] + [0x0001 | 0x0005] = [0x0000 | 0x0005]", () => {
      // Word 0 wraps to zero — its carry MUST NOT bleed into word 1.
      // This is the single most important sanity check on the per-word
      // loop boundary, doubly so because Speck32/64's block IS two 16-bit
      // words.
      expect(callAdd([[0xff, 0xff, 0x00, 0x00], [0x00, 0x01, 0x00, 0x05]])).toEqual([
        0x00, 0x00, 0x00, 0x05,
      ]);
    });

    it("four 16-bit words: per-word add holds independently", () => {
      const a = [0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04];
      const b = [0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d];
      const sum = [0x00, 0x0b, 0x00, 0x0d, 0x00, 0x0f, 0x00, 0x11];
      expect(callAdd([a, b])).toEqual(sum);
    });
  });

  describe("Beaulieu Table 4.1 sanity (Speck-schedule arithmetic)", () => {
    it("k_0 + ROR(l_0, 7) for the published test vector first iteration", () => {
      // Sanity-check the executor against ONE real schedule step.
      // Beaulieu Table 4.1: master key 1918111009080100 (BE-paper order),
      // so logical k_0 = 0x0100, l_0 = 0x0908. ROR(0x0908, 7) over 16
      // bits = (0x0908 >> 7) | (0x0908 << 9) & 0xFFFF = 0x12 | 0x1000 =
      // 0x1012. Sum = 0x0100 + 0x1012 = 0x1112. BE-encoded: [0x11, 0x12].
      expect(callAdd([[0x01, 0x00], [0x10, 0x12]])).toEqual([0x11, 0x12]);
    });
  });

  describe("output buffer is fresh (no aliasing to operand0)", () => {
    it("mutating output does not leak back into operand0", () => {
      const operand0 = new Uint8Array([0x12, 0x34]);
      const operand1 = new Uint8Array([0x00, 0x01]);
      const inputs = new Map([
        ["operand0", operand0],
        ["operand1", operand1],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      const outputs = addMod16(inputs, { inputCount: 2 } as unknown as Json, ctx);
      const out = outputs.get("output") as Uint8Array;
      out[0] = 0xff;
      expect(operand0[0]).toBe(0x12);
    });
  });

  describe("param validation", () => {
    it("throws when inputCount is missing", () => {
      const inputs = new Map([["operand0", new Uint8Array([0, 1])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod16(inputs, {} as Json, ctx)).toThrow(/inputCount.*≥ 2/);
    });

    it("throws when inputCount < 2 (no 1-operand identity case)", () => {
      const inputs = new Map([["operand0", new Uint8Array([0, 1])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod16(inputs, { inputCount: 1 } as unknown as Json, ctx)).toThrow(/≥ 2/);
    });

    it("throws when inputCount is non-integer", () => {
      const inputs = new Map([
        ["operand0", new Uint8Array([0, 1])],
        ["operand1", new Uint8Array([0, 2])],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod16(inputs, { inputCount: 2.5 } as unknown as Json, ctx)).toThrow(/≥ 2/);
    });

    it("throws when params is not an object", () => {
      const inputs = new Map<string, Uint8Array>();
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod16(inputs, null as unknown as Json, ctx)).toThrow(
        /params must be an object/,
      );
    });
  });

  describe("wiring + shape validation", () => {
    it("throws on missing operand port", () => {
      const inputs = new Map([["operand0", new Uint8Array([0, 1])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod16(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /missing required input port "operand1"/,
      );
    });

    it("throws when operand length is not a multiple of 2", () => {
      const inputs = new Map([
        ["operand0", new Uint8Array([0x12])],
        ["operand1", new Uint8Array([0x00])],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod16(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /byteLength 1 is not a multiple of 2/,
      );
    });

    it("throws on mismatched operand lengths", () => {
      const inputs = new Map([
        ["operand0", new Uint8Array([0x00, 0x01])],
        ["operand1", new Uint8Array([0x00, 0x02, 0x00, 0x03])],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => addMod16(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /operand1 length 4 does not match operand0 length 2/,
      );
    });
  });
});

// ─── PortContract function-form exercise ─────────────────────────────────

describe("add-mod-16@1 — PortContract.inputs function form", () => {
  if (typeof addMod16PortContract.inputs !== "function") {
    throw new Error("add-mod-16's PortContract.inputs must be function form");
  }
  const fn = addMod16PortContract.inputs;

  it("resolves to 2 ports at inputCount=2", () => {
    expect([...fn({ inputCount: 2 }).keys()]).toEqual(["operand0", "operand1"]);
  });

  it("resolves to 3 ports at inputCount=3", () => {
    expect([...fn({ inputCount: 3 }).keys()]).toEqual(["operand0", "operand1", "operand2"]);
  });

  it("resolves to 4 ports at inputCount=4 (Speck schedule m=4 sanity)", () => {
    expect([...fn({ inputCount: 4 }).keys()]).toEqual([
      "operand0",
      "operand1",
      "operand2",
      "operand3",
    ]);
  });

  it("every input port carries layout=raw, byteLength absent (polymorphic)", () => {
    const map = fn({ inputCount: 3 });
    for (const [, shape] of map) {
      expect(shape.layout).toBe("raw");
      expect(shape.byteLength).toBeUndefined();
    }
  });

  it("output side is static (one 'output' port; matches add-mod-32 precedent)", () => {
    if (typeof addMod16PortContract.outputs === "function") {
      throw new Error("add-mod-16's PortContract.outputs should be static, not function form");
    }
    expect([...addMod16PortContract.outputs.keys()]).toEqual(["output"]);
  });
});

// ─── Dispatch-path guards ────────────────────────────────────────────────

describe("add-mod-16@1 — runtime dispatch guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "test-add-mod-16@1",
    name: "test add-mod-16",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "a",
        type: "add-mod-16@1",
        params: { inputCount: 2 },
      },
    ],
  });

  it("port-native leaf without portInputs throws 'input port operand0 is not wired'", () => {
    // Mirrors add-mod-32's dispatch-path guard. A port-native leaf
    // without `portInputs` declarations triggers a per-port unwired-port
    // throw at the first input port.
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
      }),
    ).toThrow(/input port 'operand0' is not wired/);
  });
});
