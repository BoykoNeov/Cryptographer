/**
 * Tests for `xor@1` — port-native N-way bitwise XOR primitive
 * (universal-port plan Phase 2 Slice 2.1b, 2026-05-24).
 *
 * Coverage:
 *   1. Executor unit tests (direct invocation): identity / 2-way /
 *      3-way / 4-way / 5-way KATs; XOR self-inverse property;
 *      operand-order independence; multi-byte payloads.
 *   2. PortContract function-form exercise: resolve `inputs(params)` at
 *      multiple `inputCount` values (2, 3, 5) — the whole point of the
 *      function form per advisor sharpening; a static-only test would
 *      silently pass even if the function ignored params.
 *   3. Param + wiring validation: inputCount out of range; missing
 *      operand port; mismatched operand lengths.
 *   4. Dispatch-path guards: off-flag throws "requires
 *      portedDispatchEnabled: true"; on-flag throws "requires spec
 *      edge-wiring (Slice 2.6+)" because port-native steps are
 *      unreachable via spec dispatch until Slice 2.6 wires real edges.
 *
 * Direct executor calls for the KAT suite — same posture as
 * rotate-bits-right's test file. Building a temporary registry with a
 * legacy stub to push xor through runSpec would defeat the point of
 * port-native registration.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { xor, xorOperandPortName, xorPortContract } from "@/steps/xor";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callXor = (operands: readonly (readonly number[])[]): number[] => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(xorOperandPortName(i), new Uint8Array(op)));
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = xor(inputs, { inputCount: operands.length } as unknown as Json, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("xor: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// ─── Direct executor — KATs ──────────────────────────────────────────────

describe("xor@1 — executor (direct invocation)", () => {
  describe("identity (inputCount = 1)", () => {
    it("returns operand0 unchanged", () => {
      expect(callXor([[0x12, 0x34, 0x56, 0x78]])).toEqual([0x12, 0x34, 0x56, 0x78]);
    });

    it("returns a fresh buffer (downstream mutation must not leak back)", () => {
      const inputBytes = new Uint8Array([0xaa, 0xbb]);
      const inputs = new Map([[xorOperandPortName(0), inputBytes]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      const outputs = xor(inputs, { inputCount: 1 } as unknown as Json, ctx);
      const out = outputs.get("output") as Uint8Array;
      out[0] = 0xff;
      expect(inputBytes[0]).toBe(0xaa);
    });
  });

  describe("2-way XOR (the SHA-256 / CBC base case)", () => {
    it("[0xFF] ⊕ [0x0F] = [0xF0]", () => {
      expect(callXor([[0xff], [0x0f]])).toEqual([0xf0]);
    });

    it("a ⊕ a = 0 (self-inverse)", () => {
      expect(
        callXor([
          [0xde, 0xad, 0xbe, 0xef],
          [0xde, 0xad, 0xbe, 0xef],
        ]),
      ).toEqual([0, 0, 0, 0]);
    });

    it("a ⊕ 0 = a (zero is identity)", () => {
      expect(
        callXor([
          [0xa5, 0x5a, 0x42, 0x99],
          [0, 0, 0, 0],
        ]),
      ).toEqual([0xa5, 0x5a, 0x42, 0x99]);
    });

    it("multi-byte payload XORs byte-wise", () => {
      expect(
        callXor([
          [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
          [0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0],
        ]),
      ).toEqual([0x1d, 0x3b, 0x59, 0x77, 0x6a, 0x4c, 0x2e, 0x00]);
    });
  });

  describe("3-way XOR (SHA-256 σ0 / σ1 / Σ0 / Σ1 shape)", () => {
    it("a ⊕ b ⊕ c is commutative across operands", () => {
      // SHA-256 Σ1(e) = ROTR(e, 6) ⊕ ROTR(e, 11) ⊕ ROTR(e, 25); the
      // primitive doesn't care about operand order, so all permutations
      // yield the same result.
      const a = [0xaa, 0xbb, 0xcc, 0xdd];
      const b = [0x11, 0x22, 0x33, 0x44];
      const c = [0x55, 0x66, 0x77, 0x88];
      const r1 = callXor([a, b, c]);
      const r2 = callXor([c, b, a]);
      const r3 = callXor([b, a, c]);
      expect(r1).toEqual(r2);
      expect(r1).toEqual(r3);
    });

    it("three operands XOR byte-wise", () => {
      // 0xFF ⊕ 0x0F ⊕ 0xF0 = 0x00 (the three bytes cover all bits).
      expect(callXor([[0xff], [0x0f], [0xf0]])).toEqual([0x00]);
    });
  });

  describe("4-way XOR (SHA-256 message-schedule recurrence shape)", () => {
    it("computes the canonical 4-way XOR sample", () => {
      // 0x01 ⊕ 0x02 ⊕ 0x04 ⊕ 0x08 = 0x0F (each operand sets one bit).
      expect(callXor([[0x01], [0x02], [0x04], [0x08]])).toEqual([0x0f]);
    });

    it("four-way self-inverse: a ⊕ b ⊕ a ⊕ b = 0", () => {
      // Pairs of identical operands cancel; algebraic property pins
      // associativity + commutativity at N=4.
      const a = [0x12, 0x34, 0x56, 0x78];
      const b = [0xfe, 0xdc, 0xba, 0x98];
      expect(callXor([a, b, a, b])).toEqual([0, 0, 0, 0]);
    });
  });

  describe("5-way XOR (stress beyond SHA-256's largest XOR arity)", () => {
    it("five operands XOR byte-wise", () => {
      // 0x01 ⊕ 0x02 ⊕ 0x04 ⊕ 0x08 ⊕ 0x10 = 0x1F
      expect(callXor([[0x01], [0x02], [0x04], [0x08], [0x10]])).toEqual([0x1f]);
    });
  });

  describe("param validation", () => {
    it("throws when inputCount is missing", () => {
      const inputs = new Map([["operand0", new Uint8Array([0x12])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => xor(inputs, {} as Json, ctx)).toThrow(/inputCount.*positive integer/);
    });

    it("throws when inputCount < 1", () => {
      const inputs = new Map<string, Uint8Array>();
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => xor(inputs, { inputCount: 0 } as unknown as Json, ctx)).toThrow(
        /positive integer/,
      );
    });

    it("throws when inputCount is non-integer", () => {
      const inputs = new Map([["operand0", new Uint8Array([0x12])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => xor(inputs, { inputCount: 2.5 } as unknown as Json, ctx)).toThrow(
        /positive integer/,
      );
    });

    it("throws when params is not an object", () => {
      const inputs = new Map([["operand0", new Uint8Array([0x12])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => xor(inputs, 42 as unknown as Json, ctx)).toThrow(/params must be an object/);
    });
  });

  describe("wiring validation", () => {
    it("throws on missing operand port (operand1 missing at inputCount=2)", () => {
      const inputs = new Map([["operand0", new Uint8Array([0x12])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => xor(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /missing required input port "operand1"/,
      );
    });

    it("throws on mismatched operand lengths", () => {
      const inputs = new Map([
        ["operand0", new Uint8Array([0x12, 0x34])],
        ["operand1", new Uint8Array([0x56])],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => xor(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /operand1 length 1 does not match operand0 length 2/,
      );
    });
  });
});

// ─── PortContract function-form exercise ─────────────────────────────────

describe("xor@1 — PortContract.inputs function form", () => {
  // Critical: the function form's whole purpose is to size the port
  // map by `params.inputCount`. A static-only test (single inputCount)
  // would silently pass even if the function ignored params. Test
  // multiple Ns to actually exercise the function-form contract.
  if (typeof xorPortContract.inputs !== "function") {
    throw new Error("xor's PortContract.inputs must be function form");
  }
  const fn = xorPortContract.inputs;

  it("resolves to 2 ports at inputCount=2", () => {
    const map = fn({ inputCount: 2 });
    expect([...map.keys()]).toEqual(["operand0", "operand1"]);
  });

  it("resolves to 3 ports at inputCount=3", () => {
    const map = fn({ inputCount: 3 });
    expect([...map.keys()]).toEqual(["operand0", "operand1", "operand2"]);
  });

  it("resolves to 5 ports at inputCount=5 (SHA-256 outer-arity sanity)", () => {
    const map = fn({ inputCount: 5 });
    expect([...map.keys()]).toEqual(["operand0", "operand1", "operand2", "operand3", "operand4"]);
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
    if (typeof xorPortContract.outputs === "function") {
      throw new Error("xor's PortContract.outputs should be static, not function form");
    }
    expect([...xorPortContract.outputs.keys()]).toEqual(["output"]);
  });
});

// ─── Dispatch-path guards ────────────────────────────────────────────────

describe("xor@1 — runtime dispatch guards", () => {
  // Single-leaf spec wiring the port-native step. Until Slice 2.6 lands
  // spec edge-wiring, this spec is unreachable via either dispatch path
  // without explicit error — matches rotate-bits-right's posture.
  const buildSpec = (): CipherSpec => ({
    id: "test-xor@1",
    name: "test xor",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "x",
        type: "xor@1",
        params: { inputCount: 2 },
      },
    ],
  });

  it("on-flag dispatch with no portInputs throws 'input port operand0 is not wired' (Slice 2.6a)", () => {
    // Post-Slice-2.6a: edge-wiring landed; unwired ports surface
    // per-port via the dispatch-path guard. End-to-end wired specs
    // live in `runtime-port-edge-wiring-toy.test.ts`.
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
      }),
    ).toThrow(/input port 'operand0' is not wired/);
  });
});
