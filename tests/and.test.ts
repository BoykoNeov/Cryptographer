/**
 * Tests for `and@1` — port-native N-way bitwise AND primitive
 * (universal-port plan Phase 2 Slice 2.3, 2026-05-24).
 *
 * Coverage mirrors `tests/xor.test.ts` since `and@1` is structurally
 * identical to `xor@1` (same N≥1 floor, same operand-port naming, same
 * function-form PortContract on the input side). Differences pinned
 * where they matter: AND with all-ones is identity (XOR-with-zero
 * cousin); AND with zero is annihilation (no XOR cousin); AND is
 * idempotent (a∧a = a; XOR is self-inverse, a⊕a = 0).
 *
 * Coverage:
 *   1. Executor unit tests (direct invocation): identity / 2-way /
 *      3-way KATs; AND idempotence; annihilation; operand-order
 *      independence; multi-byte payloads.
 *   2. PortContract function-form exercise: resolve `inputs(params)`
 *      at multiple `inputCount` values (2, 3, 4) — same rationale as
 *      xor's test (a static-only test would silently pass even if the
 *      function ignored params).
 *   3. Param + wiring validation: inputCount out of range; missing
 *      operand port; mismatched operand lengths.
 *   4. Dispatch-path guards: off-flag throws "requires
 *      portedDispatchEnabled: true"; on-flag throws "requires spec
 *      edge-wiring (Slice 2.6+)".
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { and, andOperandPortName, andPortContract } from "@/steps/and";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const callAnd = (operands: readonly (readonly number[])[]): number[] => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(andOperandPortName(i), new Uint8Array(op)));
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = and(inputs, { inputCount: operands.length } as unknown as Json, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("and: no output port");
  return Array.from(out);
};

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

// ─── Direct executor — KATs ──────────────────────────────────────────────

describe("and@1 — executor (direct invocation)", () => {
  describe("identity (inputCount = 1)", () => {
    it("returns operand0 unchanged", () => {
      expect(callAnd([[0x12, 0x34, 0x56, 0x78]])).toEqual([0x12, 0x34, 0x56, 0x78]);
    });

    it("returns a fresh buffer (downstream mutation must not leak back)", () => {
      const inputBytes = new Uint8Array([0xaa, 0xbb]);
      const inputs = new Map([[andOperandPortName(0), inputBytes]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      const outputs = and(inputs, { inputCount: 1 } as unknown as Json, ctx);
      const out = outputs.get("output") as Uint8Array;
      out[0] = 0xff;
      expect(inputBytes[0]).toBe(0xaa);
    });
  });

  describe("2-way AND (the SHA-256 Ch/Maj base case)", () => {
    it("[0xFF] ∧ [0x0F] = [0x0F] (all-ones is identity on second operand)", () => {
      expect(callAnd([[0xff], [0x0f]])).toEqual([0x0f]);
    });

    it("a ∧ a = a (idempotence)", () => {
      expect(
        callAnd([
          [0xde, 0xad, 0xbe, 0xef],
          [0xde, 0xad, 0xbe, 0xef],
        ]),
      ).toEqual([0xde, 0xad, 0xbe, 0xef]);
    });

    it("a ∧ 0 = 0 (zero is annihilator)", () => {
      expect(
        callAnd([
          [0xa5, 0x5a, 0x42, 0x99],
          [0, 0, 0, 0],
        ]),
      ).toEqual([0, 0, 0, 0]);
    });

    it("a ∧ 0xFF…FF = a (all-ones is identity)", () => {
      expect(
        callAnd([
          [0xa5, 0x5a, 0x42, 0x99],
          [0xff, 0xff, 0xff, 0xff],
        ]),
      ).toEqual([0xa5, 0x5a, 0x42, 0x99]);
    });

    it("multi-byte payload ANDs byte-wise", () => {
      expect(
        callAnd([
          [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
          [0x0f, 0x0f, 0x0f, 0x0f, 0xf0, 0xf0, 0xf0, 0xf0],
        ]),
      ).toEqual([0x02, 0x04, 0x06, 0x08, 0x90, 0xb0, 0xd0, 0xf0]);
    });
  });

  describe("3-way AND (Maj inner-shape sanity, even though Maj uses 3 × 2-way ANDs)", () => {
    it("a ∧ b ∧ c is commutative across operands", () => {
      const a = [0xaa, 0xbb, 0xcc, 0xdd];
      const b = [0x11, 0x22, 0x33, 0x44];
      const c = [0x55, 0x66, 0x77, 0x88];
      const r1 = callAnd([a, b, c]);
      const r2 = callAnd([c, b, a]);
      const r3 = callAnd([b, a, c]);
      expect(r1).toEqual(r2);
      expect(r1).toEqual(r3);
    });

    it("three operands AND byte-wise (only bits set in all three survive)", () => {
      // 0xFF ∧ 0x0F ∧ 0xF0 = 0x00 (no bit position has all three set).
      expect(callAnd([[0xff], [0x0f], [0xf0]])).toEqual([0x00]);
    });

    it("three operands picking a single bit", () => {
      // Each operand sets a different bit beyond bit 4; only bit 4 is in all three.
      expect(callAnd([[0xfe], [0xf2], [0xfa]])).toEqual([0xf2]);
    });
  });

  describe("param validation", () => {
    it("throws when inputCount is missing", () => {
      const inputs = new Map([["operand0", new Uint8Array([0x12])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => and(inputs, {} as Json, ctx)).toThrow(/inputCount.*positive integer/);
    });

    it("throws when inputCount < 1", () => {
      const inputs = new Map<string, Uint8Array>();
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => and(inputs, { inputCount: 0 } as unknown as Json, ctx)).toThrow(
        /positive integer/,
      );
    });

    it("throws when inputCount is non-integer", () => {
      const inputs = new Map([["operand0", new Uint8Array([0x12])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => and(inputs, { inputCount: 2.5 } as unknown as Json, ctx)).toThrow(
        /positive integer/,
      );
    });

    it("throws when params is not an object", () => {
      const inputs = new Map([["operand0", new Uint8Array([0x12])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => and(inputs, 42 as unknown as Json, ctx)).toThrow(/params must be an object/);
    });
  });

  describe("wiring validation", () => {
    it("throws on missing operand port (operand1 missing at inputCount=2)", () => {
      const inputs = new Map([["operand0", new Uint8Array([0x12])]]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => and(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /missing required input port "operand1"/,
      );
    });

    it("throws on mismatched operand lengths", () => {
      const inputs = new Map([
        ["operand0", new Uint8Array([0x12, 0x34])],
        ["operand1", new Uint8Array([0x56])],
      ]);
      const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
      expect(() => and(inputs, { inputCount: 2 } as unknown as Json, ctx)).toThrow(
        /operand1 length 1 does not match operand0 length 2/,
      );
    });
  });
});

// ─── PortContract function-form exercise ─────────────────────────────────

describe("and@1 — PortContract.inputs function form", () => {
  if (typeof andPortContract.inputs !== "function") {
    throw new Error("and's PortContract.inputs must be function form");
  }
  const fn = andPortContract.inputs;

  it("resolves to 2 ports at inputCount=2", () => {
    const map = fn({ inputCount: 2 });
    expect([...map.keys()]).toEqual(["operand0", "operand1"]);
  });

  it("resolves to 3 ports at inputCount=3", () => {
    const map = fn({ inputCount: 3 });
    expect([...map.keys()]).toEqual(["operand0", "operand1", "operand2"]);
  });

  it("resolves to 4 ports at inputCount=4 (stress beyond SHA-256 use)", () => {
    const map = fn({ inputCount: 4 });
    expect([...map.keys()]).toEqual(["operand0", "operand1", "operand2", "operand3"]);
  });

  it("every input port carries layout=raw, byteLength absent (polymorphic)", () => {
    const map = fn({ inputCount: 3 });
    for (const [, shape] of map) {
      expect(shape.layout).toBe("raw");
      expect(shape.byteLength).toBeUndefined();
    }
  });

  it("output side is static (one 'output' port; matches rotate-bits-right precedent)", () => {
    if (typeof andPortContract.outputs === "function") {
      throw new Error("and's PortContract.outputs should be static, not function form");
    }
    expect([...andPortContract.outputs.keys()]).toEqual(["output"]);
  });
});

// ─── Dispatch-path guards ────────────────────────────────────────────────

describe("and@1 — runtime dispatch guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "test-and@1",
    name: "test and",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "a",
        type: "and@1",
        params: { inputCount: 2 },
      },
    ],
  });

  it("off-flag dispatch throws 'port-native; requires portedDispatchEnabled: true'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), { initialState: emptyBytes() }),
    ).toThrow('step type "and@1" is port-native; requires portedDispatchEnabled: true');
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
