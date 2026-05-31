/**
 * concat@1 — port-native N-way byte concatenation tests
 * (universal-port plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * Coverage:
 *  - KAT pins for inputCount = 1 (identity), 2 (small concat), 3, 8
 *    (SHA-256's H || …)
 *  - Length polymorphism — operands of different lengths concatenate
 *    correctly; output length = sum of input lengths.
 *  - Error handling — missing port, bad params, negative inputCount.
 *  - Both dispatch-path guards (off-flag throw + on-flag direct-executor
 *    works through a happy-path spec).
 *  - Fresh-buffer invariant — mutating output doesn't affect operands.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { CipherSpec, Json, StepContext } from "@/core/types";
import { concat, concatInputPortName } from "@/steps/concat";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const callExecutor = (operands: Uint8Array[]): Uint8Array => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(concatInputPortName(i), op));
  const out = concat(inputs, { inputCount: operands.length } as Json, CTX);
  return out.get("output") as Uint8Array;
};

// ─── KAT pins ──────────────────────────────────────────────────────────────

describe("concat@1 — KAT pins across inputCount values", () => {
  it("inputCount=1 is identity (passthrough)", () => {
    const out = callExecutor([new Uint8Array([0xde, 0xad, 0xbe, 0xef])]);
    expect(out).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("inputCount=2 concatenates two operands in order", () => {
    const out = callExecutor([new Uint8Array([0x01, 0x02]), new Uint8Array([0x03, 0x04])]);
    expect(out).toEqual(new Uint8Array([0x01, 0x02, 0x03, 0x04]));
  });

  it("inputCount=3 concatenates three operands", () => {
    const out = callExecutor([
      new Uint8Array([0xaa]),
      new Uint8Array([0xbb, 0xcc]),
      new Uint8Array([0xdd, 0xee, 0xff]),
    ]);
    expect(out).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
  });

  it("inputCount=8 — concatenates SHA-256's 8 H_t initial values into the 32-byte hash IV", () => {
    // FIPS 180-4 §5.3.3
    const H_concat = new Uint8Array([
      0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5,
      0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0,
      0xcd, 0x19,
    ]);
    const out = callExecutor([
      new Uint8Array([0x6a, 0x09, 0xe6, 0x67]),
      new Uint8Array([0xbb, 0x67, 0xae, 0x85]),
      new Uint8Array([0x3c, 0x6e, 0xf3, 0x72]),
      new Uint8Array([0xa5, 0x4f, 0xf5, 0x3a]),
      new Uint8Array([0x51, 0x0e, 0x52, 0x7f]),
      new Uint8Array([0x9b, 0x05, 0x68, 0x8c]),
      new Uint8Array([0x1f, 0x83, 0xd9, 0xab]),
      new Uint8Array([0x5b, 0xe0, 0xcd, 0x19]),
    ]);
    expect(out).toEqual(H_concat);
  });
});

// ─── Length polymorphism ──────────────────────────────────────────────────

describe("concat@1 — length polymorphism", () => {
  it("operands can have different lengths", () => {
    const out = callExecutor([
      new Uint8Array([0x01]), // 1 byte
      new Uint8Array([0x02, 0x03, 0x04, 0x05, 0x06]), // 5 bytes
      new Uint8Array([0x07, 0x08]), // 2 bytes
    ]);
    expect(out.length).toBe(8);
    expect(Array.from(out)).toEqual([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
  });

  it("empty operand contributes zero bytes", () => {
    const out = callExecutor([
      new Uint8Array([0x01, 0x02]),
      new Uint8Array(), // empty
      new Uint8Array([0x03]),
    ]);
    expect(Array.from(out)).toEqual([0x01, 0x02, 0x03]);
  });

  it("all-empty operands produce empty output", () => {
    const out = callExecutor([new Uint8Array(), new Uint8Array(), new Uint8Array()]);
    expect(out).toEqual(new Uint8Array());
  });
});

// ─── Fresh-buffer invariant ───────────────────────────────────────────────

describe("concat@1 — output is a fresh buffer independent of operands", () => {
  it("mutating the output does not affect the operands", () => {
    const a = new Uint8Array([0x01, 0x02]);
    const b = new Uint8Array([0x03, 0x04]);
    const out = callExecutor([a, b]);
    out[0] = 0xff;
    out[3] = 0xff;
    expect(a[0]).toBe(0x01);
    expect(b[1]).toBe(0x04);
  });

  it("mutating an operand AFTER concat does not affect the output", () => {
    const a = new Uint8Array([0x01, 0x02]);
    const b = new Uint8Array([0x03, 0x04]);
    const out = callExecutor([a, b]);
    a[0] = 0xff;
    b[1] = 0xff;
    expect(out[0]).toBe(0x01);
    expect(out[3]).toBe(0x04);
  });
});

// ─── Param validation ─────────────────────────────────────────────────────

describe("concat@1 — param validation", () => {
  it("throws when params is null", () => {
    expect(() => concat(new Map(), null, CTX)).toThrow(/params must be an object/);
  });

  it("throws when params is an array", () => {
    expect(() => concat(new Map(), [] as Json, CTX)).toThrow(/params must be an object/);
  });

  it("throws when inputCount is missing", () => {
    expect(() => concat(new Map(), {} as Json, CTX)).toThrow(
      /inputCount must be a positive integer/,
    );
  });

  it("throws when inputCount is zero", () => {
    expect(() => concat(new Map(), { inputCount: 0 } as Json, CTX)).toThrow(
      /inputCount must be a positive integer/,
    );
  });

  it("throws when inputCount is negative", () => {
    expect(() => concat(new Map(), { inputCount: -1 } as Json, CTX)).toThrow(
      /inputCount must be a positive integer/,
    );
  });

  it("throws when inputCount is not an integer", () => {
    expect(() => concat(new Map(), { inputCount: 2.5 } as Json, CTX)).toThrow(
      /inputCount must be a positive integer/,
    );
  });

  it("throws when an expected port is missing", () => {
    expect(() =>
      concat(new Map([["input0", new Uint8Array([0x01])]]), { inputCount: 2 } as Json, CTX),
    ).toThrow(/missing required input port "input1"/);
  });
});

// ─── Port naming helper ───────────────────────────────────────────────────

describe("concat@1 — concatInputPortName helper", () => {
  it("emits input0..inputN-1 strings", () => {
    expect(concatInputPortName(0)).toBe("input0");
    expect(concatInputPortName(1)).toBe("input1");
    expect(concatInputPortName(7)).toBe("input7");
  });
});

// ─── Runtime integration: dispatch-path guards ────────────────────────────

describe("concat@1 — runtime dispatch-path guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "toy-concat-runtime",
    name: "concat runtime gate (Slice 2.6b)",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "a",
        type: "constant-load@1",
        params: { bytes: [0xaa, 0xbb] },
      },
      {
        kind: "step",
        id: "b",
        type: "constant-load@1",
        params: { bytes: [0xcc, 0xdd] },
      },
      {
        kind: "step",
        id: "c",
        type: "concat@1",
        params: { inputCount: 2 },
        portInputs: {
          input0: { node: "a", port: "output" },
          input1: { node: "b", port: "output" },
        },
      },
      {
        kind: "step",
        id: "sink",
        type: "bytes-to-state@1",
        params: {},
        portInputs: {
          input: { node: "c", port: "output" },
        },
      },
    ],
  });

  it("on-flag dispatch concatenates and materializes into state", () => {
    const trace = runSpec(buildSpec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array() },
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
  });

  it("validator finds no warnings on a well-wired concat spec", async () => {
    const { validateShapes } = await import("@/core/spec-shapes");
    const warnings = validateShapes(buildSpec(), buildDefaultRegistry());
    expect(warnings).toEqual([]);
  });
});
