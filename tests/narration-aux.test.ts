/**
 * Per-step narration tests for the Phase-3 aux narrators.
 *
 * Three narrators: aux-load, aux-xor, aux-copy. All graceful on missing
 * aux (return null), so the test fabricates a fully-wired frame for the
 * happy path and a half-wired frame for the null path on a sample.
 *
 * The matrix chaining narrators (iv-load, xor-aux-into-state, state-to-aux)
 * were retired in Phase 5 Slice 5.1 (2026-05-30) with their step types +
 * the MatrixState shape.
 */

// @vitest-environment jsdom

import type { AuxValue, BytesState, TraceFrame } from "@/core/types";
import { auxCopyNarration, auxLoadNarration, auxXorNarration } from "@/ui/narration/aux-primitives";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";

afterEach(cleanup);

const bytesState = (bytes: Uint8Array): BytesState => ({ shape: "bytes", bytes });

const makeFrame = (overrides: Partial<TraceFrame>): TraceFrame => ({
  index: 0,
  path: [],
  stepId: "test.step",
  stepType: "test",
  params: {},
  stateBefore: bytesState(new Uint8Array(0)),
  stateAfter: bytesState(new Uint8Array(0)),
  auxRead: new Map<string, AuxValue>(),
  auxWritten: new Map(),
  ...overrides,
});

const proseText = (Prose: (props: { fmt: "hex" }) => unknown): string => {
  const result = render(() => Prose({ fmt: "hex" }) as never);
  const text = result.container.textContent ?? "";
  result.unmount();
  return text;
};

// ─── aux-load ────────────────────────────────────────────────────────

describe("auxLoadNarration", () => {
  it("emits 1 unit naming the published key and byte length", () => {
    const value = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const auxWritten = new Map<string, AuxValue>([["iv", value]]);
    const units = auxLoadNarration(
      makeFrame({
        stepType: "generic.aux-load@1",
        params: { auxName: "iv", value: [0xde, 0xad, 0xbe, 0xef] },
        auxWritten,
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("aux[iv]");
    expect(units[0]?.label).toContain("4-byte literal");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("aux[iv]");
    expect(text).toContain("de"); // formatByte hex without 0x
  });

  it("returns null when no aux was written (unwired)", () => {
    expect(
      auxLoadNarration(
        makeFrame({
          stepType: "generic.aux-load@1",
          params: { auxName: "", value: [] },
        }),
      ),
    ).toBeNull();
  });
});

// ─── aux-xor ─────────────────────────────────────────────────────────

describe("auxXorNarration", () => {
  it("emits 1 unit showing both operands and the XOR result", () => {
    const fromVal = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const intoOld = new Uint8Array([0xff, 0xee, 0xdd, 0xcc]);
    const intoNew = new Uint8Array([0xfe, 0xec, 0xde, 0xc8]);
    const auxRead = new Map<string, AuxValue>([
      ["plaintext", fromVal],
      ["feedback", intoOld],
    ]);
    const auxWritten = new Map<string, AuxValue>([["feedback", intoNew]]);
    const units = auxXorNarration(
      makeFrame({
        stepType: "generic.aux-xor@1",
        params: { from: "plaintext", into: "feedback" },
        auxRead,
        auxWritten,
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("aux[feedback]");
    expect(units[0]?.label).toContain("aux[plaintext]");
    expect(units[0]?.label).toContain("4 bytes");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("ff"); // intoOld byte 0
    expect(text).toContain("fe"); // result byte 0
    expect(text).toMatch(/self-inverse/);
  });

  it("returns null when an operand is missing", () => {
    expect(
      auxXorNarration(
        makeFrame({
          stepType: "generic.aux-xor@1",
          params: { from: "a", into: "b" },
          // both reads absent
        }),
      ),
    ).toBeNull();
  });
});

// ─── aux-copy ────────────────────────────────────────────────────────

describe("auxCopyNarration", () => {
  it("emits 1 unit naming source and destination keys", () => {
    const value = new Uint8Array([0x11, 0x22, 0x33]);
    const auxRead = new Map<string, AuxValue>([["iv", value]]);
    const auxWritten = new Map<string, AuxValue>([["feedback", new Uint8Array(value)]]);
    const units = auxCopyNarration(
      makeFrame({
        stepType: "generic.aux-copy@1",
        params: { from: "iv", to: "feedback" },
        auxRead,
        auxWritten,
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("aux[feedback]");
    expect(units[0]?.label).toContain("aux[iv]");
    expect(units[0]?.label).toContain("3 bytes");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toMatch(/fresh allocation/);
  });

  it("returns null when source aux is missing (unwired)", () => {
    expect(
      auxCopyNarration(
        makeFrame({
          stepType: "generic.aux-copy@1",
          params: { from: "iv", to: "feedback" },
        }),
      ),
    ).toBeNull();
  });
});
