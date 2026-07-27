/**
 * `add-mod@1` — the primitive, on its own.
 *
 * The LCG known-answer tests exercise this step end to end, but only ever at
 * one shape: three 4-byte operands, a modulus of 2³¹, and a sum that crosses it
 * roughly half the time. This file covers the contract the executor actually
 * declares — mismatched operand widths, output width, the reduction boundary,
 * and the errors — so a future consumer with different shapes (a wider modulus,
 * a short addend) is not the thing that discovers a gap.
 *
 * The `mod-mul@1` sibling has no such file; its coverage comes from RSA. This
 * one exists because the LCG is a much narrower exercise of the same contract.
 */

import type { StepContext } from "@/core/types";
import { addMod, addModPortContract } from "@/steps/add-mod";
import { describe, expect, it } from "vitest";

/** The executor ignores ctx entirely; a bare object keeps the calls readable. */
const CTX = {} as StepContext;

const bytes = (...v: number[]): Uint8Array => new Uint8Array(v);

const call = (a: Uint8Array, b: Uint8Array, modulus: Uint8Array): Uint8Array => {
  const out = addMod(
    new Map([
      ["a", a],
      ["b", b],
      ["modulus", modulus],
    ]),
    {},
    CTX,
  );
  const result = out.get("output");
  if (result === undefined) throw new Error("no output port");
  return result;
};

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("add-mod@1 — the arithmetic", () => {
  it("adds without reducing when the sum stays below the modulus", () => {
    expect(hex(call(bytes(0x10), bytes(0x05), bytes(0xff)))).toBe("15");
  });

  it("reduces when the sum reaches the modulus", () => {
    // The boundary itself: a + b === m must come out 0, not m.
    expect(hex(call(bytes(0x64), bytes(0x9c), bytes(0x01, 0x00)))).toBe("0000");
  });

  it("reduces a sum that overflows the modulus", () => {
    // 200 + 100 = 300; 300 mod 256 = 44 = 0x2c.
    expect(hex(call(bytes(0xc8), bytes(0x64), bytes(0x01, 0x00)))).toBe("002c");
  });

  it("carries across byte boundaries at full precision", () => {
    // 0xffff + 0x0001 = 0x10000, which does not fit the operand width. Reducing
    // mod 0x20000 keeps it — so a result of 0x0000 would mean the sum had been
    // truncated to the operand width before reduction, the exact bug the
    // executor's comment warns about.
    expect(hex(call(bytes(0xff, 0xff), bytes(0x00, 0x01), bytes(0x02, 0x00, 0x00)))).toBe("010000");
  });
});

describe("add-mod@1 — widths", () => {
  it("operands need not match each other in length", () => {
    // A 1-byte addend against a 4-byte one: each is read as a big-endian
    // integer, so no padding is required at the call site. The LCG relies on
    // this only incidentally; a future consumer may rely on it heavily.
    expect(
      hex(call(bytes(0x00, 0x00, 0x01, 0x00), bytes(0x01), bytes(0xff, 0xff, 0xff, 0xff))),
    ).toBe("00000101");
  });

  it("the output is always the modulus width, whatever the operands were", () => {
    // This is what gives a loop a uniform port width: the residue is < n, so it
    // always fits, and downstream wiring never has to reason about the operands.
    expect(call(bytes(0x01), bytes(0x01), bytes(0x00, 0x00, 0x00, 0xff))).toHaveLength(4);
    expect(call(bytes(0x01, 0x02, 0x03, 0x04), bytes(0x01), bytes(0xff))).toHaveLength(1);
  });

  it("declares three input ports and one output port", () => {
    // Both sides are `PortShapeMap`, which may be a function for dynamic-arity
    // steps. This one is static on both sides — asserting that is part of the
    // contract, since a function-form contract would change how the runtime
    // resolves widths.
    const { inputs, outputs } = addModPortContract;
    if (typeof inputs === "function") throw new Error("expected a static input map");
    if (typeof outputs === "function") throw new Error("expected a static output map");
    expect([...inputs.keys()].sort()).toEqual(["a", "b", "modulus"]);
    expect([...outputs.keys()]).toEqual(["output"]);
  });
});

describe("add-mod@1 — errors name the port at fault", () => {
  it("throws when an operand port is unwired", () => {
    expect(() => addMod(new Map([["a", bytes(1)]]), {}, CTX)).toThrow(/"b"/);
    expect(() =>
      addMod(
        new Map([
          ["a", bytes(1)],
          ["b", bytes(1)],
        ]),
        {},
        CTX,
      ),
    ).toThrow(/"modulus"/);
  });

  it("rejects a zero modulus rather than dividing by it", () => {
    // Reachable from the app: the modulus is an editable constant, so a learner
    // can zero it. A named error is the difference between "I broke it" and a
    // NaN propagating silently through the rest of the trace.
    expect(() => call(bytes(1), bytes(1), bytes(0x00, 0x00))).toThrow(/positive integer/);
  });
});
