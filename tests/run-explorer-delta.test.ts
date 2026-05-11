/**
 * Phase 2d — describeDelta formatter tests.
 *
 * The Run Explorer's per-tile "what changed" legend is just a list of
 * strings produced by describeDelta. Pinning the format here keeps the
 * legend stable as we iterate; we test the pure function rather than
 * scraping the rendered DOM because the format is the contract, not the
 * markup.
 */

import { describeDelta } from "@/ui/components/run-delta-format";
import type { RunDelta } from "@/ui/stores/history";
import { describe, expect, it } from "vitest";

describe("describeDelta", () => {
  it("emits a baseline marker when delta is null (first snapshot)", () => {
    const out = describeDelta(null, "hex");
    expect(out.length).toBe(1);
    expect(out[0]).toContain("baseline");
  });

  it("formats input byte changes in the active byte format", () => {
    const delta: RunDelta = {
      inputChanged: [{ index: 0, from: 0x00, to: 0x10 }],
      keyChanged: [],
      paramsChanged: [],
    };
    expect(describeDelta(delta, "hex")[0]).toBe("input byte 0: 00 → 10");
    expect(describeDelta(delta, "decimal")[0]).toBe("input byte 0: 0 → 16");
  });

  it("caps inline byte changes at MAX_BYTE_DIFFS_INLINE and emits a 'more' summary", () => {
    const delta: RunDelta = {
      inputChanged: [
        { index: 0, from: 0, to: 1 },
        { index: 1, from: 0, to: 2 },
        { index: 2, from: 0, to: 3 },
        { index: 3, from: 0, to: 4 },
        { index: 4, from: 0, to: 5 },
      ],
      keyChanged: [],
      paramsChanged: [],
    };
    const out = describeDelta(delta, "hex");
    expect(out.length).toBe(4); // 3 detail lines + 1 "more" line
    expect(out[3]).toContain("2 more input byte(s)");
  });

  it("groups param changes by stepId so 'sbox + foo on round.1.sub-bytes' renders as one line", () => {
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [],
      paramsChanged: [
        { stepId: "round.1.sub-bytes", paramName: "sbox" },
        { stepId: "round.1.sub-bytes", paramName: "auxName" },
        { stepId: "round.2.mix-cols", paramName: "matrix" },
      ],
    };
    const out = describeDelta(delta, "hex");
    expect(out.some((l) => l === "round.1.sub-bytes: sbox, auxName changed")).toBe(true);
    expect(out.some((l) => l === "round.2.mix-cols: matrix changed")).toBe(true);
  });

  it("renders key byte changes with the 'key byte' prefix to distinguish from input", () => {
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [{ index: 5, from: 0xab, to: 0xcd }],
      paramsChanged: [],
    };
    const out = describeDelta(delta, "hex");
    expect(out[0]).toBe("key byte 5: ab → cd");
  });
});
