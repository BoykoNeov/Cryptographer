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

  // ─── Phase 2d+ (May 2026) richer paramsChanged rendering ──────────────────
  // Pre-extension, every param diff collapsed to "X changed". With the
  // SpecParamDiff.scalar / SpecParamDiff.cells extensions, the legend can
  // surface the actual before/after value for the edits the user is most
  // likely to make (S-box cells, MixColumns matrix cells, scalar params).

  it("renders a scalar param change as 'paramName from → to' with no quotes for numbers", () => {
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [],
      paramsChanged: [
        { stepId: "key-expansion", paramName: "rounds", scalar: { from: 10, to: 12 } },
      ],
    };
    const out = describeDelta(delta, "hex");
    expect(out.some((l) => l === "key-expansion: rounds 10 → 12")).toBe(true);
  });

  it("quotes string scalars so '10' (string) is distinguishable from 10 (number)", () => {
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [],
      paramsChanged: [
        {
          stepId: "initial.add-round-key",
          paramName: "auxName",
          scalar: { from: "roundKey.0", to: "roundKey.1" },
        },
      ],
    };
    const out = describeDelta(delta, "hex");
    expect(out[0]).toBe('initial.add-round-key: auxName "roundKey.0" → "roundKey.1"');
  });

  it("renders 2D cell diffs (sbox-style) with hex row/col coordinates and byte-format-aware values", () => {
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [],
      paramsChanged: [
        {
          stepId: "round.1.sub-bytes",
          paramName: "sbox",
          cells: [{ kind: "2d", row: 0, col: 0, from: 0x63, to: 0x00 }],
        },
      ],
    };
    expect(describeDelta(delta, "hex")[0]).toBe("round.1.sub-bytes: sbox[row 0, col 0] 63 → 00");
    // Threading the format through means decimal mode renders the values in
    // base 10 — matches the cells the user sees in the matrix tiles.
    expect(describeDelta(delta, "decimal")[0]).toBe("round.1.sub-bytes: sbox[row 0, col 0] 99 → 0");
  });

  it("renders 1D cell diffs with a flat [index] when no 16×16 decomposition applies", () => {
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [],
      paramsChanged: [
        {
          stepId: "round.1.shift-rows",
          paramName: "shifts",
          cells: [{ kind: "1d", index: 2, from: 2, to: 3 }],
        },
      ],
    };
    expect(describeDelta(delta, "hex")[0]).toBe("round.1.shift-rows: shifts[2] 02 → 03");
  });

  it("caps inline cell diffs at MAX_PARAM_CELLS_INLINE (8) and summarizes the rest", () => {
    // Build a 10-cell diff so we exercise the cap.
    const cells = Array.from(
      { length: 10 },
      (_, i) => ({ kind: "2d", row: 0, col: i, from: 0, to: i + 1 }) as const,
    );
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [],
      paramsChanged: [{ stepId: "round.1.sub-bytes", paramName: "sbox", cells }],
    };
    const out = describeDelta(delta, "hex");
    // 8 detail lines + 1 "more" line.
    const detailLines = out.filter((l) => l.includes("sbox[row"));
    expect(detailLines.length).toBe(8);
    const moreLine = out.find((l) => l.includes("more sbox cell"));
    expect(moreLine).toBeDefined();
    expect(moreLine).toContain("2 more"); // 10 - 8
  });

  it("falls back to the legacy 'X changed' summary when a diff has no scalar or cells (unclassifiable)", () => {
    // This is the same shape as the pre-extension test — proves the legacy
    // path still works for diffs the classifier couldn't summarize.
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [],
      paramsChanged: [
        { stepId: "round.1.sub-bytes", paramName: "weirdNestedThing" },
        { stepId: "round.1.sub-bytes", paramName: "anotherWeird" },
      ],
    };
    const out = describeDelta(delta, "hex");
    expect(out.some((l) => l === "round.1.sub-bytes: weirdNestedThing, anotherWeird changed")).toBe(
      true,
    );
  });

  it("emits detail lines AND a bare summary on the same step when some diffs are classified and others aren't", () => {
    const delta: RunDelta = {
      inputChanged: [],
      keyChanged: [],
      paramsChanged: [
        {
          stepId: "round.1.sub-bytes",
          paramName: "sbox",
          cells: [{ kind: "2d", row: 1, col: 2, from: 0x77, to: 0x00 }],
        },
        { stepId: "round.1.sub-bytes", paramName: "weirdNestedThing" },
      ],
    };
    const out = describeDelta(delta, "hex");
    expect(out.some((l) => l === "round.1.sub-bytes: sbox[row 1, col 2] 77 → 00")).toBe(true);
    expect(out.some((l) => l === "round.1.sub-bytes: weirdNestedThing changed")).toBe(true);
  });
});
