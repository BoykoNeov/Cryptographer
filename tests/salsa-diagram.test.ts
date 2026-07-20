/**
 * Salsa20 quarter-round DIAGRAM MODEL (`src/core/salsa-diagram.ts`).
 *
 * The shape module answers "what is this group?"; this module answers the two
 * questions the linear diagram additionally needs — *which* of the eight
 * otherwise-identical quarter rounds am I looking at, and what does each
 * operation say in Bernstein's own notation.
 *
 * The first of those is the reason the diagram exists at all. Twelve bare ARX
 * leaves are indistinguishable between quarter rounds; the STATE-WORD INDICES
 * are the only thing that tells them apart, and they are threaded from the
 * split rather than read off a leaf id. So the strongest test available is to
 * check the derived quads against Bernstein's published columnround/rowround
 * tuples — which is what this file does, and which would catch a threading bug
 * that every structural test in `salsa-shape.test.ts` is blind to.
 */

import { salsa20DecryptSpec, salsa20EncryptSpec } from "@/ciphers/salsa20";
import { salsaDiagramModel } from "@/core/salsa-diagram";
import { type SalsaDoubleRoundShape, analyzeSalsaDoubleRound } from "@/core/salsa-shape";
import type { CipherSpec, StepGroup, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const doubleRounds = (spec: CipherSpec): SalsaDoubleRoundShape[] => {
  const out: SalsaDoubleRoundShape[] = [];
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "group") {
        const s = analyzeSalsaDoubleRound(n as StepGroup);
        if (s) out.push(s);
        walk(n.children);
      } else if (n.kind === "iterate") walk(n.children);
    }
  };
  walk(spec.steps);
  return out;
};

const firstRound = (spec: CipherSpec = salsa20EncryptSpec): SalsaDoubleRoundShape =>
  doubleRounds(spec)[0] as SalsaDoubleRoundShape;

const modelAt = (i: number, spec: CipherSpec = salsa20EncryptSpec) => {
  const m = salsaDiagramModel(firstRound(spec), i);
  if (!m) throw new Error(`expected a model for quarter round ${i}`);
  return m;
};

describe("salsaDiagramModel — the word indices that name a quarter round", () => {
  it("derives Bernstein's columnround and rowround tuples, in order and unsorted", () => {
    // The published tuples. A COLUMN quarter round starts on the state's main
    // DIAGONAL and wraps — (5, 9, 13, 1), not (1, 5, 9, 13) — because Salsa20's
    // constants sit on that diagonal and each column round must begin below its
    // own constant. Sorting these would print a plausible-looking lie and erase
    // the single most distinctive fact about Salsa's state layout, which is why
    // this assertion pins ORDER and not just membership.
    const expected = [
      "quarterround(x0, x4, x8, x12)",
      "quarterround(x5, x9, x13, x1)",
      "quarterround(x10, x14, x2, x6)",
      "quarterround(x15, x3, x7, x11)",
      "quarterround(x0, x1, x2, x3)",
      "quarterround(x5, x6, x7, x4)",
      "quarterround(x10, x11, x8, x9)",
      "quarterround(x15, x12, x13, x14)",
    ];
    expect([0, 1, 2, 3, 4, 5, 6, 7].map((i) => modelAt(i).quadLabel)).toEqual(expected);
  });

  it("the same tuples come out of the decrypt spec — one model serves both directions", () => {
    expect([0, 1, 2, 3, 4, 5, 6, 7].map((i) => modelAt(i, salsa20DecryptSpec).quadLabel)).toEqual(
      [0, 1, 2, 3, 4, 5, 6, 7].map((i) => modelAt(i).quadLabel),
    );
  });

  it("classifies the two tiers as column and row from wiring, not from the index", () => {
    // Bernstein's terms, and deliberately NOT ChaCha's "diagonal" — the second
    // half of a Salsa double round mixes ROWS.
    expect([0, 1, 2, 3, 4, 5, 6, 7].map((i) => modelAt(i).kind)).toEqual([
      "column",
      "column",
      "column",
      "column",
      "row",
      "row",
      "row",
      "row",
    ]);
  });

  it("threads a word index onto every rail of every quarter round", () => {
    for (let i = 0; i < 8; i++) {
      for (const rail of modelAt(i).rails) {
        expect(rail.wordIndex).not.toBeNull();
      }
    }
  });
});

describe("salsaDiagramModel — Bernstein's written form", () => {
  it("writes the four lines exactly as the specification does", () => {
    // Including the y→z transition: line 2 reads `z1 + y0`, because y1 has
    // already been overwritten by line 1 but y0 has not. Getting this wrong
    // would be a subtle, plausible-looking error — the reader would conclude
    // the four lines are independent, when in fact each feeds the next.
    expect(modelAt(0).lines).toEqual([
      "z1 = y1 ^ ((y0 + y3) <<< 7)",
      "z2 = y2 ^ ((z1 + y0) <<< 9)",
      "z3 = y3 ^ ((z2 + z1) <<< 13)",
      "z0 = y0 ^ ((z3 + z2) <<< 18)",
    ]);
  });

  it("labels every operation with its whole line, and every rail with its final name", () => {
    const m = modelAt(0);
    // A station's tooltip is the expression it participates in, not its own
    // token — three leaves, one written line.
    expect(m.ops.slice(0, 3).map((o) => o.label)).toEqual([
      "z1 = y1 ^ ((y0 + y3) <<< 7)",
      "z1 = y1 ^ ((y0 + y3) <<< 7)",
      "z1 = y1 ^ ((y0 + y3) <<< 7)",
    ]);
    // Every rail is written exactly once, so every rail's final name is a z.
    expect(m.rails.map((r) => r.name)).toEqual(["z0", "z1", "z2", "z3"]);
  });

  it("puts the add and the rotate on the scratch lane and only the XOR on a rail", () => {
    // The structural claim the diagram's fifth lane makes, asserted here so a
    // future refactor cannot quietly move the add onto a state rail — which
    // would redraw Salsa as if it accumulated in place like ChaCha.
    const m = modelAt(0);
    for (const op of m.ops) {
      if (op.kind === "xor") {
        expect(op.lane).toEqual({ kind: "rail", rail: op.target });
      } else {
        expect(op.lane.kind).toBe("scratch");
      }
    }
  });

  it("names the add's operands in their y/z form, matching the line", () => {
    const adds = modelAt(0).ops.filter((o) => o.kind === "add");
    expect(adds.map((o) => o.short)).toEqual(["y0+y3", "z1+y0", "z2+z1", "z3+z2"]);
    expect(adds.map((o) => o.sourceNames)).toEqual([
      ["y0", "y3"],
      ["z1", "y0"],
      ["z2", "z1"],
      ["z3", "z2"],
    ]);
  });

  it("returns null for an out-of-range quarter round rather than throwing", () => {
    expect(salsaDiagramModel(firstRound(), 8)).toBeNull();
    expect(salsaDiagramModel(firstRound(), -1)).toBeNull();
  });
});
