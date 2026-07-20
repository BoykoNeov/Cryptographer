/**
 * ChaCha20 quarter-round DIAGRAM MODEL (`src/core/chacha-diagram.ts`).
 *
 * The model's job is to recover the one fact that twelve identical-looking ARX
 * leaves cannot tell you on their own: WHICH of the sixteen state words this
 * particular quarter round is mixing. RFC 8439 §2.3.1 names its eight quarter
 * rounds exactly that way, so the strongest available check is to derive the
 * eight word-quartets from wiring and compare them against the RFC's list.
 *
 * That check is doing more than testing this module. The quartets are a
 * property of the SPEC's wiring — if `chacha20.ts` ever wired a quarter round
 * to the wrong words, the cipher would still round-trip (it is one spec used
 * both ways) and might still look plausible, but these indices would move.
 */

import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import { chachaDiagramModel } from "@/core/chacha-diagram";
import { type ChaChaDoubleRoundShape, analyzeChaChaDoubleRound } from "@/core/chacha-shape";
import type { CipherSpec, StepGroup, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const firstDoubleRound = (spec: CipherSpec): ChaChaDoubleRoundShape => {
  const out: ChaChaDoubleRoundShape[] = [];
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "group") {
        const shape = analyzeChaChaDoubleRound(n as StepGroup);
        if (shape) out.push(shape);
        walk(n.children);
      } else if (n.kind === "iterate") {
        walk(n.children);
      }
    }
  };
  walk(spec.steps);
  const first = out[0];
  if (!first) throw new Error("no ChaCha double round found");
  return first;
};

/** RFC 8439 §2.3.1's own eight quarter rounds, in order. */
const RFC_QUARTER_ROUNDS: readonly (readonly number[])[] = [
  [0, 4, 8, 12],
  [1, 5, 9, 13],
  [2, 6, 10, 14],
  [3, 7, 11, 15],
  [0, 5, 10, 15],
  [1, 6, 11, 12],
  [2, 7, 8, 13],
  [3, 4, 9, 14],
];

describe("chachaDiagramModel — recovering RFC 8439 §2.3.1 from wiring", () => {
  const round = firstDoubleRound(chacha20EncryptSpec);

  it("derives the RFC's eight word-quartets by threading the split forward", () => {
    // The load-bearing assertion of this file. Nothing in the spec labels a
    // quarter round with its word indices; they are recovered by following
    // which split output each rail descends from, and which quarter round last
    // wrote to that position.
    const derived = RFC_QUARTER_ROUNDS.map((_, i) => {
      const model = chachaDiagramModel(round, i);
      return model?.rails.map((r) => r.wordIndex);
    });
    expect(derived).toEqual(RFC_QUARTER_ROUNDS);
  });

  it("labels each quarter round the way the RFC names it", () => {
    expect(chachaDiagramModel(round, 4)?.rfcLabel).toBe("QUARTERROUND(0, 5, 10, 15)");
    expect(chachaDiagramModel(round, 0)?.rfcLabel).toBe("QUARTERROUND(0, 4, 8, 12)");
  });

  it("classifies the first four as column rounds and the last four as diagonal", () => {
    // Derived from whether the inputs read the split directly, not from the
    // index — so this would still be right if the spec listed them in another
    // order, and wrong-looking if the wiring changed.
    const kinds = RFC_QUARTER_ROUNDS.map((_, i) => chachaDiagramModel(round, i)?.kind);
    expect(kinds).toEqual([
      "column",
      "column",
      "column",
      "column",
      "diagonal",
      "diagonal",
      "diagonal",
      "diagonal",
    ]);
  });

  it("prints each operation as RFC 8439 §2.1 writes it", () => {
    // The rotation constants read 16/12/8/7 — the whole reason
    // `rotate-bits-left@1` exists instead of the right-rotate at its complement.
    expect(chachaDiagramModel(round, 0)?.ops.map((o) => o.label)).toEqual([
      "a += b",
      "d ^= a",
      "d <<< 16",
      "c += d",
      "b ^= c",
      "b <<< 12",
      "a += b",
      "d ^= a",
      "d <<< 8",
      "c += d",
      "b ^= c",
      "b <<< 7",
    ]);
  });

  it("points each rail at the leaf producing its final value", () => {
    const model = chachaDiagramModel(round, 2);
    const qr = round.quarterRounds[2];
    expect(model?.rails.map((r) => r.outputId)).toEqual([
      qr?.outputs.a,
      qr?.outputs.b,
      qr?.outputs.c,
      qr?.outputs.d,
    ]);
  });

  it("returns null for an out-of-range quarter round", () => {
    expect(chachaDiagramModel(round, 8)).toBeNull();
    expect(chachaDiagramModel(round, -1)).toBeNull();
  });

  it("every double round derives the same quartets — they are all the same shape", () => {
    // Ten double rounds, each running the same eight quarter rounds. If word
    // threading depended on anything accumulating across rounds, later rounds
    // would drift.
    const spec = chacha20EncryptSpec;
    const rounds: ChaChaDoubleRoundShape[] = [];
    const walk = (nodes: readonly StepNode[]): void => {
      for (const n of nodes) {
        if (n.kind === "group") {
          const s = analyzeChaChaDoubleRound(n as StepGroup);
          if (s) rounds.push(s);
          walk(n.children);
        } else if (n.kind === "iterate") walk(n.children);
      }
    };
    walk(spec.steps);
    expect(rounds).toHaveLength(10);
    for (const r of rounds) {
      const derived = RFC_QUARTER_ROUNDS.map((_, i) =>
        chachaDiagramModel(r, i)?.rails.map((x) => x.wordIndex),
      );
      expect(derived).toEqual(RFC_QUARTER_ROUNDS);
    }
  });
});
