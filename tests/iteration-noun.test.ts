/**
 * What a loop pass is CALLED — "block" for a loop that walks data, "attempt"
 * for ML-DSA signing's repeat-until loop (`src/core/iteration-noun.ts`).
 *
 * Every surface that names a pass reads the same derivation: the graph's
 * collapsed-loop chips ("attempt 1", "+N more attempts") and the step view's
 * badge ("Attempt 2 of 3"). The end-to-end block runs the SHIPPED signing spec
 * rather than a hand-built loop, because the property that matters is that the
 * loop the learner actually sees is recognised — a toy with `stopWhen` would
 * stay green if the signing builder stopped setting it.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  MLDSA_ATTEMPTS_ID,
  ML_DSA_44_DEFAULT_MESSAGE,
  buildMlDsa44SignSpec,
} from "@/ciphers/ml-dsa-44";
import { collapseGraph, deriveAuxGraph, expandCollapsedIterates } from "@/core/graph";
import {
  capitalNoun,
  iterationNounForPath,
  iterationNounOf,
  iterationNounsById,
  pluralNoun,
} from "@/core/iteration-noun";
import { runSpec } from "@/core/runtime";
import type { AuxValue, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

describe("iterationNounOf — the word follows the loop's shape", () => {
  it("a loop that decides when to stop counts attempts", () => {
    expect(iterationNounOf({ stopWhen: { node: "v", port: "accepted" } })).toBe("attempt");
  });

  it("a loop that walks a fixed amount of data counts blocks", () => {
    expect(iterationNounOf({})).toBe("block");
  });

  it("plural and capitalized forms read as English", () => {
    expect(pluralNoun("attempt")).toBe("attempts");
    expect(pluralNoun("block")).toBe("blocks");
    expect(capitalNoun("attempt")).toBe("Attempt");
    expect(capitalNoun("block")).toBe("Block");
  });
});

describe("iterationNounForPath — a frame takes its NEAREST enclosing loop's word", () => {
  const nouns = new Map([
    ["outer", "block" as const],
    ["inner", "attempt" as const],
  ]);

  it("skips plain groups to reach the loop they sit in", () => {
    expect(iterationNounForPath(["inner", "some-group"], nouns)).toBe("attempt");
  });

  it("the innermost loop wins over an outer one", () => {
    expect(iterationNounForPath(["outer", "inner"], nouns)).toBe("attempt");
    expect(iterationNounForPath(["outer", "g"], nouns)).toBe("block");
  });

  it("falls back to block outside any known loop", () => {
    expect(iterationNounForPath([], nouns)).toBe("block");
    expect(iterationNounForPath(["unknown"], nouns)).toBe("block");
  });
});

describe("iterationNounsById — finds loops nested inside groups", () => {
  it("walks into groups", () => {
    const tree: StepNode[] = [
      {
        kind: "group",
        id: "g",
        label: "g",
        children: [
          {
            kind: "iterate",
            id: "loop",
            countFromAux: "n",
            blocksFromAux: "b",
            outBlocksAux: "o",
            children: [],
          } as unknown as StepNode,
        ],
      },
    ];
    expect(iterationNounsById(tree).get("loop")).toBe("block");
  });
});

describe("the shipped specs get the right word", () => {
  const registry = buildDefaultRegistry();

  it("ML-DSA-44 signing's loop is an attempt loop", () => {
    const nouns = iterationNounsById(buildMlDsa44SignSpec().steps);
    expect(nouns.get(MLDSA_ATTEMPTS_ID)).toBe("attempt");
  });

  it("AES-128 ECB's loop is still a block loop", () => {
    const nouns = iterationNounsById(aes128EcbSpec.steps);
    expect([...nouns.values()]).toEqual(["block"]);
  });

  it("collapsing the signing loop shows one chip per ATTEMPT, never 'block'", () => {
    const spec = buildMlDsa44SignSpec();
    const trace = runSpec(spec, registry, {
      initialState: { shape: "bytes", bytes: ML_DSA_44_DEFAULT_MESSAGE },
      initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
    });
    const collapsed = new Set([MLDSA_ATTEMPTS_ID]);
    const graph = expandCollapsedIterates(
      collapseGraph(deriveAuxGraph(trace, spec), collapsed),
      collapsed,
    );
    const loop = graph.containers.find((c) => c.id === MLDSA_ATTEMPTS_ID);
    expect(loop?.iterationNoun).toBe("attempt");
    const labels = graph.nodes
      .filter((n) => n.blockChipOf === MLDSA_ATTEMPTS_ID)
      .map((n) => n.label);
    // The default message is signed on its third attempt (pinned in
    // `tests/ml-dsa-44-sign.test.ts`), so there are exactly three chips — the
    // count is the attempts that RAN, not the cap of 32.
    expect(labels).toEqual(["attempt 1", "attempt 2", "attempt 3"]);
  });
});
