/**
 * Per-iterate block counting — the fix for a bug the NTT is the first spec able
 * to expose (`docs/plans/unified-stargazing-quasar.md`, P1).
 *
 * **The bug.** `App.tsx`'s BlockBadge asked "how many blocks does this trace
 * have?" and answered with the largest `blockIndex` anywhere in it. Every
 * shipped spec up to now had exactly ONE `iterate` — CBC's blocks, SHA-256's
 * message blocks, a generator's words — so that was accidentally the same
 * number as "how many times did MY loop run". The NTT has SEVEN SIBLING
 * iterates running 1, 2, 4, 8, 16, 32 and 64 butterfly groups, and the badge
 * labelled layer 1's single group **"Block 1 of 64"**.
 *
 * Found by opening a browser, not by a test — the same lesson
 * `feedback_visual_smoke_vs_property_tests` records. Nothing type-checks a
 * count, and every existing assertion was written under the one-iterate
 * assumption.
 *
 * This file imports the REAL `iterateScopeKey` rather than restating the
 * grouping rule, so narrowing the shipped helper cannot leave these green.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildNttSpec } from "@/ciphers/ntt-3329-256";
import { DEFAULT_NTT_INPUT } from "@/ciphers/ntt-3329-256";
import { runSpec } from "@/core/runtime";
import { iterateScopeKey } from "@/core/step-id";
import type { AuxValue, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

/**
 * The production reading, restated in terms of the shipped helper: for the loop
 * a frame belongs to, how many iterations did it run? This mirrors `App.tsx`'s
 * `blockCounts` memo; the point of the test is the GROUPING, which comes from
 * the imported helper.
 */
const blockCountsByScope = (frames: readonly TraceFrame[]): Map<string, number> => {
  const counts = new Map<string, number>();
  for (const f of frames) {
    if (f.blockIndex === undefined) continue;
    const key = iterateScopeKey(f.path);
    const prev = counts.get(key);
    if (prev === undefined || f.blockIndex > prev) counts.set(key, f.blockIndex);
  }
  for (const [k, v] of counts) counts.set(k, v + 1);
  return counts;
};

describe("iterateScopeKey", () => {
  it("is the container chain itself — a frame's path excludes its own leaf id", () => {
    // The thing to get wrong here, and the thing that WAS got wrong while
    // writing this: `TraceFrame.path` holds only the containers a leaf sits
    // inside; the leaf's id rides `stepId`. Slicing an element off would drop a
    // real container and merge sibling scopes.
    expect(iterateScopeKey(["layer1"])).toBe("layer1");
    expect(iterateScopeKey(["blocks", "rounds"])).toBe("blocks/rounds");
  });

  it("gives a top-level leaf the empty scope", () => {
    expect(iterateScopeKey([])).toBe("");
  });

  it("separates sibling scopes and nesting levels", () => {
    // The non-collision argument rests on the spec-id grammar (lowercase,
    // digits, dots, dashes), which cannot produce a `/` — so there is no legal
    // pair of paths to demonstrate a collision with. What IS demonstrable, and
    // what the block count depends on, is that distinct legal scopes differ.
    const keys = [["layer1"], ["layer2"], ["layer1", "inner"], []].map(iterateScopeKey);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("the NTT's seven sibling iterates each count their own groups", () => {
  const trace = runSpec(buildNttSpec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: DEFAULT_NTT_INPUT },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  const counts = blockCountsByScope(trace.frames);

  it("reports 1, 2, 4, 8, 16, 32, 64 — not 64 seven times", () => {
    // The pre-fix behaviour was the trace-wide maximum, so every one of these
    // would have read 64. That is the assertion this file exists for.
    expect([1, 2, 3, 4, 5, 6, 7].map((n) => counts.get(`layer${n}`))).toEqual([
      1, 2, 4, 8, 16, 32, 64,
    ]);
  });

  it("the trace-wide maximum really is 64, so the old reading was wrong for six of seven", () => {
    // Stated explicitly so the test documents what it is ruling out rather than
    // just asserting the right answer.
    const traceWideMax = Math.max(...trace.frames.map((f) => f.blockIndex ?? -1)) + 1;
    expect(traceWideMax).toBe(64);
    expect(counts.get("layer1")).toBe(1);
    expect(counts.get("layer1")).not.toBe(traceWideMax);
  });

  it("top-level leaves are outside every loop, so they get no count", () => {
    // `zeta-table` / `cursor-split` / `cursor` run once, before any iterate.
    // The badge hides itself when the count is 1, and these have no entry at
    // all — `blockCountFor` falls back to 1.
    expect(counts.has("")).toBe(false);
  });
});
