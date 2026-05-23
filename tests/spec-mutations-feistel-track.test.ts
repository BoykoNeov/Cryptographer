/**
 * Tests for the per-track structural mutators introduced in DES Phase 6d
 * (`docs/plans/des-feistel.md`). Two responsibilities:
 *
 *   1. `transformParentArray` (the walker shared by `insertStepAfter`,
 *      `insertStepBefore`, `removeStep`, `reorderStep`) now descends into
 *      a `feistel-round`'s tracks instead of treating the round as a
 *      structural leaf. So a stepId living inside an L or R track is a
 *      valid anchor for any of the four primitives.
 *
 *   2. The new `prependChildToTrack` primitive (Phase 6d-iii) handles
 *      the at-start drop case — necessary because an empty track has
 *      no chip to anchor `insertStepBefore` against, just like an empty
 *      group needed `prependChildToContainer`.
 *
 * Critical invariant tested here: **reference equality on untouched
 * tracks**. A drop into R must keep L's `track` reference === its
 * pre-edit value, so the spec store's debounced
 * `createEffect(on(spec, ...))` doesn't spuriously re-run the trace on
 * every per-track edit. Documented in the plan as the advisor-flagged
 * risk; pinned here so a future refactor of `transformParentArray`
 * doesn't silently break it.
 *
 * 6d-iii's `prependChildToTrack` is exercised below the
 * `transformParentArray`-based block. The `findStepAndParent`
 * descent + `StepLocation.trackIdx` tests live in
 * `tests/spec-mutations-structure.test.ts` once 6d-ii lands.
 */

import { desSpec } from "@/ciphers/des";
import {
  insertStepAfter,
  insertStepBefore,
  prependChildToContainer,
  prependChildToTrack,
  removeStep,
  reorderStep,
} from "@/core/spec-mutations";
import type { FeistelRoundGroup, StepGroup, StepLeaf, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

/** Same throwaway leaf shape every structural mutation test uses. */
const fixtureLeaf = (id: string): StepLeaf => ({
  kind: "step",
  id,
  type: "test.fixture@1",
  params: {},
});

/**
 * Locate the `rounds` group + a specific round inside it. Pre-6d-ii
 * `findStepAndParent` doesn't descend into feistel-round tracks, so we
 * walk the spec tree manually here. After 6d-ii, the equivalent
 * lookups via `findStepAndParent` join `tests/spec-mutations-structure
 * .test.ts`.
 */
const getRound = (spec: typeof desSpec, roundId: string): FeistelRoundGroup => {
  const roundsGroup = spec.steps.find(
    (n): n is StepGroup => n.kind === "group" && n.id === "rounds",
  );
  if (!roundsGroup) throw new Error("rounds group not found in DES spec");
  const round = roundsGroup.children.find(
    (n): n is FeistelRoundGroup => n.kind === "feistel-round" && n.id === roundId,
  );
  if (!round) throw new Error(`${roundId} not found in rounds group`);
  return round;
};

const trackChildren = (round: FeistelRoundGroup, trackIdx: number): readonly StepNode[] => {
  const track = round.tracks[trackIdx];
  if (!track) throw new Error(`track ${trackIdx} not found on ${round.id}`);
  return track.children;
};

describe("transformParentArray — Feistel track descent (6d-i)", () => {
  describe("insertStepAfter inside an R track", () => {
    it("inserts after the first chip in R track", () => {
      // round.1's R track children: expand-R, xor-K, s-boxes, p-permute.
      const updated = insertStepAfter(
        desSpec,
        "round.1.expand-R",
        fixtureLeaf("round.1.r-injected"),
      );
      const round1 = getRound(updated, "round.1");
      const r = trackChildren(round1, 1);
      expect(r.length).toBe(5);
      expect(r[0]?.id).toBe("round.1.expand-R");
      expect(r[1]?.id).toBe("round.1.r-injected");
      expect(r[2]?.id).toBe("round.1.xor-K");
    });

    it("inserts after the last chip in R track", () => {
      const updated = insertStepAfter(desSpec, "round.1.p-permute", fixtureLeaf("round.1.r-tail"));
      const r = trackChildren(getRound(updated, "round.1"), 1);
      expect(r.length).toBe(5);
      expect(r[4]?.id).toBe("round.1.r-tail");
    });

    it("throws when the anchor is a synthetic passthrough id", () => {
      // The passthrough chip is materialized by `walkSpec` (graph layer),
      // not a real spec node. transformParentArray walks the spec tree
      // and won't find it.
      expect(() => insertStepAfter(desSpec, "round.1:passthrough-0", fixtureLeaf("x"))).toThrow(
        /no step with id/,
      );
    });

    it("throws when the anchor is the synthetic rejoin id", () => {
      expect(() => insertStepAfter(desSpec, "round.1:rejoin", fixtureLeaf("x"))).toThrow(
        /no step with id/,
      );
    });
  });

  describe("insertStepBefore inside an R track", () => {
    it("inserts before the first chip in R track", () => {
      const updated = insertStepBefore(desSpec, "round.1.expand-R", fixtureLeaf("round.1.r-head"));
      const r = trackChildren(getRound(updated, "round.1"), 1);
      expect(r.length).toBe(5);
      expect(r[0]?.id).toBe("round.1.r-head");
      expect(r[1]?.id).toBe("round.1.expand-R");
    });
  });

  describe("removeStep inside an R track", () => {
    it("removes a single R-track chip", () => {
      const updated = removeStep(desSpec, "round.1.s-boxes");
      const r = trackChildren(getRound(updated, "round.1"), 1);
      expect(r.length).toBe(3);
      expect(r.map((n) => n.id)).toEqual([
        "round.1.expand-R",
        "round.1.xor-K",
        "round.1.p-permute",
      ]);
    });

    it("leaves the L track empty AND reference-equal after R-track removal", () => {
      const before = getRound(desSpec, "round.1");
      const updated = removeStep(desSpec, "round.1.s-boxes");
      const after = getRound(updated, "round.1");
      // L track wasn't touched, so its `track` object reference must be
      // identical. This is the spec-store-debounce safety net.
      expect(after.tracks[0]).toBe(before.tracks[0]);
      // L track's children array reference, too.
      expect(after.tracks[0]?.children).toBe(before.tracks[0]?.children);
    });
  });

  describe("reorderStep inside an R track", () => {
    it("moves an R-track chip to a new index", () => {
      // Move p-permute (index 3) to index 0 inside R track.
      const updated = reorderStep(desSpec, "round.1.p-permute", 0);
      const r = trackChildren(getRound(updated, "round.1"), 1);
      expect(r.map((n) => n.id)).toEqual([
        "round.1.p-permute",
        "round.1.expand-R",
        "round.1.xor-K",
        "round.1.s-boxes",
      ]);
    });

    it("preserves L-track reference identity after R-track reorder", () => {
      const before = getRound(desSpec, "round.1");
      const updated = reorderStep(desSpec, "round.1.p-permute", 0);
      const after = getRound(updated, "round.1");
      expect(after.tracks[0]).toBe(before.tracks[0]);
    });
  });

  describe("reference equality across rounds", () => {
    it("does not clone untouched rounds when one round's track is edited", () => {
      // Insert into round.5's R track; round.1's reference must be unchanged.
      const updated = insertStepAfter(
        desSpec,
        "round.5.expand-R",
        fixtureLeaf("round.5.r-injected"),
      );
      const beforeR1 = getRound(desSpec, "round.1");
      const afterR1 = getRound(updated, "round.1");
      expect(afterR1).toBe(beforeR1);
    });

    it("does not mutate the original spec", () => {
      const snapshot = JSON.stringify(desSpec);
      insertStepAfter(desSpec, "round.1.expand-R", fixtureLeaf("ephemeral"));
      expect(JSON.stringify(desSpec)).toBe(snapshot);
    });
  });
});

describe("prependChildToTrack (6d-iii)", () => {
  it("prepends into an empty L track", () => {
    const newLeaf = fixtureLeaf("round.1.l-prepended");
    const updated = prependChildToTrack(desSpec, "round.1", 0, newLeaf);
    const round1 = getRound(updated, "round.1");
    expect(round1.tracks[0]?.children.length).toBe(1);
    expect(round1.tracks[0]?.children[0]?.id).toBe("round.1.l-prepended");
  });

  it("prepends into a non-empty R track", () => {
    const newLeaf = fixtureLeaf("round.1.r-prepended");
    const updated = prependChildToTrack(desSpec, "round.1", 1, newLeaf);
    const r = trackChildren(getRound(updated, "round.1"), 1);
    expect(r.length).toBe(5);
    expect(r[0]?.id).toBe("round.1.r-prepended");
    expect(r[1]?.id).toBe("round.1.expand-R");
  });

  it("preserves L-track reference when prepending into R", () => {
    const before = getRound(desSpec, "round.1");
    const updated = prependChildToTrack(desSpec, "round.1", 1, fixtureLeaf("x"));
    const after = getRound(updated, "round.1");
    expect(after.tracks[0]).toBe(before.tracks[0]);
  });

  it("preserves sibling-round references when prepending into one round", () => {
    const beforeR2 = getRound(desSpec, "round.2");
    const updated = prependChildToTrack(desSpec, "round.1", 1, fixtureLeaf("x"));
    const afterR2 = getRound(updated, "round.2");
    expect(afterR2).toBe(beforeR2);
  });

  it("throws when the round id resolves to a non-feistel-round node", () => {
    expect(() => prependChildToTrack(desSpec, "key-schedule", 0, fixtureLeaf("x"))).toThrow(
      /not a feistel-round/,
    );
  });

  it("throws when the round id doesn't exist", () => {
    expect(() => prependChildToTrack(desSpec, "no-such-round", 0, fixtureLeaf("x"))).toThrow(
      /no node with id "no-such-round"/,
    );
  });

  it("throws when trackIdx is out of range (high)", () => {
    expect(() => prependChildToTrack(desSpec, "round.1", 5, fixtureLeaf("x"))).toThrow(
      /trackIdx 5 out of range/,
    );
  });

  it("throws when trackIdx is out of range (negative)", () => {
    expect(() => prependChildToTrack(desSpec, "round.1", -1, fixtureLeaf("x"))).toThrow(
      /trackIdx -1 out of range/,
    );
  });

  it("does not mutate the original spec", () => {
    const snapshot = JSON.stringify(desSpec);
    prependChildToTrack(desSpec, "round.1", 0, fixtureLeaf("ephemeral"));
    expect(JSON.stringify(desSpec)).toBe(snapshot);
  });
});

describe("prependChildToContainer — feistel-round error pointer (6d-iii)", () => {
  it("throws with a pointer to prependChildToTrack when given a feistel-round id", () => {
    expect(() => prependChildToContainer(desSpec, "round.1", fixtureLeaf("x"))).toThrow(
      /is a feistel-round; use prependChildToTrack/,
    );
  });
});

// UX-F regression — populate an empty L-track via palette drop, then
// remove the inserted leaf. The track must be empty again so the
// graph derivation re-emits the synthetic L-passthrough chip
// (`round.N:passthrough-0`). Without this round-trip working, a user
// who experiments with a palette drop into L is stuck — `reset spec`
// nuked all their other edits. The path-(a) per-leaf delete UX
// (advisor-confirmed 2026-05-22) rides on `removeStep`; this test
// pins that the round-trip really lands at an empty track, not a
// track containing an empty wrapper or some other partial state.
describe("removeStep — empty-to-populated-to-empty L-track round-trip (UX-F)", () => {
  it("round-trips an L-track through prepend → remove back to empty", () => {
    const inserted = prependChildToTrack(
      desSpec,
      "round.1",
      0,
      fixtureLeaf("round.1.l-experimental"),
    );
    expect(trackChildren(getRound(inserted, "round.1"), 0).length).toBe(1);

    const restored = removeStep(inserted, "round.1.l-experimental");
    // L-track must be empty again so the graph derivation re-emits
    // the synthetic L-passthrough chip (`round.1:passthrough-0`).
    expect(trackChildren(getRound(restored, "round.1"), 0)).toEqual([]);
  });

  it("after remove, the R-track is unchanged and reference-equal to the original", () => {
    const inserted = prependChildToTrack(
      desSpec,
      "round.1",
      0,
      fixtureLeaf("round.1.l-experimental"),
    );
    const restored = removeStep(inserted, "round.1.l-experimental");

    const originalR = getRound(desSpec, "round.1").tracks[1];
    const restoredR = getRound(restored, "round.1").tracks[1];

    // The R-track wasn't touched by the L-side mutations, so the
    // structural walker must return the same reference for it. This is
    // the trace-coupling safety net: if it broke, every L-track edit
    // would spuriously re-run the trace because the R-track's `track`
    // object reference would change.
    expect(restoredR).toBe(originalR);
  });
});
