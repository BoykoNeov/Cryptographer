/**
 * Spec-store tests for the `into-track-start` anchor introduced in DES
 * Phase 6d-iv. The store's `insertStepIntoSpec` router now recognizes
 * `{ kind: "into-track-start", roundId, trackIdx }` and routes to
 * `prependChildToTrack` with the same try/catch fallback the
 * `into-start` branch uses for unexpected throws.
 *
 * Node env — no DOM. B4 (universal-port Phase 4d) made DES port-native, so
 * `setCipher("des")` no longer yields a `feistel-round` spec. We inject the
 * shared synthetic Feistel fixture into the store via `__setSpecForTests`
 * instead — `feistel-round` is not in the selector, but the `into-track-start`
 * routing survives until Phase 5 and needs a spec that uses the primitive.
 */

import { findStepAndParent } from "@/core/spec-mutations";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  __setSpecForTests,
  insertStepIntoSpec,
  useSpec,
} from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSyntheticFeistelSpec } from "./fixtures/synthetic-feistel-rounds";

const resetAll = (): void => {
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
};

const selectDes = (): void => {
  __setSpecForTests(buildSyntheticFeistelSpec());
};

describe("insertStepIntoSpec — into-track-start anchor (6d-iv)", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("inserts into the empty L track of a DES round", () => {
    selectDes();
    const newId = insertStepIntoSpec("generic.byte-substitution@1", {
      kind: "into-track-start",
      roundId: "round.3",
      trackIdx: 0,
    });
    const loc = findStepAndParent(useSpec()(), newId);
    expect(loc, "newly inserted leaf must be findable").not.toBeNull();
    expect(loc?.parent?.kind, "parent must be the feistel-round").toBe("feistel-round");
    expect(loc?.parent?.id, "parent's id must be round.3").toBe("round.3");
    expect(loc?.indexInParent, "must land at position 0 of the L track").toBe(0);
    expect(loc?.trackIdx, "must be in L track (index 0)").toBe(0);
  });

  it("inserts into the non-empty R track at position 0", () => {
    selectDes();
    const newId = insertStepIntoSpec("generic.byte-substitution@1", {
      kind: "into-track-start",
      roundId: "round.3",
      trackIdx: 1,
    });
    const loc = findStepAndParent(useSpec()(), newId);
    expect(loc?.parent?.id).toBe("round.3");
    expect(loc?.trackIdx).toBe(1);
    expect(loc?.indexInParent).toBe(0); // before round.3.expand-R
  });

  it("returns the generated id so callers can route trace focus", () => {
    selectDes();
    const newId = insertStepIntoSpec("generic.shift-rows@1", {
      kind: "into-track-start",
      roundId: "round.1",
      trackIdx: 0,
    });
    expect(typeof newId).toBe("string");
    expect(newId.length).toBeGreaterThan(0);
    // The id-generator base segment for `generic.shift-rows@1` is
    // `shift-rows`. The DES canonical spec has no prior `shift-rows-N`
    // leaves, so this should land as `shift-rows-1`.
    expect(newId).toBe("shift-rows-1");
  });

  it("falls back to root-append on unexpected mutator throws (out-of-range trackIdx)", () => {
    selectDes();
    const newId = insertStepIntoSpec("generic.byte-substitution@1", {
      kind: "into-track-start",
      roundId: "round.1",
      trackIdx: 99, // out of range — prependChildToTrack throws
    });
    // The fallback path logs + appends to root. The leaf should still
    // be findable in the spec; just at the top level instead of inside
    // a track.
    const loc = findStepAndParent(useSpec()(), newId);
    expect(loc, "fallback must still leave the leaf in the spec").not.toBeNull();
    expect(loc?.parent, "fallback lands at root").toBeNull();
  });

  it("falls back to root-append when round id doesn't exist", () => {
    selectDes();
    const newId = insertStepIntoSpec("generic.byte-substitution@1", {
      kind: "into-track-start",
      roundId: "no-such-round",
      trackIdx: 0,
    });
    const loc = findStepAndParent(useSpec()(), newId);
    expect(loc?.parent).toBeNull(); // landed at root via fallback
  });
});
