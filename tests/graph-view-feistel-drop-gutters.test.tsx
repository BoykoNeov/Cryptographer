// @vitest-environment jsdom

/**
 * DES Phase 6d-v — per-track drop gutters inside Feistel rounds.
 *
 * Three responsibilities:
 *   1. Gutter render: each non-collapsed feistel-round in the rendered
 *      DES graph emits horizontal gutter strips inside its track
 *      columns. R track (populated) gets standard before/between/after
 *      strips; L track (empty in canonical DES) gets ONE sentinel
 *      strip encoded `into-track-start:${roundId}#${trackIdx}`.
 *   2. Drop dispatch: a `drop` event on the L-track sentinel fires
 *      `insertStepIntoSpec({ kind: "into-track-start", roundId, trackIdx })`
 *      → the new leaf appears at position 0 of the L track.
 *   3. Regression: the AES drop-gutter scenarios continue to work
 *      unchanged (no feistel containers in AES specs → the feistel
 *      branch is a no-op for them).
 *
 * Per `[[feedback-jsdom-pointer-events-gap]]` jsdom doesn't honor CSS
 * pointer-events, so we set up the drop event manually with a mock
 * DataTransfer and dispatch directly against the gutter `<rect>`.
 * Phase 6e's manual browser smoke pass is the discriminating check
 * for real-world hit-testing.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { findStepAndParent } from "@/core/spec-mutations";
import { bytesFromHex } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { STEP_TYPE_DRAG_MIME } from "@/ui/components/StepPalette";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const seedDesTrace = (): void => {
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: { shape: "bytes" as const, bytes: bytesFromHex("0123456789abcdef") },
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetHistoryForTests();
  __resetLayoutsForTests();
  __resetPaddingForTests();
  __resetReplicationForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
};

/** DataTransfer shim — same shape as `drop-gutters.test.tsx`. */
const mockDataTransfer = (payload: { readonly [mime: string]: string }) => ({
  getData: (mime: string) => payload[mime] ?? "",
  types: Object.keys(payload),
  setData: (_mime: string, _value: string) => {},
  effectAllowed: "" as DataTransfer["effectAllowed"],
  dropEffect: "" as DataTransfer["dropEffect"],
});

const fireDropAt = (target: Element, stepType: string): void => {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: mockDataTransfer({
      [STEP_TYPE_DRAG_MIME]: stepType,
      "text/plain": stepType,
    }),
  });
  target.dispatchEvent(event);
};

describe("GraphView — feistel per-track drop gutters (6d-v)", () => {
  beforeEach(() => {
    resetAll();
    setCipher("des");
    seedDesTrace();
  });

  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("emits an into-track-start sentinel for the L track of each round", () => {
    const { container } = render(() => <GraphView />);
    // DES has 16 rounds; each one's L track is empty so we expect 16
    // sentinel gutters with encoding `into-track-start:round.N#0`.
    for (let n = 1; n <= 16; n++) {
      const encoding = `into-track-start:round.${n}#0`;
      const rect = container.querySelector(`[data-drop-gutter="${encoding}"]`);
      expect(rect, `L-track sentinel missing for round.${n}`).not.toBeNull();
    }
  });

  it("emits standard before/between/after gutters for each round's R track", () => {
    const { container } = render(() => <GraphView />);
    // round.1's R track: expand-R, xor-K, s-boxes, p-permute → expect
    // 5 strips: 1 at-start + 3 between + 1 at-end.
    const expected = [
      "before:round.1.expand-R",
      "before:round.1.xor-K",
      "before:round.1.s-boxes",
      "before:round.1.p-permute",
      "after:round.1.p-permute",
    ];
    for (const enc of expected) {
      const rect = container.querySelector(`[data-drop-gutter="${enc}"]`);
      expect(rect, `R-track gutter missing for ${enc}`).not.toBeNull();
    }
  });

  it("drop on L-track sentinel inserts at position 0 of the L track", () => {
    const { container } = render(() => <GraphView />);
    const sentinel = container.querySelector('[data-drop-gutter="into-track-start:round.3#0"]');
    expect(sentinel, "round.3 L-track sentinel not found").not.toBeNull();
    if (!sentinel) return;
    fireDropAt(sentinel, "generic.byte-substitution@1");
    // The new leaf should land at position 0 of round.3's L track.
    const loc = findStepAndParent(useSpec()(), "byte-substitution-1");
    expect(loc).not.toBeNull();
    expect(loc?.parent?.kind).toBe("feistel-round");
    expect(loc?.parent?.id).toBe("round.3");
    expect(loc?.trackIdx).toBe(0);
    expect(loc?.indexInParent).toBe(0);
  });

  it("drop on R-track between-siblings gutter inserts at the right position", () => {
    const { container } = render(() => <GraphView />);
    // before:round.5.s-boxes → land BEFORE s-boxes (index 2) in R track.
    const gutter = container.querySelector('[data-drop-gutter="before:round.5.s-boxes"]');
    expect(gutter, "between-siblings R-track gutter not found").not.toBeNull();
    if (!gutter) return;
    fireDropAt(gutter, "generic.byte-substitution@1");
    const loc = findStepAndParent(useSpec()(), "byte-substitution-1");
    expect(loc?.parent?.id).toBe("round.5");
    expect(loc?.trackIdx).toBe(1); // R track
    expect(loc?.indexInParent).toBe(2); // before s-boxes (which was at 2)
  });

  it("drop on R-track at-end gutter inserts after the last chip", () => {
    const { container } = render(() => <GraphView />);
    const gutter = container.querySelector('[data-drop-gutter="after:round.2.p-permute"]');
    expect(gutter).not.toBeNull();
    if (!gutter) return;
    fireDropAt(gutter, "generic.byte-substitution@1");
    const loc = findStepAndParent(useSpec()(), "byte-substitution-1");
    expect(loc?.parent?.id).toBe("round.2");
    expect(loc?.trackIdx).toBe(1); // R track
    expect(loc?.indexInParent).toBe(4); // after p-permute (last, was at index 3)
  });

  it("drop on the feistel-round container (inter-track gap / header) inserts AFTER the round in its parent — " +
    "not into a track, not root-appended via the prependChildToContainer-throws fallback", () => {
    // Inter-track gap UX (DES plan Phase 6d, user-picked): drops
    // that fall through to the round chip's outer `data-drop-anchor`
    // should land "after this round in its parent" (the `rounds`
    // group's children, for DES). Without the dispatch
    // special-case, `prependChildToContainer` would throw on the
    // feistel-round kind (6d-iii's clearer error) and the store's
    // try/catch fallback would root-append — silently mis-scoping
    // the drop. Pin the explicit "after" semantic so a future
    // refactor of either branch can't silently regress it.
    const { container } = render(() => <GraphView />);
    // Find the round.4 container's data-drop-anchor element. The
    // anchor lives on the round chip's outer `<g>` per
    // ContainerRect's `data-drop-anchor={container.id}`.
    const roundAnchor = container.querySelector('[data-drop-anchor="round.4"]');
    expect(roundAnchor, "round.4 drop anchor must exist on the chip").not.toBeNull();
    if (!roundAnchor) return;
    fireDropAt(roundAnchor, "generic.byte-substitution@1");
    // Expected landing: as a child of the `rounds` group, at the
    // position immediately after round.4 (i.e. index 4, since the
    // group's children are round.1..round.16 at indices 0..15).
    const loc = findStepAndParent(useSpec()(), "byte-substitution-1");
    expect(loc, "inter-track-gap drop must land in the spec").not.toBeNull();
    expect(loc?.parent?.kind).toBe("group");
    expect(loc?.parent?.id).toBe("rounds");
    expect(loc?.indexInParent).toBe(4); // immediately after round.4
  });

  it("does not emit gutters for the synthetic passthrough or rejoin ids", () => {
    const { container } = render(() => <GraphView />);
    // The L-track passthrough id is in feistelTracks[0], but the gutter
    // logic filters it out — neither `before:` nor `after:` of any
    // passthrough id should appear as a gutter encoding.
    for (let n = 1; n <= 16; n++) {
      const passthroughId = `round.${n}:passthrough-0`;
      expect(
        container.querySelector(`[data-drop-gutter="before:${passthroughId}"]`),
        `unexpected gutter targeting passthrough ${passthroughId}`,
      ).toBeNull();
      expect(
        container.querySelector(`[data-drop-gutter="after:${passthroughId}"]`),
        `unexpected gutter targeting passthrough ${passthroughId}`,
      ).toBeNull();
      // Same for the rejoin synthetic.
      expect(container.querySelector(`[data-drop-gutter="before:round.${n}:rejoin"]`)).toBeNull();
      expect(container.querySelector(`[data-drop-gutter="after:round.${n}:rejoin"]`)).toBeNull();
    }
  });

  // UX-K (2026-05-23) — Surfaced during the manual browser smoke pass
  // after UX-F shipped: dragging a palette item onto the R-passthrough
  // chip (DES rounds 1..15 under feistel-standard) did nothing useful,
  // because the populated-track gutter emission only covered the REAL
  // chips' before/between/after strips — the R-passthrough chip's
  // visible footprint had no gutter at all, so drops fell through to
  // the round container's outer drop-anchor and silently inserted
  // AFTER the round in its parent. Asymmetric with the L-passthrough
  // drop semantic (which populates the empty track). Fix emits an
  // `into-track-start:${roundId}#1` gutter over the R-passthrough
  // chip's box too; drops prepend to the R-track without removing the
  // chip (the chip still represents R_in's bypass flow regardless of
  // what's at the head of the R-track).
  describe("UX-K — R-passthrough chip drop gutter (populated R-track)", () => {
    it("emits an into-track-start sentinel over the R-passthrough chip for rounds 1..15", () => {
      const { container } = render(() => <GraphView />);
      // Rounds 1..15 carry the R-bypass passthrough (feistel-standard).
      for (let n = 1; n <= 15; n++) {
        const encoding = `into-track-start:round.${n}#1`;
        const gutters = container.querySelectorAll(`[data-drop-gutter="${encoding}"]`);
        // ≥1 because the same encoding could be emitted once (over the
        // passthrough box). We only assert presence; geometry is
        // exercised by the drop-dispatch test below.
        expect(
          gutters.length,
          `R-track passthrough sentinel missing for round.${n}`,
        ).toBeGreaterThan(0);
      }
    });

    it("does NOT emit an R-track sentinel for round 16 (feistel-no-swap, no R-passthrough)", () => {
      const { container } = render(() => <GraphView />);
      const encoding = "into-track-start:round.16#1";
      const gutter = container.querySelector(`[data-drop-gutter="${encoding}"]`);
      expect(
        gutter,
        "round 16 has no R-passthrough chip so it must not emit an R-track sentinel",
      ).toBeNull();
    });

    it("drop on the R-passthrough sentinel prepends the new step at index 0 of the R-track", () => {
      const { container } = render(() => <GraphView />);
      // Pick a non-trivial round so we can distinguish "prepended to
      // R-track" from "appended to rounds group" cleanly.
      const sentinel = container.querySelector('[data-drop-gutter="into-track-start:round.5#1"]');
      expect(sentinel, "round.5 R-passthrough sentinel must exist").not.toBeNull();
      if (!sentinel) return;
      fireDropAt(sentinel, "generic.byte-substitution@1");
      const loc = findStepAndParent(useSpec()(), "byte-substitution-1");
      expect(loc, "drop must land somewhere in the spec").not.toBeNull();
      expect(loc?.parent?.kind).toBe("feistel-round");
      expect(loc?.parent?.id).toBe("round.5");
      expect(loc?.trackIdx).toBe(1); // R track
      expect(loc?.indexInParent).toBe(0); // prepended
    });

    it("R-track at-start (`before:expand-R`) strip still exists alongside the new passthrough sentinel", () => {
      // The fix adds the passthrough sentinel BEFORE the existing
      // at-start strip in the gutter array. We rely on the geometry
      // not overlapping (passthrough box ends at colTop+LEAF_H=colTop+28;
      // at-start strip starts at colTop+LEAF_H+STACK_GAP-CONTAINER_PAD =
      // colTop+30 — 2px clean gap). Asserting both are present so a
      // future refactor that accidentally merges them gets caught.
      const { container } = render(() => <GraphView />);
      expect(
        container.querySelector('[data-drop-gutter="into-track-start:round.1#1"]'),
      ).not.toBeNull();
      expect(
        container.querySelector('[data-drop-gutter="before:round.1.expand-R"]'),
      ).not.toBeNull();
    });
  });
});
