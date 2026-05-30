// @vitest-environment jsdom

/**
 * Phase 5f of `docs/plans/des-feistel.md` — scrubber timeline badges.
 *
 * Per-frame markers above the slider track:
 *   - L / R (track name letter) for in-track Feistel frames
 *   - ⇄ for synthetic rejoin frames
 *   - nothing for root-scope frames (IP, FP, key-schedule)
 *
 * For non-Feistel ciphers the badge strip stays empty (no badges render)
 * since the trace has no track or rejoin frames. AES gets no strip; a
 * `feistel-round` trace gets the full track + ⇄ overlay.
 *
 * Retargeted to the toy Feistel fixture in B4 (universal-port Phase 4d):
 * after the DES rebuild no shipped cipher emits track/rejoin frames, so the
 * `feistel-round` badge path is exercised against `FEISTEL_TOY_SPEC` — 2
 * rounds, each with one R-track leaf (`add-k`) → 2 track badges + 2 rejoin
 * badges (vs DES's 64 + 16). TraceTimeline is trace-driven (no spec store),
 * so the toy trace drives it directly.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { TraceTimeline } from "@/ui/components/TraceTimeline";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const seedToy = () => {
  const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
    initialState: makeBytesState(new Uint8Array([0x01, 0x02, 0x03, 0x04])),
  });
  setTrace(trace);
  return trace;
};

const seedAes = () => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
    portedDispatchEnabled: true,
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
    ]),
  });
  setTrace(trace);
  return trace;
};

describe("TraceTimeline — Phase 5f track badges", () => {
  beforeEach(() => __resetTraceForTests());
  afterEach(() => {
    cleanup();
    __resetTraceForTests();
  });

  it("renders no badge strip when the trace has no Feistel frames (AES-128)", () => {
    seedAes();
    const { container } = render(() => <TraceTimeline />);
    expect(container.querySelector(".trace-timeline-badge-strip")).toBeNull();
  });

  it("renders an R badge for every in-track Feistel frame", () => {
    const trace = seedToy();
    const { container } = render(() => <TraceTimeline />);
    expect(container.querySelector(".trace-timeline-badge-strip")).not.toBeNull();
    // The toy has 2 rounds × 1 R-track leaf = 2 in-track frames. Each renders
    // a track badge labelled "R" (the L track is empty, so no L badges).
    const trackBadges = container.querySelectorAll(".trace-timeline-badge-track");
    expect(trackBadges.length).toBe(2);
    for (const b of Array.from(trackBadges)) {
      expect(b.textContent).toBe("R");
    }
    // Cross-check against the trace itself.
    const inTrackFrameCount = trace.frames.filter(
      (f) => f.branchPath !== undefined && f.branchPath.length > 0,
    ).length;
    expect(trackBadges.length).toBe(inTrackFrameCount);
  });

  it("renders a ⇄ badge for each rejoin frame (2 in the toy)", () => {
    seedToy();
    const { container } = render(() => <TraceTimeline />);
    const rejoinBadges = container.querySelectorAll(".trace-timeline-badge-rejoin");
    expect(rejoinBadges.length).toBe(2);
    for (const b of Array.from(rejoinBadges)) {
      expect(b.textContent).toBe("⇄");
    }
  });

  it("badges position by frame index — first track badge at small percent, last near 100%", () => {
    const trace = seedToy();
    const { container } = render(() => <TraceTimeline />);
    const badges = Array.from(container.querySelectorAll(".trace-timeline-badge")) as HTMLElement[];
    expect(badges.length).toBeGreaterThan(0);
    // The first track badge's index in the trace is the first frame
    // whose branchPath is set — round.1.expand-R is what we expect.
    // Its percentage should be (firstIdx / maxIdx) * 100.
    const firstIdx = trace.frames.findIndex((f) => f.branchPath !== undefined);
    const maxIdx = trace.frames.length - 1;
    const expectedFirstPct = (firstIdx / maxIdx) * 100;
    const firstLeft = badges[0]?.style.left ?? "";
    expect(firstLeft).toBe(`${expectedFirstPct}%`);
    // Last badge ≈ last rejoin or last R-track step → near 100% but not
    // necessarily exactly 100 (FP comes after the rounds). Just confirm
    // it's > 0% and < 100%.
    const lastLeft = badges[badges.length - 1]?.style.left ?? "";
    const lastPct = Number.parseFloat(lastLeft);
    expect(lastPct).toBeGreaterThan(0);
    expect(lastPct).toBeLessThanOrEqual(100);
  });
});
