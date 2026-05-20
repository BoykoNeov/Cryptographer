// @vitest-environment jsdom

/**
 * Phase 5f of `docs/plans/des-feistel.md` — scrubber timeline badges.
 *
 * Per-frame markers above the slider track:
 *   - L / R (track name letter) for in-track Feistel frames
 *   - ⇄ for synthetic rejoin frames
 *   - nothing for root-scope frames (IP, FP, key-schedule)
 *
 * For non-Feistel ciphers the badge strip stays empty (no badges
 * render) since the trace has no track or rejoin frames at all. AES
 * gets no strip; DES gets the full L/R + ⇄ overlay.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { TraceTimeline } from "@/ui/components/TraceTimeline";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const seedDes = () => {
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])),
    initialAux: new Map<string, AuxValue>([
      ["key", new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1])],
    ]),
  });
  setTrace(trace);
  return trace;
};

const seedAes = () => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex("00112233445566778899aabbccddeeff")),
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

  it("renders an R badge for every in-track DES frame", () => {
    const trace = seedDes();
    const { container } = render(() => <TraceTimeline />);
    expect(container.querySelector(".trace-timeline-badge-strip")).not.toBeNull();
    // DES has 16 rounds × 4 R-track leaves = 64 in-track frames. Each
    // renders a track badge labelled "R" (L track is empty, so no L badges).
    const trackBadges = container.querySelectorAll(".trace-timeline-badge-track");
    expect(trackBadges.length).toBe(64);
    for (const b of Array.from(trackBadges)) {
      expect(b.textContent).toBe("R");
    }
    // Cross-check against the trace itself.
    const inTrackFrameCount = trace.frames.filter(
      (f) => f.branchPath !== undefined && f.branchPath.length > 0,
    ).length;
    expect(trackBadges.length).toBe(inTrackFrameCount);
  });

  it("renders a ⇄ badge for each rejoin frame (16 in DES)", () => {
    seedDes();
    const { container } = render(() => <TraceTimeline />);
    const rejoinBadges = container.querySelectorAll(".trace-timeline-badge-rejoin");
    expect(rejoinBadges.length).toBe(16);
    for (const b of Array.from(rejoinBadges)) {
      expect(b.textContent).toBe("⇄");
    }
  });

  it("badges position by frame index — first L/R badge at small percent, last near 100%", () => {
    const trace = seedDes();
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
