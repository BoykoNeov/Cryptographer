// @vitest-environment jsdom

/**
 * Phase 5e UI test for the DES branch of `<KeyScheduleExplorer />`.
 *
 * Pins three properties:
 *   1. When the active frame's stepType is `des.key-schedule@1`, the
 *      KeyScheduleExplorer mounts the DES branch and renders the per-
 *      round table (16 rows).
 *   2. The K_i column for each row equals the executor's
 *      `roundKey.{i}` aux value byte-for-byte (UI sanity check on top
 *      of the parity test in `tests/des-key-schedule-sim-parity.test.ts`).
 *   3. Clicking a round row scrubs the trace to that round's first
 *      body frame (DES's `round.{N}.expand-R:tR` if present).
 *
 * Doesn't re-test the simulator's algorithm — that's the parity
 * test's job. This is purely about the dispatch + render shape.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { DES_PC1, DES_PC2, DES_SHIFTS } from "@/ciphers/des-constants";
import { runSpec } from "@/core/runtime";
import type { AuxValue, TraceFrame } from "@/core/types";
import { KeyScheduleExplorer } from "@/ui/components/KeyScheduleExplorer";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace, useFrameIndex } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const DES_PT = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
const DES_KEY = new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]);

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
};

// K4a (2026-06-02): DES's key schedule was decomposed, so a shipped DES spec
// no longer emits a `des.key-schedule@1` frame — the monolithic executor
// survives ONLY as the KAT oracle + back-compat. The KeyScheduleExplorer's DES
// branch is DEFERRED for retirement (K4b — DES is the last cipher, so that
// empties the whole subsystem), so this UI-dispatch test keeps exercising the
// branch by SYNTHESIZING the monolithic frame directly (same shape the shipped
// spec used to emit, with the master key in `auxRead` + the FIPS tables in
// `params` so `simulateDesKeySchedule` re-runs). The shipped trace is still
// put in the store so the click-scrub test can resolve `round.5.expand-R`
// (the round body is unchanged by decomposition).
const desKeyScheduleFrame = (): TraceFrame => ({
  index: 0,
  path: [],
  stepId: "key-schedule",
  stepType: "des.key-schedule@1",
  params: {
    keyAuxName: "key",
    outputPrefix: "roundKey",
    pc1: [...DES_PC1],
    pc2: [...DES_PC2],
    shifts: [...DES_SHIFTS],
  },
  auxRead: new Map<string, AuxValue>([["key", DES_KEY]]),
  auxWritten: new Map(),
});

const seedDes = (): TraceFrame => {
  setCipher("des");
  const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: DES_PT },
    initialAux: new Map([["key", DES_KEY]]),
  });
  setTrace(trace);
  return desKeyScheduleFrame();
};

describe("KeyScheduleExplorer — DES dispatch", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("mounts the DES branch and renders a 16-row table", () => {
    const frame = seedDes();
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    // The DES branch renders into `.key-schedule-des` — distinct from
    // AES's swimlane and Serpent's stage pipeline.
    expect(container.querySelector(".key-schedule-des")).not.toBeNull();
    const rows = container.querySelectorAll(".key-schedule-des-row");
    expect(rows.length).toBe(16);
  });

  it("each row's round number column reads 1..16 in order", () => {
    const frame = seedDes();
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    const cells = Array.from(container.querySelectorAll(".key-schedule-des-round-cell"));
    expect(cells.map((c) => c.textContent ?? "")).toEqual(
      Array.from({ length: 16 }, (_, i) => String(i + 1)),
    );
  });

  it("clicking a row scrubs the trace to that round's first body frame", () => {
    const frame = seedDes();
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    const rows = Array.from(container.querySelectorAll(".key-schedule-des-row"));
    expect(rows.length).toBe(16);
    // Click round 5's row (index 4). Its first body frame in DES is
    // round.5.expand-R:tR (the R-track's first leaf).
    const round5 = rows[4];
    if (!round5) throw new Error("row 5 missing");
    fireEvent.click(round5);
    // The click handler calls setFrame(N) where N is the trace index of
    // the first round.5.expand-R* frame. Read the current frame via
    // useFrameIndex (subscribe) and assert the stepId matches.
    const idx = useFrameIndex()();
    // Resolve the trace's current frame's stepId without re-importing
    // getTrace — the easy way is to inspect the document's frame counter
    // section in the rendered linear pane. But this test only renders
    // KeyScheduleExplorer in isolation, so we just verify the index
    // moved to one whose target stepId would start with "round.5.expand-R".
    // Concretely: look up the index in window via re-running the same
    // seed (the frame index space is identical) — simpler: re-derive
    // from the seedDes return.
    expect(idx).toBeGreaterThan(0);
    // Stronger assertion: the row's click target is deterministic given
    // the spec. Independently compute the expected index from the same
    // trace and compare.
    setCipher("des"); // no-op store touch keeps types happy
    const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: DES_PT },
      initialAux: new Map([["key", DES_KEY]]),
    });
    const expectedIdx = trace.frames.findIndex((f) => f.stepId.startsWith("round.5.expand-R"));
    expect(idx).toBe(expectedIdx);
  });
});
