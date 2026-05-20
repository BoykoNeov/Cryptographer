// @vitest-environment jsdom

/**
 * Phase 5a of `docs/plans/des-feistel.md` — `FeistelTrackContext` panel.
 *
 * The panel renders when the active frame's `branchPath` is non-empty
 * (i.e. inside a feistel-round body) and otherwise stays hidden. It
 * reconstructs the round's L_in / R_in from the rejoin frame's stashed
 * params (Phase 5c runtime change) and the round's outputs from
 * `rejoin.stateAfter` split at L_in.length.
 *
 * Pins:
 *   - Hidden when frame.branchPath is empty (root-scope frames: IP,
 *     FP, key-schedule).
 *   - Renders when frame.branchPath has an entry (DES R-track leaves).
 *   - Round entry / Right now / Round output sections all appear.
 *   - The current track's row carries `.feistel-context-track-current`
 *     while the other track's row does not.
 *   - The round id matches the spec (round.N for DES).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { TraceFrame } from "@/core/types";
import { FeistelTrackContext } from "@/ui/components/FeistelTrackContext";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
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

type SeedResult = {
  ipFrame: TraceFrame; // root scope, no branchPath
  rTrackFrame: TraceFrame; // inside round 1 R track
};

const seed = (): SeedResult => {
  setCipher("des");
  const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: DES_PT },
    initialAux: new Map([["key", DES_KEY]]),
  });
  setTrace(trace);
  const ipFrame = trace.frames.find((f) => f.stepType === "des.initial-permutation@1");
  const rTrackFrame = trace.frames.find((f) => f.stepId.startsWith("round.1.expand-R"));
  if (!ipFrame || !rTrackFrame) throw new Error("expected frames missing from seed");
  return { ipFrame, rTrackFrame };
};

describe("FeistelTrackContext — DES rendering", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing when frame.branchPath is empty (root-scope IP frame)", () => {
    const { ipFrame } = seed();
    expect(ipFrame.branchPath).toBeUndefined();
    const { container } = render(() => <FeistelTrackContext frame={ipFrame} />);
    expect(container.querySelector(".feistel-track-context")).toBeNull();
  });

  it("renders the round context panel when inside an R-track frame", () => {
    const { rTrackFrame } = seed();
    expect(rTrackFrame.branchPath).toEqual(["R"]);
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    const panel = container.querySelector(".feistel-track-context");
    expect(panel).not.toBeNull();
    const text = panel?.textContent ?? "";
    expect(text).toContain("round.1");
    expect(text).toContain("R");
  });

  it("renders all three sections (round entry, right now, round output)", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    const sectionTitles = Array.from(
      container.querySelectorAll(".feistel-context-section-title"),
    ).map((el) => el.textContent ?? "");
    expect(sectionTitles).toEqual(["round entry", "right now", "round output"]);
  });

  it("flags the current track row with .feistel-context-track-current", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    // Round entry has L + R rows. The R row (current track) should be
    // flagged; the L row should NOT be.
    const entrySection = container.querySelectorAll(".feistel-context-section")[0];
    if (!entrySection) throw new Error("round entry section missing");
    const rows = entrySection.querySelectorAll(".feistel-context-track-row");
    expect(rows.length).toBe(2);
    const trackNames = Array.from(rows).map(
      (row) => row.querySelector(".feistel-context-track-name")?.textContent ?? "",
    );
    expect(trackNames).toEqual(["L", "R"]);
    // L (index 0) is not current; R (index 1) is current.
    expect(rows[0]?.classList.contains("feistel-context-track-current")).toBe(false);
    expect(rows[1]?.classList.contains("feistel-context-track-current")).toBe(true);
  });

  it("renders new_L and new_R labels in the round output section", () => {
    const { rTrackFrame } = seed();
    const { container } = render(() => <FeistelTrackContext frame={rTrackFrame} />);
    const outputSection = container.querySelectorAll(".feistel-context-section")[2];
    if (!outputSection) throw new Error("round output section missing");
    const names = Array.from(outputSection.querySelectorAll(".feistel-context-track-name")).map(
      (el) => el.textContent ?? "",
    );
    expect(names).toEqual(["L'", "R'"]);
  });
});
