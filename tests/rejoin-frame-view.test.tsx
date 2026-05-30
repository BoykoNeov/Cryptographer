// @vitest-environment jsdom

/**
 * `RejoinFrameView` regression — retargeted to the toy Feistel fixture in B4
 * (universal-port Phase 4d). After the DES rebuild no shipped cipher emits
 * `:rejoin` frames, so this view is app-unreachable + Phase-5-doomed. It is
 * frame-driven (renders entirely from the rejoin frame's stashed params —
 * combineKind + L_in/L_out/R_in/R_out — and stateAfter; it does NOT read the
 * spec store), so the toy fixture exercises it directly.
 *
 * The toy's two rounds cover both combine kinds: round 1 = `feistel-standard`
 * (the common case), round 2 = `feistel-no-swap` (the DES round-16 analog).
 * Toy block is 4 bytes (vs DES's 8) — the only count that changed.
 *
 * Pins:
 *   - Header shows the combine kind + its formula text.
 *   - The 4 snapshots render in `COMBINE_KINDS[kind].inspectorRowOrder`.
 *   - Snapshots not consumed by the combine get `.rejoin-snapshot-unused`.
 *   - The result block splits `stateAfter` into `new_L` / `new_R`.
 *   - The fallback error renders when params lack the expected 4 keys.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { COMBINE_KINDS, REJOIN_STEP_TYPE } from "@/core/combine-kinds";
import { runSpec } from "@/core/runtime";
import type { BytesState, CombineKind, TraceFrame } from "@/core/types";
import { RejoinFrameView } from "@/ui/components/RejoinFrameView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const TOY_PT = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
};

const seedToyRejoinFrames = () => {
  const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: TOY_PT },
  });
  const round1 = trace.frames.find((f) => f.stepId === "round.1:rejoin");
  const round2 = trace.frames.find((f) => f.stepId === "round.2:rejoin");
  if (!round1) throw new Error("round.1 rejoin frame missing");
  if (!round2) throw new Error("round.2 rejoin frame missing");
  return { round1, round2 };
};

describe("RejoinFrameView — toy Feistel rejoin frames", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the combine kind and formula text in the header", () => {
    const { round1 } = seedToyRejoinFrames();
    const { container } = render(() => <RejoinFrameView frame={round1} />);
    const text = container.textContent ?? "";
    expect(round1.stepType).toBe(REJOIN_STEP_TYPE);
    expect(text).toContain("feistel-standard");
    expect(text).toContain(COMBINE_KINDS["feistel-standard"].formulaText);
  });

  it("renders all 4 snapshot rows in COMBINE_KINDS inspectorRowOrder", () => {
    const { round1 } = seedToyRejoinFrames();
    const { container } = render(() => <RejoinFrameView frame={round1} />);
    const labelEls = Array.from(container.querySelectorAll(".rejoin-snapshot-label"));
    const labels = labelEls.map((el) => el.textContent ?? "");
    expect(labels).toEqual([...COMBINE_KINDS["feistel-standard"].inspectorRowOrder]);
  });

  it("marks snapshots not consumed by the combine as `.rejoin-snapshot-unused`", () => {
    const { round1 } = seedToyRejoinFrames();
    const { container } = render(() => <RejoinFrameView frame={round1} />);
    const rows = Array.from(container.querySelectorAll(".rejoin-snapshot-row"));
    // feistel-standard: usesLOut=false, usesROut=true → L_out is the only
    // unused snapshot. L_in and R_in are always used.
    const unusedLabels = rows
      .filter((r) => r.classList.contains("rejoin-snapshot-unused"))
      .map((r) => r.querySelector(".rejoin-snapshot-label")?.textContent ?? "");
    expect(unusedLabels).toEqual(["L_out"]);
  });

  it("renders new_L and new_R rows derived from stateAfter", () => {
    const { round1 } = seedToyRejoinFrames();
    const { container } = render(() => <RejoinFrameView frame={round1} />);
    const resultLabels = Array.from(container.querySelectorAll(".rejoin-result-row-label")).map(
      (el) => el.textContent ?? "",
    );
    expect(resultLabels).toEqual(["new_L", "new_R"]);
    // Toy block is 4 bytes (L = 2, R = 2). The KAT test covers the values.
    const after = round1.stateAfter as BytesState;
    expect(after.bytes.length).toBe(4);
  });

  it("swaps row order between feistel-standard and feistel-no-swap (round 2)", () => {
    const { round2 } = seedToyRejoinFrames();
    const params = round2.params as Record<string, unknown>;
    expect(params.combineKind).toBe("feistel-no-swap" satisfies CombineKind);
    const { container } = render(() => <RejoinFrameView frame={round2} />);
    const labels = Array.from(container.querySelectorAll(".rejoin-snapshot-label")).map(
      (el) => el.textContent ?? "",
    );
    expect(labels).toEqual([...COMBINE_KINDS["feistel-no-swap"].inspectorRowOrder]);
  });

  it("renders the fallback error when params lack the expected snapshot fields", () => {
    // Hand-rolled malformed rejoin frame — the runtime never produces this
    // (the stash is unconditional), but the inspector must degrade gracefully.
    const malformed: TraceFrame = {
      index: 0,
      path: [],
      stepId: "round.1:rejoin",
      stepType: REJOIN_STEP_TYPE,
      params: { combineKind: "feistel-standard" },
      stateBefore: { shape: "bytes", bytes: new Uint8Array(4) },
      stateAfter: { shape: "bytes", bytes: new Uint8Array(4) },
      auxRead: new Map(),
      auxWritten: new Map(),
    };
    const { container } = render(() => <RejoinFrameView frame={malformed} />);
    expect(container.querySelector(".rejoin-frame-error")).not.toBeNull();
  });
});
