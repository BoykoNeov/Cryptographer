// @vitest-environment jsdom

/**
 * Phase 5c of `docs/plans/des-feistel.md` — `RejoinFrameView` regression.
 *
 * The default `<FrameStateView />` rendering for a synthetic rejoin frame
 * showed two opaque 8-byte concatenation blobs (stateBefore =
 * L_out || R_out; stateAfter = new_L || new_R). Pedagogically meaningless.
 *
 * `<RejoinFrameView />` replaces it with a 4-snapshot inspector + result
 * split. This file pins:
 *   - The header shows the combine kind + its formula text.
 *   - The 4 snapshots render in `COMBINE_KINDS[kind].inspectorRowOrder`.
 *   - Snapshots NOT consumed by the combine (e.g. `L_out` under
 *     `feistel-standard`) render with the `.rejoin-snapshot-unused` class.
 *   - The result block splits `stateAfter` into `new_L` / `new_R`.
 *   - The fallback error renders when params lack the expected 4 keys
 *     (defensive — runtime today always emits them, but a malformed
 *     fixture shouldn't crash the view).
 *
 * Uses the DES spec's round-1 rejoin frame as the primary fixture since
 * it exercises the most common combine kind (`feistel-standard`); a
 * second case (`feistel-no-swap` from DES round 16) confirms the row
 * order swaps in lock-step with the formula.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { COMBINE_KINDS, REJOIN_STEP_TYPE } from "@/core/combine-kinds";
import { runSpec } from "@/core/runtime";
import type { BytesState, CombineKind, TraceFrame } from "@/core/types";
import { RejoinFrameView } from "@/ui/components/RejoinFrameView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
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

const seedDesRejoinFrames = () => {
  setCipher("des");
  const trace = runSpec(useSpec()(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: DES_PT },
    initialAux: new Map([["key", DES_KEY]]),
  });
  const round1 = trace.frames.find((f) => f.stepId === "round.1:rejoin");
  const round16 = trace.frames.find((f) => f.stepId === "round.16:rejoin");
  if (!round1) throw new Error("round.1 rejoin frame missing");
  if (!round16) throw new Error("round.16 rejoin frame missing");
  return { round1, round16 };
};

describe("RejoinFrameView — DES rejoin frames", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the combine kind and formula text in the header", () => {
    const { round1 } = seedDesRejoinFrames();
    const { container } = render(() => <RejoinFrameView frame={round1} />);
    const text = container.textContent ?? "";
    expect(round1.stepType).toBe(REJOIN_STEP_TYPE);
    expect(text).toContain("feistel-standard");
    // Formula text comes from COMBINE_KINDS metadata so it tracks the
    // canonical formula instead of duplicating the literal here.
    expect(text).toContain(COMBINE_KINDS["feistel-standard"].formulaText);
  });

  it("renders all 4 snapshot rows in COMBINE_KINDS inspectorRowOrder", () => {
    const { round1 } = seedDesRejoinFrames();
    const { container } = render(() => <RejoinFrameView frame={round1} />);
    const labelEls = Array.from(container.querySelectorAll(".rejoin-snapshot-label"));
    const labels = labelEls.map((el) => el.textContent ?? "");
    expect(labels).toEqual([...COMBINE_KINDS["feistel-standard"].inspectorRowOrder]);
  });

  it("marks snapshots not consumed by the combine as `.rejoin-snapshot-unused`", () => {
    const { round1 } = seedDesRejoinFrames();
    const { container } = render(() => <RejoinFrameView frame={round1} />);
    const rows = Array.from(container.querySelectorAll(".rejoin-snapshot-row"));
    // feistel-standard: usesLOut=false, usesROut=true → L_out is the
    // only unused snapshot. L_in and R_in are always used.
    const unusedLabels = rows
      .filter((r) => r.classList.contains("rejoin-snapshot-unused"))
      .map((r) => r.querySelector(".rejoin-snapshot-label")?.textContent ?? "");
    expect(unusedLabels).toEqual(["L_out"]);
  });

  it("renders new_L and new_R rows derived from stateAfter", () => {
    const { round1 } = seedDesRejoinFrames();
    const { container } = render(() => <RejoinFrameView frame={round1} />);
    const resultLabels = Array.from(container.querySelectorAll(".rejoin-result-row-label")).map(
      (el) => el.textContent ?? "",
    );
    expect(resultLabels).toEqual(["new_L", "new_R"]);
    // Sanity check: stateAfter for round 1 is the published intermediate
    // (L_1 || R_1) per FIPS 46-3 Appendix B; we only need to confirm a
    // result block exists, not its byte value (the KAT test covers that).
    const after = round1.stateAfter as BytesState;
    expect(after.bytes.length).toBe(8);
  });

  it("swaps row order between feistel-standard and feistel-no-swap (round 16)", () => {
    const { round16 } = seedDesRejoinFrames();
    const params = round16.params as Record<string, unknown>;
    expect(params.combineKind).toBe("feistel-no-swap" satisfies CombineKind);
    const { container } = render(() => <RejoinFrameView frame={round16} />);
    const labels = Array.from(container.querySelectorAll(".rejoin-snapshot-label")).map(
      (el) => el.textContent ?? "",
    );
    expect(labels).toEqual([...COMBINE_KINDS["feistel-no-swap"].inspectorRowOrder]);
  });

  it("renders the fallback error when params lack the expected snapshot fields", () => {
    // Hand-rolled malformed rejoin frame — runtime never produces this
    // today (Phase 5c stash is unconditional), but the inspector must
    // degrade gracefully rather than crashing on a missing key.
    const malformed: TraceFrame = {
      index: 0,
      path: [],
      stepId: "round.1:rejoin",
      stepType: REJOIN_STEP_TYPE,
      params: { combineKind: "feistel-standard" },
      stateBefore: { shape: "bytes", bytes: new Uint8Array(8) },
      stateAfter: { shape: "bytes", bytes: new Uint8Array(8) },
      auxRead: new Map(),
      auxWritten: new Map(),
    };
    const { container } = render(() => <RejoinFrameView frame={malformed} />);
    expect(container.querySelector(".rejoin-frame-error")).not.toBeNull();
  });
});
