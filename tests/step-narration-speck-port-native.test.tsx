// @vitest-environment jsdom

/**
 * B2 (scaffolding-suppression) regression pin — the port-native Speck round
 * frame still renders correctly in the linear inspector.
 *
 * When `speck.round@1` went byte-native (B2), its trace frames flipped from
 * lifted-legacy (`legacy` defined → port fields undefined) to port-native
 * (`legacy === undefined` → `portInputs`/`portOutputs` populated, runtime.ts).
 * That flips two things in the linear view, NEITHER of which the green gate
 * otherwise covers for Speck:
 *
 *   1. `isPortNativeFrame` now returns true, so `FrameStateView` routes the
 *      round to `PortFlowView` instead of `BytesView`. Speck rounds are a
 *      HYBRID — port-native AND state-threading (they keep `meta.stateOutputPort`
 *      so `stateBefore !== stateAfter`), unlike the pure-port SHA/AES frames
 *      the existing `port-flow-view` test uses. This pins that PortFlowView
 *      renders the round's `state` + `roundKey` input ports and `state` output.
 *
 *   2. `<StepNarration>` is rendered unconditionally below the state view and
 *      looks the narrator up by `stepType` — it is NOT gated on the port
 *      fields. This pins that the ARX prose still appears for a port-native
 *      Speck round (the pedagogy is preserved; the narrator reads
 *      `frame.stateBefore`/`auxRead`, both still populated). Speck rounds carry
 *      NO `narrationOverride` (unlike AES byte-native rounds) — they rely on the
 *      registry-keyed narration fn, so this is the load-bearing check that the
 *      registry path survives the lifted → port-native flip.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, TraceFrame } from "@/core/types";
import { PortFlowView, isPortNativeFrame } from "@/ui/components/PortFlowView";
import { StepNarration } from "@/ui/components/StepNarration";
import "@/ui/narration/index"; // eagerly register the narrators
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const BE_KEY = "1918111009080100";
const BE_PT = "6574694c";

const speckRoundFrame = (): TraceFrame => {
  const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(BE_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
  });
  // frame 0 = key-schedule; frame 1 = round.1 (the first port-native ARX round).
  const f = trace.frames.find((fr) => fr.stepId === "round.1");
  if (!f) throw new Error("expected a round.1 frame");
  return f;
};

describe("port-native Speck round frame — linear inspector surfaces", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("the round frame is port-native (routes to PortFlowView)", () => {
    expect(isPortNativeFrame(speckRoundFrame())).toBe(true);
  });

  it("<StepNarration> still renders the 3 ARX sub-op disclosures with the ROR prose", () => {
    const { container } = render(() => <StepNarration frame={speckRoundFrame()} />);
    const units = container.querySelectorAll(".step-narration-unit");
    // The forward round narrator yields exactly 3 ARX sub-op units.
    expect(units.length).toBe(3);
    const firstSummary = units[0]?.querySelector("summary")?.textContent ?? "";
    expect(firstSummary).toContain("ROR");
    // The body prose names the cipher-defining rotation amount α = 7.
    const allText = container.textContent ?? "";
    expect(allText).toContain("α = 7");
  });

  it("<PortFlowView> renders the round's state + roundKey inputs and state output", () => {
    const { container } = render(() => <PortFlowView frame={speckRoundFrame()} />);
    const inputLabels = Array.from(
      container.querySelectorAll(".port-flow-section[data-section='inputs'] .port-label"),
    ).map((el) => el.textContent ?? "");
    const outputLabels = Array.from(
      container.querySelectorAll(".port-flow-section[data-section='outputs'] .port-label"),
    ).map((el) => el.textContent ?? "");
    // Two inputs (the threaded block + the projected round key); one output.
    expect(inputLabels.some((l) => l.includes("state"))).toBe(true);
    expect(inputLabels.some((l) => l.includes("roundKey"))).toBe(true);
    expect(outputLabels.some((l) => l.includes("state"))).toBe(true);

    // The 4-byte block port has 4 cells; the 2-byte round-key port has 2.
    const inputRows = container.querySelectorAll(
      ".port-flow-section[data-section='inputs'] .port-row",
    );
    const cellCounts = Array.from(inputRows).map((r) => r.querySelectorAll(".bytes-cell").length);
    expect(cellCounts).toContain(4); // state block
    expect(cellCounts).toContain(2); // round-key word
  });
});
