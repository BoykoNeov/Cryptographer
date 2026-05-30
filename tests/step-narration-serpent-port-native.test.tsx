// @vitest-environment jsdom

/**
 * B3 (scaffolding-suppression) regression pin — the port-native Serpent
 * round-body and IP/FP frames still render correctly in the linear inspector.
 *
 * When the five Serpent round-body executors went byte-native (B3), their
 * trace frames flipped from lifted-legacy (`legacy` defined → port fields
 * undefined) to port-native (`legacy === undefined` → `portInputs`/
 * `portOutputs` populated, runtime.ts). That flips two things in the linear
 * view, NEITHER of which the green gate otherwise covers for Serpent:
 *
 *   1. `isPortNativeFrame` now returns true for every converted leaf, so
 *      `FrameStateView` routes them to `PortFlowView` instead of `BytesView`.
 *      Serpent rounds are a HYBRID — port-native AND state-threading (they keep
 *      `meta.stateOutputPort` so `stateBefore !== stateAfter`), like B2 Speck.
 *      This pins that AddRoundKey's PortFlowView renders its `state` AND
 *      `roundKey` input ports — the `roundKey` port is projected by the runtime
 *      from `aux[roundKeyAux]` via `meta.auxReadPorts`, the single highest-risk
 *      change in B3 (the executor dropped its `ctx.aux` access + `auxReads`).
 *
 *   2. `<StepNarration>` is rendered unconditionally below the state view and
 *      looks the narrator up by `stepType` — it is NOT gated on the port
 *      fields. This pins that the per-type prose still appears for port-native
 *      frames. Serpent round-body leaves carry NO `narrationOverride` (unlike
 *      AES byte-native rounds) — they rely on the registry-keyed narration fn,
 *      so this is the load-bearing check that the registry path survives the
 *      lifted → port-native flip.
 *
 * Narration coverage note (corrects the B3 handoff brief, which lumped all four
 * pure transforms together): `serpent.bit-permutation@1` (IP/FP) IS narrated
 * (1 structural-overview + 16 per-output-byte drills = 17 units — each output
 * bit comes from a single input bit, so the per-byte drill is honest). Only
 * `serpent.linear-transform@1` / `serpent.inv-linear-transform@1` are on
 * `NARRATION_NO_OP_ALLOWLIST` (each output bit XORs 6–7 input bits, where
 * byte-level prose would mislead). SubBytes (16 units) + AddRoundKey (16 units)
 * are narrated too.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, TraceFrame } from "@/core/types";
import { PortFlowView, isPortNativeFrame } from "@/ui/components/PortFlowView";
import { StepNarration } from "@/ui/components/StepNarration";
import "@/ui/narration/index"; // eagerly register the narrators
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const KEY = "80000000000000000000000000000000";
const PT = "00000000000000000000000000000000";

const serpentFrames = (): TraceFrame[] => {
  const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
    portedDispatchEnabled: true,
  });
  return [...trace.frames];
};

const frameBy = (fs: TraceFrame[], stepId: string): TraceFrame => {
  const f = fs.find((fr) => fr.stepId === stepId);
  if (!f) throw new Error(`expected a ${stepId} frame`);
  return f;
};

const unitCount = (frame: TraceFrame): number => {
  const { container } = render(() => <StepNarration frame={frame} />);
  return container.querySelectorAll(".step-narration-unit").length;
};

describe("port-native Serpent frames — linear inspector surfaces (B3)", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("all five converted step types produce port-native frames (route to PortFlowView)", () => {
    const fs = serpentFrames();
    // The two bit-permutation leaves are TOP-LEVEL (outside any round group):
    // IP before round 1, FP after round 32. The other three are round-body.
    // (inv-linear-transform is decrypt-only — pinned by the golden checksum +
    // KAT in runtime-ported-dispatch-serpent; not present in this encrypt run.)
    for (const id of [
      "initial-permutation",
      "final-permutation",
      "round.1.add-round-key",
      "round.1.sub-bytes",
      "round.1.linear-transform",
    ]) {
      expect(isPortNativeFrame(frameBy(fs, id)), `${id} should be port-native`).toBe(true);
    }
  });

  it("<PortFlowView> for AddRoundKey renders the state + roundKey input ports and state output", () => {
    const f = frameBy(serpentFrames(), "round.1.add-round-key");
    const { container } = render(() => <PortFlowView frame={f} />);
    const inputLabels = Array.from(
      container.querySelectorAll(".port-flow-section[data-section='inputs'] .port-label"),
    ).map((el) => el.textContent ?? "");
    const outputLabels = Array.from(
      container.querySelectorAll(".port-flow-section[data-section='outputs'] .port-label"),
    ).map((el) => el.textContent ?? "");
    // The threaded 128-bit block + the aux-projected round key on inputs; the
    // XORed block on output. The `roundKey` port appearing here is the visual
    // proof that `meta.auxReadPorts` still projects `aux[roundKeyAux]`.
    expect(inputLabels.some((l) => l.includes("state"))).toBe(true);
    expect(inputLabels.some((l) => l.includes("roundKey"))).toBe(true);
    expect(outputLabels.some((l) => l.includes("state"))).toBe(true);

    // Both Serpent ports carry a 16-byte buffer → 16 cells each.
    const inputRows = container.querySelectorAll(
      ".port-flow-section[data-section='inputs'] .port-row",
    );
    const cellCounts = Array.from(inputRows).map((r) => r.querySelectorAll(".bytes-cell").length);
    expect(cellCounts.filter((c) => c === 16).length).toBe(2);
  });

  it("<StepNarration> still renders the per-type prose on port-native frames", () => {
    const fs = serpentFrames();
    // SubBytes — one unit per byte (16 nibble-pairs).
    expect(unitCount(frameBy(fs, "round.1.sub-bytes"))).toBe(16);
    cleanup();
    // AddRoundKey — one unit per XORed byte (reads the consumed K_i from the
    // populated `auxRead`, which only exists because the meta projection fired).
    expect(unitCount(frameBy(fs, "round.1.add-round-key"))).toBe(16);
    cleanup();
    // IP (bit-permutation) — 1 structural overview + 16 per-output-byte drills.
    expect(unitCount(frameBy(fs, "initial-permutation"))).toBe(17);
  });

  it("<StepNarration> stays empty for the no-op LinearTransform (NARRATION_NO_OP_ALLOWLIST)", () => {
    // serpent.linear-transform@1 is allowlisted — byte-level prose would mislead
    // (each output bit XORs 6–7 input bits). The narrator returns null → no units.
    expect(unitCount(frameBy(serpentFrames(), "round.1.linear-transform"))).toBe(0);
  });
});
