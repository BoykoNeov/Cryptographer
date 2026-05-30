// @vitest-environment jsdom

/**
 * B4 (universal-port Phase 4d) regression pin — the port-native DES round
 * leaves still narrate the ROUND-LOCAL bytes in the linear inspector.
 *
 * **The trap this guards.** Unlike Speck (B2) / Serpent (B3) — which stayed
 * state-threading hybrids (kept `meta.stateInputPort`/`stateOutputPort`, so
 * each frame's `stateBefore`/`stateAfter` held the correct round-local value)
 * — DES dropped those projection meta fields on all six F-leaves (correct for
 * the clean port-native graph). The runtime only reconstructs the threaded
 * `state` when `meta.stateOutputPort` is set, so for port-native DES the
 * threaded `state` is NEVER updated through the rounds: every DES frame's
 * `stateBefore`/`stateAfter` holds the STALE initial plaintext. The honest
 * per-leaf bytes live on the port I/O (`frame.portInputs`/`portOutputs`).
 *
 * The DES narrators were written in the feistel era when `stateBefore` was
 * correct. B4 repointed them at the port I/O (`frameStateIn`/`frameStateOut`
 * in `ui/narration/des.tsx`). This test pins that fix with a sharp
 * discriminator: the E / S-box / xor-K narrators check their input length
 * (4 / 6 / 6 bytes), so if they read the 8-byte stale state they would return
 * `null` (narration vanishes) — rendering non-empty proves they read the
 * correctly-sized port input. `narration-registry-contract` only checks a
 * narrator EXISTS, not that it reads the right bytes; this is the missing half.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, BytesState, TraceFrame } from "@/core/types";
import { PortFlowView, isPortNativeFrame } from "@/ui/components/PortFlowView";
import { StepNarration } from "@/ui/components/StepNarration";
import {
  desExpandRNarration,
  desInitialPermutationNarration,
  desSBoxesNarration,
  desXorWithKNarration,
} from "@/ui/narration/des";
import "@/ui/narration/index"; // eagerly register the narrators
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// FIPS 46-3 Appendix B vector (PT=0123456789abcdef, K=133457799bbcdff1).
// From tests/fixtures/des-kat.json: ip = cc00ccfff0aaf0aa; round 1 R_in =
// f0aaf0aa, E = 7a15557a1555.
const DES_PT = "0123456789abcdef";
const DES_KEY = "133457799bbcdff1";

const frameById = (stepId: string): TraceFrame => {
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(DES_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(DES_KEY)]]),
    portedDispatchEnabled: true,
  });
  const f = trace.frames.find((fr) => fr.stepId === stepId);
  if (!f) throw new Error(`expected a ${stepId} frame`);
  return f;
};

describe("port-native DES round leaves — narration reads port I/O, not stale state", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("a round F-leaf frame is port-native (routes to PortFlowView)", () => {
    expect(isPortNativeFrame(frameById("round.1.expand-R"))).toBe(true);
  });

  it("the threaded state is stale (8-byte plaintext) while the port input is the round-local R", () => {
    const f = frameById("round.1.expand-R");
    // Threaded state never advances through port-native rounds → stale plaintext.
    expect((f.stateBefore as BytesState).bytes.length).toBe(8);
    expect(hexFromBytes((f.stateBefore as BytesState).bytes)).toBe(DES_PT);
    // The honest round-local R_in (4 bytes) lives on the input port.
    expect(f.portInputs?.get("state")?.length).toBe(4);
    expect(hexFromBytes(f.portInputs?.get("state") ?? new Uint8Array())).toBe("f0aaf0aa");
  });

  it("expand-R narrator reads the 4-byte port input (would null on the 8-byte stale state)", () => {
    const units = desExpandRNarration(frameById("round.1.expand-R"));
    // 1 structural overview + 6 output-byte drills. With the stale 8-byte
    // state the length check (before.length !== 4) would return null.
    expect(units).not.toBeNull();
    expect((units ?? []).length).toBe(7);
  });

  it("s-boxes narrator reads the 6-byte port input (would null on the 8-byte stale state)", () => {
    const units = desSBoxesNarration(frameById("round.1.s-boxes"));
    expect(units).not.toBeNull();
    expect((units ?? []).length).toBe(8); // one unit per S-box
  });

  it("xor-K narrator reads the 6-byte port input + the round-key aux read", () => {
    const units = desXorWithKNarration(frameById("round.1.xor-K"));
    expect(units).not.toBeNull();
    expect((units ?? []).length).toBe(6); // one cell per byte of the 48-bit value
  });

  it("IP narrator's output is the permuted block, not the stale plaintext", () => {
    const f = frameById("initial-permutation");
    // The IP output port carries the round-local permutation result.
    expect(hexFromBytes(f.portOutputs?.get("state") ?? new Uint8Array())).toBe("cc00ccfff0aaf0aa");
    // And the narrator renders (it sources output from the port).
    expect(desInitialPermutationNarration(f)).not.toBeNull();
  });

  it("<StepNarration> renders non-empty units for a port-native DES round leaf", () => {
    const { container } = render(() => <StepNarration frame={frameById("round.1.expand-R")} />);
    const units = container.querySelectorAll(".step-narration-unit");
    expect(units.length).toBeGreaterThan(0);
  });

  it("<PortFlowView> renders the round leaf's state input + state output ports", () => {
    const { container } = render(() => <PortFlowView frame={frameById("round.1.expand-R")} />);
    const inputLabels = Array.from(
      container.querySelectorAll(".port-flow-section[data-section='inputs'] .port-label"),
    ).map((el) => el.textContent ?? "");
    const outputLabels = Array.from(
      container.querySelectorAll(".port-flow-section[data-section='outputs'] .port-label"),
    ).map((el) => el.textContent ?? "");
    expect(inputLabels.some((l) => l.includes("state"))).toBe(true);
    expect(outputLabels.some((l) => l.includes("state"))).toBe(true);
  });
});
