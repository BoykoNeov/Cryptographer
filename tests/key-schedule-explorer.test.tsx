// @vitest-environment jsdom

/**
 * KeyScheduleExplorer — component test.
 *
 * The simulator-parity tests (`tests/serpent-key-schedule-sim-parity.test.ts`
 * + `tests/des-key-schedule-explorer.test.tsx`) pin the pure decomposition
 * logic against the executor. This file pins the UI dispatch layer:
 *
 *   1. Serpent key-expansion frame → Serpent multi-stage pipeline
 *      renders. The four <details> sections are present.
 *   2. Bad-shape frame (params missing master key, etc.) → graceful error
 *      stub renders instead of crashing.
 *   3. Byte-format toggle re-renders the values.
 *
 * (The AES branch was RETIRED in key-schedule-decomposition K1c — AES's
 * schedule is now decomposed into real trace frames, so there is no AES
 * swimlane to dispatch to. DES dispatch is covered by
 * `tests/des-key-schedule-explorer.test.tsx`.)
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, TraceFrame } from "@/core/types";
import { KeyScheduleExplorer } from "@/ui/components/KeyScheduleExplorer";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const SERPENT128_PT = "00112233445566778899aabbccddeeff";

const findFrameByStepType = (
  spec: typeof serpent128Spec,
  initialAux: Map<string, AuxValue>,
  initialState: ReturnType<typeof makeBytesState>,
  predicate: (stepType: string) => boolean,
): TraceFrame => {
  // Serpent's round body is port-native (B3) → the spec requires ported
  // dispatch; `runSpec` defaults to it. Lifted-legacy steps run via the
  // adapter to identical frames.
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState,
    initialAux,
  });
  const f = trace.frames.find((fr) => predicate(fr.stepType));
  if (!f) throw new Error("no matching frame in trace");
  return f;
};

describe("<KeyScheduleExplorer /> — Serpent branch", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders the multi-stage pipeline with 4 <details> sections for Serpent-128", () => {
    const frame = findFrameByStepType(
      serpent128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
      makeBytesState(bytesFromHex(SERPENT128_PT)),
      (t) => t.startsWith("serpent.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    expect(container.querySelector(".key-schedule-serpent")).not.toBeNull();
    // Four sections: pad, prekey-init, recurrence, sbox-groups+IP.
    const sections = container.querySelectorAll(".key-schedule-serpent-section");
    expect(sections.length).toBe(4);
  });

  it("renders 132 recurrence rows", () => {
    const frame = findFrameByStepType(
      serpent128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
      makeBytesState(bytesFromHex(SERPENT128_PT)),
      (t) => t.startsWith("serpent.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    const recurrenceItems = container.querySelectorAll(".key-schedule-serpent-recurrence > li");
    expect(recurrenceItems.length).toBe(132);
  });

  it("renders 33 sbox-group rows (one per round key K_0..K_32)", () => {
    const frame = findFrameByStepType(
      serpent128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
      makeBytesState(bytesFromHex(SERPENT128_PT)),
      (t) => t.startsWith("serpent.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    const groups = container.querySelectorAll(".key-schedule-serpent-sbox-groups > li");
    expect(groups.length).toBe(33);
  });

  it("renders the inline error stub when the master key isn't readable from auxRead", () => {
    // Parallel to the AES "missing params" test — Serpent's failure
    // mode is "no master key in aux." Pin the graceful fallback so
    // the two branches' error-handling stays in lockstep.
    const badFrame: TraceFrame = {
      index: 0,
      path: [],
      stepId: "key-expansion",
      stepType: "serpent.key-expansion@1",
      params: { keyAuxName: "key", outputPrefix: "roundKey", keyByteLength: 16 },
      // Empty auxRead — the "key" entry the simulator needs isn't here.
      auxRead: new Map<string, AuxValue>(),
      auxWritten: new Map(),
    };
    const { container } = render(() => <KeyScheduleExplorer frame={badFrame} />);
    expect(container.querySelector(".key-schedule-explorer-error")).not.toBeNull();
    expect(container.querySelector(".key-schedule-serpent")).toBeNull();
  });
});
