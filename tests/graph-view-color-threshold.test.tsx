// @vitest-environment jsdom

/**
 * Component test for the source-coloring fanout-threshold input in the
 * graph toolbar (2026-05-30). This is the REAL "color by source" knob —
 * distinct from the replication threshold, which the user previously
 * mistook for a coloring control because it rendered next to the
 * "color by source" checkbox.
 *
 * Verifies:
 *   1. The input renders with the default (DEFAULT_COLOR_THRESHOLD = 3).
 *   2. The input is `disabled` when the master "color by source" toggle is
 *      OFF (the knob has no effect, shown at a glance).
 *   3. Enabled when the master toggle is ON.
 *   4. Typing flows into `useColorThreshold()`.
 *   5. **Minimum is 0** — typing "0" sets the signal to 0 (NOT clamped up),
 *      so every edge can be colored. This is the headline of the change.
 *   6. Out-of-range high clamps to MAX; non-numeric falls back to default.
 *
 * AES-128 is the fixture (key-expansion fanout 11, always colored).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import {
  COLOR_THRESHOLD_MAX,
  DEFAULT_COLOR_THRESHOLD,
  __resetSourceColorsForTests,
  setSourceColoringEnabled,
  useColorThreshold,
} from "@/ui/stores/view-source-colors";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetSourceColorsForTests();
  __resetLayoutsForTests();
};

const findColorThresholdInput = (container: HTMLElement): HTMLInputElement => {
  const input = container.querySelector(
    "input.graph-color-threshold-input",
  ) as HTMLInputElement | null;
  if (!input) throw new Error("color threshold input not found");
  return input;
};

describe("GraphView — source-coloring fanout threshold input", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders with the default coloring threshold", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const input = findColorThresholdInput(container);
    expect(input.value).toBe(String(DEFAULT_COLOR_THRESHOLD));
  });

  it("is disabled when the 'color by source' master toggle is OFF", () => {
    seedAes128Trace();
    setSourceColoringEnabled(false);
    const { container } = render(() => <GraphView />);
    const input = findColorThresholdInput(container);
    expect(input.disabled).toBe(true);
  });

  it("is enabled when the master toggle is ON (the default)", () => {
    seedAes128Trace();
    setSourceColoringEnabled(true);
    const { container } = render(() => <GraphView />);
    const input = findColorThresholdInput(container);
    expect(input.disabled).toBe(false);
  });

  it("typing a new value updates the signal", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const input = findColorThresholdInput(container);
    input.value = "5";
    fireEvent.input(input);
    expect(useColorThreshold()()).toBe(5);
  });

  it("allows the minimum of 0 (NOT clamped up) so all edges can be colored", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const input = findColorThresholdInput(container);
    input.value = "0";
    fireEvent.input(input);
    expect(useColorThreshold()()).toBe(0);
  });

  it("clamps an out-of-range high input to the MAX bound", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const input = findColorThresholdInput(container);
    input.value = "999";
    fireEvent.input(input);
    expect(useColorThreshold()()).toBe(COLOR_THRESHOLD_MAX);
  });

  it("falls back to default on a non-numeric input", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const input = findColorThresholdInput(container);
    input.value = "abc";
    fireEvent.input(input);
    expect(useColorThreshold()()).toBe(DEFAULT_COLOR_THRESHOLD);
  });

  it("lowering the threshold to 0 colors MORE edges than the default", () => {
    // Empirical end-to-end check: at the default (3) only key-expansion
    // (fanout 11) auto-colors; at 0 every non-endpoint source colors, so
    // the count of inline-stroked edges strictly increases.
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const countColored = (): number => {
      let n = 0;
      for (const p of Array.from(container.querySelectorAll<SVGPathElement>("path.graph-edge"))) {
        if (p.style.stroke && p.style.stroke !== "") n++;
      }
      return n;
    };
    const input = findColorThresholdInput(container);
    input.value = String(DEFAULT_COLOR_THRESHOLD);
    fireEvent.input(input);
    const atDefault = countColored();
    input.value = "0";
    fireEvent.input(input);
    const atZero = countColored();
    expect(atZero).toBeGreaterThan(atDefault);
  });
});
