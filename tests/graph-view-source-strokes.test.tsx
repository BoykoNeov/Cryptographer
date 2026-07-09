// @vitest-environment jsdom

/**
 * Component-level tests for source-STROKE coding in the graph view
 * (Part A / chunk A3a of `docs/plans/toasty-zooming-harp.md`, 2026-07-09).
 *
 * The pure catalogue + auto-assignment is pinned by `source-strokes.test.ts`
 * (chunk A1) and the persistence by the layout/document tests (chunk A2).
 * This file pins the JSX WIRE-UP — that the store toggle + the
 * `LayoutSpec.strokeStyles` overrides actually reach the rendered `<path>`
 * as the four SVG channels, and that the un-styled fall-through is
 * byte-identical to today.
 *
 * Deterministic control: rather than depend on which auto-index a given
 * source lands on, most tests pin a KNOWN source (`key-schedule`, which
 * fans out to 11 round-key consumers on AES-128 ECB) to a KNOWN catalogue
 * entry via `setSourceStroke`, then assert the rendered channels. Manual
 * overrides win over auto (mirrors the colours manual-override test).
 *
 * The master toggle ships OFF, so every test that expects styling MUST
 * enable it first (`setSourceStrokeStylingEnabled(true)`) — otherwise it
 * asserts on the un-styled fall-through and passes for the wrong reason
 * (the `jsdom_replication_off_default` gotcha class).
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, setSourceStroke } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { __resetSourceColorsForTests, setColorThreshold } from "@/ui/stores/view-source-colors";
import {
  __resetSourceStrokesForTests,
  setSourceStrokeStylingEnabled,
} from "@/ui/stores/view-source-strokes";
import { __resetValueInspectorForTests } from "@/ui/stores/view-value-inspector";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const ECB_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a";

const seedAes128Ecb = (): void => {
  setCipher("aes-128");
  setCipherMode("ecb");
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT)),
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
  __resetLayoutsForTests();
  __resetValueInspectorForTests();
  __resetSourceColorsForTests();
  __resetSourceStrokesForTests();
};

/**
 * Collect the inline value of one CSS property across every rendered visible
 * edge path. Reads via `getPropertyValue` (the generic accessor) because the
 * renderer sets the dash channels through Solid's kebab-case style object →
 * `style.setProperty("stroke-dasharray", …)`, which stores them regardless
 * of whether jsdom's cssstyle exposes a typed accessor. Empty strings (the
 * un-styled fall-through) are filtered out.
 */
const collectInlineProp = (root: ParentNode, prop: string): string[] => {
  const out: string[] = [];
  const paths = root.querySelectorAll<SVGPathElement>("path.graph-edge");
  for (const p of Array.from(paths)) {
    const v = p.style.getPropertyValue(prop);
    if (v !== "") out.push(v);
  }
  return out;
};

/** Whether a dash-list string carries the given numeric tokens (jsdom may or
 *  may not append units / reorder whitespace, so match on token presence). */
const hasTokens = (dash: string, tokens: number[]): boolean => {
  const nums = (dash.match(/[\d.]+/g) ?? []).map(Number);
  return tokens.every((t) => nums.includes(t));
};

describe("GraphView — source-stroke coding wire-up", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("auto-assignment reaches the DOM: with styling ON and threshold 0, ≥1 edge is dashed", () => {
    // Threshold 0 → every non-endpoint source is styled; index 0 gets the
    // `solid` baseline (no dash) but indices 1+ walk the catalogue
    // (`round-dot`, `short-dash`, …), so at least one rendered edge must
    // carry an inline `stroke-dasharray`. Proves the full auto pipeline:
    // assignSourceStrokes → effective memo → per-edge resolver → DOM.
    seedAes128Ecb();
    setSourceStrokeStylingEnabled(true);
    setColorThreshold(0);
    const { container } = render(() => <GraphView />);

    const dashes = collectInlineProp(container, "stroke-dasharray");
    expect(dashes.length).toBeGreaterThan(0);
  });

  it("manual override applies the dash + linecap channels to the source's edges", () => {
    // `short-dash` = dasharray `4 3`, linecap `butt`. key-schedule fans out
    // to 11 round-key edges → all 11 pick up the same inline dash.
    seedAes128Ecb();
    setSourceStrokeStylingEnabled(true);
    setSourceStroke(aes128EcbSpec.id, "key-schedule", "short-dash");
    const { container } = render(() => <GraphView />);

    const dashes = collectInlineProp(container, "stroke-dasharray");
    expect(dashes.length).toBeGreaterThan(0);
    expect(dashes.some((d) => hasTokens(d, [4, 3]))).toBe(true);
    // linecap butt is set explicitly (harmless default) — assert it reached
    // at least one edge so a regression that drops the linecap channel bites.
    const caps = collectInlineProp(container, "stroke-linecap");
    expect(caps).toContain("butt");
  });

  it("the round-dot style sets a round linecap", () => {
    // `round-dot` = dasharray `0 5`, linecap `round` — the channel that turns
    // a `0 N` pattern into round dots. Distinct from `short-dash`'s `butt`.
    seedAes128Ecb();
    setSourceStrokeStylingEnabled(true);
    setSourceStroke(aes128EcbSpec.id, "key-schedule", "round-dot");
    const { container } = render(() => <GraphView />);

    const caps = collectInlineProp(container, "stroke-linecap");
    expect(caps).toContain("round");
  });

  it("the heavy weight tier MULTIPLIES the base width (2.625 = aux base 1.5 × 1.75), not replaces it", () => {
    // `short-dash-heavy` = widthMul 1.75. key-schedule → round.N.add-round-key
    // edges are aux singletons (bundleCount 1), so base = 1.5 → inline width
    // 2.625. Asserting 2.625 (neither the base 1.5, the mul 1.75, nor an
    // absolute) proves the multiply — the plan's "stacks on density width"
    // requirement. Inline (not attribute) so it beats the `.graph-edge-aux`
    // base-width class in a real browser; jsdom doesn't apply external CSS,
    // so the inline value reads straight back.
    seedAes128Ecb();
    setSourceStrokeStylingEnabled(true);
    setSourceStroke(aes128EcbSpec.id, "key-schedule", "short-dash-heavy");
    const { container } = render(() => <GraphView />);

    const widths = collectInlineProp(container, "stroke-width").map(Number);
    expect(widths).toContain(2.625);
  });

  it("the phase tier sets a stroke-dashoffset (half the pattern period)", () => {
    // `short-dash-phase` = dasharray `4 3`, dashoffset = (4+3)/2 = 3.5.
    seedAes128Ecb();
    setSourceStrokeStylingEnabled(true);
    setSourceStroke(aes128EcbSpec.id, "key-schedule", "short-dash-phase");
    const { container } = render(() => <GraphView />);

    const offsets = collectInlineProp(container, "stroke-dashoffset").map((s) =>
      Number.parseFloat(s),
    );
    expect(offsets).toContain(3.5);
  });

  it("master toggle OFF: an overridden source renders NO stroke channels (byte-identical to today)", () => {
    // The override is persisted on the layout, but with the master toggle OFF
    // the effective map is empty → every edge falls through un-styled. This
    // is the non-disruptive invariant: turning the channel off reverts every
    // channel without discarding the saved override.
    seedAes128Ecb();
    setSourceStroke(aes128EcbSpec.id, "key-schedule", "short-dash-heavy");
    // Toggle left at its default (OFF).
    const { container } = render(() => <GraphView />);

    expect(collectInlineProp(container, "stroke-dasharray")).toHaveLength(0);
    expect(collectInlineProp(container, "stroke-dashoffset")).toHaveLength(0);
    // No inline stroke-width from the stroke channel (bundles may still set
    // the width ATTRIBUTE, but never an inline style width when un-styled).
    expect(collectInlineProp(container, "stroke-width")).toHaveLength(0);
  });

  it("the `solid` baseline renders NO channels even when explicitly assigned (resolver falls through)", () => {
    // Threshold 99 → auto assigns nothing; override key-schedule to `solid`
    // explicitly. The per-edge resolver folds the solid baseline into
    // `undefined`, so no edge gains a dash/offset/inline-width. This is the
    // correctness anchor: solid-assigned sources are byte-identical to
    // un-styled edges, so a single-source (index-0) graph stays clean.
    seedAes128Ecb();
    setSourceStrokeStylingEnabled(true);
    setColorThreshold(99);
    setSourceStroke(aes128EcbSpec.id, "key-schedule", "solid");
    const { container } = render(() => <GraphView />);

    expect(collectInlineProp(container, "stroke-dasharray")).toHaveLength(0);
    expect(collectInlineProp(container, "stroke-dashoffset")).toHaveLength(0);
    expect(collectInlineProp(container, "stroke-width")).toHaveLength(0);
  });
});
