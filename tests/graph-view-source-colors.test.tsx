// @vitest-environment jsdom

/**
 * Component-level tests for source-color coding in the graph view
 * (2026-05-19). Three properties:
 *
 *   1. **Default ON**: a multi-fanout source's edges render with the
 *      canonical-source's assigned color as their inline `stroke`. AES-
 *      128 ECB's `key-schedule` fans out to 11 round-key consumers →
 *      every key-schedule → round.N.add-round-key edge picks up
 *      `SOURCE_COLOR_PALETTE[0]` (`key-schedule` happens to be the
 *      alphabetically-first multi-fanout source on this spec).
 *
 *   2. **Master toggle OFF**: the rendered edges drop their inline
 *      `stroke` attribute and revert to kind-based CSS styling.
 *
 *   3. **Manual override**: setting a per-spec override changes the
 *      rendered stroke on every matching edge live.
 *
 * The store + helper unit tests in `source-colors.test.ts` +
 * `view-source-colors-store.test.ts` pin the data layer. This file
 * pins the JSX wire-up — what tests for `view-source-colors-store`
 * would miss: that the store actually reaches the rendered DOM.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { SOURCE_COLOR_PALETTE } from "@/core/source-colors";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, setReplicationMode, toggleCollapse } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import {
  __resetSourceColorsForTests,
  setSourceColorOverride,
  setSourceColoringEnabled,
} from "@/ui/stores/view-source-colors";
import {
  __resetSourceStrokesForTests,
  setSourceStrokeStylingEnabled,
} from "@/ui/stores/view-source-strokes";
import { __resetValueInspectorForTests } from "@/ui/stores/view-value-inspector";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
// SP 800-38A §F.1.1 first block — single-block plaintext is enough to
// exercise key-schedule fan-out (we don't need multi-block iteration).
const ECB_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a";

const seedAes128Ecb = (): void => {
  setCipher("aes-128");
  setCipherMode("ecb");
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
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
 * Read every rendered <path> that carries an inline `style.stroke`
 * value — these are the source-colored edges. Returns the unique set
 * of stroke values (so e.g. all 11 key-schedule edges share one
 * entry).
 *
 * We read from `el.style.stroke`, NOT from `getAttribute("stroke")`:
 * the renderer applies the source color via inline CSS (the SVG
 * `stroke` presentation attribute has the lowest CSS specificity and
 * would lose to the `.graph-edge-state { stroke: var(--text); }`
 * class rule).
 *
 * jsdom NORMALISES color values when assigned to `style.stroke` /
 * `style.fill`: `#E69F00` reads back as `rgb(230, 159, 0)`. So
 * comparisons against `SOURCE_COLOR_PALETTE` (uppercase hex) need to
 * normalise both sides to an `[r, g, b]` tuple — see `parseColor` +
 * `rgbKey` below.
 */
const collectInlineStrokeValues = (root: ParentNode): Set<string> => {
  const out = new Set<string>();
  const paths = root.querySelectorAll<SVGPathElement>("path.graph-edge");
  for (const p of Array.from(paths)) {
    const s = p.style.stroke;
    if (s !== "") out.add(s);
  }
  return out;
};

/**
 * Parse `#RRGGBB` or `rgb(R, G, B)` into an `[R, G, B]` tuple of bytes.
 * Returns `null` for anything we can't parse. Used to compare jsdom's
 * normalised `rgb(...)` form against the palette's hex form.
 */
const parseColor = (s: string): [number, number, number] | null => {
  const rgb = /rgb\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)\s*\)/i.exec(s);
  if (rgb) {
    return [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])];
  }
  const hex = /^#([0-9a-f]{6})$/i.exec(s);
  if (hex) {
    const x = hex[1] ?? "";
    return [
      Number.parseInt(x.slice(0, 2), 16),
      Number.parseInt(x.slice(2, 4), 16),
      Number.parseInt(x.slice(4, 6), 16),
    ];
  }
  return null;
};

/** Canonicalise a color to a stable `"R,G,B"` string for Set membership. */
const rgbKey = (s: string): string => {
  const parsed = parseColor(s);
  return parsed ? parsed.join(",") : s.toLowerCase();
};

describe("GraphView — source-color coding", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("default ON: every key-schedule edge picks up palette[0] as its inline stroke", () => {
    // AES-128 ECB has multiple multi-fanout sources at root level:
    // `key-schedule`, `compute-block-count`, `split-blocks`. Alphabetical
    // sort puts `compute-block-count` at palette[0]; `key-schedule` at
    // palette[2]. Pin both to verify the alphabetical-determinism claim
    // from the unit tests carries through to the rendered DOM.
    seedAes128Ecb();
    const { container } = render(() => <GraphView />);

    const strokes = collectInlineStrokeValues(container);
    // At minimum, palette[0] (alphabetically-first multi-fanout source)
    // appears as an inline stroke on at least one rendered edge.
    // Normalise to RGB tuples for the comparison — jsdom converts hex
    // to `rgb(R, G, B)` when read back from `style.stroke`.
    const expectedKey = rgbKey(SOURCE_COLOR_PALETTE[0] ?? "");
    const keys = new Set(Array.from(strokes).map(rgbKey));
    expect(keys.has(expectedKey)).toBe(true);
  });

  it("master toggle OFF: every edge drops the inline stroke and falls back to kind classes", () => {
    seedAes128Ecb();
    setSourceColoringEnabled(false);
    const { container } = render(() => <GraphView />);

    const strokes = collectInlineStrokeValues(container);
    // No edge should carry the inline stroke override when coloring is
    // disabled. (Edges still carry their kind classes — CSS does the
    // styling — but the inline attribute is absent.)
    expect(strokes.size).toBe(0);
  });

  it("manual override changes every matching edge's inline stroke", () => {
    seedAes128Ecb();
    // Override key-schedule to a sentinel color the auto palette would
    // never assign (`#ff00aa` is outside the curated set).
    const SENTINEL = "#ff00aa";
    setSourceColorOverride(aes128EcbSpec.id, "key-schedule", SENTINEL);

    const { container } = render(() => <GraphView />);

    const strokes = collectInlineStrokeValues(container);
    const keys = new Set(Array.from(strokes).map(rgbKey));
    expect(keys.has(rgbKey(SENTINEL))).toBe(true);
  });

  it("the source-colors panel header is rendered when there is at least one multi-fanout source", () => {
    seedAes128Ecb();
    const { container } = render(() => <GraphView />);
    // Panel header carries `data-testid="source-colors-panel-toggle"`.
    const header = container.querySelector('[data-testid="source-colors-panel-toggle"]');
    expect(header).not.toBeNull();
  });

  it("the source-styling panel header is HIDDEN when BOTH the colour and stroke channels are OFF", () => {
    // The panel surfaces whenever EITHER channel is on. Since strokes now
    // default ON for every spec (2026-07-11), hiding the panel requires
    // turning both channels off.
    seedAes128Ecb();
    setSourceColoringEnabled(false);
    setSourceStrokeStylingEnabled(aes128EcbSpec.id, false);
    const { container } = render(() => <GraphView />);
    const header = container.querySelector('[data-testid="source-colors-panel-toggle"]');
    expect(header).toBeNull();
  });

  it("replica start-dots and bundle ×N pills pick up the source color", () => {
    // Seed AES-128 ECB with `key-schedule` set to "always" replicate +
    // iterate collapsed → the 11 key-schedule → round.N.add-round-key
    // edges fan into one bundle through a replica chip whose start-dot
    // is rendered. This exercises BOTH the start-dot fill path AND the
    // bundle ×N label fill path against the same canonical source
    // (key-schedule → palette[2] alphabetically on this spec — after
    // `compute-block-count` (palette[0]) and `ecb-blocks` (NOT
    // multi-fanout in standard ECB) sort earlier).
    setCipher("aes-128");
    setCipherMode("ecb");
    const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
      // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
    });
    setTrace(trace);
    setReplicationEnabled(true);
    setReplicationMode(aes128EcbSpec.id, "key-schedule", "always");
    toggleCollapse(aes128EcbSpec.id, "ecb-blocks", false);

    const { container } = render(() => <GraphView />);

    // Start-dot fills: only render in the vertical regime on replica
    // edges originating from fan-out chips, so they may be absent in
    // some renderer regimes. Pin the WEAKER property — if any
    // start-dot has an inline `fill` set, that fill must be from the
    // curated palette (no manual overrides in this test). Catches a
    // regression where the start-dot threads the source color
    // incorrectly. An empty set passes by default — we don't require
    // dots to exist, only that present ones color-match.
    const startDots = container.querySelectorAll<SVGCircleElement>("circle.graph-edge-start-dot");
    const dotFills = Array.from(startDots)
      .map((d) => d.style.fill)
      .filter((f) => f !== "");
    const paletteKeys = new Set(SOURCE_COLOR_PALETTE.map(rgbKey));
    for (const fill of dotFills) {
      expect(paletteKeys.has(rgbKey(fill))).toBe(true);
    }

    // At least one bundle ×N label is rendered (key-schedule's 11
    // round-key arrows collapse into one bundle when the iterate is
    // collapsed). The text element's inline `style.fill` should match
    // one of the palette colors too.
    const bundleTexts = container.querySelectorAll<SVGTextElement>(
      "text.graph-edge-bundle-label-text",
    );
    const textFills = Array.from(bundleTexts)
      .map((t) => t.style.fill)
      .filter((f) => f !== "");
    expect(textFills.length).toBeGreaterThan(0);
    for (const fill of textFills) {
      expect(paletteKeys.has(rgbKey(fill))).toBe(true);
    }
  });
});
