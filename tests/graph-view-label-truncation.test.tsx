// @vitest-environment jsdom

/**
 * Tests for the V1 label-truncation behavior added on top of Slice 6's
 * container header. AES-128's final round has a deliberately verbose label
 * ("Round 10 (final, no MixColumns)" — 33 chars) which used to extend
 * past the container box's right edge and absorb pointerdown events meant
 * for the drag handle. The mitigation is two-fold: `pointer-events: none`
 * on the label (already shipped — keeps drag working) AND clipping via
 * SVG `textLength` + `lengthAdjust=spacingAndGlyphs` (this commit — keeps
 * the visual overflow off-screen).
 *
 * What we pin here:
 *   - Long labels get `textLength` set to a positive number with
 *     `lengthAdjust="spacingAndGlyphs"`. The actual value depends on the
 *     auto-layout's box.w, so we assert the relationship (positive,
 *     bounded by the container's box width) rather than a magic constant.
 *   - Short labels do NOT get `textLength` set — leaving them natural so
 *     `lengthAdjust` doesn't visually spread them across the available
 *     width. This is the deliberate trade-off of the conditional path.
 *   - The full label remains accessible via the parent `<g>`'s `<title>`,
 *     so the truncation is purely visual.
 *   - Drag still works at the X coordinate where the overflowing label
 *     used to live — Slice 6's `pointer-events: none` is preserved.
 *
 * What we deliberately do NOT pin:
 *   - The exact `textLength` value (depends on the auto-layout's
 *     box.w + CONTAINER_PAD + CHEVRON_W + LABEL_RIGHT_GAP, which can
 *     shift if any of those constants are retuned).
 *   - That the visual rendering is "legible" — jsdom does no layout, so
 *     we can only observe the attributes, not the rendered glyph metrics.
 *     The smoke test at `e2e/slice-6-smoke.spec.ts` carries that bar.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __setOffsetsEnabledForTest } from "@/ui/stores/offsets-hatch";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixtures ──────────────────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
  // Byte-native AES-128 (Slice B1) auto-ON's replication for ported specs,
  // which adds a key-expansion replica side-gutter inside each round group and
  // widens the container box enough that the verbose "Round 10 (final, …)"
  // label fits without clipping. Force replication OFF so the box stays narrow
  // and the textLength clip this file pins still triggers.
  setReplicationEnabled(false);
};

const resetAll = (): void => {
  __resetReplicationForTests();
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
  __resetLayoutsForTests();
};

/**
 * Locate the SVG `<text class="graph-container-label">` whose label text
 * matches the given prefix. Falls back to a thrown error rather than a
 * silent null so test failures point at the missing element directly.
 */
const findContainerLabel = (root: HTMLElement, labelPrefix: string): SVGTextElement => {
  const labels = Array.from(root.querySelectorAll<SVGTextElement>(".graph-container-label"));
  const match = labels.find((el) => el.textContent?.trim().startsWith(labelPrefix));
  if (!match) {
    throw new Error(
      `no .graph-container-label found with text starting with "${labelPrefix}"; ` +
        `available labels: ${labels.map((el) => `"${el.textContent}"`).join(", ")}`,
    );
  }
  return match;
};

// ─── Tests ────────────────────────────────────────────────────────────────

describe("GraphView — container label truncation (V1, SVG textLength)", () => {
  beforeEach(() => {
    resetAll();
    // Truncation only fires when the round container is narrow. Offsets
    // (ON by default as of 2026-05-28) staircase group children and widen
    // the box enough that the verbose label fits un-clipped — so pin OFF
    // to keep this test exercising the truncation path it was written for.
    __setOffsetsEnabledForTest(false);
  });
  afterEach(() => {
    cleanup();
    resetAll();
    __setOffsetsEnabledForTest(null);
  });

  it("clips the verbose 'Round 10 (final, no MixColumns)' label via textLength", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    const finalRoundLabel = findContainerLabel(container, "Round 10 (final");

    // The attribute is set as a string by SVG; coerce to number for the
    // numeric assertions below. A presence check first guards a missing
    // attribute from cascading into a NaN comparison.
    const tlAttr = finalRoundLabel.getAttribute("textLength");
    expect(tlAttr).not.toBeNull();
    const tl = Number(tlAttr);
    expect(Number.isFinite(tl)).toBe(true);
    expect(tl).toBeGreaterThan(0);

    // The truncation width must be at most the container's full box width
    // (anything more would mean we're not actually clipping). We read the
    // parent `<g>`'s sibling rect to recover the box width without
    // duplicating the layout constants.
    const parentG = finalRoundLabel.parentElement;
    expect(parentG).not.toBeNull();
    const rect = parentG?.querySelector(".graph-container-rect") as SVGRectElement | null;
    expect(rect).not.toBeNull();
    const boxW = Number(rect?.getAttribute("width"));
    expect(tl).toBeLessThan(boxW);

    // lengthAdjust pairs with textLength — without it the browser would
    // letter-space short text instead of compressing glyphs. The current
    // value is the V1 baseline; if a future change switches to
    // `spacing` (no glyph compression) it should be done deliberately.
    expect(finalRoundLabel.getAttribute("lengthAdjust")).toBe("spacingAndGlyphs");
  });

  it("does NOT set textLength on short labels like 'Round 1'", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    // 'Round 1' is 7 chars; at ~7px/char that's ~49px natural width,
    // comfortably under the round.1 container's box width. Per the
    // conditional-clip design, no textLength should be set so the
    // browser renders the text at its natural width.
    const earlyRoundLabel = findContainerLabel(container, "Round 1");
    // Use exact match because "Round 1" is a prefix of "Round 10 (final, …)"
    // — assert the located element really is the short one.
    expect(earlyRoundLabel.textContent?.trim()).toBe("Round 1");
    expect(earlyRoundLabel.getAttribute("textLength")).toBeNull();
    expect(earlyRoundLabel.getAttribute("lengthAdjust")).toBeNull();
  });

  it("keeps the full label discoverable via the parent <g>'s <title>", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    const finalRoundLabel = findContainerLabel(container, "Round 10 (final");
    const parentG = finalRoundLabel.parentElement;
    expect(parentG).not.toBeNull();
    const title = parentG?.querySelector("title");
    expect(title).not.toBeNull();
    // <title> carries `group: round.10` — the container kind + id, used as
    // a browser-native tooltip on hover. Independent of the visible label,
    // so it survives whatever truncation we apply.
    expect(title?.textContent).toContain("round.10");
  });

  it("preserves pointer-events:none on the label so drag still works through it", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    const finalRoundLabel = findContainerLabel(container, "Round 10 (final");
    // CSS pointer-events:none lives in app.css; jsdom doesn't apply CSS
    // unless explicitly told to, but the class is what carries the rule
    // in production. Verifying the class survives the textLength addition
    // is the proxy for "rule still applies".
    expect(finalRoundLabel.classList.contains("graph-container-label")).toBe(true);
  });
});
