// @vitest-environment jsdom

/**
 * "Option B" — click-to-expand for squeezed container header labels.
 *
 * The V2 of the 2026-05-13 label-truncation work. V1 keeps a long label
 * inside its box by compressing it (SVG `textLength` +
 * `lengthAdjust="spacingAndGlyphs"`), which is fine at 1.2× and unreadable
 * at 3.5×: Salsa20's "Double round 1 of 10 (column round then row round)" is
 * ~350px of text rendered into 102px. Clicking the header band draws that
 * label at natural width in the late overlay layer instead, and the choice
 * persists per-spec in `LayoutSpec.expandedLabels`.
 *
 * What this file pins, in the order the mechanism can break:
 *
 *   1. **The gesture is armed on exactly the squeezed headers.** A header
 *      whose label fits stays as inert as it was before this feature.
 *   2. **The round trip.** Click expands, click again collapses. This is the
 *      one that would have shipped broken: the obvious gate ("is this label
 *      currently squeezed?") closes the moment the label expands, trapping
 *      the user in the expanded state with no way back. The real gate reads
 *      `labelTextLength`, which depends on label + box width and NOT on the
 *      expansion state.
 *   3. **Exactly one label per container.** The in-box label is suppressed
 *      while expanded, so a squeezed copy never sits under the readable one.
 *   4. **A drag is not a click.** Moving past the 4px threshold must drag the
 *      container and leave the label alone, exactly as before.
 *
 * What this file CANNOT check, and `e2e/slice-6-smoke.spec.ts` therefore
 * must: that the click lands in a real browser at all. jsdom's event
 * dispatch ignores `pointer-events: none`, and the label sitting over the
 * header band carries exactly that — so this file would stay green even if
 * the gesture were unreachable behind a live hit-test (see
 * `feedback_jsdom_pointer_events_gap`).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { SALSA20_IV_BYTES, salsa20EncryptSpec } from "@/ciphers/salsa20";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests, getLayoutForSpec } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixtures ──────────────────────────────────────────────────────────────

const SALSA_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SALSA_PT = "4c616469657320616e642047656e746c";
const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

/**
 * Salsa20 is the fixture on purpose. AES-128's verbose final-round label
 * only squeezes once BOTH the offsets layout and replication are switched
 * off (see the sibling truncation file, which does exactly that) — a
 * configuration no user runs. Salsa20's ten double-round labels squeeze in
 * the shipped defaults, so this file exercises the feature through the same
 * door a reader walks through.
 */
const seedSalsaTrace = (): void => {
  setCipher("salsa20");
  const iv = new Uint8Array(SALSA20_IV_BYTES);
  iv.set(bytesFromHex("0001020304050607"), 8);
  const trace = runSpec(salsa20EncryptSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SALSA_PT)),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex(SALSA_KEY)],
      ["iv", iv],
    ]),
  });
  setTrace(trace);
};

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetReplicationForTests();
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  // The cipher selector leaks across tests — `__resetSpecForTests` does NOT
  // reset it, and a Salsa20 spec left behind would silently drive an
  // "AES-128" case. Reset it explicitly (see `feedback_app_test_cipher_selector_leak`).
  __resetCipherForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
  __resetLayoutsForTests();
};

/**
 * Same MouseEvent-shaped stand-in the drag tests use: jsdom's `PointerEvent`
 * support varies by version, and the handlers only read clientX/clientY.
 */
const pointerEvt = (type: string, x: number, y: number): MouseEvent => {
  const e = new MouseEvent(type, { clientX: x, clientY: y, bubbles: true });
  Object.defineProperty(e, "pointerId", { value: 1 });
  return e;
};

/** Press and release without moving — the sub-threshold "click" gesture. */
const clickHeader = (root: HTMLElement, containerId: string): void => {
  const header = root.querySelector(`[data-testid="graph-container-header-${containerId}"]`);
  if (!header) throw new Error(`no header for ${containerId}`);
  header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
  window.dispatchEvent(pointerEvt("pointerup", 100, 100));
};

const squeezedHeaderIds = (root: HTMLElement): string[] =>
  Array.from(root.querySelectorAll("[data-label-squeezed]")).map(
    (el) => el.getAttribute("data-drop-anchor") ?? "?",
  );

const labelTexts = (root: HTMLElement, selector: string): string[] =>
  Array.from(root.querySelectorAll(selector)).map((el) => el.textContent?.trim() ?? "");

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("GraphView — container label click-to-expand (Option B)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("marks Salsa20's double-round headers as squeezed in the SHIPPED defaults", () => {
    // The regression this guards: the truncation path used to be reachable
    // only with offsets AND replication disabled. If a future layout change
    // widens these boxes until nothing squeezes, the whole feature becomes
    // dead UI — and this assertion is what says so out loud.
    seedSalsaTrace();
    const { container } = render(() => <GraphView />);

    const squeezed = squeezedHeaderIds(container);
    expect(squeezed.length).toBeGreaterThan(0);
    expect(squeezed).toContain("double-round.0");
  });

  it("does NOT arm the gesture on a header whose label fits", () => {
    // AES-128's "Round 5" is 7 characters; nothing to expand, so the header
    // must behave exactly as it did before this feature existed.
    seedAes128Trace();
    const { container } = render(() => <GraphView />);

    expect(squeezedHeaderIds(container)).not.toContain("round.5");

    clickHeader(container, "round.5");

    expect(getLayoutForSpec(useSpec()().id)).toBeNull();
  });

  it("expands a squeezed label on click and persists the choice", () => {
    seedSalsaTrace();
    const { container } = render(() => <GraphView />);

    expect(container.querySelectorAll(".graph-container-label-expanded")).toHaveLength(0);

    clickHeader(container, "double-round.0");

    // The overlay carries the full text at natural width...
    const expanded = labelTexts(container, ".graph-container-label-expanded");
    expect(expanded).toHaveLength(1);
    expect(expanded[0]).toContain("Double round 1 of 10");

    // ...and the choice is in the layout sidecar, ready for Save / Share.
    expect(getLayoutForSpec(useSpec()().id)?.expandedLabels).toEqual(["double-round.0"]);
  });

  it("renders exactly ONE label for an expanded container (no squeezed copy underneath)", () => {
    // The in-box `<text>` is suppressed while expanded. If it were merely
    // hidden by paint order instead, a 3.5×-compressed ghost would sit under
    // the readable one and show through at the ends.
    seedSalsaTrace();
    const { container } = render(() => <GraphView />);

    clickHeader(container, "double-round.0");

    const all = labelTexts(container, ".graph-container-label").filter((t) =>
      t.startsWith("Double round 1 of 10"),
    );
    expect(all).toHaveLength(1);
    // And the surviving one is the overlay's — no `textLength` compression.
    const survivor = Array.from(
      container.querySelectorAll<SVGTextElement>(".graph-container-label"),
    ).find((el) => (el.textContent ?? "").startsWith("Double round 1 of 10"));
    expect(survivor?.getAttribute("textLength")).toBeNull();
    expect(survivor?.classList.contains("graph-container-label-expanded")).toBe(true);
  });

  it("collapses again on a second click — the gate does not close behind the user", () => {
    // THE regression test for this feature. Gating the click on "is this
    // label currently squeezed?" reads naturally and traps the user: once
    // expanded, the label is no longer squeezed, so the gesture disarms and
    // the expansion can never be undone. The shipped gate reads
    // `labelTextLength`, which knows nothing about expansion state.
    seedSalsaTrace();
    const { container } = render(() => <GraphView />);
    const specId = useSpec()().id;

    clickHeader(container, "double-round.0");
    expect(getLayoutForSpec(specId)?.expandedLabels).toEqual(["double-round.0"]);
    // The header must still advertise itself as squeezable while expanded —
    // that mark is what keeps the second click armed.
    expect(squeezedHeaderIds(container)).toContain("double-round.0");

    clickHeader(container, "double-round.0");

    expect(container.querySelectorAll(".graph-container-label-expanded")).toHaveLength(0);
    // Re-collapsing the ONLY customization drops the layout entry entirely,
    // so spec-only saves stay byte-stable (the URL-share hash depends on it).
    expect(getLayoutForSpec(specId)).toBeNull();
  });

  it("expands each container independently", () => {
    seedSalsaTrace();
    const { container } = render(() => <GraphView />);

    clickHeader(container, "double-round.0");
    clickHeader(container, "double-round.2");

    expect(getLayoutForSpec(useSpec()().id)?.expandedLabels).toEqual([
      "double-round.0",
      "double-round.2",
    ]);
    expect(container.querySelectorAll(".graph-container-label-expanded")).toHaveLength(2);
  });

  it("treats a DRAG as a drag: past the threshold, the label is untouched", () => {
    // The expansion rides `onClickFallback`, which only fires on a release
    // that never cleared `DRAG_THRESHOLD_PX`. A user repositioning a double
    // round must not have its label pop open as a side effect.
    seedSalsaTrace();
    const { container } = render(() => <GraphView />);
    const specId = useSpec()().id;

    const header = container.querySelector(
      '[data-testid="graph-container-header-double-round.0"]',
    ) as Element;
    header.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 200, 150));
    window.dispatchEvent(pointerEvt("pointerup", 200, 150));

    const layout = getLayoutForSpec(specId);
    expect(layout?.positions["double-round.0"]).toBeDefined();
    expect(layout?.expandedLabels).toBeUndefined();
    expect(container.querySelectorAll(".graph-container-label-expanded")).toHaveLength(0);
  });
});
