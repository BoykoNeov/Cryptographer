// @vitest-environment jsdom

/**
 * Phase 1 of the trace-coupling-bug-fix plan: a fix-pinning regression test
 * for the editor-flow bug where palette drops produced no orphan warnings,
 * no clickable ParamEditor, and no replicate-fanout effect because the
 * cipher hadn't auto-run yet.
 *
 * Root cause (see `docs/plans/trace-coupling-bug-fix.md`): the `hasRunOnce`
 * gate in `App.tsx` blocks the spec→rerun effect until the user clicks Run
 * manually. So a freshly-rendered App with a freshly-dropped aux-xor has
 * no trace, and `validateGraph` (which walks `trace.frames`) emits zero
 * warnings. The graph view's structural skeleton renders, but the affordance
 * the user is looking for — the orphan-read glyph telling them "this step
 * is unwired" — never appears.
 *
 * The fix (Phase 2 of that plan): `onMount(() => run())` in `App.tsx` fires
 * a boot-time run so a trace exists before the user touches anything.
 *
 * This test asserts the user-visible outcome of the fix:
 *   render App → switch to graph view → drop aux-xor onto a leaf → assert
 *   an orphan-read warning glyph appears, WITHOUT explicitly clicking Run.
 *
 * It fails today (zero glyphs because no trace) and passes after Phase 2.
 * It stays as a permanent regression guard against ever re-introducing the
 * "edits before manual Run do nothing" coupling.
 */

import { App } from "@/ui/App";
import { STEP_TYPE_DRAG_MIME } from "@/ui/components/StepPalette";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, getTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests, setViewMode } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetHistoryForTests();
  __resetLayoutsForTests();
  __resetPaddingForTests();
  __resetReplicationForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetViewModeForTests();
};

// Mirror the DataTransfer shim used in `step-palette.test.tsx` and
// `built-from-palette-roundtrip.test.tsx` — jsdom's native DragEvent
// constructor doesn't accept a populated dataTransfer, so we attach our
// own to a plain Event of type "drop".
const mockDataTransfer = (payload: { readonly [mime: string]: string }) => ({
  getData: (mime: string) => payload[mime] ?? "",
  types: Object.keys(payload),
  setData: (_mime: string, _value: string) => {},
  effectAllowed: "" as DataTransfer["effectAllowed"],
  dropEffect: "" as DataTransfer["dropEffect"],
});

const fireDropAt = (target: Element, stepType: string): void => {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: mockDataTransfer({
      [STEP_TYPE_DRAG_MIME]: stepType,
      "text/plain": stepType,
    }),
  });
  target.dispatchEvent(event);
};

describe("trace-coupling fix — palette drop surfaces warning glyph without manual Run", () => {
  beforeEach(() => {
    resetAll();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("drops aux-xor onto a leaf in graph view and an orphan-read glyph appears WITHOUT clicking Run", async () => {
    // Render the App fresh. No fireEvent.click(findButton("run")). The
    // boot-time onMount(() => run()) must produce a trace on its own.
    const { container } = render(() => <App />);

    // Flip to graph view via the store boundary the tab strip ends up at.
    setViewMode("graph");

    // Boot-run completed → trace present. This is the first observable
    // contract the fix introduces; capturing it before the drop makes the
    // failure mode explicit (no trace vs. trace-but-no-glyph render).
    await waitFor(() => {
      expect(getTrace(), "boot-time onMount should have produced a trace").not.toBeNull();
    });

    // Drop aux-xor onto the initial.add-round-key leaf. Same anchor pattern as
    // `built-from-palette-roundtrip.test.tsx`. We use a root-level leaf so
    // the insertion lands in the spec without requiring an iterate body.
    const anchorLeaf = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="initial.add-round-key"]',
    );
    expect(anchorLeaf, "initial.add-round-key leaf must be drop-targetable").not.toBeNull();
    if (!anchorLeaf) return;
    fireDropAt(anchorLeaf, "generic.aux-xor@1");

    // The drop triggers the spec mutation → debounced auto-rerun → new
    // trace → graph re-derives → validateGraph sees the empty-string aux
    // reads → orphan-read warning surfaces as a glyph on the new leaf.
    // Default debounce is 200ms (AUTO_RERUN_DEBOUNCE_MS), so we wait.
    await waitFor(
      () => {
        const glyphs = container.querySelectorAll('[data-testid="graph-warning-dot"]');
        expect(
          glyphs.length,
          "orphan-read glyph must appear on the freshly dropped aux-xor leaf",
        ).toBeGreaterThan(0);
      },
      { timeout: 1000 },
    );
  });
});
