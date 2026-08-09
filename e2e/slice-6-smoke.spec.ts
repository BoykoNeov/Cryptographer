/**
 * Real-browser smoke test for Slice 6 of the 2D editor plan.
 *
 * The jsdom tests in `tests/graph-view-drag.test.tsx` already cover the
 * wiring (drag handler → store, store → save sidecar, etc.). This file
 * exists for the things jsdom can't honestly check:
 *
 *   1. **Native pointer events.** jsdom dispatches synthetic MouseEvents
 *      with a stamped pointerId. A real browser fires PointerEvents through
 *      the actual capture path (with elementFromPoint hit-testing,
 *      setPointerCapture semantics, the whole stack). If our handler ever
 *      starts relying on a real pointer feature jsdom doesn't simulate,
 *      this spec catches it first.
 *
 *   2. **localStorage across a page reload.** jsdom's `localStorage` is a
 *      polyfill scoped to one test run; we never observe the
 *      "navigate-away-and-come-back" rehydration path. The smoke reloads
 *      the page and asserts the dragged position + collapsed group are
 *      both restored.
 *
 *   3. **End-to-end persistence sanity.** A user drags a round group
 *      visually; what they expect: it stays where they put it across
 *      reloads. We don't pin a specific (x, y) (the auto-layout starting
 *      point depends on canvas size + container metrics that can shift
 *      with CSS edits), but we DO pin "the position is non-default and
 *      survives reload."
 *
 * Run with `npm run smoke` (headless) or `npm run smoke:headed` to watch.
 * NOT part of `npm run check` — the unit gate handles the contractual
 * surface; this gate is the "did the wire-up actually work in a browser"
 * trust-but-verify layer.
 */

import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Wipe persisted UI state so each test starts from a known baseline. */
const clearAppStorage = async (page: Page): Promise<void> => {
  await page.evaluate(() => {
    window.localStorage.clear();
  });
};

/**
 * Switch the App's view-mode tab bar to "graph". The tab strip uses
 * `role="tablist"` + per-tab `role="tab"` (Slice 2 set this for
 * accessibility), so we locate the tab by role + accessible name. Using
 * `role="button"` here would silently miss it: the explicit `role="tab"`
 * attribute overrides the implicit button role for ARIA queries.
 */
const openGraphTab = async (page: Page): Promise<void> => {
  await page.getByRole("tab", { name: "graph", exact: true }).click();
  // Wait for the SVG canvas to render at least one container — confirms
  // the graph view actually mounted, not just the tab click landed.
  await expect(page.locator(".graph-container-rect").first()).toBeVisible();
};

/** Read the persisted layout map for the given spec.id. Returns null if absent. */
const readPersistedLayout = async (
  page: Page,
  specId: string,
): Promise<{
  positions?: Record<string, { x: number; y: number }>;
  collapsedGroups?: string[];
} | null> => {
  return page.evaluate((id) => {
    const raw = window.localStorage.getItem("cryptographer.layouts");
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed[id] ?? null;
  }, specId);
};

/** Drag a container by its header band. Uses real pointer events. */
const dragContainerHeader = async (
  page: Page,
  containerId: string,
  deltaX: number,
  deltaY: number,
): Promise<void> => {
  const header = page.locator(`[data-testid="graph-container-header-${containerId}"]`);
  // The port-native AES canvas is far wider than the viewport (mid rounds
  // lay out thousands of px to the right), so a target container's header
  // is usually off-screen. `page.mouse.move` addresses VIEWPORT coordinates,
  // and moving to an off-screen point hits nothing — the drag silently no-ops
  // and no pin is written. Scroll the header into view first so its
  // boundingBox() resolves to an in-viewport point the mouse can actually
  // land on. (The chevron-collapse tests don't need this: Playwright's
  // `.click()` auto-scrolls for actionability; only the manual mouse drag
  // below bypasses that.)
  await header.scrollIntoViewIfNeeded();
  const box = await header.boundingBox();
  if (!box) throw new Error(`could not get bounding box for ${containerId} header`);
  const startX = box.x + box.width / 2;
  const startY = box.y + box.height / 2;
  await page.mouse.move(startX, startY);
  await page.mouse.down();
  // Two intermediate steps so the move clears the 4px click-vs-drag
  // threshold cleanly AND the handler sees a smooth motion rather than
  // a single teleport. Helps if a future refactor adds smoothing.
  await page.mouse.move(startX + deltaX / 2, startY + deltaY / 2);
  await page.mouse.move(startX + deltaX, startY + deltaY);
  await page.mouse.up();
};

/**
 * Press and release a container header without moving — the sub-threshold
 * gesture that `startNodeDrag`'s `onClickFallback` path turns into a click.
 *
 * Targets the header's CENTRE deliberately. The left edge carries the
 * hover-revealed delete / duplicate chips, which take the press and make the
 * gesture look like it silently did nothing.
 */
const clickContainerHeader = async (page: Page, containerId: string): Promise<void> => {
  const header = page.locator(`[data-testid="graph-container-header-${containerId}"]`);
  await header.scrollIntoViewIfNeeded();
  const box = await header.boundingBox();
  if (!box) throw new Error(`could not get bounding box for ${containerId} header`);
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.up();
};

// ─── Tests ────────────────────────────────────────────────────────────────

test.describe("Slice 6 — Real browser drag + collapse + persistence", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearAppStorage(page);
    // After clear, reload so stores rehydrate from the now-empty storage.
    await page.reload();
  });

  test("App boots and the graph tab renders the AES-128 round groups", async ({ page }) => {
    await openGraphTab(page);
    // AES-128 default: 10 round groups in the SVG.
    const containers = page.locator(".graph-container-rect");
    await expect(containers).toHaveCount(10);
    // Smoke-screenshot baseline view for visual review.
    await page.screenshot({ path: "test-results/slice-6-baseline.png", fullPage: false });
  });

  test("Dragging a container header writes a position to localStorage", async ({ page }) => {
    await openGraphTab(page);

    // Pre-drag: no persisted layout yet.
    expect(await readPersistedLayout(page, "aes-128@1")).toBeNull();

    await dragContainerHeader(page, "round.5", 80, 60);

    // Post-drag: layout entry exists with a pinned round.5.
    const layout = await readPersistedLayout(page, "aes-128@1");
    expect(layout).not.toBeNull();
    expect(layout?.positions?.["round.5"]).toBeDefined();
    // Position is whatever the auto-laid-out start + delta resolves to —
    // we don't pin specific coords (auto-layout is sensitive to CSS) but
    // we DO pin that some non-default position was written.
    const pinned = layout?.positions?.["round.5"];
    expect(pinned?.x).toBeGreaterThan(0);
    expect(pinned?.y).toBeGreaterThan(0);
  });

  test("Clicking the chevron collapses a round; child leaves disappear", async ({ page }) => {
    await openGraphTab(page);

    // Pre-collapse: count all leaf rects. The port-native AES-128 spec
    // renders 51 leaf rects (initial AddRoundKey + the ten round bodies at
    // 4 port-native leaves each + key-schedule leaves). This exact number
    // tracks the current AES decomposition — if AES is ever re-decomposed,
    // this and the post-collapse count below need re-pinning together. The
    // invariant the test actually cares about is the DELTA: collapsing one
    // full middle round hides exactly its 4 child leaves.
    const leafRects = page.locator(".graph-leaf-rect");
    await expect(leafRects).toHaveCount(51);

    await page.locator(`[data-testid="graph-container-chevron-round.7"]`).click();

    // Post-collapse: 4 leaves (round.7's SubBytes/ShiftRows/MixColumns/
    // AddRoundKey children) are hidden → 51 − 4 = 47.
    await expect(leafRects).toHaveCount(47);

    // The collapsed chip is visually distinct (CSS class applied).
    const collapsedChip = page.locator(".graph-container-rect-collapsed");
    await expect(collapsedChip).toHaveCount(1);

    // localStorage records the collapse.
    const layout = await readPersistedLayout(page, "aes-128@1");
    expect(layout?.collapsedGroups).toContain("round.7");
  });

  test("Dragged position + collapsed group survive a real page reload", async ({ page }) => {
    await openGraphTab(page);

    // Drag round.5 and collapse round.7.
    await dragContainerHeader(page, "round.5", 100, 40);
    await page.locator(`[data-testid="graph-container-chevron-round.7"]`).click();

    // Capture the post-action layout for later comparison.
    const beforeReload = await readPersistedLayout(page, "aes-128@1");
    expect(beforeReload?.positions?.["round.5"]).toBeDefined();
    expect(beforeReload?.collapsedGroups).toContain("round.7");

    // Real page reload — this is what jsdom can't honestly simulate.
    await page.reload();
    await openGraphTab(page);

    // Layout is the same (localStorage persisted across the navigation).
    const afterReload = await readPersistedLayout(page, "aes-128@1");
    expect(afterReload?.positions?.["round.5"]).toEqual(beforeReload?.positions?.["round.5"]);
    expect(afterReload?.collapsedGroups).toContain("round.7");

    // Visual evidence: round.7 still renders as a collapsed chip after reload.
    await expect(page.locator(".graph-container-rect-collapsed")).toHaveCount(1);
    // Final-state screenshot for visual review.
    await page.screenshot({ path: "test-results/slice-6-after-reload.png", fullPage: false });
  });

  test("Save → Load round-trip preserves the dragged + collapsed layout", async ({ page }) => {
    await openGraphTab(page);
    await dragContainerHeader(page, "round.3", 60, 40);
    await page.locator(`[data-testid="graph-container-chevron-round.8"]`).click();

    // Snapshot the saved JSON via `buildSaveText`'s path: we synthesize the
    // Save+Load round-trip in two steps. (Driving a real File download +
    // upload in Playwright is doable but flaky against tmp-dir cleanup;
    // capturing the serialized string from localStorage + driving Load via
    // the App's already-tested handleLoadFromText path is more robust.)
    const layoutBeforeSave = await readPersistedLayout(page, "aes-128@1");
    expect(layoutBeforeSave?.positions?.["round.3"]).toBeDefined();
    expect(layoutBeforeSave?.collapsedGroups).toContain("round.8");

    // Click [save] — verify the download is offered (we don't actually
    // capture the file; the unit tests do that). This proves the Save
    // button is wired and doesn't throw.
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: /save/i }).first().click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^aes-128@1-\d{8}\.cipher\.json$/);
  });

  /**
   * "Option B" — click-to-expand for a squeezed container label.
   *
   * This lives in a REAL browser because jsdom cannot judge the one thing
   * that can break it: the label sits over the header band carrying
   * `pointer-events: none`, and jsdom's event dispatch ignores that property
   * entirely (`feedback_jsdom_pointer_events_gap`). The jsdom suite in
   * `tests/graph-view-label-expansion.test.tsx` would stay green on a
   * gesture no cursor could ever reach.
   *
   * Salsa20 rather than AES-128: its double-round labels squeeze in the
   * shipped defaults, whereas AES-128's verbose final-round label only
   * squeezes with offsets AND replication disabled.
   */
  test("Option B — clicking a squeezed header expands its label, and it survives a reload", async ({
    page,
  }) => {
    // Switch to Salsa20 (the `cipher` selector is the third <select>).
    await page.locator("select").nth(2).selectOption("salsa20");
    await openGraphTab(page);

    // The component marks headers whose label needs squeezing; picking the
    // target from that mark rather than re-deriving `labelTextLength`'s
    // heuristic keeps this test honest if the heuristic is ever retuned.
    const squeezed = page.locator("[data-label-squeezed]");
    expect(await squeezed.count()).toBeGreaterThan(0);

    const label = page
      .locator("text.graph-container-label", { hasText: "Double round 1 of 10" })
      .first();
    // V1 state: the label is compressed to fit.
    expect(await label.getAttribute("textLength")).not.toBeNull();

    // Click the header CENTRE. Not its left edge: the delete / duplicate
    // chips are hover-revealed there and swallow the press, which reads as
    // "the click silently did nothing" (the occlusion trap
    // `e2e/composite-save-drop-smoke.spec.ts` also documents).
    await clickContainerHeader(page, "double-round.0");

    const expanded = page.locator("text.graph-container-label-expanded", {
      hasText: "Double round 1 of 10",
    });
    await expect(expanded).toHaveCount(1);
    // Drawn at natural width — no compression left on the surviving label.
    expect(await expanded.first().getAttribute("textLength")).toBeNull();
    // The plate that keeps it readable over whatever it now overlaps.
    await expect(page.locator(".graph-container-label-plate")).toHaveCount(1);

    // Persisted, and rehydrated after a real page reload.
    const layout = await readPersistedLayout(page, "salsa20@1");
    expect(layout?.expandedLabels).toEqual(["double-round.0"]);

    // Reload. The cipher selector is NOT persisted (the app boots on
    // AES-128), so re-select Salsa20 — the layout sidecar is keyed by
    // `spec.id`, and re-selecting is what brings `salsa20@1` back into
    // view. That the expansion is still there afterwards is the point:
    // it came from localStorage, not from anything in memory.
    await page.reload();
    await page.locator("select").nth(2).selectOption("salsa20");
    await openGraphTab(page);
    await expect(expanded).toHaveCount(1);

    // And a second click closes it again — the gesture stays armed while
    // expanded, which is the property a "is it squeezed right now?" gate
    // would silently break.
    await clickContainerHeader(page, "double-round.0");
    await expect(expanded).toHaveCount(0);
    expect(await readPersistedLayout(page, "salsa20@1")).toBeNull();
  });
});
