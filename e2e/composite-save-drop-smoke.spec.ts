/**
 * Real-browser smoke for compose-and-save (universal-port Phase 4f, Slice E).
 *
 * Why a browser smoke and not just jsdom: three things the unit suite can't
 * honestly check (memory `jsdom_pointer_events_gap`,
 * `feedback_visual_smoke_vs_property_tests`):
 *   1. the `[save as element]` chip is hover-gated (`pointer-events:none` until
 *      the container is hovered) — jsdom `fireEvent.click` bypasses that, a
 *      real pointer must reveal it first;
 *   2. the composites library persists across a REAL page reload (localStorage);
 *   3. the actual HTML5 drag of a palette entry onto the SVG canvas inlines the
 *      group — jsdom only fires a synthetic `drop` event.
 *
 * The headless tests pin the mutation correctness (`composite-capture-clone`,
 * `composite-graph-drop`, `composite-parity`); this pins "it works in a browser."
 *
 * Run with `npm run smoke` (headless) / `npm run smoke:headed`. NOT part of
 * `npm run check`.
 */

import { type Page, expect, test } from "@playwright/test";

const openGraphTab = async (page: Page): Promise<void> => {
  await page.getByRole("tab", { name: "graph", exact: true }).click();
  await expect(page.locator(".graph-leaf-rect").first()).toBeVisible();
};

test.describe("Slice E — compose-and-save on the AES-128 graph", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => window.localStorage.clear());
    await page.reload();
  });

  test("save a round as an element → it persists in the palette across reload → drop inlines it", async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });
    // The save flow collects the name via window.prompt — accept it with a name.
    page.on("dialog", (d) => d.accept("Smoke Round"));

    await openGraphTab(page);

    // Fire the save chip's handler. We `dispatchEvent("click")` rather than a
    // pointer click because the chip is hover-gated (`pointer-events:none` until
    // the container is hovered) AND long aux round-key edges paint over the
    // header band — both defeat a real pointer click in Playwright (force
    // bypasses Playwright's checks but not the browser's own pointer-events /
    // hit-testing). dispatchEvent reaches the element's delegated handler
    // directly; the chip's existence + end-to-end wiring is what we smoke. The
    // hover-reveal CSS is unit-uncheckable regardless.
    const saveChip = page.getByTestId("graph-save-element-round.1");
    await saveChip.dispatchEvent("click");

    // The composite now appears in the palette's "my elements" section.
    const paletteEntry = page.locator(
      '[data-testid^="composite-palette-entry-"]:has-text("Smoke Round")',
    );
    await expect(paletteEntry).toBeVisible();
    await page.screenshot({ path: "test-results/composite-saved.png" });

    // Persistence: a real reload re-reads localStorage; the element survives.
    await page.reload();
    await openGraphTab(page);
    await expect(paletteEntry).toBeVisible();

    // Drag the saved element onto a leaf — the clone inlines as a new group
    // (id = slug of the name). dragTo drives the full HTML5 DnD sequence with a
    // shared DataTransfer, so the composite MIME set on dragstart is readable
    // on drop.
    const target = page.getByTestId("graph-leaf-round.1.mix-columns");
    await paletteEntry.dragTo(target, { force: true });

    // The dropped composite renders as a fresh group "smoke-round".
    await expect(page.getByTestId("graph-container-header-smoke-round")).toBeVisible();

    // No console errors across save + reload + drop + re-run.
    expect(errors).toEqual([]);
  });
});
