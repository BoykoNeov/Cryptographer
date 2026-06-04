/**
 * Real-browser smoke for the inspector cell-level provenance hover
 * (inspector-cell-hover plan, Slice 3, 2026-06-04).
 *
 * Why a browser smoke and not just jsdom: the jsdom suite
 * (`tests/port-flow-view.test.tsx`) drives the hover with `fireEvent`, which
 * bypasses CSS hit-testing — so it proves the handler/signal logic but NOT that
 * a REAL pointer over the cell paints the `.provenance-source` highlight, nor
 * that the scoped CSS actually renders (memory `jsdom_pointer_events_gap`,
 * `feedback_visual_smoke_vs_property_tests`). This pins the live pointer path on
 * the AES-128 MixColumns frame — the headline case — and screenshots it.
 *
 * Run with `npm run smoke` (headless) / `npm run smoke:headed`. NOT part of
 * `npm run check`.
 */

import { type Page, expect, test } from "@playwright/test";

/** Click the timeline "next ▶" button until the inspector's frame-type label
 *  equals `target`, or throw after `cap` steps. Uses the real button (Solid's
 *  onClick fires from a real click; the range input's onInput would NOT fire
 *  from a synthetic event — memory `feedback_solid_needs_real_keyboard_events`). */
const scrubToFrameType = async (page: Page, target: string, cap = 700): Promise<void> => {
  const frameType = page.locator(".frame-type");
  const next = page.locator(".trace-timeline button").last(); // ◀ then ▶ → ▶ is last
  for (let i = 0; i < cap; i++) {
    if ((await frameType.textContent())?.trim() === target) return;
    await next.click();
  }
  throw new Error(`never reached a "${target}" frame within ${cap} steps`);
};

test.describe("Slice 3 — inspector cell-level provenance hover", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => window.localStorage.clear());
    await page.reload();
    // Linear view owns the inspector (PortFlowView); it's the default, but click
    // the tab explicitly so the smoke doesn't depend on the default staying put.
    await page.getByRole("tab", { name: "linear", exact: true }).click();
  });

  test("hovering an AES MixColumns output cell highlights its 4 GF contributors with ×N badges", async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });

    // Scrub to the first round's MixColumns (gf-matrix-multiply@1).
    await scrubToFrameType(page, "gf-matrix-multiply@1");

    const outputCells = page.locator(".port-flow-section[data-section='outputs'] .bytes-cell");
    await expect(outputCells.first()).toBeVisible();

    // Before hover: nothing is highlighted.
    await expect(page.locator(".bytes-cell.provenance-source")).toHaveCount(0);

    // Hover output cell 5 (column 1, row 1) with a REAL pointer.
    await outputCells.nth(5).hover();

    // The 4 same-column input contributors light up — live, through CSS.
    await expect(page.locator(".bytes-cell.provenance-source")).toHaveCount(4);
    // Each carries a GF(2⁸) coefficient badge "×N".
    const badges = page.locator(".provenance-label");
    await expect(badges).toHaveCount(4);
    await expect(badges.first()).toHaveText(/^×\d+$/);

    await page.screenshot({ path: "test-results/inspector-cell-hover-mixcolumns.png" });

    // Moving the pointer off the strip clears the highlight.
    await page.locator(".frame-header").hover();
    await expect(page.locator(".bytes-cell.provenance-source")).toHaveCount(0);

    expect(errors).toEqual([]);
  });
});
