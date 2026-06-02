/**
 * Real-browser smoke for the port-wiring click-to-arm gesture (universal-port
 * Phase 4d-bis, Slice E).
 *
 * Why a browser smoke and not just jsdom: the gesture is SVG port handles that
 * a real pointer must actually hit. jsdom `fireEvent.click` dispatches straight
 * to the handler and can't tell you whether the handle is visible, sized, and
 * not occluded — exactly the failure mode that passes the unit suite but is
 * broken for a user (memory `jsdom_pointer_events_gap`,
 * `feedback_visual_smoke_vs_property_tests`). The headless tests pin the
 * binding-VALUE correctness (`tests/port-sources.test.ts`,
 * `tests/graph-view-wiring.test.tsx`); this pins "the handles are real and the
 * gesture completes in a browser," plus scope-bounding (a cross-scope leaf
 * offers no bind handle) and a screenshot for human eyeballing.
 *
 * Run with `npm run smoke` (headless) / `npm run smoke:headed`. NOT part of
 * `npm run check`.
 */

import { type Page, expect, test } from "@playwright/test";

const openGraphTab = async (page: Page): Promise<void> => {
  await page.getByRole("tab", { name: "graph", exact: true }).click();
  await expect(page.locator(".graph-leaf-rect").first()).toBeVisible();
};

test.describe("Slice E — port-wiring click-to-arm on the AES-128 graph", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => window.localStorage.clear());
    await page.reload();
  });

  test("arm an input port → legal source rings + bind handle → click binds and disarms", async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });

    await openGraphTab(page);

    // round.1.mix-columns is a visible leaf reading round.1.shift-rows. Its
    // input handle is the arm target.
    const armHandle = page.getByTestId("graph-port-in-round.1.mix-columns-input");
    await expect(armHandle).toBeVisible();
    await armHandle.click();

    // The armed leaf gets the dashed-accent "wire-armed" outline.
    await expect(page.getByTestId("graph-leaf-round.1.mix-columns")).toHaveClass(
      /graph-leaf-wire-armed/,
    );

    // A preceding same-scope sibling (sub-bytes) is a legal source: it rings
    // AND grows a bind handle.
    await expect(page.getByTestId("graph-leaf-round.1.sub-bytes")).toHaveClass(
      /graph-leaf-wire-target/,
    );
    const bindHandle = page.getByTestId("graph-port-bind-round.1.sub-bytes");
    await expect(bindHandle).toBeVisible();

    // A DIFFERENT-scope leaf (round.2's body) is NOT offered — scope-bounding
    // holds in the real browser, not just the enumerator unit test.
    await expect(page.getByTestId("graph-port-bind-round.2.sub-bytes")).toHaveCount(0);

    // Screenshot the armed state for human eyeballing.
    await page.screenshot({ path: "test-results/port-wiring-armed.png" });

    // Complete the wire: click the bind handle. It disarms (handle + ring gone).
    await bindHandle.click();
    await expect(page.getByTestId("graph-port-bind-round.1.sub-bytes")).toHaveCount(0);
    await expect(page.getByTestId("graph-leaf-round.1.mix-columns")).not.toHaveClass(
      /graph-leaf-wire-armed/,
    );

    // The rewire re-ran the trace without blowing up.
    expect(errors).toEqual([]);
  });

  test("Esc cancels a pending wire", async ({ page }) => {
    await openGraphTab(page);
    await page.getByTestId("graph-port-in-round.1.mix-columns-input").click();
    await expect(page.getByTestId("graph-port-bind-round.1.sub-bytes")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("graph-port-bind-round.1.sub-bytes")).toHaveCount(0);
  });

  test("the dropdown wiring panel mounts below the graph for the selected leaf", async ({
    page,
  }) => {
    await openGraphTab(page);
    // Selecting a leaf (click its rect, not a port handle) shows its param +
    // wiring panel. Confirms PortWiringEditor is actually mounted in the App,
    // not just unit-rendered — and gives the keyboard/a11y path a smoke.
    await page.getByTestId("graph-leaf-round.1.mix-columns").locator("rect").first().click();
    await expect(page.getByText("Input wiring")).toBeVisible();
    await expect(page.locator(".port-wiring-select").first()).toBeVisible();
  });
});
