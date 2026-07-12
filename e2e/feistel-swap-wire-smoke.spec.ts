/**
 * Real-browser smoke for the DES Feistel swap wires (`R` / `L⊕F`) being
 * CLICKABLE → the value inspector, and their arrowheads matching the wire
 * colour (reported + fixed 2026-07-13).
 *
 * Why a browser smoke and not just jsdom (memory `jsdom_pointer_events_gap`,
 * `visual_smoke_vs_property_tests`): jsdom neither hit-tests `pointer-events`
 * (so a `fireEvent.click` would pass even if the wire were unclickable) NOR
 * renders SVG `context-stroke` markers (so the arrowhead-colour bug is
 * invisible to it). This drives a REAL pointer onto the swap wire's hit path
 * and screenshots the crossing so the arrowhead hue can be eyeballed.
 *
 * The unit test `tests/feistel-swap-wire-inspect.test.ts` already pins that
 * each wire's key resolves to the CORRECT half; this only proves the live
 * click path reaches the inspector at all.
 *
 * Run with `npm run smoke`. NOT part of `npm run check`.
 */

import { expect, test } from "@playwright/test";

// The cipher-variant dropdown is the only <select> carrying an aes-128 option.
const CIPHER_SELECT = 'select:has(option[value="aes-128"])';

test.describe("DES Feistel swap wires — clickable + coloured arrowhead", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => window.localStorage.clear());
    await page.reload();
    await page.locator(CIPHER_SELECT).first().selectOption("des");
    // Run so the trace exists and the inspector can resolve a value.
    await page.getByRole("button", { name: "run", exact: true }).click();
    await page.waitForTimeout(80);
    await page.getByRole("tab", { name: "graph", exact: true }).click();
  });

  test("swap rails render, a real click lands in the inspector with a value", async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });

    // DES opens fully expanded (no curated collapse), so the inter-round swap
    // wires render immediately. ≥1 swap × 2 rails.
    const hits = page.locator(".graph-feistel-swap-hit");
    await expect(hits.first()).toBeAttached({ timeout: 15000 });
    expect(await hits.count()).toBeGreaterThanOrEqual(2);

    // Click ON the wire's stroke by aiming at a landing dot — the dot sits at a
    // wire endpoint (so it's ON the hit path) but is `pointer-events:none`, so
    // the click falls through to the 12px hit stroke rather than the dot. This
    // exercises REAL hit-testing (a bbox-centre click on a curved path can miss
    // the stroke entirely). Scroll it into the viewport first — the graph sits
    // below the fold, so an unscrolled boundingBox is off-screen.
    const dot = page.locator(".graph-feistel-swap-dot").first();
    await dot.scrollIntoViewIfNeeded();
    const box = await dot.boundingBox();
    expect(box, "swap dot has a bounding box").not.toBeNull();
    if (!box) return;

    // Screenshot the crossing (now on-screen) for a visual arrowhead-colour
    // check — the only way to verify `context-stroke` resolves (jsdom can't
    // render markers).
    await page.screenshot({ path: "test-results/des-feistel-swap-wires.png" });

    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);

    const body = page.locator("[data-testid='value-inspector-body']");
    await expect(body).toBeVisible();
    const badge = body.locator(".graph-value-inspector-kind-badge");
    await expect(badge).toBeVisible();
    // A resolved half is a "state" value — NOT "no value" (the missing branch).
    await expect(badge).not.toHaveText(/no value/i);
    await expect(body.locator(".graph-value-inspector-value-row")).toHaveText(/[0-9a-f]{2}/i);

    expect(errors).toEqual([]);
  });
});
