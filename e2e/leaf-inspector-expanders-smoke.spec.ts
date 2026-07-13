/**
 * Real-browser smoke for the graph value-inspector LEAF expanders
 * (leaf-inspector-expanders plan, 2026-07-13).
 *
 * Why a browser smoke and not just jsdom: the jsdom suite
 * (`tests/graph-inspector-leaf-expanders.test.tsx`) proves the components mount
 * and the DOM carries the two <details> — but jsdom does no CSS layout, so it
 * can't show that the expanders render inside the fixed-width inspector without
 * blowing out the panel, or that clicking a native <summary> actually reveals
 * the PortFlowView / StepNarration body (memory
 * `feedback_visual_smoke_vs_property_tests`). This drives the live path on a DES
 * S-box leaf — the case that exercises BOTH expanders (port values + a
 * registered narrator) — and screenshots it.
 *
 * Run with `npm run smoke` (headless) / `npm run smoke:headed`. NOT part of
 * `npm run check`.
 */

import { expect, test } from "@playwright/test";

test.describe("graph value-inspector leaf expanders", () => {
  test("selecting a DES round leaf shows 'all port values' + 'what this step does'", async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });

    await page.goto("/");
    await page.evaluate(() => window.localStorage.clear());
    await page.reload();

    // Switch to DES (its round leaves have registered narrators, unlike AES's
    // port-native round body) via the actual cipher <select>.
    const cipherSelect = page.locator("select", {
      has: page.locator('option[value="des"]'),
    });
    await cipherSelect.selectOption("des");

    // Graph view owns the value inspector.
    await page.getByRole("tab", { name: "graph", exact: true }).click();

    // Open the value-inspector panel (collapsed by default).
    await page.locator('[data-testid="value-inspector-panel-toggle"]').click();

    // Click the round-1 S-box leaf. Leaves are draggable; a plain click is a
    // sub-threshold pointerdown+up that runs the drag handler's click fallback
    // (select + scrub). Located by its SVG <title> (full stepId).
    const sBoxLeaf = page.locator("g.graph-leaf", {
      has: page.locator("title", { hasText: "round.1.s-boxes" }),
    });
    await expect(sBoxLeaf).toBeVisible();
    await sBoxLeaf.click();

    // Both expander summaries appear in the inspector body.
    const body = page.locator('[data-testid="value-inspector-body"]');
    const portValues = body.locator(".graph-value-inspector-expander-summary", {
      hasText: "all port values",
    });
    const whatItDoes = body.locator(".graph-value-inspector-expander-summary", {
      hasText: "what this step does",
    });
    await expect(portValues).toBeVisible();
    await expect(whatItDoes).toBeVisible();

    // Expand "all port values" → PortFlowView mounts with labelled port rows.
    await portValues.click();
    await expect(body.locator(".port-flow-view .port-row").first()).toBeVisible();

    // Expand "what this step does" → StepNarration mounts its disclosure(s).
    await whatItDoes.click();
    await expect(body.locator("details").nth(1)).toHaveAttribute("open", "");

    await page.screenshot({
      path: "M:/claud_projects/temp/leaf-inspector-expanders-smoke.png",
    });

    expect(errors).toEqual([]);
  });
});
