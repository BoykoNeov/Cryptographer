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

  test("clicking DES's collapsed Key Schedule shows an aux-fanout summary + all 16 round keys — not 'no resolvable state'", async ({
    page,
  }) => {
    // Regression for the reported bug (2026-07-13): clicking DES's collapsed
    // "Key Schedule" showed the raw jargon `step "key-schedule" has no
    // resolvable state at frame 34` in the value row. The schedule group's
    // terminal leaf is the `des.publish-round-keys@1` tail — 0 output ports,
    // 16 input ports, each fanned into aux — so there is no single scalar
    // value. The fix reports `"aux-fanout"` (a friendly summary of what was
    // published) and leans on the "all port values" expander to show each of
    // the 16 round keys. This drives the EXACT user path: even with
    // replication off, the collapsed group is reference-replicated into
    // per-round chips (`key-schedule@->round.N.xor-K`) whose click routes to
    // the group id `key-schedule`.
    const errors: string[] = [];
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });

    await page.goto("/");
    await page.evaluate(() => window.localStorage.clear());
    await page.reload();

    const cipherSelect = page.locator("select", {
      has: page.locator('option[value="des"]'),
    });
    await cipherSelect.selectOption("des");
    await page.getByRole("tab", { name: "graph", exact: true }).click();
    await page.locator('[data-testid="value-inspector-panel-toggle"]').click();

    // One of the 16 collapsed-key-schedule reference replicas. Its click
    // routes `inspectorTargetId → "key-schedule"` (the group id).
    const ksChip = page.locator("g.graph-leaf", {
      has: page.locator("title", { hasText: "key-schedule@->round.1.xor-K" }),
    });
    await expect(ksChip).toBeVisible();
    await ksChip.click();

    const body = page.locator('[data-testid="value-inspector-body"]');

    // The value row must NOT read as an error, and must summarise the fan-out.
    const valueRow = body.locator(".graph-value-inspector-value-row");
    await expect(valueRow).toBeVisible();
    await expect(valueRow).not.toContainText("no resolvable state");
    await expect(valueRow).toContainText("roundKey");

    // The badge reads as info ("aux fan-out"), not the "no value" absence.
    await expect(
      body.locator(".graph-value-inspector-kind-badge", { hasText: "aux fan-out" }),
    ).toBeVisible();

    // "all port values" expander is present; expanding it shows the 16 round
    // keys as port rows (the publish tail's key0 … key15 inputs).
    const portValues = body.locator(".graph-value-inspector-expander-summary", {
      hasText: "all port values",
    });
    await expect(portValues).toBeVisible();
    await portValues.click();
    // 16 published round keys → at least 16 port rows in the expander body.
    await expect(body.locator(".port-flow-view .port-row").first()).toBeVisible();
    expect(await body.locator(".port-flow-view .port-row").count()).toBeGreaterThanOrEqual(16);

    await page.screenshot({
      path: "M:/claud_projects/temp/des-key-schedule-aux-fanout-smoke.png",
    });

    expect(errors).toEqual([]);
  });
});
