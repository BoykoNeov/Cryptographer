/**
 * Smoke — SHA-256 message-schedule REFERENCE replication (2026-06-08).
 *
 * The `msg-schedule` for-each-subgraph-with-history publishes aux["W"] to all
 * 64 compression rounds. Before reference replication those 64 edges rendered
 * as a long fan-out bundle crossing the whole round column. The fix keeps the
 * "Message schedule W_0..W_63" box on the canvas and reroutes each W edge to a
 * short per-round "W" reference chip. Replication defaults ON on a fresh load,
 * so this is what the user sees the moment they open SHA-256 in graph view.
 *
 * This smoke checks the real-Chromium render (jsdom can't judge layout):
 *   1. the message-schedule box SURVIVES (it is not deleted),
 *   2. 64 per-round "W" reference chips appear (the fan-out became chips), and
 *   3. NO canonical source still draws a long-edge bundle across the rounds —
 *      the user's ACTUAL complaint, not "W" by name (K, the other fanout-64
 *      source, is already full-replicated, so nothing bundles anymore).
 * It also writes a screenshot for the eyeball check the unit tests can't make:
 * does the kept box read as the SOURCE of the W chips, or as an orphan?
 */

import { type Page, expect, test } from "@playwright/test";

const selKind = (page: Page) =>
  page.locator('select:has(option[value="cipher"]):has(option[value="hash"])').first();

test("SHA-256 graph view keeps the msg-schedule box and shows per-round W reference chips", async ({
  page,
}) => {
  await page.goto("/");
  await page.evaluate(() => window.localStorage.clear());
  await page.reload();
  await expect(page.locator("select").first()).toBeVisible();

  // Hash → SHA-256 (default), then the graph tab.
  await selKind(page).selectOption("hash");
  await page.getByRole("tab", { name: "graph", exact: true }).click();

  // The graph renders at least one container box.
  await expect(page.locator(".graph-container-rect").first()).toBeVisible();

  // (1) The message-schedule box survives reference replication (kept, not
  // deleted). Its container chip carries the "Message schedule" label.
  await expect(page.getByText("Message schedule", { exact: false }).first()).toBeVisible();

  // (2) Per-round reference chips: leaves whose stepId is `msg-schedule@->...`.
  // Replication is ON by default on a fresh session. Wait for the first chip
  // to attach before counting — the replicated graph settles a tick after the
  // tab switch, so a bare count races the render.
  const refChips = page.locator('[data-testid^="graph-leaf-msg-schedule@->"]');
  await refChips.first().waitFor({ state: "attached" });
  // The full fan-out is 64 rounds — one reference chip per round.
  expect(await refChips.count()).toBe(64);

  // Eyeball artifact: scroll the first reference chip into view, then capture
  // the viewport so the "box reads as source vs orphan" question is legible
  // (the full graph is ~16k px wide and the chips sit ~1100px in).
  await refChips.first().scrollIntoViewIfNeeded();
  await page.screenshot({ path: "e2e/.artifacts/msg-schedule-refs-clip.png" });

  // (3) The user's complaint was a VISUAL bundle crossing containers, not "W"
  // specifically. The real success criterion: NO canonical source still draws
  // a fan of long edges across the round column. Measure every rendered edge's
  // horizontal span, grouped by canonical source (replicas fold to `src@->*`),
  // and assert no source exceeds a handful of long (>800px) edges. Before the
  // fix, `msg-schedule` drew 64 such edges (the yellow bundle); K (round
  // constants, also fanout-64) is already full-replicated into short hops, so
  // the only remaining long edges are singletons (init.fetch-H's chain seed,
  // the final digest-assembly hops) — never a bundle.
  const maxLongPerSource = await page.evaluate(() => {
    const longBySource = new Map<string, number>();
    for (const p of Array.from(document.querySelectorAll<SVGPathElement>("path.graph-edge-hit"))) {
      const d = p.getAttribute("d");
      if (d === null) continue;
      const t = d
        .trim()
        .split(/[\s,]+/)
        .map(Number);
      const sx = t[1];
      const tx = t[t.length - 2];
      if (!Number.isFinite(sx) || !Number.isFinite(tx)) continue;
      if (Math.abs((tx as number) - (sx as number)) <= 800) continue;
      const key = p.getAttribute("data-edge-key") ?? "";
      const stripped = key.startsWith("bundle:") ? key.slice("bundle:".length) : key;
      const src = stripped.split("|")[0] ?? "?";
      const srcKey = src.includes("@->") ? `${src.split("@->")[0]}@->*` : src;
      longBySource.set(srcKey, (longBySource.get(srcKey) ?? 0) + 1);
    }
    return Math.max(0, ...longBySource.values());
  });
  // A "bundle" is ~64 long edges; singletons are fine. 10 is a safe ceiling.
  expect(maxLongPerSource).toBeLessThanOrEqual(10);
});
