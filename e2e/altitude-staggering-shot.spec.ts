/**
 * Ad-hoc visual A/B harness for the 2026-05-27 altitude-staggering
 * investigation. Captures SHA-256 expanded view + AES-128 ECB expanded
 * view screenshots into `e2e/.artifacts/`. Run on `main` and on
 * `explore/altitude-staggering` and md5/visual-compare the outputs.
 *
 * Pulls all containers fully expanded so the busy fan-INs are visible
 * (SHA-256 final.assemble 8-fan-IN is the motivating fixture).
 *
 * NOT load-bearing — diagnostic only. Delete after the investigation
 * closes if it gets stale.
 */

import { type Page, expect, test } from "@playwright/test";

// SHA-256 boot is slow (1800+ leaves to register + parse) so the
// default 30s test timeout is tight. Bump per-test to 120s and wait
// generously for the kind <select> to appear before driving anything.
test.setTimeout(120_000);

const BASE_URL = process.env.ALT_SHOT_URL ?? "http://localhost:5176";
const VIEWPORT = { width: 1920, height: 1200 } as const;
const ART_DIR = "e2e/.artifacts";

const freshLoad = async (page: Page): Promise<void> => {
  await page.setViewportSize(VIEWPORT);
  await page.goto(`${BASE_URL}/`, { waitUntil: "domcontentloaded" });
  // Wait for vite + Solid mount before clearing storage + reloading.
  await expect(page.locator("select").first()).toBeVisible({ timeout: 60_000 });
  await page.evaluate(() => window.localStorage.clear());
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator("select").first()).toBeVisible({ timeout: 60_000 });
};

const expandAll = async (page: Page): Promise<void> => {
  // Click every "expand" container button at most 50 times — UI hides
  // the chip once it's expanded, so the locator count shrinks.
  for (let i = 0; i < 50; i += 1) {
    const collapsed = page.locator(".graph-container-rect-collapsed");
    const count = await collapsed.count();
    if (count === 0) break;
    // Click the first; the iteration loop re-queries.
    await collapsed.first().click();
    await page.waitForTimeout(80);
  }
};

const shootGraph = async (page: Page, fileName: string): Promise<void> => {
  await page.getByRole("tab", { name: "graph", exact: true }).click();
  await page.waitForSelector(".graph-container-rect, .graph-leaf-rect", {
    timeout: 5000,
  });
  await expandAll(page);
  // Let the layout settle.
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${ART_DIR}/${fileName}`, fullPage: true });
};

test.describe("altitude-staggering visual A/B (diagnostic, 2026-05-27)", () => {
  test("SHA-256 expanded graph", async ({ page }) => {
    await freshLoad(page);
    // Flip to hash, then run, then graph.
    await page.locator('select:has(option[value="hash"])').first().selectOption("hash");
    await page.getByRole("button", { name: "run", exact: true }).click();
    await page.waitForTimeout(200);
    await shootGraph(page, "sha-256-expanded.png");
  });

  test("AES-128 ECB expanded graph", async ({ page }) => {
    await freshLoad(page);
    await page.locator('select:has(option[value="aes-128"])').first().selectOption("aes-128");
    await page.getByRole("button", { name: "run", exact: true }).click();
    await page.waitForTimeout(200);
    await shootGraph(page, "aes-128-ecb-expanded.png");
  });
});
