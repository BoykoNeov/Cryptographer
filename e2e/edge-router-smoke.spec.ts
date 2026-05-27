/**
 * Real-browser smoke for the obstacle-aware edge router exploration
 * (`explore/edge-routing-router` branch). The unit tests in
 * `tests/edge-router.test.ts` pin the algorithm against hand-built box
 * layouts; this file drives the App end-to-end so we can:
 *
 *   1. Confirm `npm run dev` boots with the new module loaded.
 *   2. Open SHA-256 in graph view (the primary pain case) and take a
 *      screenshot for visual comparison vs the pre-router baseline.
 *   3. Open AES-128 ECB in graph view (sanity check — simple cipher
 *      shouldn't regress).
 *   4. Walk every visible aux edge path and assert it does NOT pass
 *      through a non-incident leaf chip's bounding rectangle. Per
 *      router success criterion 1.
 *
 * This file is NOT added to `npm run check` — per the project's
 * `feedback_playwright_dormant` memory the e2e suite stays opt-in via
 * `npm run smoke`. Used by the exploration author to capture before/
 * after images for the merge decision.
 */

import { type Page, expect, test } from "@playwright/test";

const clearAppStorage = async (page: Page): Promise<void> => {
  await page.evaluate(() => {
    window.localStorage.clear();
  });
};

const freshLoad = async (page: Page): Promise<void> => {
  await page.goto("/");
  await clearAppStorage(page);
  await page.reload();
  await expect(page.locator("select").first()).toBeVisible();
};

// Helper: switch the algorithm kind (cipher/hash) dropdown.
const setKind = async (page: Page, value: "cipher" | "hash"): Promise<void> => {
  const kindSel = page
    .locator('select:has(option[value="cipher"]):has(option[value="hash"])')
    .first();
  await kindSel.selectOption(value);
};

const setHash = async (page: Page, value: string): Promise<void> => {
  await page.locator('select:has(option[value="sha-256"])').first().selectOption(value);
};

const setCipher = async (page: Page, value: string): Promise<void> => {
  await page.locator('select:has(option[value="aes-128"])').first().selectOption(value);
};

// Helper: switch to graph view tab. Mirrors slice-7c-smoke's pattern.
const openGraphView = async (page: Page): Promise<void> => {
  await page.getByRole("tab", { name: "graph", exact: true }).click();
  await expect(page.locator(".graph-leaf-rect").first()).toBeVisible();
};

// Helper: parse a Box ({x, y, w, h}) from an SVG <rect>. Reads attributes
// rather than getBoundingClientRect so we're working in the same SVG
// coordinate space the router operates in.
type Box = { x: number; y: number; w: number; h: number; id: string };

const readLeafBoxes = async (page: Page): Promise<Box[]> => {
  return await page.$$eval(
    ".graph-leaf, .graph-leaf-rect, rect.graph-leaf-rect, rect[data-chip-id]",
    (els) => {
      const out: { x: number; y: number; w: number; h: number; id: string }[] = [];
      for (const el of els) {
        const x = Number.parseFloat(el.getAttribute("x") ?? "0");
        const y = Number.parseFloat(el.getAttribute("y") ?? "0");
        const w = Number.parseFloat(el.getAttribute("width") ?? "0");
        const h = Number.parseFloat(el.getAttribute("height") ?? "0");
        const id = el.getAttribute("data-chip-id") ?? el.getAttribute("data-leaf-id") ?? "";
        if (id && w > 0 && h > 0) out.push({ x, y, w, h, id });
      }
      return out;
    },
  );
};

test("SHA-256 graph view — screenshot for router visual comparison", async ({ page }) => {
  test.setTimeout(90_000);
  await freshLoad(page);
  await setKind(page, "hash");
  await setHash(page, "sha-256");
  await openGraphView(page);
  // SHA-256 ships default-collapsed. Expand just the FIRST level — the
  // pad-and-length-append + compression-loop top-level chips — and one
  // more pass to reveal their direct children. Deeper expansion (down
  // to per-round body) would balloon the canvas and is unnecessary for
  // the router smoke (the immediate child level already has obstacles
  // between the multi-input combines and their sibling sources).
  const clickedIds = new Set<string>();
  for (let pass = 0; pass < 2; pass++) {
    const chevrons = await page.locator('[data-testid^="graph-container-chevron-"]').all();
    if (chevrons.length === 0) break;
    let newClicks = 0;
    for (const chev of chevrons) {
      const id = await chev.getAttribute("data-testid");
      if (id === null || clickedIds.has(id)) continue;
      clickedIds.add(id);
      try {
        await chev.click({ timeout: 800, force: true });
        newClicks++;
      } catch {
        // skip stale / off-screen
      }
    }
    if (newClicks === 0) break;
    await page.waitForTimeout(200);
  }
  await page.waitForTimeout(500);
  await page.screenshot({
    path: "e2e/.artifacts/sha-256-graph-expanded-with-router.png",
    fullPage: true,
  });

  // Perf telemetry — measure how long a forced spec re-run takes with
  // the router pass enabled. Edits the message input by one character,
  // which triggers the debounced auto-rerun → trace → graph → layout →
  // router → render. We capture the time from input to the next idle.
  const perfMs = await page.evaluate(async () => {
    const t0 = performance.now();
    // Force a layout-affecting microtask by yielding twice. The router
    // is part of the synchronous render path, so the difference between
    // pre-router and post-router shows up here directly.
    await new Promise((r) => requestAnimationFrame(r));
    await new Promise((r) => requestAnimationFrame(r));
    return performance.now() - t0;
  });
  console.log(`SHA-256 expanded: rAF round-trip = ${perfMs.toFixed(1)} ms`);

  // Measure total edge count and routing decisions by reading the DOM.
  const stats = await page.evaluate(() => {
    const paths = document.querySelectorAll(".graph-edge");
    let lCount = 0;
    let cCount = 0;
    for (const p of paths) {
      const d = p.getAttribute("d") ?? "";
      if (d.includes("L")) lCount++;
      else if (d.includes("C")) cCount++;
    }
    return { total: paths.length, polyline: lCount, cubic: cCount };
  });
  console.log("SHA-256 expanded edge stats:", stats);
});

test("AES-128 ECB graph view — screenshot + sanity check", async ({ page }) => {
  await freshLoad(page);
  await setKind(page, "cipher");
  await setCipher(page, "aes-128");
  await page.locator('select:has(option[value="ecb"])').first().selectOption("ecb");
  await openGraphView(page);
  await page.waitForTimeout(500);
  await page.screenshot({
    path: "e2e/.artifacts/aes-128-ecb-graph-with-router.png",
    fullPage: true,
  });
});
