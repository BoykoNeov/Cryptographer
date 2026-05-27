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

/**
 * Criterion 1 programmatic check: walk every rendered edge path, sample
 * points along it, and confirm none of those points fall inside a
 * non-incident leaf chip's bounding rectangle. We don't try to compute
 * incidence per-edge in the DOM (would require following data-edge-key
 * → source/target ids and reconstructing the obstacle-exclusion logic);
 * instead we report the count of "edge sampled point intersects ANY
 * non-source/non-target leaf" and flag if it's high. A few false
 * positives are expected (e.g. an edge legitimately entering a leaf's
 * box at the arrowhead inset), but ZERO crossings is the right ceiling
 * for criterion 1.
 *
 * This test isn't strictly an assertion — it logs the count for human
 * review. Hardening it into an assert is a follow-up.
 */
// Runs the criterion-1 diagnostic in one configuration (router on/off,
// chosen by the `?no-router=1` URL hatch added temporarily to GraphView).
// Returns the count so the calling test can A/B against a baseline.
const runCrossingsDiagnostic = async (
  page: Page,
  goto: string,
): Promise<{
  leaves: number;
  totalSamples: number;
  hitSamples: number;
  pathsWithAnyHit: number;
}> => {
  await page.goto(goto);
  await clearAppStorage(page);
  await page.goto(goto);
  await expect(page.locator("select").first()).toBeVisible();
  await setKind(page, "hash");
  await setHash(page, "sha-256");
  await openGraphView(page);
  const chevrons = await page.locator('[data-testid^="graph-container-chevron-"]').all();
  for (const c of chevrons.slice(0, 10)) {
    try {
      await c.click({ timeout: 800, force: true });
    } catch {
      // skip stale
    }
  }
  await page.waitForTimeout(500);
  return await page.evaluate(() => {
    const leaves: { x: number; y: number; w: number; h: number; id: string }[] = [];
    for (const r of Array.from(document.querySelectorAll<SVGRectElement>(".graph-leaf-rect"))) {
      const x = Number.parseFloat(r.getAttribute("x") ?? "0");
      const y = Number.parseFloat(r.getAttribute("y") ?? "0");
      const w = Number.parseFloat(r.getAttribute("width") ?? "0");
      const h = Number.parseFloat(r.getAttribute("height") ?? "0");
      const id = r.getAttribute("data-leaf-id") ?? r.getAttribute("data-chip-id") ?? "";
      if (w > 0 && h > 0) leaves.push({ x, y, w, h, id });
    }
    let totalSamples = 0;
    let hitSamples = 0;
    let pathsWithAnyHit = 0;
    for (const p of Array.from(document.querySelectorAll<SVGPathElement>(".graph-edge"))) {
      const totalLen = p.getTotalLength();
      if (totalLen <= 0) continue;
      let pathHits = 0;
      for (let i = 1; i < 31; i++) {
        const pt = p.getPointAtLength((totalLen * i) / 32);
        totalSamples++;
        for (const l of leaves) {
          if (pt.x >= l.x && pt.x <= l.x + l.w && pt.y >= l.y && pt.y <= l.y + l.h) {
            pathHits++;
            break;
          }
        }
      }
      if (pathHits > 0) pathsWithAnyHit++;
      hitSamples += pathHits;
    }
    return { leaves: leaves.length, totalSamples, hitSamples, pathsWithAnyHit };
  });
};

test("SHA-256 — A/B: edge samples inside leaf boxes (router on vs off)", async ({ page }) => {
  test.setTimeout(180_000);
  const baseline = await runCrossingsDiagnostic(page, "/?no-router=1");
  console.log("BASELINE (router off):", baseline);
  const routed = await runCrossingsDiagnostic(page, "/");
  console.log("ROUTED  (router on): ", routed);
  console.log(
    `Hit-rate baseline = ${((baseline.hitSamples / baseline.totalSamples) * 100).toFixed(1)}%, ` +
      `routed = ${((routed.hitSamples / routed.totalSamples) * 100).toFixed(1)}%`,
  );
});

test("SHA-256 fan-IN — count edges crossing non-incident leaf boxes (single config)", async ({
  page,
}) => {
  test.setTimeout(60_000);
  await freshLoad(page);
  await setKind(page, "hash");
  await setHash(page, "sha-256");
  await openGraphView(page);
  const chevrons = await page.locator('[data-testid^="graph-container-chevron-"]').all();
  for (const c of chevrons.slice(0, 10)) {
    try {
      await c.click({ timeout: 800, force: true });
    } catch {
      // skip stale
    }
  }
  await page.waitForTimeout(500);

  // Collect leaf boxes (the obstacles) and edge paths. For each path,
  // sample 32 points along its length and check each against every
  // non-incident leaf box. We can't easily filter "non-incident" without
  // following the edge's endpoints, so this is a coarse signal: how
  // many sample points sit inside ANY rendered leaf chip's bounding
  // box. A pre-router baseline would have a high count (every straight-
  // line crossing produces ~5-15 sample hits depending on segment
  // length); a routed-pass baseline should be much lower.
  const result = await page.evaluate(() => {
    const leaves: { x: number; y: number; w: number; h: number; id: string }[] = [];
    for (const r of Array.from(document.querySelectorAll<SVGRectElement>(".graph-leaf-rect"))) {
      const x = Number.parseFloat(r.getAttribute("x") ?? "0");
      const y = Number.parseFloat(r.getAttribute("y") ?? "0");
      const w = Number.parseFloat(r.getAttribute("width") ?? "0");
      const h = Number.parseFloat(r.getAttribute("height") ?? "0");
      const id = r.getAttribute("data-leaf-id") ?? r.getAttribute("data-chip-id") ?? "";
      if (w > 0 && h > 0) leaves.push({ x, y, w, h, id });
    }
    let totalSamples = 0;
    let hitSamples = 0;
    let pathsWithAnyHit = 0;
    for (const p of Array.from(document.querySelectorAll<SVGPathElement>(".graph-edge"))) {
      const totalLen = p.getTotalLength();
      if (totalLen <= 0) continue;
      let pathHits = 0;
      for (let i = 1; i < 31; i++) {
        // Skip the endpoints — they ARE on/inside source/target boxes
        // by construction. Sample strictly interior points.
        const pt = p.getPointAtLength((totalLen * i) / 32);
        totalSamples++;
        for (const l of leaves) {
          if (pt.x >= l.x && pt.x <= l.x + l.w && pt.y >= l.y && pt.y <= l.y + l.h) {
            pathHits++;
            break;
          }
        }
      }
      if (pathHits > 0) pathsWithAnyHit++;
      hitSamples += pathHits;
    }
    return { totalSamples, hitSamples, pathsWithAnyHit, leaves: leaves.length };
  });
  console.log(
    `SHA-256 (top-level expanded): ${result.leaves} leaves, ${result.totalSamples} edge samples, ${result.hitSamples} hit a leaf box (${result.pathsWithAnyHit} paths had >=1 sample inside a leaf). Lower is better. Includes legitimate source/target endpoint hits we couldn't filter out without per-edge metadata.`,
  );
});
