/**
 * Real-browser smoke test for Slice 7c of the graph-narrative-and-zoom
 * plan (replica placement: by-source columns above each consumer).
 *
 * The unit tests in `tests/graph-view-replica-placement.test.ts` already
 * pin the layout math against synthetic graphs + the AES-128 ECB derived
 * graph. This file adds:
 *
 *   1. **End-to-end real-codepath** verification — start from the cipher
 *      selector dropdown, exercise the App's reactive memo chain
 *      (spec → trace → graph → layout → SVG), and assert the rendered
 *      `<rect>` x/y attributes carry the by-source-row geometry. The
 *      unit tests drive `layoutRoot` directly; this drives the App.
 *
 *   2. **The intersection of Slice 2 (iterate first-non-replica-child
 *      anchor) and Slice 7c (by-source rows).** Both `compute-block-count`
 *      and `split-blocks` target the SAME consumer (`ecb-blocks`, the
 *      iterate). Slice 2 says both replicas anchor at
 *      `initial.add-round-key.x`. Slice 7c says they stack vertically.
 *      Together: same x, different y. Neither unit test exercises both
 *      policies at once on the real cipher graph — this fills that gap.
 *
 *   3. **Pedagogical-look companion** — the test takes a screenshot of
 *      the post-overrides canvas so a human reviewer (or a future PR
 *      author) can eyeball "the canonical bad case is no longer
 *      tangled."
 *
 * Run with `npm run smoke` (headless) or `npm run smoke:headed` to watch.
 * NOT part of `npm run check` — the unit gate handles the contractual
 * surface; this gate is the "did the wire-up actually work in a browser"
 * trust-but-verify layer.
 */

import { type Page, expect, test } from "@playwright/test";

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Wipe persisted UI state so each test starts from a known baseline. */
const clearAppStorage = async (page: Page): Promise<void> => {
  await page.evaluate(() => {
    window.localStorage.clear();
  });
};

/** Switch the App's view-mode tab bar to "graph". Mirrors slice-6-smoke. */
const openGraphTab = async (page: Page): Promise<void> => {
  await page.getByRole("tab", { name: "graph", exact: true }).click();
  // Wait for the SVG to render — confirms the tab swap landed.
  await expect(page.locator(".graph-leaf-rect").first()).toBeVisible();
};

/**
 * Enable the global "replicate fan-out" checkbox. The replication
 * overrides panel is gated on this AND on `replicationSources().length
 * > 0`, so without flipping the toggle the panel doesn't render and
 * `data-testid="replication-panel-toggle"` never appears.
 *
 * Default is OFF (the conservative baseline — see `view-replication.ts`).
 */
const enableReplication = async (page: Page): Promise<void> => {
  await page.getByLabel("replicate fan-out").check();
  // Wait for the override panel header to appear before returning. This
  // proves the createMemo chain (replicate → replicationSources →
  // <Show>) ran to completion before the test reaches for testids
  // inside the panel.
  await expect(page.getByTestId("replication-panel-toggle")).toBeVisible();
};

/**
 * Read the rendered <rect> x/y/w/h for a given stepId. The data-testid
 * is on the wrapping <g>; the <rect.graph-leaf-rect> inside carries the
 * actual layout coordinates as SVG attributes.
 */
const readLeafBox = async (
  page: Page,
  stepId: string,
): Promise<{ x: number; y: number; w: number; h: number }> => {
  const leafG = page.getByTestId(`graph-leaf-${stepId}`);
  await expect(leafG).toBeVisible();
  const rect = leafG.locator("rect.graph-leaf-rect");
  const [x, y, w, h] = await Promise.all([
    rect.getAttribute("x"),
    rect.getAttribute("y"),
    rect.getAttribute("width"),
    rect.getAttribute("height"),
  ]);
  if (x === null || y === null || w === null || h === null) {
    throw new Error(`missing SVG attribute on leaf ${stepId}`);
  }
  return { x: Number(x), y: Number(y), w: Number(w), h: Number(h) };
};

// ─── Tests ────────────────────────────────────────────────────────────────

test.describe("Slice 7c — by-source replica rows on the real AES-128 ECB graph", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearAppStorage(page);
    // After clear, reload so stores rehydrate from the now-empty storage.
    await page.reload();
  });

  test("two always-overrides on AES-128 ECB stack VERTICALLY at the iterate's first body child", async ({
    page,
  }) => {
    // Switch the cipher mode to ECB. AES-128 is the default cipher; the
    // mode selector picks ECB, which boots the ECB factory and produces
    // the iterate `ecb-blocks` plus aux sources `compute-block-count`
    // and `split-blocks` at root.
    await page.getByLabel(/mode of operation/).selectOption("ecb");

    await openGraphTab(page);
    await enableReplication(page);

    // Open the replication overrides panel. The panel header is visible
    // (we waited for it above), but its body auto-opens only when the
    // spec already carries overrides — on a clean spec we click to open.
    await page.getByTestId("replication-panel-toggle").click();

    // Set BOTH `compute-block-count` and `split-blocks` to "always".
    // Both target the iterate `ecb-blocks`, so we get TWO replicas
    // pointing at the same consumer — the multi-source-on-iterate
    // case the unit tests don't cover (Slice 2 single-source +
    // synthetic Slice 7c multi-source on a non-iterate consumer
    // each cover their half but not the intersection).
    await page
      .getByTestId("replication-row-compute-block-count")
      .getByRole("button", { name: "always", exact: true })
      .click();
    await page
      .getByTestId("replication-row-split-blocks")
      .getByRole("button", { name: "always", exact: true })
      .click();

    // Both replicas now exist as synthetic chips with predictable ids.
    const computeReplica = await readLeafBox(page, "compute-block-count@->ecb-blocks");
    const splitReplica = await readLeafBox(page, "split-blocks@->ecb-blocks");

    // The iterate body's first non-replica child is `initial.add-round-key`
    // (Slice 2 anchors replicas there, NOT at the iterate's left edge).
    const firstBodyChild = await readLeafBox(page, "initial.add-round-key");

    // ── Slice 2 anchor (intersection assertion #1) ────────────────────
    // Both replicas should anchor at first-body-child.x — NOT at the
    // iterate `ecb-blocks`'s left edge. Half-leaf tolerance to absorb
    // future CONTAINER_PAD / LEAF_W ratio shifts without re-baselining.
    expect(Math.abs(computeReplica.x - firstBodyChild.x)).toBeLessThanOrEqual(computeReplica.w / 2);
    expect(Math.abs(splitReplica.x - firstBodyChild.x)).toBeLessThanOrEqual(splitReplica.w / 2);

    // ── Slice 7c by-source rows (intersection assertion #2) ──────────
    // Both replicas at the SAME x (no horizontal tiling — vertical
    // stack only).
    expect(splitReplica.x).toBe(computeReplica.x);

    // Different y — one chip + STACK_GAP apart. The DOM exposes the
    // raw coordinates without the STACK_GAP constant, so verify the
    // weaker "row separation > 0 AND ≥ one chip height" property.
    // This pins "no overlap" without coupling the test to the exact
    // STACK_GAP value (which lives in module scope of GraphView.tsx
    // and isn't exported).
    expect(splitReplica.y).not.toBe(computeReplica.y);
    expect(Math.abs(splitReplica.y - computeReplica.y)).toBeGreaterThanOrEqual(computeReplica.h);

    // ── Sanity: both replicas above the iterate's first body child ──
    // (orthogonal to the spine, the visual point of the lift).
    expect(computeReplica.y).toBeLessThan(firstBodyChild.y);
    expect(splitReplica.y).toBeLessThan(firstBodyChild.y);

    // Pedagogical-look companion: capture a screenshot for visual
    // review. Lives in test-results/ alongside slice-6's baselines.
    await page.screenshot({
      path: "test-results/slice-7c-multi-source-overrides.png",
      fullPage: false,
    });
  });

  test("single-source override (baseline regression): replicas land at the same y across consumers", async ({
    page,
  }) => {
    // The flip-side guarantee: with ONE always-source, every replica is
    // at row 0. Pre-7c and post-7c are byte-identical here. This pins
    // that the refactor didn't shift the AES-128 + key-expansion-only
    // case — the pedagogical headline "key-expansion fans to every
    // round" still renders the same.
    await openGraphTab(page);
    await enableReplication(page);
    await page.getByTestId("replication-panel-toggle").click();
    await page
      .getByTestId("replication-row-key-expansion")
      .getByRole("button", { name: "always", exact: true })
      .click();

    // Sample two structurally-identical round consumers (both have the
    // full 4-step body: sub-bytes / shift-rows / mix-columns / add-round-key).
    // Their key-expansion replicas should land at the same y because
    // the round group's child layout is identical → add-round-key sits
    // at the same offset → replica's left-gutter y matches.
    //
    // Round.10 is intentionally excluded: it omits mix-columns (the
    // FIPS-197 final-round exception), so its add-round-key sits one
    // row higher inside the round group, and a multi-round y comparison
    // including it would conflate Slice 7c's by-source policy with
    // FIPS-197's per-round structural difference.
    const r1 = await readLeafBox(page, "key-expansion@->round.1.add-round-key");
    const r5 = await readLeafBox(page, "key-expansion@->round.5.add-round-key");

    // Same y (both replicas at the LEFT gutter of their respective
    // round groups, centered against an add-round-key that sits at
    // the same in-group y).
    expect(r5.y).toBe(r1.y);
    // Different x (replicas live above DIFFERENT round consumer columns).
    expect(r5.x).not.toBe(r1.x);
  });
});
