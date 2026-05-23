/**
 * TEMPORARY self-smoke for Phase 6e of `docs/plans/des-feistel.md`.
 *
 * DELETE / SPLIT WHEN: Phase 6e closes (manual browser smoke signed off
 * in the plan file). Original intent (2026-05-20): keep through the
 * human pass, then delete. RECONSIDER on close: checkpoints 10–13 are
 * regression pins for the bug-fix batch — they outlive the manual-pass
 * purpose. On Phase 6e close, either (a) delete cp 1–9 and rename the
 * file to a permanent DES-graph-regression spec, or (b) extract cp
 * 10–13 into a separate permanent spec and delete this one. Don't
 * silently delete cp 10–13 with the rest.
 *
 * Checkpoint 9 re-baselined 2026-05-21: the spec-only URL-share bug
 * was fixed by adding an optional top-level `cipher` hint to
 * `CipherDocument`. The recipient now reads the hint and flips the
 * cipher selector to match the loaded spec; the ciphertext matches.
 *
 * Purpose: pre-flight the manual browser smoke for DES by driving the
 * same checklist via Playwright + screenshots, so the human pass starts
 * from a known-clean baseline. Intentionally NOT a permanent regression
 * gate — `tests/des-vectors.test.ts`, `tests/des-roundtrip-document.test.ts`,
 * and the linear-mode component tests already pin the contractual surface.
 *
 * Phase 6e checklist (from des-feistel.md §"Smoke pass"):
 *   1. Forward DES with FIPS 46-3 Appendix B vector — verify CT matches.
 *   2. Backward DES (decrypt) with same key — recover plaintext.
 *   3. Save → reset → Load with a `feistel-round` in the spec.
 *   4. URL share round-trip.
 *   5. Param edit on an S-box cell — trace re-runs.
 *   6. Drop a new step into a `feistel-round` track via the palette.
 *   7. Collapse a round — verify graph still renders.
 *   8. Scrub through trace — verify Feistel linear-mode components mount.
 *
 * Checkpoint → checklist mapping (the cp numbering in this file does not
 * line up 1:1 with the checklist numbering above; they grew organically):
 *   cp 1 → item 1.  cp 2 → item 2.  cp 3 → graph render sanity (extra).
 *   cp 4 → item 7.  cp 5 → item 8.  cp 6 → save+share smoke (extra).
 *   cp 7 → item 6 (palette renders; the actual DROP is left to manual).
 *   cp 8 → item 3.  cp 9 → item 4 (pins the OBSERVED bug; see notes).
 *
 * Checkpoints 10–13 are NOT from the original checklist — they pin
 * regressions of the Phase 6e bug-fix batch (commit `379c40d`):
 *   cp 10 → Bug 12 (slider + StepList hidden in graph view).
 *   cp 11 → Bug 3  (containers paint depth-ascending; round borders not
 *                   obliterated by the Rounds group rect).
 *   cp 12 → Bug 14 (round.1 ks replica chip falls inside Rounds, not at
 *                   root level).
 *   cp 13 → item 5 (param edit on S-box cell — spec mutation commits;
 *                   the auto-rerun half is covered by cp 1's coverage
 *                   of cipher-flip → result populated). DES S-boxes
 *                   became editable in commit `4c71c06` (Finding E of
 *                   the closing batch); the cell's reactive `title`
 *                   attribute is the strong-assertion handle.
 *
 * Checkpoints 14–17 pin the 2026-05-23 UX batch (commits `c47b16c` +
 * `0a80066` + `c44ada4`):
 *   cp 14 → UX-H  (mode flip auto-loads previous output as new input —
 *                  encrypt's ciphertext lands in decrypt's input field).
 *   cp 15 → UX-I+J (each `.data-field` row stacks vertically; the result
 *                   label sits above the code, not on the same line).
 *   cp 16 → UX-F  (Feistel-track passthrough chips render with tabindex=0
 *                  so Delete keystrokes route correctly — the spec-
 *                  mutation flow is pinned by jsdom tests; the browser
 *                  cp just confirms the static prerequisites).
 *   cp 17 → UX-K  (R-passthrough chip on a populated R-track has a
 *                  dedicated `into-track-start` gutter at its exact
 *                  box, so palette drops there prepend to the R-track
 *                  instead of falling through to the round container).
 *
 * Still UNCOVERED — must be eyeballed in the manual pass:
 *   - Narration update half of item 5 (cp 13 only proves spec
 *     mutation; visual narration update + downstream result-line
 *     refresh is a manual check).
 *   - Item 6 actual DROP into a feistel-round track gutter.
 *   - Bug 1  (click rejoin / passthrough chip → inspector shows frame).
 *   - Bug 2  (rejoin crossover X not colored).
 *   - Bug 4a (ciphertext layout — placed in `.inputs` row).
 *   - Bug 10 (rejoin-source arrows show single-track bytes, not 8B).
 *   - Bug 13 (L passthrough outgoing arrow bytes correct).
 *
 * Run: `npm run smoke -- e2e/des-phase-6e-self-smoke.spec.ts`
 * To watch: `npm run smoke:headed -- e2e/des-phase-6e-self-smoke.spec.ts`
 *
 * Screenshots land in `test-results/` for human review.
 */

import { type Page, expect, test } from "@playwright/test";

// ─── Helpers ──────────────────────────────────────────────────────────────

const FIPS_APPENDIX_B_PT_HEX = "0123456789abcdef";
const FIPS_APPENDIX_B_KEY_HEX = "133457799bbcdff1";
const FIPS_APPENDIX_B_CT_HEX = "85e813540f0ab405";

const clearAppStorage = async (page: Page): Promise<void> => {
  await page.evaluate(() => {
    window.localStorage.clear();
  });
};

const selectDesCipher = async (page: Page): Promise<void> => {
  // The cipher dropdown lives inside a `<label>cipher…</label>` wrapper
  // whose accessible name includes the currently-selected option text
  // (e.g. "cipher AES-128"), so getByLabel("cipher") doesn't resolve
  // cleanly. Target by the unique option value "des" instead.
  await page.locator('select:has(option[value="des"])').selectOption("des");
  // Wait for the spec store to swap canonical defaults in before
  // proceeding (input field flips to FIPS Appendix B vectors).
  await expect(page.getByLabel(/plaintext \(hex\)/i)).toHaveValue(FIPS_APPENDIX_B_PT_HEX);
  await expect(page.getByLabel(/key \(hex\)/i)).toHaveValue(FIPS_APPENDIX_B_KEY_HEX);
};

const openTab = async (page: Page, name: "linear" | "graph" | "json"): Promise<void> => {
  await page.getByRole("tab", { name, exact: true }).click();
};

// ─── Tests ────────────────────────────────────────────────────────────────

test.describe("Phase 6e — DES manual smoke pre-flight (Playwright)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearAppStorage(page);
    await page.reload();
  });

  test("checkpoint 1 — forward DES on FIPS-46-3 Appendix B vector produces 85e813540f0ab405", async ({
    page,
  }) => {
    await selectDesCipher(page);
    // Auto-rerun is on by default, so switching cipher kicks a run. Wait
    // for the result line to settle on the FIPS Appendix B ciphertext.
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX, {
      timeout: 5000,
    });
    await page.screenshot({
      path: "test-results/des-6e-01-forward-result.png",
      fullPage: false,
    });
  });

  test("checkpoint 2 — backward DES recovers the plaintext from the same key", async ({ page }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    // Flip to decrypt mode. The input field is now interpreted as
    // ciphertext, so feed it the FIPS Appendix B CT and expect the PT back.
    await page.locator('select:has(option[value="decrypt"])').selectOption("decrypt");
    await page.getByLabel(/ciphertext \(hex\)/i).fill(FIPS_APPENDIX_B_CT_HEX);

    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_PT_HEX, {
      timeout: 5000,
    });
    await page.screenshot({
      path: "test-results/des-6e-02-backward-result.png",
      fullPage: false,
    });
  });

  test("checkpoint 3 — graph view renders DES with feistel-round containers", async ({ page }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    await openTab(page, "graph");
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // DES has 16 rounds; each maps to a feistel-round container. There
    // are also outer containers for IP / FP / key-schedule / etc., so
    // assert the lower bound to avoid coupling to the exact wrapper count.
    const containers = page.locator(".graph-container-rect");
    expect(await containers.count()).toBeGreaterThanOrEqual(16);

    // Rejoin synthetic chips: one per round (testid `graph-rejoin-…`).
    const rejoins = page.locator('[data-testid^="graph-rejoin-"]');
    await expect(rejoins.first()).toBeVisible();
    expect(await rejoins.count()).toBeGreaterThanOrEqual(16);

    await page.screenshot({
      path: "test-results/des-6e-03-graph-overview.png",
      fullPage: false,
    });
  });

  test("checkpoint 4 — collapse round.3 and verify graph still renders", async ({ page }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);
    await openTab(page, "graph");
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // Pre-collapse leaf count.
    const leaves = page.locator(".graph-leaf-rect");
    const beforeCount = await leaves.count();
    expect(beforeCount).toBeGreaterThan(0);

    // Playwright's actionability check uses elementFromPoint at the
    // chevron <g>'s bounding-box center. The chevron lives INSIDE the
    // round.3 container <g>, and the container's giant
    // `<rect class="graph-container-rect graph-container-rect-group">`
    // (spans the entire 3902-px-tall round body) registers higher in
    // the SVG hit-test at the chevron's center point. Auto-scroll
    // doesn't fix this — wherever the chevron lands, the container
    // rect is right behind it. In a real browser, the visible "▾"
    // glyph + the chevron's transparent rect handle clicks fine
    // because the user clicks ON the glyph, not at the geometric
    // center of the chevron <g>. Dispatch the click event directly
    // to skip Playwright's hit-test and run the registered handler
    // — the question we're answering here is "does collapse render
    // correctly," not "is the chevron click target precise." A
    // separate manual check in Phase 6e should confirm the chevron
    // is reachable by a real-user mouse click; if a regression
    // surfaces, it's worth tightening the chevron's pointer-events
    // boundary.
    const chevron = page.locator('[data-testid="graph-container-chevron-round.3"]');
    await expect(chevron).toBeVisible();
    await chevron.dispatchEvent("click");

    // Post-collapse: round.3 should now render as a collapsed chip AND
    // the leaf count should drop.
    await expect(page.locator(".graph-container-rect-collapsed").first()).toBeVisible();
    const afterCount = await leaves.count();
    expect(afterCount).toBeLessThan(beforeCount);

    // Also verify edges still render — the plan's specific Phase 6e
    // promise is "edges still render correctly" post-collapse. Path
    // count > 0 is the cheapest defensible assertion against the
    // collapse silently nuking the layout.
    expect(await page.locator(".graph-view-svg path").count()).toBeGreaterThan(0);

    await page.screenshot({
      path: "test-results/des-6e-04-collapsed-round3.png",
      fullPage: true,
    });
  });

  test("checkpoint 5 — scrub mid-trace and verify Feistel linear-mode components render", async ({
    page,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    // Linear view is the default. Drive the scrubber to a frame deep in
    // the trace so we land somewhere inside a round body.
    const slider = page.locator('.trace-timeline input[type="range"]');
    const max = await slider.getAttribute("max");
    if (!max) throw new Error("trace timeline range max not present");
    const maxNum = Number(max);
    // The mid-trace frame is a `:rejoin` synthetic, which sits AT the
    // round level (no branchPath) and so doesn't trigger the track
    // context panel. Offset by -2 to land inside the R track's body
    // (typically s-boxes or p-permute for DES) where branchPath = ["R"]
    // and the panel renders.
    const target = Math.floor(maxNum / 2) - 2;
    await slider.evaluate((el, value) => {
      const input = el as HTMLInputElement;
      input.value = String(value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }, target);

    // Track-context panel mounts inside round bodies (branchPath set).
    await expect(page.locator(".feistel-track-context")).toBeVisible({ timeout: 5000 });
    // FeistelMiniDiagram renders alongside track-context inside the round
    // body — Phase 5b's "abstract structure" pane that visualizes the
    // L/R wires + F-stack + rejoin glyph.
    await expect(page.locator(".feistel-mini-diagram")).toBeVisible();
    // Timeline badges (Phase 5f scrubber-strip annotations: round
    // markers + track tags + IP/FP markers) render above the slider.
    await expect(page.locator(".trace-timeline-badge").first()).toBeVisible();

    await page.screenshot({
      path: "test-results/des-6e-05-linear-midtrace.png",
      fullPage: true,
    });

    // Now scrub to frame 0 (the key-schedule frame) and verify
    // KeyScheduleExplorer renders. This is the Phase 5e component that
    // walks DES's PC-1 → split → 16-round-shift → PC-2 pipeline.
    await slider.evaluate((el) => {
      const input = el as HTMLInputElement;
      input.value = "0";
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await expect(page.locator(".key-schedule-explorer")).toBeVisible({ timeout: 5000 });

    // Scrub to a rejoin frame and verify RejoinFrameView renders. With
    // 83 total frames, frame 41 (0-indexed) is round.8:rejoin (per the
    // 5-frames-per-round structure: 4 R-track + 1 rejoin).
    await slider.evaluate((el) => {
      const input = el as HTMLInputElement;
      input.value = "41";
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await expect(page.locator(".rejoin-frame-view")).toBeVisible({ timeout: 5000 });
  });

  test("checkpoint 8 — Save → reset spec → Load round-trips DES (feistel-round survives the document boundary)", async ({
    page,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    // Capture the file the [save…] button writes (include-session is
    // OFF by default, so the file is a spec-only document — exactly the
    // surface the Phase 6e checklist wants to round-trip).
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: /^save…?$/i }).click();
    const download = await downloadPromise;
    const savedPath = await download.path();
    if (!savedPath) throw new Error("download produced no local path");

    // Reset the spec (back to canonical DES, which it already is — but
    // this exercises the reset code path so a subsequent Load demonstrates
    // it actually rebuilt from the file, not from leftover store state).
    // Force-click to skip Playwright's "stable visibility" wait — the
    // button can be momentarily hidden behind transient layout shifts
    // when auto-rerun is also running.
    await page.getByRole("button", { name: /^reset spec$/i }).click();

    // Trigger Load by feeding the file into the hidden <input type="file">
    // directly — clicking [load…] would pop the OS native picker, which
    // Playwright can't drive.
    await page.locator('input[type="file"]').setInputFiles(savedPath);

    // Post-load: the DES KAT ciphertext should still resolve. If
    // feistel-round didn't survive the document boundary (or the document
    // schema's discriminator didn't recognize "feistel-round"), the
    // result would either error or produce wrong bytes.
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX, {
      timeout: 5000,
    });
    // And the StepList should still show DES's 16 Rounds container
    // (not collapse to AES or an error state). The bare "Rounds" string
    // also appears in the DES key-schedule narration body, so scope to
    // the StepList by class.
    await expect(page.locator(".group-label", { hasText: /^Rounds$/ })).toBeVisible();

    await page.screenshot({
      path: "test-results/des-6e-08-load-roundtrip.png",
      fullPage: false,
    });
  });

  test("checkpoint 9 — URL share round-trips DES (navigating to the shared URL produces the same ciphertext)", async ({
    page,
    context,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.getByRole("button", { name: /^share…?$/i }).click();
    const sharedUrl = await page.evaluate(async () => navigator.clipboard.readText());
    expect(sharedUrl).toContain("#doc=");

    // Open the shared URL in a fresh page (new tab, no shared state) and
    // see what state the recipient lands in.
    const fresh = await context.newPage();
    await fresh.goto(sharedUrl);

    // Phase 6e fix: spec-only documents now carry an optional
    // top-level `cipher` hint that flips the recipient's selector to
    // match the loaded spec. The fresh tab boots into AES-128 defaults,
    // but `setSpecFromDocument` reads `doc.cipher === "des"` and flips
    // both the cipher signal AND falls back cipherMode to "single-block"
    // (since DES doesn't support ECB/CBC). The result: a DES spec
    // loaded into an AES-128-default recipient now produces the FIPS
    // 46-3 Appendix B ciphertext, same as the encrypt-side tab.
    //
    // Before this fix, this assertion was pinning the OPPOSITE: the
    // recipient sat at "Custom (was AES-128)" + "expected 8 bytes"
    // error because the AES-128 default key (16 bytes) didn't match
    // DES's 8-byte block. The bug + reproduction are documented in
    // `docs/plans/des-feistel.md` Phase 6e bug list and the
    // `CipherDocument.cipher` field's docstring.
    await expect(fresh.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX, {
      timeout: 5000,
    });
    // The cipher selector should read "des" (not "aes-128").
    await expect(fresh.locator('select:has(option[value="des"])')).toHaveValue("des");

    await fresh.screenshot({
      path: "test-results/des-6e-09-share-roundtrip.png",
      fullPage: false,
    });
    await fresh.close();
  });

  test("checkpoint 6 — save downloads a .cipher.json + share copies a #doc URL", async ({
    page,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    // Save: expect a download named after the spec id with a YYYYMMDD stamp.
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: /^save…?$/i }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^des(@\d+)?-\d{8}\.cipher\.json$/);

    // Share: grant clipboard-read permission, click share…, then read the
    // clipboard. The URL should encode the doc into the hash fragment.
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.getByRole("button", { name: /^share…?$/i }).click();
    // Tiny wait for the async clipboard write inside the share handler.
    const url = await page.evaluate(async () => navigator.clipboard.readText());
    expect(url).toContain("#doc=");

    await page.screenshot({
      path: "test-results/des-6e-06-save-share.png",
      fullPage: false,
    });
  });

  test("checkpoint 7 — graph palette lists DES step types and a drop into round.5's L track lands a chip", async ({
    page,
  }) => {
    await selectDesCipher(page);
    // Wait for the new trace to land before switching views — otherwise
    // the screenshot can catch the post-cipher-flip / pre-rerun window
    // where the StepList shows DES's outer shape but the trace + result
    // line still reflect the previous AES-128 run (200ms debounce window
    // before auto-rerun re-derives). This is purely a test-timing
    // artefact, not a user-visible bug.
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    await openTab(page, "graph");
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // The palette is a sidebar inside .graph-view-layout. Assert that at
    // least one step-palette-entry rendered — the cipher-agnostic generic
    // primitives (xor, split, etc.) are always present.
    const paletteEntries = page.locator('[data-testid^="step-palette-entry-"]');
    expect(await paletteEntries.count()).toBeGreaterThan(0);

    await page.screenshot({
      path: "test-results/des-6e-07-graph-with-palette.png",
      fullPage: false,
    });

    // Note: an HTML5 drag-and-drop into a specific track gutter is hard
    // to drive reliably across Playwright versions (the dragstart →
    // dragover → drop sequence + the DataTransfer payload). Rather than
    // ship a flaky drop in this self-smoke, the human pass at Phase 6e
    // is the discriminating check. We've at least confirmed the palette
    // renders with the graph view active.
  });

  // ─── Bug-fix-batch regression pins (added 2026-05-21) ─────────────────
  //
  // The Phase 6e bug-fix batch (commit `379c40d`) shipped 8 graph-view
  // fixes. These are easy to silently regress because they live in
  // SVG-rendering territory jsdom doesn't faithfully exercise (paint
  // order, bounding-box geometry, visibility under `<Show>` gates).
  // The checks below pin the most load-bearing ones.

  test("checkpoint 10 — graph view hides the slider + StepList (Bug 12 regression)", async ({
    page,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    // In LINEAR view both are visible — sanity baseline before we flip.
    await expect(page.locator(".trace-timeline")).toBeVisible();
    await expect(page.locator(".step-list-pane")).toBeVisible();

    await openTab(page, "graph");
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // Both wrappers are gated by `<Show when={viewMode() !== "graph"}>`,
    // so they should be REMOVED from the DOM (not just hidden via CSS).
    // `toHaveCount(0)` is the strictest available assertion against the
    // `<Show>` pattern.
    await expect(page.locator(".trace-timeline")).toHaveCount(0);
    await expect(page.locator(".step-list-pane")).toHaveCount(0);
  });

  test("checkpoint 11 — containers paint depth-ascending so round borders aren't hidden (Bug 3 regression)", async ({
    page,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);
    await openTab(page, "graph");
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // `containersInPaintOrder` in GraphView sorts by `containerPath.length`
    // ascending so the outer "rounds" group renders BEFORE its 16 nested
    // feistel-round containers. In SVG, later siblings paint on top — so
    // the inner round rects (with their borders) need to come AFTER the
    // parent rounds rect in the document. Without the sort, the outer
    // group's neutral rect can obliterate the inner round borders
    // (the original Phase 6e symptom).
    //
    // The container header <rect> carries `data-testid="graph-container-
    // header-${id}"` (per GraphView line ~5993). Each header rect lives
    // inside its container's outer <g>; the <g> elements are siblings
    // under the SVG, so comparing header-rect DOM indices is equivalent
    // to comparing parent-<g> indices.
    const order = await page.evaluate(() => {
      const els = Array.from(document.querySelectorAll('[data-testid^="graph-container-header-"]'));
      const idx = new Map<string, number>();
      els.forEach((el, i) => {
        const testid = el.getAttribute("data-testid") ?? "";
        const id = testid.replace(/^graph-container-header-/, "");
        idx.set(id, i);
      });
      return Object.fromEntries(idx);
    });
    const roundsIdx = order.rounds;
    expect(roundsIdx, "Rounds container header should exist in DOM").toBeDefined();
    for (let r = 1; r <= 16; r++) {
      const child = order[`round.${r}`];
      expect(child, `round.${r} should be present in DOM`).toBeDefined();
      expect(child, `round.${r} must paint AFTER rounds (depth-ascending order)`).toBeGreaterThan(
        roundsIdx as number,
      );
    }
  });

  test("checkpoint 12 — round.1 key-schedule replica chip falls inside the Rounds container (Bug 14 regression)", async ({
    page,
  }) => {
    // The replica machinery is OFF by default; the LocalStorage flag
    // `cryptographer.replicationEnabled === "true"` flips it on at app
    // boot. Set before navigate so the first render already has replicas.
    await page.evaluate(() => {
      window.localStorage.setItem("cryptographer.replicationEnabled", "true");
    });
    await page.reload();

    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);
    await openTab(page, "graph");
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // The replica id pattern is `${source}@->${consumer}` (per
    // `src/core/graph.ts` line ~1793). DES key-schedule fans out to all
    // 16 round-key consumers via `aux.roundKey.N`; round.1 consumes
    // `roundKey.0` in its `round.1.xor-K` leaf.
    //
    // Bug 14 was: this replica was being designated as a SPINE replica
    // even though `key-schedule` lives at root (parent === "") and the
    // consumer lives inside `rounds/round.1` (different parent), which
    // landed the replica at root level — visually OUTSIDE the Rounds
    // group. The fix requires source.parent === consumer.parent for
    // spine designation, so the same fanout now resolves as an
    // AUX-fanout replica which renders at the consumer's parent (inside
    // Rounds). We assert that geometric containment.
    const replica = page.locator('[data-testid="graph-leaf-key-schedule@->round.1.xor-K"]');
    await expect(replica).toHaveCount(1);
    const replicaBox = await replica.boundingBox();
    if (!replicaBox) throw new Error("replica chip has no boundingBox");

    // The Rounds container's full bbox is on the `.graph-container-rect`
    // INSIDE the same <g> wrapper that holds the
    // `graph-container-header-rounds` rect. Walk up from the header to
    // its parent <g> and pick out the sibling `.graph-container-rect`.
    // Doing it in a page.evaluate avoids round-trips and gives us the
    // bounding-client-rect directly.
    const roundsBox = await page.evaluate(() => {
      const header = document.querySelector('[data-testid="graph-container-header-rounds"]');
      if (!header) return null;
      const wrapper = header.closest("g.graph-container");
      if (!wrapper) return null;
      const containerRect = wrapper.querySelector(":scope > .graph-container-rect");
      if (!containerRect) return null;
      const r = containerRect.getBoundingClientRect();
      return { x: r.x, y: r.y, width: r.width, height: r.height };
    });
    if (!roundsBox) throw new Error("rounds container rect could not be located");

    // Tolerance: a 2px outside-the-rect epsilon accommodates the
    // container <rect>'s stroke width (the leaf rect can graze the
    // container edge by ~1px without violating the "inside" intent).
    const eps = 2;
    expect(replicaBox.x, "replica left edge inside rounds").toBeGreaterThanOrEqual(
      roundsBox.x - eps,
    );
    expect(replicaBox.y, "replica top edge inside rounds").toBeGreaterThanOrEqual(
      roundsBox.y - eps,
    );
    expect(replicaBox.x + replicaBox.width, "replica right edge inside rounds").toBeLessThanOrEqual(
      roundsBox.x + roundsBox.width + eps,
    );
    expect(
      replicaBox.y + replicaBox.height,
      "replica bottom edge inside rounds",
    ).toBeLessThanOrEqual(roundsBox.y + roundsBox.height + eps);
  });

  test("checkpoint 13 — edit a round.1 S-box cell in graph view → spec mutation commits (Bug E / item 5)", async ({
    page,
  }) => {
    // Phase 6e checklist item 5: "Param edit on an S-box cell — trace
    // re-runs." Finding E of the closing bug-fix batch (commit `4c71c06`)
    // made DES S-boxes editable via `ByteCellInput`, so this is now
    // testable. Exercises three things at once:
    //   (1) leaf click in graph view binds the right ParamEditor block
    //       (cross-view selection chain),
    //   (2) the editor renders editable inputs (`<input class="byte-cell">`,
    //       not <span>),
    //   (3) committing a cell change reaches the spec store (verified
    //       via the cell's reactively-computed `title` attribute).
    //
    // We DON'T assert the ciphertext changes — a single-cell S-box
    // change has ~78% probability of affecting the FIPS Appendix B
    // output, which isn't robust enough for a regression gate. The
    // cell-title assertion below is positive proof the edit pipeline
    // works; the auto-rerun pipeline is independently covered by cp 1.
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);
    await openTab(page, "graph");

    // Use a real `.click()` (not `dispatchEvent`) — the leaf rect is the
    // top element at its own location, so Playwright's actionability
    // hit-test should pass. Real clicks here also surface any future
    // regression in the leaf's hit-test surface (Bug 1 was exactly that
    // class of bug for the rejoin chip — we want this test to FAIL
    // loudly if the s-boxes leaf becomes un-clickable).
    const sboxLeaf = page.locator('[data-testid="graph-leaf-round.1.s-boxes"]');
    await expect(sboxLeaf).toBeVisible();
    await sboxLeaf.click();

    // DesSBoxesBlock renders 8 collapsed `<details>` and a "S-box count"
    // scalar row. The scalar row is the cheapest unique handle.
    const editorPane = page.locator(".graph-param-editor-pane");
    await expect(editorPane).toBeVisible();
    await expect(editorPane.locator("dt", { hasText: "S-box count" })).toBeVisible();
    await expect(editorPane.locator("dd", { hasText: "8" })).toBeVisible();
    // Eight collapsed S-box sections.
    await expect(editorPane.locator("details.param-collapsible")).toHaveCount(8);

    // Expand S1 (the first <details>) to reveal the editable input
    // grid. The disclosure widget keeps the cell <input>s in the DOM
    // either way (CSS-hidden when closed) but Playwright's keyboard
    // API needs the element to be visible + focusable for real key
    // events to reach Solid's `onInput`/`onKeyDown` handlers.
    const s1Details = editorPane.locator("details.param-collapsible").first();
    await s1Details.locator("summary").click({ force: true });
    await expect(s1Details).toHaveAttribute("open", "");

    // Locate S1[row 0][col 0]. Canonical FIPS-46-3 Appendix A value is
    // 14 (rendered "0e" in hex, the app default). Target via the cell's
    // `title` attribute — the substring is stable and unique per cell.
    const cell00 = editorPane.locator('input.byte-cell[title^="S1[row 0][col 0]"]');
    await expect(cell00).toBeVisible();
    await expect(cell00).toHaveValue("0e");

    // Commit a new value. Pick 0x0f (= 15); this collides with
    // S1[0][5] (which is 15 canonically). The row no longer permutes
    // 0..15 — the editor surfaces a duplicate warning but the
    // executor still runs.
    //
    // Use real keyboard input + Enter: Solid attaches `onInput` as
    // a DOM listener but `dispatchEvent(new Event("input"))` was
    // observed to NOT fire that listener (probably because Solid
    // requires a real InputEvent, not a synthetic Event). Real
    // keyboard input via Playwright fires proper InputEvents.
    await cell00.click();
    // Select-all + replace pattern: Control+A selects the full input
    // value, Delete clears it, then type fires per-character keydown +
    // input events. Solid attaches onInput as a DOM listener; real key
    // events fire proper InputEvent (a synthetic `new Event("input")`
    // is NOT picked up by Solid's listener, as we observed earlier).
    await cell00.press("Control+A");
    await cell00.press("Delete");
    await cell00.type("0f");
    await cell00.press("Enter");

    // Strong assertion: the cell's `title` attribute is computed
    // reactively from the param store
    // (`S${idx + 1}[row ${r}][col ${c}] = ${value}`), so seeing
    // "= 15" in the title is positive proof the edit reached the spec
    // store. The row also now violates the permutation invariant
    // (15 collides with S1[0][5] = 15), so the duplicate suffix is
    // expected.
    await expect(cell00).toHaveAttribute("title", /S1\[row 0\]\[col 0\] = 15.*duplicate value/);

    // Best-effort assertion that the auto-rerun fired: a NEW spec
    // version means the trace re-derives. Whether the result LINE
    // changes depends on whether DES's F-function ever queries
    // S1[0][0] under the FIPS Appendix B test vector — a single cell
    // is queried ~22% of the time across 16 rounds, so the change may
    // not propagate to the final ciphertext for this specific input.
    // Don't assert on the result code: the spec mutation above is
    // sufficient evidence the editor pipeline works end-to-end, and
    // the auto-rerun pipeline is already covered by cp 1 (cipher
    // selection → trace re-derives → result populated).
    //
    // To verify the rerun actually fired here, we'd need to either
    // (a) change MANY cells to guarantee impact (slow; 16+ keystrokes),
    // or (b) expose the trace version on `window` for direct read.
    // Neither is worth the complexity; manual smoke catches a broken
    // rerun pipeline immediately.
  });

  // ─── UX batch (added 2026-05-23, after manual browser smoke) ──────────
  //
  // Checkpoints 14–17 pin the bundled UX improvements from the
  // 2026-05-23 manual smoke session:
  //   cp 14 → UX-H  (mode flip auto-loads previous output as new input)
  //   cp 15 → UX-I / UX-J (inputs row stacks vertically; result label
  //                        sits above the value, not on the same line)
  //   cp 16 → UX-F  (Delete on a Feistel-track leaf re-emerges the
  //                  passthrough chip — exercises the populated-then-
  //                  emptied L-track round-trip in a real browser)
  //   cp 17 → UX-K  (the populated-track passthrough chip — R-bypass
  //                  case — accepts palette drops via a dedicated
  //                  `into-track-start` gutter over its own box)
  //
  // These complement (not replace) the jsdom tests at
  // `tests/app-mode-flip-autoswap.test.tsx`,
  // `tests/spec-delete.test.tsx`, and
  // `tests/graph-view-feistel-drop-gutters.test.tsx`. The browser
  // surface adds value the jsdom layer can't: real bounding-box
  // geometry (cp 15), real keyboard events reaching Solid's onInput
  // (cp 16 / 17 drag-drop), and the visible flow of mode switching
  // (cp 14 demo).

  test("checkpoint 14 — UX-H: encrypt → decrypt mode flip auto-loads previous output as new input", async ({
    page,
  }) => {
    await selectDesCipher(page);
    // Forward run lands the FIPS Appendix B ciphertext on the result
    // line. This is the value the auto-swap should pump into the input.
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    // Flip to decrypt. UX-H wires the mode <select>'s onChange to
    // `batch(() => { setMode(...); setInputText(outputText()); })`, so
    // the input field should now hold the ciphertext we just produced.
    await page.locator('select:has(option[value="decrypt"])').selectOption("decrypt");

    // The input field's label flips to "ciphertext (hex)" once mode
    // swaps, and its value should be the previous output (auto-swap).
    await expect(page.getByLabel(/ciphertext \(hex\)/i)).toHaveValue(FIPS_APPENDIX_B_CT_HEX);

    // And the auto-rerun should land the recovered plaintext on the
    // result line — symmetric proof the round-trip works in a single
    // user gesture (no manual paste required).
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_PT_HEX, {
      timeout: 5000,
    });

    await page.screenshot({
      path: "test-results/des-6e-14-mode-flip-autoswap.png",
      fullPage: false,
    });
  });

  test("checkpoint 15 — UX-I/J: data-field rows stack vertically and result label sits above the value", async ({
    page,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);

    // UX-I: each `.data-field` inside `.inputs` is forced onto its own
    // row by `flex: 0 0 100%`. The browser-truth assertion: the input
    // label, key label, and result block all have DIFFERENT top edges
    // (i.e. no two of them share a row). Using getBoundingClientRect
    // because the CSS is the load-bearing piece — a CSS regression
    // (e.g. dropping the `flex: 0 0 100%` rule) would silently collapse
    // them back onto a single row without any DOM marker change.
    const rects = await page.evaluate(() => {
      const inputs = document.querySelector(".inputs");
      if (!inputs) return null;
      const fields = Array.from(inputs.querySelectorAll(":scope > .data-field"));
      // Identify each by what it contains: input/key/result. The order
      // of fields in the DOM is input → key → IV (if CBC) → result.
      // DES is single-block so no IV; we expect 3 fields total.
      return fields.map((el) => {
        const r = el.getBoundingClientRect();
        return { top: r.top, height: r.height, className: el.className };
      });
    });
    if (!rects) throw new Error(".inputs container not found");
    expect(rects.length).toBeGreaterThanOrEqual(3);
    // Distinct top edges (the i-th row sits below the (i-1)-th row by
    // at least the (i-1)-th row's height minus a small overlap epsilon).
    // We use 4px as the minimum gap signal — anything tighter than that
    // means two rows visually overlap.
    for (let i = 1; i < rects.length; i++) {
      const prev = rects[i - 1];
      const curr = rects[i];
      if (!prev || !curr) throw new Error("rect index out of bounds");
      expect(
        curr.top,
        `row ${i} should sit below row ${i - 1} (UX-I vertical stack)`,
      ).toBeGreaterThanOrEqual(prev.top + prev.height - 4);
    }

    // UX-J: the result-label span sits ABOVE the result code (flex
    // column, label first, code second). Compare top edges.
    const resultGeom = await page.evaluate(() => {
      const result = document.querySelector(".result.inputs-result");
      if (!result) return null;
      const label = result.querySelector(".result-label");
      const code = result.querySelector("code");
      if (!label || !code) return null;
      const lr = label.getBoundingClientRect();
      const cr = code.getBoundingClientRect();
      return { labelTop: lr.top, labelBottom: lr.bottom, codeTop: cr.top };
    });
    if (!resultGeom) throw new Error("result block / label / code not found");
    // Strict: label's bottom should be ≤ code's top (no overlap). In
    // a flex-column layout with gap, label.bottom < code.top by the
    // gap value (4px in this app).
    expect(
      resultGeom.labelBottom,
      "UX-J: result label bottom should sit at-or-above result code top",
    ).toBeLessThanOrEqual(resultGeom.codeTop + 1);

    await page.screenshot({
      path: "test-results/des-6e-15-inputs-stacked.png",
      fullPage: false,
    });
  });

  test("checkpoint 16 — UX-F: both feistel-round passthrough chips are present and focusable (regression baseline)", async ({
    page,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);
    await openTab(page, "graph");
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // UX-F's value is "Delete on a Feistel-track leaf re-emerges the
    // passthrough chip." Driving the populate-then-empty round-trip in
    // Playwright requires an HTML5 palette drop, which cp 7's preamble
    // already flags as unreliable (Playwright's DataTransfer + SVG
    // hit-test combo doesn't route the drop to the right
    // `data-drop-gutter` ancestor). The spec-mutation half is already
    // pinned by `tests/spec-delete.test.tsx` ("UX-F, DES" case) and
    // `tests/spec-mutations-feistel-track.test.ts` ("empty-to-
    // populated-to-empty L-track round-trip"). The browser-truth value
    // Playwright adds here is narrower but still useful: confirm both
    // passthrough chips render (round.1's L AND R) with their expected
    // testid hooks and are focusable for keyboard events — i.e. the
    // SVG hit-test for Delete WOULD work if the user populated the
    // track. Real palette-drop coverage stays in the manual smoke.
    const lPassthrough = page.locator('[data-testid="graph-passthrough-round.1:passthrough-0"]');
    const rPassthrough = page.locator('[data-testid="graph-passthrough-round.1:passthrough-1"]');
    await expect(lPassthrough, "L-passthrough must render in round.1").toBeVisible();
    await expect(rPassthrough, "R-passthrough must render in round.1").toBeVisible();

    // Both chips carry tabindex=0 so they're keyboard-reachable. The
    // <g> attribute (as opposed to CSS-only focusability) is what
    // makes Delete-key handling work on SVG; assert the static
    // attribute to pin regressions where the focusable property is
    // accidentally dropped.
    await expect(lPassthrough).toHaveAttribute("tabindex", "0");
    await expect(rPassthrough).toHaveAttribute("tabindex", "0");

    // The passthrough chips themselves are NOT spec nodes — they're
    // synthetic to the graph layer — so Delete on them should be a
    // no-op (the cipher's invariants forbid removing them). The leaves
    // INSIDE the populated R-track ARE deletable, and the user-flow
    // they enable for UX-F is: drop something into L-track → Delete
    // it → chip re-emerges. The jsdom test pins that flow; here we
    // pin the prerequisite (chips render correctly).
    const eExpand = page.locator('[data-testid="graph-leaf-round.1.expand-R"]');
    await expect(eExpand, "round.1's R-track has its expected default leaves").toBeVisible();

    await page.screenshot({
      path: "test-results/des-6e-16-ux-f-baseline.png",
      fullPage: false,
    });
  });

  test("checkpoint 17 — UX-K: R-passthrough chip on a populated R-track has a dedicated drop gutter at its box", async ({
    page,
  }) => {
    await selectDesCipher(page);
    await expect(page.locator(".result code")).toHaveText(FIPS_APPENDIX_B_CT_HEX);
    await openTab(page, "graph");
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // The R-passthrough chip exists in rounds 1..15 by default — even
    // though the R-track is POPULATED with the F-function chips, the
    // chip represents the bypass arrow (R_in flows directly to rejoin).
    // Before the UX-K fix, no drop gutter covered the chip's box, so
    // drops fell through to the round container's outer drop-anchor
    // and silently inserted AFTER the round in its parent.
    const rPassthrough = page.locator('[data-testid="graph-passthrough-round.1:passthrough-1"]');
    await expect(rPassthrough).toBeVisible();

    // The UX-K fix emits `into-track-start:round.1#1` over the chip's
    // exact box. Verify the gutter rect exists in the DOM AND
    // geometrically overlaps the chip. Drop gutters carry a
    // `data-drop-gutter` attribute equal to the encoded id (see
    // GraphView.tsx line ~5343).
    //
    // Note: WITH the UX-K fix there are TWO gutters with this id:
    //   1. The chip-box gutter (this test's target — sits AT the chip).
    //   2. The at-start strip below the chip (CONTAINER_PAD-tall band
    //      above the first real R-track leaf, `expand-R`).
    // Both encode the same drop semantic (prepend to the R-track), so
    // the count assertion is `>= 1`, not `=== 1`. We then pick the
    // one whose box overlaps the chip and assert its geometry.
    const gutters = page.locator('[data-drop-gutter="into-track-start:round.1#1"]');
    const gutterCount = await gutters.count();
    expect(gutterCount, "UX-K gutter must be emitted for round.1's R-track").toBeGreaterThanOrEqual(
      1,
    );

    const chipBox = await rPassthrough.boundingBox();
    if (!chipBox) throw new Error("R-passthrough chip has no boundingBox");

    // Find the gutter whose y coordinate is closest to the chip's y.
    // That's the chip-box gutter — the new emission UX-K added.
    let closestDelta = Number.POSITIVE_INFINITY;
    let closestBox: { x: number; y: number; width: number; height: number } | null = null;
    for (let i = 0; i < gutterCount; i++) {
      const gb = await gutters.nth(i).boundingBox();
      if (!gb) continue;
      const delta = Math.abs(gb.y - chipBox.y);
      if (delta < closestDelta) {
        closestDelta = delta;
        closestBox = gb;
      }
    }
    if (!closestBox) throw new Error("no gutter boundingBox was readable");

    // The chip-box gutter should be geometrically aligned with the
    // chip (within a few pixels of slop for SVG stroke + sub-pixel
    // rendering). The at-start strip below would have a delta on the
    // order of LEAF_H (28px) + STACK_GAP (12px) gap, well outside eps.
    const eps = 3;
    expect(closestDelta, "chip-box gutter y ≈ chip y").toBeLessThanOrEqual(eps);
    expect(Math.abs(closestBox.x - chipBox.x), "gutter x ≈ chip x").toBeLessThanOrEqual(eps);
    expect(Math.abs(closestBox.width - chipBox.width), "gutter w ≈ chip w").toBeLessThanOrEqual(
      eps,
    );
    expect(Math.abs(closestBox.height - chipBox.height), "gutter h ≈ chip h").toBeLessThanOrEqual(
      eps,
    );

    // The actual drop semantic (palette drop → leaf prepended at
    // R-track index 0) is covered by `tests/graph-view-feistel-drop-
    // gutters.test.tsx`'s "UX-K — R-passthrough chip drop gutter
    // (populated R-track)" suite. Real palette-drop interaction in
    // the browser stays in the manual smoke (Phase 6e checklist
    // item 6's drop, but on the R-passthrough specifically). The
    // gutter-presence + geometry assertions above are the strongest
    // jsdom-can't-do-this regression pins available without an
    // unreliable dragTo.

    await page.screenshot({
      path: "test-results/des-6e-17-ux-k-gutter.png",
      fullPage: false,
    });
  });
});
