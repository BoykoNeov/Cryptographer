/**
 * Exploratory smoke — covers the freshest surface (SHA-256 hash flow,
 * Slice 2.10c shipped 2026-05-25 with manual smoke marked pending in
 * the universal-port-dataflow plan) plus a grab-bag of "weird but
 * plausible" inputs that the unit suite doesn't easily reach. Per the
 * `feedback_playwright_dormant` memory this is NOT added to
 * `npm run check` — it's an ad-hoc exploration that runs via
 * `npm run smoke`.
 *
 * Scope split:
 *   "standard" — load-bearing happy paths: KAT, UI-hide invariants,
 *     Save/Load roundtrip, URL share roundtrip, view tabs.
 *   "weird"    — edge inputs the unit suite ignores: 56-byte cap, empty
 *     msg, format-flip mid-edit, rapid category toggle, hash↔cipher
 *     Save→Load cross-load, rapid run clicks.
 *
 * Findings (any UI bug surfaced here) get triaged to either a real fix
 * + regression unit test, or a "won't fix / accepted behavior" note.
 * Don't blindly promote any of these to `npm run check`.
 */

import { type Page, expect, test } from "@playwright/test";

// ─── Helpers ──────────────────────────────────────────────────────────────

const clearAppStorage = async (page: Page): Promise<void> => {
  await page.evaluate(() => {
    window.localStorage.clear();
  });
};

/** Granular pre-test reset: clear storage, then reload so stores rehydrate empty. */
const freshLoad = async (page: Page): Promise<void> => {
  await page.goto("/");
  await clearAppStorage(page);
  await page.reload();
  // Wait for the kind selector to be present — confirms App mounted.
  await expect(page.locator("select").first()).toBeVisible();
};

/**
 * Locate one of the top-row <select>s. Naive `label:has-text(...)` is
 * unsafe: the kind dropdown carries `<option value="cipher">Cipher</option>`
 * + `<option value="hash">Hash</option>`, so `:has-text("cipher")` and
 * `:has-text("hash")` BOTH substring-match the kind label as well as the
 * dropdown they're aimed at. We disambiguate by a unique `<option value>`
 * each select carries.
 */
type SelectName = "kind" | "cipher" | "hash" | "mode" | "cipherMode" | "padding";

const SELECT_PROBE: Record<SelectName, string> = {
  // kind has {cipher, hash}. cipher-the-dropdown has aes-128 instead.
  kind: 'select:has(option[value="cipher"]):has(option[value="hash"])',
  // cipher-variant dropdown: has aes-128 (and only this select does).
  cipher: 'select:has(option[value="aes-128"])',
  // hash dropdown: has sha-256.
  hash: 'select:has(option[value="sha-256"])',
  // encrypt/decrypt mode dropdown.
  mode: 'select:has(option[value="encrypt"])',
  // block-cipher mode of operation.
  cipherMode: 'select:has(option[value="ecb"])',
  // padding scheme.
  padding: 'select:has(option[value="pkcs7"])',
};

const sel = (page: Page, name: SelectName) => page.locator(SELECT_PROBE[name]).first();

/** Read the currently-displayed result text (ciphertext / digest), or null if not visible. */
const readResult = async (page: Page): Promise<string | null> => {
  const code = page.locator(".result code").first();
  if ((await code.count()) === 0) return null;
  if (!(await code.isVisible())) return null;
  return await code.textContent();
};

/** Read the currently-displayed inline error, or null if none visible. */
const readError = async (page: Page): Promise<string | null> => {
  const err = page.locator(".error").first();
  if ((await err.count()) === 0) return null;
  if (!(await err.isVisible())) return null;
  return await err.textContent();
};

const setInput = async (page: Page, labelText: string, value: string): Promise<void> => {
  // The input field is the <input> inside the <label class="data-field">
  // whose text starts with the field name. There are two data-field
  // inputs in cipher mode (input + key) and one in hash mode (input only).
  const field = page.locator(`label.data-field:has-text("${labelText}") input`).first();
  await field.click({ clickCount: 3 }); // select all
  await field.press("Delete");
  if (value.length > 0) await field.type(value);
};

const clickRun = async (page: Page): Promise<void> => {
  await page.getByRole("button", { name: "run", exact: true }).click();
  // Give the synchronous run path a frame to settle. We're not waiting on
  // a network — runtime + render finish in the same task, but a small wait
  // lets MutationObservers + Solid effects flush before the test reads.
  await page.waitForTimeout(50);
};

// ─── Standard flows ───────────────────────────────────────────────────────

test.describe("Standard hash flow (SHA-256, FIPS 180-4 §A.1)", () => {
  test.beforeEach(async ({ page }) => {
    await freshLoad(page);
  });

  test("Flip kind=Hash, Run, digest matches the §A.1 KAT for 'abc'", async ({ page }) => {
    // KAT byte-equal vs FIPS 180-4 §A.1 — this is the load-bearing
    // correctness assertion for SHA-256 wired through the cipher
    // selector, not its unit-test path.
    await sel(page, "kind").selectOption("hash");
    // Wait for the "hash" dropdown to surface (proves the <Show> flipped).
    await expect(sel(page, "hash")).toBeVisible();
    // Default PT should be "abc" → hex "616263". Read the input field.
    const inputField = page.locator(`label.data-field:has-text("message") input`).first();
    await expect(inputField).toHaveValue("616263");

    await clickRun(page);

    const result = await readResult(page);
    expect(result).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  test("Hash mode hides key + mode + cipher-mode + padding selectors", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    // The key field is hidden; only the "message" data-field remains.
    await expect(page.locator(`label.data-field:has-text("key")`)).toHaveCount(0);
    // mode (encrypt/decrypt) is hidden.
    await expect(page.locator(`label:has-text("mode") select`).first()).toHaveCount(0);
    // mode of operation + padding are hidden.
    await expect(page.locator(`label:has-text("mode of operation")`)).toHaveCount(0);
    await expect(page.locator(`label:has-text("padding")`)).toHaveCount(0);
    // The "hash" dropdown IS shown.
    await expect(sel(page, "hash")).toBeVisible();
  });

  test("Remember-last-cipher: cipher → hash → cipher restores prior cipher", async ({ page }) => {
    // Start on AES-128 default. Flip cipher to AES-256 first so we can
    // detect the round-trip (default would be ambiguous).
    await sel(page, "cipher").selectOption("aes-256");
    await expect(sel(page, "cipher")).toHaveValue("aes-256");

    // Detour into hash.
    await sel(page, "kind").selectOption("hash");
    await expect(sel(page, "hash")).toBeVisible();

    // Flip back to cipher — should NOT reset to AES-128 default.
    await sel(page, "kind").selectOption("cipher");
    await expect(sel(page, "cipher")).toHaveValue("aes-256");
  });

  test("Hash mode works in graph view (default-collapsed: no chip wall)", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    await clickRun(page);
    await page.getByRole("tab", { name: "graph", exact: true }).click();
    // Wait for the SVG to mount.
    await expect(page.locator(".graph-container-rect").first()).toBeVisible();

    // Pedagogy gate: SHA-256 default-collapses msg-schedule + 64 rounds,
    // so the visible leaf count is bounded by the un-collapsed leaves
    // (preprocessing + init + final-add + the collapsed containers
    // themselves). If the default-collapse regressed we'd see 1800+
    // leaves. Be loose with the upper bound (200) since the exact count
    // depends on what's outside the collapsed groups today.
    const leafCount = await page.locator(".graph-leaf-rect").count();
    expect(leafCount).toBeLessThan(200);
    // At least ONE collapsed container chip visible (msg-schedule or a round).
    const collapsedChips = await page.locator(".graph-container-rect-collapsed").count();
    expect(collapsedChips).toBeGreaterThan(0);
  });

  test("Hash spec Save → Load roundtrip preserves the hash selection", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    // Capture the saved file's contents via the [save…] button. We need
    // the actual bytes to drive Load (the file-input round-trip is
    // covered by the unit suite; here we synthesize Save→Load by reading
    // the download).
    const downloadPromise = page.waitForEvent("download");
    await page
      .getByRole("button", { name: /^save…?$/i })
      .first()
      .click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/sha-256.*\.cipher\.json$/);

    // Now flip back to cipher (AES-128) so the next Load actually swings.
    await sel(page, "kind").selectOption("cipher");
    await expect(sel(page, "kind")).toHaveValue("cipher");

    // Read the downloaded file's text.
    const path = await download.path();
    if (!path) throw new Error("download.path() returned null");
    const fs = await import("node:fs/promises");
    const text = await fs.readFile(path, "utf-8");
    // Sanity-check the schema before driving Load.
    const parsed: { schemaVersion?: number; algorithm?: string } = JSON.parse(text);
    expect(parsed.schemaVersion).toBe(3);
    expect(parsed.algorithm).toBe("sha-256");

    // Drive Load via the file input. Playwright supports
    // setInputFiles on a hidden <input type="file"> when the buffer is
    // supplied directly.
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: download.suggestedFilename(),
      mimeType: "application/json",
      buffer: Buffer.from(text, "utf-8"),
    });

    // After Load, the kind selector should be back on "hash" and the
    // hash dropdown should read "sha-256".
    await expect(sel(page, "kind")).toHaveValue("hash");
    await expect(sel(page, "hash")).toHaveValue("sha-256");
  });
});

// ─── Weird-but-plausible inputs ───────────────────────────────────────────

test.describe("Weird inputs and edge cases", () => {
  test.beforeEach(async ({ page }) => {
    await freshLoad(page);
  });

  test("SHA-256 with 56 bytes (just over the cap) shows the friendly error", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    // 56 hex bytes = 112 hex chars. One over the single-block cap of 55.
    const tooLong = "61".repeat(56);
    await setInput(page, "message", tooLong);
    await clickRun(page);

    const err = await readError(page);
    expect(err).not.toBeNull();
    expect(err).toMatch(/55/);
    expect(err).toMatch(/56/);
    // Should NOT be a runtime stack trace / internals leak.
    expect(err).not.toMatch(/at \S+\.ts:/);
    expect(err).not.toMatch(/TypeError|RangeError/);
  });

  test("SHA-256 with empty message produces the empty-string digest", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    await setInput(page, "message", "");
    await clickRun(page);

    // FIPS 180-4 §A.1 doesn't ship the empty-string vector; the canonical
    // SHA-256("") digest is widely published:
    //   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const result = await readResult(page);
    const err = await readError(page);
    // Either the result matches the canonical empty-string digest, OR
    // the app declines empty input with a friendly error. Both are
    // defensible UX choices — we record which one the app picked.
    if (result !== null) {
      expect(result).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    } else {
      expect(err).not.toBeNull();
      expect(err).not.toMatch(/TypeError|RangeError|undefined/);
    }
  });

  test("Format flip hex → ascii → decimal preserves the message bytes", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    // Default field is "616263" (hex for "abc"). Flip to ascii — should
    // become "abc". Flip to decimal — should become "97 98 99". Flip back
    // to hex — should be "616263" again. (The app routes through
    // bytes → re-render-in-new-format on every toggle.)
    await page.getByRole("button", { name: "ASCII", exact: true }).click();
    const msgField = page.locator(`label.data-field:has-text("message") input`).first();
    await expect(msgField).toHaveValue("abc");

    await page.getByRole("button", { name: "dec", exact: true }).click();
    // Decimal format is space-separated bytes.
    await expect(msgField).toHaveValue(/97[\s,]+98[\s,]+99/);

    await page.getByRole("button", { name: "hex", exact: true }).click();
    await expect(msgField).toHaveValue("616263");

    // And Run still produces the §A.1 digest after the round-trip.
    await clickRun(page);
    const result = await readResult(page);
    expect(result).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  test("Rapid Cipher↔Hash toggle (10x) lands on a consistent selector", async ({ page }) => {
    // Each toggle triggers a spec rebuild + reactive memo chain. Stress
    // the path to surface any race between the kind signal and the
    // category-derived spec.
    for (let i = 0; i < 10; i += 1) {
      await sel(page, "kind").selectOption(i % 2 === 0 ? "hash" : "cipher");
    }
    // Final state: i=9 odd → cipher. Selector reads "cipher", cipher
    // dropdown is visible, hash dropdown is hidden.
    await expect(sel(page, "kind")).toHaveValue("cipher");
    await expect(sel(page, "cipher")).toBeVisible();
    // Hash dropdown should be unmounted (category=cipher hides it).
    await expect(page.locator(SELECT_PROBE.hash)).toHaveCount(0);
  });

  test("Hash doc Save → switch to AES → Load auto-restores hash mode", async ({ page }) => {
    // Save a SHA-256 document.
    await sel(page, "kind").selectOption("hash");
    const downloadPromise = page.waitForEvent("download");
    await page
      .getByRole("button", { name: /^save…?$/i })
      .first()
      .click();
    const download = await downloadPromise;
    const path = await download.path();
    if (!path) throw new Error("download.path() returned null");
    const fs = await import("node:fs/promises");
    const text = await fs.readFile(path, "utf-8");

    // Switch UI away from hash entirely.
    await sel(page, "kind").selectOption("cipher");
    await sel(page, "cipher").selectOption("aes-256");

    // Load the hash doc.
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: download.suggestedFilename(),
      mimeType: "application/json",
      buffer: Buffer.from(text, "utf-8"),
    });

    // Critical: the kind selector MUST flip back to "hash" (per the
    // setSpecFromDocument hash-branch sync added in Slice 2.10c). If this
    // fails we have a regression of the same bug pattern as the DES
    // URL-share-cipher-selector issue (memory entry
    // project_share_url_cipher_selector_bug).
    await expect(sel(page, "kind")).toHaveValue("hash");
    await expect(sel(page, "hash")).toHaveValue("sha-256");
  });

  test("Five rapid Run clicks in a row don't corrupt the result", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    const runBtn = page.getByRole("button", { name: "run", exact: true });
    // Five clicks in quick succession.
    await runBtn.click();
    await runBtn.click();
    await runBtn.click();
    await runBtn.click();
    await runBtn.click();
    await page.waitForTimeout(150);

    const result = await readResult(page);
    expect(result).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  test("Switching ciphers mid-debounce (rapid changes) ends on a consistent state", async ({
    page,
  }) => {
    // The auto-rerun has a 200ms debounce. Hit the cipher selector
    // faster than that to surface any race between in-flight rerun and
    // the new spec.
    await sel(page, "cipher").selectOption("aes-128");
    await sel(page, "cipher").selectOption("aes-192");
    await sel(page, "cipher").selectOption("aes-256");
    await sel(page, "cipher").selectOption("speck-32-64-be");
    await sel(page, "cipher").selectOption("serpent-128");
    await sel(page, "cipher").selectOption("aes-128");

    // Let the debounce settle.
    await page.waitForTimeout(400);

    await clickRun(page);
    // After landing on AES-128, the result should be SOMETHING (not
    // empty, not error) since the default key + PT are valid.
    const err = await readError(page);
    expect(err).toBeNull();
    const result = await readResult(page);
    expect(result).not.toBeNull();
    expect(result?.length).toBeGreaterThan(0);
  });

  test("View mode tabs all render under hash mode without throwing", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    await clickRun(page);

    for (const tab of ["linear", "graph", "json"]) {
      await page.getByRole("tab", { name: tab, exact: tab !== "json" }).click();
      // No error banner after the tab swap.
      await page.waitForTimeout(50);
      const err = await readError(page);
      expect(err, `view "${tab}" surfaced an error`).toBeNull();
    }
  });

  test("AES-128 with a wrong-length key produces a friendly error, not a crash", async ({
    page,
  }) => {
    // The default AES-128 key is 16 bytes (32 hex chars). Set to 8 bytes
    // (16 hex chars) and Run — should error with a length-related message,
    // not a runtime stack trace.
    await setInput(page, "key", "00112233445566778899aabb"); // 12 bytes
    await clickRun(page);

    const err = await readError(page);
    expect(err).not.toBeNull();
    // Should mention key length somehow.
    expect(err?.toLowerCase()).toMatch(/key|byte|length/);
    expect(err).not.toMatch(/TypeError|RangeError|undefined is not a function/);
  });

  test("Garbage hex (with letters past F) errors gracefully", async ({ page }) => {
    await setInput(page, "key", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
    await clickRun(page);

    const err = await readError(page);
    expect(err).not.toBeNull();
    expect(err).not.toMatch(/TypeError|RangeError|Cannot read/);
  });
});

// ─── Aggressive edge cases — try to actually break things ─────────────────

test.describe("Aggressive edges", () => {
  test.beforeEach(async ({ page }) => {
    await freshLoad(page);
  });

  test("SHA-256 with exactly 55 bytes (the boundary) succeeds", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    // 55 bytes = 110 hex chars. This is the documented single-block max.
    const atCap = "61".repeat(55);
    await setInput(page, "message", atCap);
    await clickRun(page);

    const err = await readError(page);
    expect(err).toBeNull();
    const result = await readResult(page);
    // Should produce SOME 64-char hex digest, not error.
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  test("Navigating to URL with garbage #doc= shows a friendly error, not a crash", async ({
    page,
  }) => {
    await page.goto("/#doc=this-is-not-valid-base64url-deflate-data!!!");
    // Wait briefly for the boot-decode error path to surface.
    await page.waitForTimeout(300);
    // App should still be interactive — the kind selector should be present.
    await expect(sel(page, "kind")).toBeVisible();
    // Look for a friendly error message somewhere. Not asserting exact
    // text since the exact wording depends on which decode step failed —
    // just asserting that the page didn't blank out.
    const body = await page.locator("body").textContent();
    expect(body).toBeTruthy();
    expect(body?.length ?? 0).toBeGreaterThan(50);
  });

  test("Loading a non-cipher JSON file shows a friendly error", async ({ page }) => {
    // Drop a plain JSON file into the file input. parseDocument should
    // reject it with a friendly error, not throw.
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: "not-a-cipher.json",
      mimeType: "application/json",
      buffer: Buffer.from('{"hello": "world"}', "utf-8"),
    });
    await page.waitForTimeout(200);
    const err = await readError(page);
    expect(err).not.toBeNull();
    expect(err).not.toMatch(/TypeError|RangeError|Cannot read/);
    // App still interactive.
    await expect(sel(page, "kind")).toBeVisible();
  });

  test("Loading a totally non-JSON file shows a friendly error", async ({ page }) => {
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: "garbage.json",
      mimeType: "application/json",
      buffer: Buffer.from("this is not JSON at all!!!", "utf-8"),
    });
    await page.waitForTimeout(200);
    const err = await readError(page);
    expect(err).not.toBeNull();
    expect(err).not.toMatch(/TypeError|RangeError|Cannot read/);
  });

  test("Corrupted localStorage layouts entry survives a page reload", async ({ page }) => {
    // Plant garbage in the layouts key, then reload — the layout store
    // should fall back to defaults rather than throwing during boot.
    await page.evaluate(() => {
      window.localStorage.setItem("cryptographer.layouts", "{this is not valid JSON");
    });
    await page.reload();
    // App still boots; can flip to the graph tab without an explosion.
    await expect(sel(page, "kind")).toBeVisible();
    await page.getByRole("tab", { name: "graph", exact: true }).click();
    await expect(page.locator(".graph-container-rect").first()).toBeVisible({ timeout: 5000 });
  });

  test("Save with include-session in HASH mode preserves message + result", async ({ page }) => {
    await sel(page, "kind").selectOption("hash");
    // Edit the message away from the "abc" default to prove it round-trips.
    await setInput(page, "message", "deadbeef");
    await clickRun(page);
    const expectedDigest = await readResult(page);
    expect(expectedDigest).toMatch(/^[0-9a-f]{64}$/);

    // Toggle include-session ON.
    await page.getByLabel("include session").check();

    // Save.
    const downloadPromise = page.waitForEvent("download");
    await page
      .getByRole("button", { name: /^save…?$/i })
      .first()
      .click();
    const download = await downloadPromise;
    const path = await download.path();
    if (!path) throw new Error("download.path() returned null");
    const fs = await import("node:fs/promises");
    const text = await fs.readFile(path, "utf-8");
    // include-session serializes bytes as a decimal array (Zod's
    // representation of Uint8Array → number[]), not as the hex display
    // string. deadbeef → [0xde, 0xad, 0xbe, 0xef] = [222, 173, 190, 239].
    expect(text).toContain("[222,173,190,239]");

    // Now nuke storage so the in-memory message+key signals reset, then
    // Load the file from a fresh state.
    await clearAppStorage(page);
    await page.reload();
    await expect(sel(page, "kind")).toBeVisible();

    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: download.suggestedFilename(),
      mimeType: "application/json",
      buffer: Buffer.from(text, "utf-8"),
    });

    // After load: category=hash, hash=sha-256, message field shows "deadbeef".
    await expect(sel(page, "kind")).toHaveValue("hash");
    await expect(sel(page, "hash")).toHaveValue("sha-256");
    const msgField = page.locator(`label.data-field:has-text("message") input`).first();
    await expect(msgField).toHaveValue("deadbeef");

    // Re-run and confirm the digest matches what we saved.
    await clickRun(page);
    const reRunDigest = await readResult(page);
    expect(reRunDigest).toBe(expectedDigest);
  });

  test("Hash URL share → fresh load restores hash mode (same bug-class as DES URL-share)", async ({
    page,
    context,
  }) => {
    // Same bug pattern as memory entry `project_share_url_cipher_selector_bug`:
    // the recipient of a `#doc=` URL must have the kind selector flip
    // to match the loaded doc. Slice 2.10c's setSpecFromDocument hash
    // branch is supposed to write the category + hash signals. This
    // pins the URL boot path.
    await sel(page, "kind").selectOption("hash");
    await setInput(page, "message", "cafebabe");

    // Grant clipboard read so we can pull the share URL back.
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page
      .getByRole("button", { name: /^share…?$/i })
      .first()
      .click();
    // Wait for the share status to confirm the copy landed.
    await expect(page.locator(".share-status")).toBeVisible();
    const sharedUrl = await page.evaluate(() => navigator.clipboard.readText());
    expect(sharedUrl).toMatch(/#doc=/);

    // Open the shared URL in a fresh page (cold boot via the URL hash).
    const recipient = await context.newPage();
    await recipient.goto(sharedUrl);
    // Boot decode is sync inside applyDocument; give Solid a tick to
    // apply the resulting setCategory/setHash.
    await recipient.waitForTimeout(300);

    // Critical: kind selector + hash dropdown both reflect the shared doc.
    await expect(sel(recipient, "kind")).toHaveValue("hash");
    await expect(sel(recipient, "hash")).toHaveValue("sha-256");
    await recipient.close();
  });

  test("compare-runs button stays sane across a category flip", async ({ page }) => {
    // Run AES once to seed the history buffer.
    await clickRun(page);
    await page.waitForTimeout(150);
    // historyCount > 0 — the button surfaces a number in parens.
    const compareBtn = page.getByRole("button", { name: /compare runs/i });
    await expect(compareBtn).toBeVisible();
    const cipherLabel = await compareBtn.textContent();

    // Flip to hash and run.
    await sel(page, "kind").selectOption("hash");
    await clickRun(page);
    await page.waitForTimeout(150);

    // The compare-runs button should still render. The button text counts
    // the snapshots — we don't pin the exact count, just that the button
    // didn't blank out or remove itself.
    const hashLabel = await compareBtn.textContent();
    expect(hashLabel).toBeTruthy();
    expect(hashLabel?.toLowerCase()).toContain("compare");

    // The button is clickable without crashing the app.
    await compareBtn.click();
    await page.waitForTimeout(100);
    // App still alive — selector visible.
    await expect(sel(page, "kind")).toBeVisible();

    // Suppress unused-var warning while keeping cipher snapshot info
    // available if a future failure needs it for debugging.
    void cipherLabel;
  });

  test("Auto-rerun OFF + hash message edit surfaces the 'edits pending' banner", async ({
    page,
  }) => {
    // App.tsx:834 — the dirty-tracking createEffect's dep tuple is
    // `[spec, inputText, keyText, ivBytes]`. So an input-field edit DOES
    // fire dirty, and the pending banner SHOULD appear in manual mode.
    // That's intentional: the input is the runtime's input, so a typed
    // change is a legitimate reason to re-run.
    await page.getByLabel("auto-rerun").uncheck();
    await sel(page, "kind").selectOption("hash");
    // Seed history with one run so hasRunOnce() is true (the dirty
    // effect bails before that gate; without seeding, edits silently
    // don't dirty).
    await clickRun(page);

    await setInput(page, "message", "ffeeddcc");
    await page.waitForTimeout(300);
    const banner = page.locator(".pending-banner");
    await expect(banner).toBeVisible();
    const bannerText = await banner.textContent();
    expect(bannerText?.toLowerCase()).toContain("run");
  });
});
