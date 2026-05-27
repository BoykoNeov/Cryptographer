#!/usr/bin/env node
/**
 * Ad-hoc screenshot harness for the 2026-05-27 altitude-staggering
 * visual A/B investigation. Bypasses the playwright test runner
 * (which auto-detects 5173 and would hit a stale dev server) and
 * speaks directly to a chromium instance launched by the playwright
 * SDK. Writes two PNGs into `e2e/.artifacts/` plus the md5 of each.
 *
 * Run:
 *   node scripts/altitude-staggering-shots.mjs [URL]
 *
 * URL defaults to `http://localhost:5176`. If you launch your own
 * `npm run dev` first, pass whatever port vite chose. Vite scans for
 * free ports starting at 5173 and writes the chosen one to stderr.
 *
 * Diagnostic only; delete after the investigation closes.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { chromium } from "playwright";

const URL = process.argv[2] ?? "http://localhost:5176";
const OUT_DIR = resolve("e2e/.artifacts");
mkdirSync(OUT_DIR, { recursive: true });

const VIEWPORT = { width: 1920, height: 1200 };

const md5 = (path) => createHash("md5").update(readFileSync(path)).digest("hex");

const expandAll = async (page) => {
  for (let i = 0; i < 60; i += 1) {
    const collapsed = page.locator(".graph-container-rect-collapsed");
    const count = await collapsed.count();
    if (count === 0) break;
    await collapsed.first().click();
    await page.waitForTimeout(80);
  }
};

const shootGraph = async (page, fileName) => {
  await page.getByRole("tab", { name: "graph", exact: true }).click();
  await page.waitForSelector(".graph-container-rect, .graph-leaf-rect", {
    timeout: 30_000,
  });
  await expandAll(page);
  await page.waitForTimeout(400);
  const outPath = resolve(OUT_DIR, fileName);
  await page.screenshot({ path: outPath, fullPage: true });
  return outPath;
};

const freshLoad = async (page) => {
  await page.setViewportSize(VIEWPORT);
  await page.goto(URL, { waitUntil: "domcontentloaded" });
  await page.waitForSelector("select", { timeout: 60_000, state: "visible" });
  await page.evaluate(() => window.localStorage.clear());
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForSelector("select", { timeout: 60_000, state: "visible" });
};

const main = async () => {
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: VIEWPORT });
    const page = await ctx.newPage();

    // SHA-256.
    await freshLoad(page);
    await page.locator('select:has(option[value="hash"])').first().selectOption("hash");
    await page.getByRole("button", { name: "run", exact: true }).click();
    await page.waitForTimeout(400);
    const shaPath = await shootGraph(page, "sha-256-expanded.png");
    console.log(`SHA-256 expanded: ${shaPath}  md5=${md5(shaPath)}`);

    // AES-128 ECB.
    await freshLoad(page);
    await page.locator('select:has(option[value="aes-128"])').first().selectOption("aes-128");
    await page.getByRole("button", { name: "run", exact: true }).click();
    await page.waitForTimeout(400);
    const aesPath = await shootGraph(page, "aes-128-ecb-expanded.png");
    console.log(`AES-128 ECB expanded: ${aesPath}  md5=${md5(aesPath)}`);
  } finally {
    await browser.close();
  }
};

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
