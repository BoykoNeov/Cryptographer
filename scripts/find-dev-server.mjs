// Finds an already-running Cryptographer dev server, for "Start Cryptographer.bat".
//
// Why this exists: the launcher used to start ANOTHER Vite dev server on every
// double-click. Vite does not fail when its port is busy — it climbs to the next
// free one — so nothing ever complained, and the servers quietly stacked up
// (sixteen of them across 5173-5190, each holding a render loop open in any tab
// still pointed at it). So the launcher asks this script first: is one of mine
// already up? Reuse it if so; start a fresh one only if not.
//
// THE ONE RULE: a port does not tell you whose server it is. Several Vite
// projects on this machine climb past each other, so 5173 is very often a
// DIFFERENT app. Checking "is something listening on 5173" is the same bug in a
// different costume — it hijacks whatever is there. We identify a server by what
// it SERVES: fetch each port and match index.html's <title>.
//
// Reuse is safe, and not a bet on staleness: Vite transforms from disk on every
// request, so a server left running for days serves the code as it is now. The
// one thing a running server cannot pick up is a vite.config change, which is
// why the launcher prints how to start fresh.
//
// Constraints this file has to keep:
//   - Dependency-free. It runs before the launcher's node_modules check, on a
//     machine where nothing is set up. Global fetch + node:url, nothing more.
//   - stdout is the URL and NOTHING else; the .bat reads it straight into a
//     variable. Diagnostics go to stderr.
//   - It lives outside tsconfig's `include` and vitest's globs on purpose.

import { pathToFileURL } from "node:url";

// Must match index.html's <title> EXACTLY.
//
// This string is load-bearing: it is the whole basis on which the launcher tells
// our dev server apart from every other Vite app on this machine. Renaming the
// <title> without renaming this constant does not fail loudly — it silently
// returns the launcher to stacking a new server on every run. There is a
// matching comment next to the <title> tag in index.html.
const APP_TITLE = "Cryptographer";

// Vite starts at 5173 and climbs ONE port at a time when busy, so a contiguous
// sweep is the only honest scan. A sparse list (the old launcher probed
// 5173 5174 5175 5180 5190) misses ours whenever it landed on, say, 5176
// because three other projects got there first.
const PORT_START = 5173;
const PORT_END = 5188;

// Per-port budget. A closed port refuses instantly, so this only bounds the
// pathological case: something accepts the connection and then stalls.
const PROBE_TIMEOUT_MS = 700;

/** Trimmed text of the first <title> element, or null if there isn't one. */
function titleOf(html) {
  const match = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  return match?.[1] === undefined ? null : match[1].trim();
}

/**
 * Fetch one port and report whether it is serving THIS app.
 *
 * Owns its timer instead of using AbortSignal.timeout(). On Windows/libuv the
 * timers that AbortSignal.timeout arms outlive the answer, and exiting under
 * them dies with "Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file
 * src\\win\\async.c" and exit code 127 rather than exiting. Clearing it in
 * `finally` leaves the event loop empty so node drains and exits on its own.
 *
 * Note `localhost`, not 127.0.0.1: Vite binds [::1] here, so the v4 literal
 * would find nothing. `localhost` lets node try both families.
 */
async function servesThisApp(port) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  try {
    const response = await fetch(`http://localhost:${port}/`, { signal: controller.signal });
    if (!response.ok) return false;
    return titleOf(await response.text()) === APP_TITLE;
  } catch {
    // Nothing listening (the common case — ECONNREFUSED), something that isn't
    // HTTP, or a stall that hit the timeout. None of these is our server, and
    // none is worth saying anything about.
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * URL of the first port in the range serving this app, or null if none is.
 *
 * Sequential on purpose: it keeps exactly one timer armed at a time (see
 * servesThisApp), and closed ports refuse instantly, so the sweep costs
 * milliseconds in practice.
 */
export async function findRunningServer() {
  for (let port = PORT_START; port <= PORT_END; port++) {
    if (await servesThisApp(port)) return `http://localhost:${port}`;
  }
  return null;
}

// `import.meta.main` would be the obvious way to spell this, and it is a trap:
// it only exists on node 24.2+. On anything older it is silently `undefined`, so
// the detector prints nothing, the launcher reads nothing, and it goes straight
// back to stacking with no sign that anything broke. Compare explicitly.
const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const url = await findRunningServer();
  // stdout carries the URL and nothing else; the .bat captures it verbatim.
  if (url !== null) console.log(url);
  // Deliberately no process.exit() — see servesThisApp. Every timer is cleared,
  // so the loop drains and the process exits 0 by itself.
}
