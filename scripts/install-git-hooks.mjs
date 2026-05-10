// Run via `npm install` (the `prepare` lifecycle script).
// Points git at the tracked hooks directory so contributors automatically
// pick up the pre-commit gate without installing any extra package
// (husky/simple-git-hooks/etc.).
//
// Skips on CI (where it would be wasted work, and not all CI images even
// have git config writable in the way we need) and skips quietly when the
// project isn't a git checkout (e.g. someone extracted a tarball).

import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

// Most CI providers set CI=true; honor that so we don't muck with config there.
if (process.env.CI) {
  process.exit(0);
}

// If there's no .git directory, this isn't a git checkout — nothing to do.
if (!existsSync(resolve(repoRoot, ".git"))) {
  process.exit(0);
}

try {
  // Tell git to look for hooks in `.githooks/` (tracked) rather than the
  // default `.git/hooks/` (untracked). Local config; doesn't affect remote.
  execSync("git config core.hooksPath .githooks", {
    cwd: repoRoot,
    stdio: "inherit",
  });
  console.log("[install-git-hooks] core.hooksPath = .githooks");
} catch (err) {
  // Don't fail npm install over hook setup — just warn.
  console.warn("[install-git-hooks] could not configure hooks:", err.message);
}
