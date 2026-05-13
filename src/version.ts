/**
 * Single source of truth for the app's semver version.
 *
 * Sourced from `package.json` so a release bump is a one-file change:
 *   1. bump `package.json` "version"
 *   2. update `CHANGELOG.md` heading
 *   3. tag with the matching `vX.Y.Z`
 *
 * `resolveJsonModule: true` is on in `tsconfig.json`; Vite (production +
 * vitest) and TypeScript both honour the JSON import. The narrow `: string`
 * annotation discards the wider literal type — we don't want every consumer
 * to be a compile-time dependency of the exact version string.
 *
 * Surfaced by:
 *   - the UI footer (informational; visitors learn which build they're on)
 *   - `buildSaveText` in App.tsx (stamps `metadata.appVersion` into exports
 *     when session bytes are included — spec-only saves stay byte-stable so
 *     the Slice 7 URL-share invariant survives)
 */

import pkg from "../package.json" with { type: "json" };

export const APP_VERSION: string = pkg.version;
