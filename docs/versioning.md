# Versioning policy

Cryptographer has three independent versioned surfaces. Each answers a different "did anything I rely on change?" question, so they're tracked separately rather than collapsed into one number.

| Surface | Where it lives | Who cares |
|---|---|---|
| **App version** (semver) | [`package.json`](../package.json) → [`src/version.ts`](../src/version.ts) → UI footer + exported `metadata.appVersion` | End users, anyone reading [`CHANGELOG.md`](../CHANGELOG.md) |
| **Step-type contract** (`@N` suffix on every step's type key) | `src/ciphers/default-registry.ts`, every `CipherSpec` JSON | Saved-document longevity |
| **Document schema** (`schemaVersion: 3`) | [`src/core/document.ts`](../src/core/document.ts) + [`src/core/document-schema.ts`](../src/core/document-schema.ts) | Anyone loading a `.cipher.json` file produced by an older build |

This page describes how each one is bumped and what's invariant across a bump.

---

## 1. App version (semver)

[`package.json`](../package.json)'s `"version"` is the single source of truth. [`src/version.ts`](../src/version.ts) re-exports it as `APP_VERSION`; the UI footer and the document-export path read from there.

### When to bump

Standard semver — applied at the granularity of "what a user can observe":

- **MAJOR** (`X.0.0`) — a previously valid input now produces a different output, or a published shortcut/UI affordance is removed without a one-version deprecation window. Practically: any change that breaks a `.cipher.json` from an older build without an automatic migration falls here, even if `schemaVersion` is bumped (the migration counts as the major signal).
- **MINOR** (`0.X.0`) — a new cipher, a new mode of operation, a new padding scheme, a new UI feature, a new step type. Backward compatible. Most releases.
- **PATCH** (`0.0.X`) — a bug fix, a doc tweak, a CSS adjustment, a refactor with no observable change. The trace output for any existing spec is byte-identical before and after.

Pre-1.0: the API is "stable as a learning tool" but not yet "stable as a library." MINOR bumps may include breaking refinements to internal contracts (`src/core/types.ts` for example) — those land with a `CHANGELOG.md` entry under **Changed** and are flagged in any plan doc that depended on them.

### Release process

1. **Land all the substantive changes** on `main` (or merge them).
2. **Bump `package.json` "version"** (one-line edit).
3. **Update `CHANGELOG.md`** — convert the `[Unreleased]` section into a dated `[X.Y.Z]` heading; start a fresh empty `[Unreleased]`; append the compare-link at the bottom.
4. **Commit** with title `Release vX.Y.Z` (or fold into a feature commit if the bump rides one).
5. **Push the tag**: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.

The tag triggers GitHub's "Releases" surface — the release page auto-populates from the changelog entry plus the tagged commit's diff.

### What's stamped in artifacts

- **UI footer**: every build shows `Cryptographer v{APP_VERSION}` at the bottom of the page, so a user can match what they see to a CHANGELOG entry.
- **Saved `.cipher.json` files**: when the user ticks "include session" on Save, `metadata.appVersion` lands alongside `metadata.createdAt`. Spec-only saves are deliberately byte-stable across builds (no version stamp) so the planned URL-share feature can derive deterministic share links from the spec alone — see [`docs/key-files.md`](./key-files.md) for the byte-stability invariant.

---

## 2. Step-type contract (`@N` suffix)

Every step type registered in `src/ciphers/default-registry.ts` carries an `@N` suffix on its key:

```ts
r.register("generic.byte-substitution@1", { executor: subBytes, doc: subBytesDoc });
r.register("aes.key-expansion@1",          { executor: keyExpansion, doc: keyExpansionDoc });
```

Every `CipherSpec` references step types by string key, and those strings get baked into saved `CipherSpec` JSON files **forever**. The suffix is what lets a future contract change land without invalidating files produced by today's build.

The bump rules and the new-step-type checklist live alongside the step implementations themselves — see [`src/steps/CLAUDE.md`](../src/steps/CLAUDE.md). The short version:

- **`@N` is mandatory** on every registration, even the first one (`@1`).
- **Bump to `@2`** when the parameter shape or step semantics change in a backwards-incompatible way. Examples that would force a bump: renaming a `params` field, changing a field's type, changing what auxKey the step writes, changing the output state's shape.
- **Refinements that don't break** an old spec stay at `@N`: a new optional param with a documented default, a UI-only doc-text edit, a performance refactor with the same observable behavior.
- **Keep `@1` registered** when you ship `@2` — old saved specs reference `@1` by string and the registry resolves them via exact match. Two implementations coexist until you're ready to migrate every shipped spec (and that migration belongs in a separate commit with its own CHANGELOG entry).

No step type has been bumped past `@1` yet. The protocol exists so the first bump isn't disruptive.

---

## 3. Document schema (`schemaVersion`)

`schemaVersion: 3` is the current literal. Older documents still load via forward migration in [`parseDocument`](../src/core/document.ts): v1 saves (produced before Phase 4 of `docs/plans/des-feistel.md` shipped DES into the cipher selector) and v2 saves (produced before the `cipher` → `algorithm` field rename) both walk forward to v3 — see "Migration mechanics" below for the concrete shape of each hop. The strict/loose layer split in [`src/core/document-schema.ts`](../src/core/document-schema.ts) decides what triggers a bump:

- **Wrapper layers** (`CipherDocument`, `LayoutSpec`, `SessionSnapshot`, `DocumentMetadata`) use Zod's `.strict()` — unknown fields are rejected. **Adding a new field at any wrapper layer requires bumping `schemaVersion`.**
- **`CipherSpec` and `StepNode` interiors** are loose by default — they mirror `core/types.ts`, which is "load-bearing forever." Spec-level extensions (a new step kind, a new aux key, optional fields on a step's params) can land without forcing a migration; they're caught by the per-step Zod schemas when relevant.

### When to bump

(Phase 4 of `docs/plans/des-feistel.md` made the v1 → v2 hop; Slice 2.10b of `docs/plans/universal-port-dataflow.md` made the v2 → v3 hop — the `cipher` → `algorithm` field rename. The triggers below apply to the next bump, v3 → v4.)

- A new required field at a wrapper layer.
- A removed wrapper-layer field that loaders rely on.
- A change in the semantics of an existing wrapper-layer field (e.g. `LayoutSpec.flowDirection` gaining a new legal value if existing v1 readers can't tolerate it — though `"ltr"` was chosen as the only legal value precisely so a future `"ttb"` doesn't force a bump).
- A breaking change to a step-type contract that the `CipherSpec` interior loose-pass can't handle gracefully (rare; the `@N` suffix usually absorbs this).

### Migration mechanics

[`parseDocument`](../src/core/document.ts) holds the seam:

1. **Phase 2 pre-check** — `parseDocument` inspects `raw.schemaVersion` before running the full Zod schema. Today it accepts any version in `ACCEPTED_SCHEMA_VERSIONS` (currently `[1, 2, 3]`) and rejects everything else with a friendly forward/backward-compat error message listing the accepted set.
2. **`migrateDocument`** — when the version doesn't equal `CURRENT_SCHEMA_VERSION`, the pre-check hands off to `migrateDocument(raw, fromVersion)`, which is a pure function that walks v1 → v2 → v3 → … → CURRENT applying any per-version transforms. The v1 → v2 step (shipped in Phase 4 of `docs/plans/des-feistel.md`) is a pure version-field bump — v1 documents predate DES being in the cipher selector, so they cannot contain `feistel-round` nodes and no node-level changes are required. The v2 → v3 step (Slice 2.10b of `docs/plans/universal-port-dataflow.md`) renames the top-level cipher-hint field `cipher` → `algorithm`; the value passes through unchanged because every v2 cipher value is still a valid `Algorithm`.
3. **When v4 lands** — add a `if (fromVersion <= 3)` step inside `migrateDocument` that returns a v4 document. Add `4` to `ACCEPTED_SCHEMA_VERSIONS`, bump `CURRENT_SCHEMA_VERSION` to 4, and flip `CipherDocumentSchema`'s `z.literal(3)` to `z.literal(4)`. Existing v1/v2/v3 documents are now migrated forward to v4 transparently.
4. **Loaders ≥ vN** — happily accept any version in `ACCEPTED_SCHEMA_VERSIONS` (migrated on the fly) and reject newer versions with the friendly error. Old loaders (v(N-1)-only builds) reject v(N) files with the friendly error; this is intended and the user-facing message tells them which app version their file came from.

The strictness split is doing real work here: a `.strict()` wrapper layer means that the moment someone tries to land an unannounced field at that layer, Zod fails the parse and the change is forced through the migration discipline rather than silently passed through.

---

## Cross-references

- [`CHANGELOG.md`](../CHANGELOG.md) — the release log.
- [`src/version.ts`](../src/version.ts) — the version constant.
- [`src/core/document.ts`](../src/core/document.ts), [`src/core/document-schema.ts`](../src/core/document-schema.ts) — the document format.
- [`src/steps/CLAUDE.md`](../src/steps/CLAUDE.md) — step-type checklist + `@N` rules.
- [`docs/key-files.md`](./key-files.md) — the file-by-file map, including the byte-stability invariant for URL-share.
