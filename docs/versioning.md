# Versioning policy

Cryptographer has three independent versioned surfaces. Each answers a different "did anything I rely on change?" question, so they're tracked separately rather than collapsed into one number.

| Surface | Where it lives | Who cares |
|---|---|---|
| **App version** (semver) | [`package.json`](../package.json) → [`src/version.ts`](../src/version.ts) → UI footer + exported `metadata.appVersion` | End users, anyone reading [`CHANGELOG.md`](../CHANGELOG.md) |
| **Step-type contract** (`@N` suffix on every step's type key) | `src/ciphers/default-registry.ts`, every `CipherSpec` JSON | Saved-document longevity |
| **Document schema** (`schemaVersion: 1`) | [`src/core/document.ts`](../src/core/document.ts) + [`src/core/document-schema.ts`](../src/core/document-schema.ts) | Anyone loading a `.cipher.json` file produced by an older build |

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

`schemaVersion: 1` is the migration anchor on the `CipherDocument` file format. The strict/loose layer split in [`src/core/document-schema.ts`](../src/core/document-schema.ts) decides what triggers a bump:

- **Wrapper layers** (`CipherDocument`, `LayoutSpec`, `SessionSnapshot`, `DocumentMetadata`) use Zod's `.strict()` — unknown fields are rejected. **Adding a new field at any wrapper layer requires bumping `schemaVersion`.**
- **`CipherSpec` and `StepNode` interiors** are loose by default — they mirror `core/types.ts`, which is "load-bearing forever." Spec-level extensions (a new step kind, a new aux key, optional fields on a step's params) can land without forcing a migration; they're caught by the per-step Zod schemas when relevant.

### When to bump from v1 to v2

- A new required field at a wrapper layer.
- A removed wrapper-layer field that loaders rely on.
- A change in the semantics of an existing wrapper-layer field (e.g. `LayoutSpec.flowDirection` gaining a new legal value if existing v1 readers can't tolerate it — though `"ltr"` was chosen as the only legal value precisely so a future `"ttb"` doesn't force a bump).
- A breaking change to a step-type contract that the `CipherSpec` interior loose-pass can't handle gracefully (rare; the `@N` suffix usually absorbs this).

### Migration mechanics

[`parseDocument`](../src/core/document.ts) already has the seam:

1. **Phase 2 pre-check** — `parseDocument` inspects `raw.schemaVersion` before running the full Zod schema. Today, any number other than `1` returns a friendly forward/backward-compat error message.
2. **When v2 lands** — replace the friendly-reject for `2` with an explicit `migrate(v1 → v2)` step that returns a v2 document. The full Zod schema then validates as v2. The migration is a pure function: `(rawV1Doc): RawV2Doc`. Test it both directions if v2 is going to write back to v1 (usually it isn't — v2 is what you save).
3. **Loaders ≥ v2** — happily accept both v1 (migrated on the fly) and v2 (validated directly). Old loaders (v1-only builds) reject v2 files with the friendly error; this is intended and the user-facing message tells them which app version their file came from.

The strictness split is doing real work here: a `.strict()` wrapper layer means that the moment someone tries to land an unannounced field at that layer, Zod fails the parse and the change is forced through the migration discipline rather than silently passed through.

---

## Cross-references

- [`CHANGELOG.md`](../CHANGELOG.md) — the release log.
- [`src/version.ts`](../src/version.ts) — the version constant.
- [`src/core/document.ts`](../src/core/document.ts), [`src/core/document-schema.ts`](../src/core/document-schema.ts) — the document format.
- [`src/steps/CLAUDE.md`](../src/steps/CLAUDE.md) — step-type checklist + `@N` rules.
- [`docs/key-files.md`](./key-files.md) — the file-by-file map, including the byte-stability invariant for URL-share.
