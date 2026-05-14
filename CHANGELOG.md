# Changelog

All notable changes to Cryptographer are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [`docs/versioning.md`](./docs/versioning.md) for the versioning policy (release process, step-type `@N` suffix bumps, and document `schemaVersion` migrations).

## [Unreleased]

### Added
- **Delete affordances on graph nodes** — palette-dropped (and any other) leaves + containers can now be removed via three surfaces: a small red `×` button at each node's top-left corner (hover-revealed via CSS opacity so the canvas stays uncluttered; suppressed on replicas), a "Delete this step" button at the bottom of the `ParamEditor` panel, and the <kbd>Delete</kbd> key while a node is focused (<kbd>Backspace</kbd> deliberately *not* bound — reserved for future navigation). All three route through a new `removeStepFromSpec` wrapper in `src/ui/stores/spec.ts` around the existing pure `removeStep` mutator in `core/spec-mutations.ts` (tree-aware: deleting a container removes every descendant in one step). The wrapper is lenient on stale ids (warns to console but doesn't throw) so a delete that races with another spec edit doesn't crash the UI. No undo, no confirmation — pedagogy is "experiment freely, see what breaks"; recover by dragging from the palette. 7 new tests in `tests/spec-delete.test.tsx` covering all three surfaces + the store wrapper's leniency contract. Suite at 705 tests across 58 files.
- **State-shape contracts on step types** — every step type now declares (via the new optional `shapeContract` field on `StepDocumentation`) which `StateShape` its executor accepts and what shape it produces (`bytes` / `matrix4x4-bytes` / `"any"`; `output: "preserveInput"` for the common passthrough case). Three UX surfaces consume the contract: (1) the step palette renders a small chip ("bytes" / "4×4 matrix" / "any") on every entry plus a "Expects: bytes state" tooltip; (2) during a palette drag, drop anchors whose inferred state shape doesn't match the dragged step's input dim to 35% opacity (advisory only — the drop is not blocked); (3) `validateGraph` gains a fourth warning kind `state-shape-mismatch`, surfaced as the same orange `!` glyph used by the other validators but emitted statically (trace-free) so the warning lights up the moment a shape-incompatible step is dropped, *before* the user clicks Run — catching what was previously the "compute-block-count expects bytes state" runtime exception. New `src/core/spec-shapes.ts` (`inferShapesAtAnchors` + `validateShapes`) does one spec walk that drives both the drop-anchor `data-state-shape` decoration and the static warning. Contracts backfilled across all 28 shipped step files in one commit; `tests/state-shape-contracts.test.ts` enforces 100% coverage on the default registry so a future step shipped without a contract fails CI. 20 new tests across four files (`spec-shapes`, `state-shape-contracts`, `step-palette` extension, `graph-view-drop-greying`). Suite at 698 tests across 57 files. Bundle 84.02 KB → 84.99 KB gzipped.
- **End-to-end integration + in-app help (Slice 11 of the 2D editor plan, the final slice)** — ships nothing structurally new on its own; instead it pins the prior 10 slices' composition in `tests/built-from-palette-roundtrip.test.tsx` (jsdom). The test drives the full user pathway: open app → switch to graph view → drop a step from the palette via the real DataTransfer pathway → mutate two more via the same store boundary → edit each step's params → pin a layout position on a *user-inserted* id → Save with session ON → fully reset every store → Load → assert the inserted leaves, edited params, and layout pin all survive, plus the cipher's final-state bytes are byte-equal across the boundary. Also adds an in-app `?` help button on the graph toolbar that opens a `<dialog>` rendering `docs/help/graph-view.md` (loaded via Vite `?raw` so the .md file is the single source of truth for both GitHub readers and the in-app modal). New `src/ui/components/GraphHelpModal.tsx`, new `docs/help/graph-view.md`, four new tests across two new files. Suite at 678 tests across 54 files. Bundle 81.92 KB → 84.02 KB gzipped (the +2 KB is the help modal component + bundled markdown + CSS).
- **Edge-aware graph validation (Slice 9 of the 2D editor plan)** — `core/graph.ts` now exports `validateGraph(graph, trace) → GraphWarning[]` plus a `GraphWarning` discriminated union (`orphaned-read` | `unused-write` | `cycle`). GraphView overlays a small orange `!` glyph on any leaf or container that carries at least one warning; the glyph's `<title>` shows the formatted message as a native tooltip (the plan also mentioned an inline message panel — that's an optional V2 follow-up, V1 is the tooltip + `cursor: help`). Warnings that target a node hidden by a collapsed container surface on the outermost visible ancestor so collapse can't silently hide wiring problems. Today's shipped specs produce zero warnings across all ciphers (AES-128/192/256, AES-128-ECB, Speck32/64 BE+LE, Serpent-128/192/256) — locked in by `tests/graph-validation.test.ts`. Orphaned-read coverage will light up naturally when Slice 10's graceful aux primitives (`aux-xor`, `aux-copy`, `aux-load`) land; today's strict consumers throw on missing aux rather than emit a flag-able frame.
- `TraceFrame.auxReadMissing?: readonly string[]` — runtime now records aux-read requests that returned `undefined` (in addition to the existing `auxRead` map of successful reads). Required for orphaned-read detection; in-memory only, never serialized.
- 23 new tests: 21 in `tests/graph-validation.test.ts` (zero-warning baseline per cipher, orphan/unused-write/cycle detection, runtime capture verification) and 2 in `tests/graph-view.test.tsx` (clean traces render no dots; synthetic `auxReadMissing` frame produces one dot with the missing key in the title). Suite at 643 tests across 51 files. Bundle 77.4 KB → 78.4 KB gzipped.
- **URL hash sharing (Slice 7 of the 2D editor plan)** — new `[share…]` button next to Save/Load. Encodes the current `CipherDocument` as `${origin}${pathname}#doc=<base64url-deflate-raw>` and copies it to the clipboard; opening that URL in a fresh tab decodes on mount and snaps the spec / layout / session to the shared values, then strips the hash from the address bar so a refresh doesn't re-apply. Honors the same `include session` toggle as Save (default off → spec-only, byte-stable across sessions). Compression uses the browser-native `CompressionStream("deflate-raw")`, no new dependencies; measured payloads land at ~1.6 KB for spec-only AES-128 and ~1.9 KB for the AES-256 + session worst case (vs. ~20 KB without compression). Bundle grew from 72 KB → 76 KB gzipped (compression is built-in; the +4 KB is the new `src/ui/stores/url-share.ts` module + handler wiring).
- Clipboard-write failure (HTTP context / permission denied) falls back to writing the URL into the address bar so the user can copy it manually.
- 20 new tests across `tests/url-share.test.ts` (node env — encode/decode round-trip, determinism, size budget, malformed payload handling) and `tests/app-url-share.test.tsx` (jsdom — Share button → clipboard, boot-mount hash decode for spec-only + session + layout sidecar, malformed-payload error path, no-hash noop). Suite now at 608 tests across 49 files.

## [0.2.0] — 2026-05-13

### Added — release infrastructure
- **README.md** as the public-facing GitHub entry point — what the project is, install + run, command table, architecture summary, project layout, pointers into the docs.
- **CHANGELOG.md** (this file) tracking releases retrospectively from v0.1.0.
- **LICENSE** (MIT).
- **`docs/versioning.md`** formalizing the versioning policy: app semver release process, the `stepType@N` suffix convention, and the document `schemaVersion` migration path.
- **`src/version.ts`** re-exporting `package.json` version as `APP_VERSION` so the UI and the document-export path share one source of truth.
- **UI footer** showing the current build version and a link to the GitHub repo.
- **`metadata.appVersion`** is now stamped into exported `.cipher.json` documents — but only on the session-included save path, alongside the existing `createdAt`. Spec-only saves remain byte-identical across builds so the planned URL-share feature (Slice 7) stays deterministic.

### Notes
The schema field `DocumentMetadata.appVersion?: string` has been part of `schemaVersion: 1` since Slice 3 — this release just starts populating it. No schema bump.

## [0.1.0] — 2026-05-13 (retrospective)

The initial release, reconstructed from `git log`. This entry covers everything that landed before the release-infrastructure work in v0.2.0.

### Added — ciphers
- **AES-128** forward + inverse (FIPS-197 Appendix C.1 vectors).
- **AES-192** and **AES-256** with NIST AES Core known-answer tests + the FIPS-197 §A.2/§A.3 round-key assertions. Shared step types with AES-128; the `aes.key-expansion@1` step has an Nk>6 branch that fires only for AES-256.
- **Speck32/64** in two byte-order conventions: big-endian (the original paper) and little-endian (the NSA reference implementation). Both directions for both. 22 rounds, 4-byte block, 8-byte key.
- **Serpent** (128/192/256) — SP-network in **standard form** (visible IP/FP, per-nibble S-box, table-based linear transform). Single-block today; multi-block lands when the existing `iterate` primitive is plugged in.

### Added — modes of operation
- **Multi-block ECB** for AES-128 (Phase 1 of the multi-block plan). CBC/CTR scaffolding is in place but specs aren't shipped yet.
- The runtime's **`iterate` primitive** — the same loop body executes once per block, the trace's per-iteration frames get a `:b{i}` suffix on every `stepId`, and `frame.blockIndex` annotations let the UI render block badges.
- Boundary steps **`generic.split-blocks@1`** and **`generic.concat-blocks@1`** to convert `BytesState ↔ MatrixState[]` around the loop.

### Added — padding
- **PKCS#7**, **zero-pad**, **ISO 7816-4**, and **none** padding schemes — each rendered as a visible step in the trace (not hidden by the runtime).
- Per-`(mode, scheme, cipher, cipherMode)` length limits surface as friendly errors on Run.

### Added — UI
- Per-frame **state view**: 4×4 grid for `MatrixState`, 1×N wrap for `BytesState`, mixed-shape view for `load-block`/`store-block` boundaries.
- **StepDescription** panel with markdown rendering, FIPS / paper references, inline parameters.
- **ParamEditor** blocks for every step's params (matrix, S-box, AddRoundKey, padding/load/store, key-expansion) — edit a value and the trace re-runs in ~200ms.
- **Auto-rerun toggle**: in manual mode, an "edits pending" banner replaces the live re-run.
- **Keyboard navigation**: ←/→ step, Home/End jump, PgUp/PgDn round.
- **Neighborhood strip** of nearby steps with virtualization.
- **Run history** (5-deep ring) + **previous-run overlay** showing diff cells against the last run.
- **Run Explorer modal** for side-by-side run comparison with a pure delta-string formatter (testable in node-env).
- **Byte format toggle**: hex / decimal / ASCII; the active format propagates to every byte-rendering site. S-box axis labels stay hex (addresses, not values).
- **Cipher selector** + per-cipher key auto-swap when the field still holds the previous cipher's default.
- **Mode-of-operation selector** with cross-cipher matrix (`SUPPORTED_CIPHER_MODES_BY_CIPHER`) so unsupported combos disable gracefully.
- **Multi-block visual grouping**: ECB output renders as 4×4 block panels so identical plaintext blocks produce visibly-identical ciphertext blocks (the Tux-image pedagogy).
- **2D graph view tab** (Slices 1–6 of the visual editor plan):
  - `deriveAuxGraph(trace, spec): CipherGraph` — pure derivation of nodes, containers, aux-flow edges (with iterate-mediated synthesis), and the state-edge spine.
  - `collapseGraph(graph, collapsedIds): CipherGraph` — pure view-time transform; collapsed containers become chips, internal nodes disappear, edges remap to surviving endpoints.
  - SVG renderer with hand-rolled FIPS-197-flavored layout (top-level + iterate bodies flow left-to-right, groups stack vertically). Container drag + chevron-toggle collapse. Arrowhead markers + state-vs-aux edge styling. Container label truncation via SVG `textLength`.
  - Layout sidecar persistence — pinned positions + collapsed groups survive reload.
- **File Save / Load** for `CipherDocument` JSON (Slice 5), with an include-session checkbox controlling whether plaintext/key bytes are written. Spec-only saves are byte-stable.

### Added — core
- **`CipherSpec`** as JSON (`src/core/types.ts`): tree of `StepNode`s (step leaves, groups, iterate groups). Saved-document forever-shape.
- **`StepRegistry`** mapping `stepType → { executor, doc }` so adding a step type registers behavior and documentation together.
- **`Runtime`** — pure walk-and-trace engine; the only piece that knows about tracing or iteration.
- **`CipherDocument`** file format (`schemaVersion: 1`) — required `spec`, optional `layout` (graph positions + collapsed groups), `session` (selector snapshot + optional bytes), `metadata` (name / createdAt / appVersion). `serializeDocument` is deterministic (alphabetical key order).
- **`spec-mutations.ts`** — `findStep`, `findStepAndParent`, `updateStepParams`, `updateAllStepsByType`, `insertStepAfter`/`insertStepBefore`, `removeStep`, `reorderStep`, `compareSpecs`. Pure spec-in/spec-out with reference equality preserved on untouched branches.

### Added — quality gate
- **Pre-commit hook** in `.githooks/pre-commit` running the full `npm run check` (biome + tsc + vitest + vite build) plus a step-coverage gate (new files in `src/steps/` require a `tests/` change in the same commit).
- **GitHub Actions** running the same on push.
- **Playwright real-browser smoke tests** in `e2e/` (currently the Slice 6 graph drag/collapse spec).
- ~528 tests across ~42 files; ~7s for the full gate, ~4s for vitest alone.

[Unreleased]: https://github.com/BoykoNeov/Cryptographer/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/BoykoNeov/Cryptographer/compare/2afe2d6...v0.2.0
[0.1.0]: https://github.com/BoykoNeov/Cryptographer/tree/2afe2d6
