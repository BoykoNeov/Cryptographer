# Cryptographer

Interactive cryptography explorer. The user enters plaintext + key, sees every intermediate state of every step of every round, and can experiment by editing the cipher's parameters (swap the S-box, reorder steps, change the MixColumns matrix) and watch the trace re-run within ~200ms. Built as a learning tool, not a production crypto library.

## Quick reference

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server at `http://localhost:5173`. Hot-reloads on file changes. |
| `npm test` | Vitest, single run. Currently 1389 tests across 122 files, ~30s total (jsdom UI tests dominate). |
| `npm run typecheck` | `tsc --noEmit`, strict. |
| `npm run check` | The gate: `biome ci . && tsc --noEmit && vitest run && vite build`. Runs in ~40s on this machine. |
| `npm run build` | Production build into `dist/`. ~132 KB gzipped JS. |

The pre-commit hook in `.githooks/pre-commit` runs `npm run check`. GitHub Actions in `.github/workflows/ci.yml` runs the same on push. Don't bypass with `--no-verify` unless you have a specific reason; both gates exist for a reason.

## Architecture

The whole app is built around one idea: **a cipher is JSON, not code.**

```
CipherSpec (JSON tree)  ──►  Runtime  ──►  Trace (immutable frames)  ──►  UI (Solid)
                              ▲
                              │ looks up by stepType
                           Registry: stepType → { executor, doc }
```

A `CipherSpec` (`src/core/types.ts`) is a tree of `StepNode`s. Leaves are `{ kind: "step", id, type, params }`; groups are `{ kind: "group", id, label, children }`; iterate nodes are `{ kind: "iterate", id, label?, countFromAux, blocksFromAux, outBlocksAux, children }`. The `Runtime` (`src/core/runtime.ts`) walks the tree, looks each leaf's `type` up in the `StepRegistry` (`src/core/registry.ts`), and calls its executor with `(state, params, ctx)`. Each executor is pure — `(state, params) → state` — and the runtime is the only place that knows about tracing or iteration.

**Multi-block modes via the `iterate` primitive.** Block-cipher modes of operation (ECB shipped Phase 1; CBC/CTR queued for Phase 2/3) run AES's per-block body once per plaintext block by wrapping it in an `iterate` group. The runtime reads `aux[countFromAux]` and `aux[blocksFromAux]: MatrixState[]`, sets `state = blocks[i]` per iteration, walks the children body, suffixes every emitted frame's `stepId` with `:b{i}` so the flat trace stays uniquely keyed, stamps each frame with `blockIndex: i`, and appends the iteration's final state into `aux[outBlocksAux]`. Boundary steps `generic.split-blocks@1` (`BytesState → MatrixState[]`) and `generic.concat-blocks@1` (reverse) make this composable. See `docs/plans/multi-block-aes-modes.md`.

**Spine terminates at the iterate boundary (2026-05-17).** `inferStateEdges` suppresses any state edge whose endpoint is an iterate id. Reason: every shipped iterate is aux-mediated — the runtime overwrites `state` from `aux[blocksFromAux]` at iteration entry and publishes per-iteration output into `aux[outBlocksAux]` at exit, so the predecessor's stateAfter never reaches body steps and the body's stateAfter never reaches the successor. Drawing a white spine arrow there showed phantom data (e.g. `compute-block-count → ecb-blocks` rendered the plaintext bytes, which the iterate ignored). The aux arrows are the honest depiction of the handoff. A future Feistel-style iterate with branching state would need an opt-out flag.

Each step type registers an executor *and* a `StepDocumentation` block (`name`, `summary`, `detail` markdown, `params`, `references`). The UI looks up the same key for both. Adding a new cipher = registering its step types in `src/ciphers/default-registry.ts` plus authoring a `CipherSpec` JSON file. **No UI changes needed for new step types** unless their params can't be edited by the existing `ParamEditor` blocks.

State is a discriminated union: `BytesState`, `MatrixState` (4×4 byte matrix, column-major), `BitVecState`, `BigIntState`. AES uses `MatrixState`; Speck32/64 uses `BytesState` of length 4 (the two-word ARX interpretation lives inside the executor via a byte ↔ word codec); Serpent uses `BytesState` of length 16. `BitVecState` and `BigIntState` are declared but not yet exercised by a shipped cipher.

The future "binary export" feature is what *forced* the spec-as-data choice: a code generator can consume JSON, not closures.

**Detailed file-by-file inventory: see `docs/key-files.md`.** For step-type-specific guidance (adding new ones), see `src/steps/CLAUDE.md`.

### Graph view + persistence

The 2D editor (the "graph" view tab, alongside `linear` / `json` in
`src/ui/stores/view-mode.ts`) is a second derivation layered on top of
the same trace the linear view consumes. Pure functions own each step:
`deriveAuxGraph(trace, spec) → CipherGraph` builds the DAG from the
recorded `auxRead`/`auxWritten`/`auxReadMissing` on each `TraceFrame`;
`collapseGraph` rewrites it for collapsed containers; `replicateHighFanoutSources`
splits source nodes whose fanout exceeds a threshold; `validateGraph(graph, trace)`
emits `GraphWarning[]` (orphaned-read / unused-write / cycle). The SVG
renderer in `src/ui/components/GraphView.tsx` consumes the post-pipeline
graph and overlays the layout sidecar (`src/ui/stores/layout.ts`,
per-spec.id, persisted to localStorage) for pinned positions + collapsed
sets.

**Authoring** is a two-channel surface. The palette
(`src/ui/components/StepPalette.tsx`) lists every non-padding registered
step type and emits HTML5 drags carrying the `STEP_TYPE_DRAG_MIME`
payload; `GraphView`'s drop handler walks `closest("[data-drop-anchor]")`
to map cursor → spec node, and routes to `insertStepIntoSpec(stepType,
anchor)` in the spec store. The same store boundary handles in-place
param edits via `editStepParams(stepId, params)` (driven by the
`ParamEditor` rendered below `<GraphView />` so the panel is reachable
from inside graph mode).

**Persistence** lives in `src/core/document.ts` (the `CipherDocument`
schema) and routes all I/O through `applyDocument` in `App.tsx`. Three
entry points produce the same envelope:
[save] downloads it as a `.cipher.json` blob; [share…] packs it into
`#doc=<base64url-deflate-raw>` via the browser-native `CompressionStream`
(`src/ui/stores/url-share.ts`); a paste of the URL into a fresh tab
boots through `applyDocument` again. Spec-only saves (the default,
without "include session") are byte-stable so URL-share hashes are
deterministic — `metadata.createdAt` and `metadata.appVersion` are
session-gated to keep that property. Layout pins survive Save/Share
when the user has dragged or collapsed at least one container.

**The end-to-end round-trip** — palette drop → param edit → layout pin
→ Save → reset → Load — is pinned by
`tests/built-from-palette-roundtrip.test.tsx`, the integration assertion
the 11-slice plan promises. The in-app `?` button on the graph toolbar
opens `docs/help/graph-view.md` (loaded via Vite `?raw`) inside a
`<dialog>` for users who want a quick reference.

## Conventions

**Commits:** push to GitHub after every batch of related changes. Don't accumulate. Each commit message: 1 short title + a "why this exists" paragraph + bullet list of the substantive parts. Co-author trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`.

**Comments:** *override the default "no comments" rule for this project.* Comment frequently — file headers explaining purpose, JSDoc on step executors, FIPS-197 references where the code implements a published algorithm, "why" rather than "what." User explicitly requested this. Educational project; the user reads the code to learn.

**Tests:** new step types and new ciphers ship with tests **in the same commit** as the implementation. Test names should explain the property being checked, not just "it works." Known-answer tests against published vectors (FIPS-197 Appendix C, etc.) are the gold standard for cryptographic correctness. The pre-commit hook enforces "if a new file lands in `src/steps/`, at least one `tests/` file must also be modified."

**Type safety:** `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax` are on. Use `import type` for type-only imports (biome enforces). Cast through `Record<string, Json>` when you need to spread JSON params.

**Param editing in the UI:** when the user edits a step's params, the spec store creates a new spec via the helpers in `src/core/spec-mutations.ts` (which preserve reference equality on untouched branches). A `createEffect(on(spec, ...))` then debounces 200ms before re-running the cipher and producing a new trace.

**Frame preservation across re-runs:** `src/ui/stores/trace.ts::setTrace` is the single boundary that swaps in a new trace. It captures the current `stepId` and tries to land the scrubber back on the same step in the new trace; if that stepId is gone, it clamps the previous numeric index. Universal — every cipher's traces flow through this same boundary.

**Byte format toggle:** `src/core/format.ts` defines `ByteFormat = "hex" | "decimal" | "ascii"`. The App-level toggle parses with the old format and re-renders with the new one so user data survives. S-box axis labels stay hex regardless — they're addresses, not values.

**UI testing:** Most tests run in vitest's `node` environment (fast, no DOM). UI component tests opt into jsdom with a `// @vitest-environment jsdom` directive at the top of the file, then use `@solidjs/testing-library`. The Solid plugin needs `resolve.conditions: ["development", "browser"]` and `server.deps.inline: [/solid-js/]` in `vite.config.ts` — without those, `createSignal` throws "Client-only API called on the server side." Module-scope signals in stores produce a harmless "computations created outside createRoot" warning during tests; ignore.

**Cross-mode mirror buttons:** Encrypt and decrypt specs are held simultaneously in the store but *never* auto-synced — the user edits either side independently and learns what breaks. Every step whose param has a known cross-mode relationship ships with a labelled, opt-in button below its editor. Two classes today: class-1 *identity-mirror* ("Copy S-box to decrypt" — AES key-expansion per FIPS-197 §5.2: key expansion uses the FORWARD S-box even when decrypting) and class-2 *inverse-mirror* ("Sync inverse S-box to decrypt" — AES SubBytes; "Sync inverse S_i to decrypt" — Serpent SubBytes, per-`sboxIndex`; "Sync inverse MixColumns to decrypt" — AES MixColumns per FIPS-197 §5.3.3, gated on GF(2^8) invertibility via `gfMatInverse4x4` in `src/core/state/gf-matrix.ts`). The label names the specific operation; the tooltip cites the spec section that justifies the relationship. `src/ui/components/cross-mode-mirror-registry.ts` is the canonical list of (stepType, paramKey, class) entries; `tests/cross-mode-mirror-coverage.test.tsx` walks it and fails if a registered entry has no rendered button — so a new cipher in class 1 or 2 cannot ship without its mirror affordance.

## Things to avoid

A list of footguns Claude has historically tripped on, grouped by topic (AES, padding overlay, multi-block/iterate, Speck, Serpent, Solid UI, Graph view, port-native primitives, PowerShell tooling) lives in **`docs/gotchas.md`** — consult the relevant section when working on that area. Highlights that bite *cross-cutting* code:

- **Solid components need `createMemo` for derived values** read multiple times in JSX, and **`For` callbacks aren't reactive scopes** — inline dynamic prop reads into the JSX, don't capture them in a `const`.
- **Solid signal setters return the value they set**, so a `: void` wrapper around a setter must use a block body, not an expression body, under `exactOptionalPropertyTypes`.
- **Don't redirect native command stderr in PowerShell with `2>&1`** — wraps stderr in `NativeCommandError` and falsely flips `$?`.
- **Adding a new (cipher, cipherMode) spec means updating TWO tables**: `defaults` in `stores/spec.ts` AND `SUPPORTED_CIPHER_MODES_BY_CIPHER` in `stores/cipher-mode.ts`. `tests/cipher-mode-fallback.test.ts` is the canary.
- **Port-native primitives use DIFFERENT param names than legacy steps**: `rotate-bits-right` / `shift-bits-right` use `bits` (not `shift`), no `byteLength`; `add-mod-32` / `xor` / `and` / `concat` use `inputCount`, no `byteLength`; `not` takes empty params; `split-bytes` uses `widths`. Copy-pasting a spec node from a legacy step fails with "params.X must be …" naming the param the executor WANTED — not the wrong one supplied. Full table in `docs/gotchas.md`.

For AES gotchas (column-major state, FIPS-197 appendix keys, AES-256 Nk>6 branch, SubBytes/ShiftRows commute), Speck byte-order conventions, Serpent standard-vs-bitslice form mixing, and the padding overlay's three branches: read `docs/gotchas.md`.

## Planning mode usage

**Mandatory** for: new ciphers (Speck, ChaCha20, RSA), big architecture changes (DAG instead of linear pipeline, codegen target, file encryption), new state shape support, anything touching `core/types.ts`.

**Skip** for: typo fixes, tiny tweaks, isolated UI polish, fixing a failing test, adding a known-answer test for an existing cipher.

When in plan mode, exit with `ExitPlanMode` only after the plan file has the **Context** section answered and **Critical files** listed. The plan should match the scope of the requested change — don't propose a 12-step refactor when the user asked for one editor.

## What we explicitly chose not to adopt (yet)

These are common Claude Code best-practice recommendations; we considered each and skipped for now:

- **Custom subagents** (code-reviewer, build-fixer, etc.) — gatekeeps context for solo dev.
- **Skills system + UserPromptSubmit hook** — disproportionate setup for our scope.
- **Three-file dev-docs system** (plan/context/tasks per task) — the existing plan + memory + commits cover it.
- **Auto-format hooks** on every edit — confirmed token waste; biome runs in pre-commit gate instead.
- **PM2** — single dev server, no service mesh.
- **Worktrees** — solo dev, one branch.
- **MCPs beyond the bundled ones** — no integration target needs them yet.
- **Branded type pattern** — domain has few string IDs.

If a future need argues for one of these, revisit then.

## Pointers

**In this repo:**
- `README.md` — public-facing GitHub entry point (project description, install, command table, links). Keep it in sync with shipped features when the user-visible surface changes — adding a new cipher, mode, or major UI feature should update the "What's in the box" table.
- `CHANGELOG.md` — release log (Keep-a-Changelog format). Convert the `[Unreleased]` section into a dated `[X.Y.Z]` heading on each release; bump `package.json`'s `version` and tag in the same commit. `docs/versioning.md` carries the release process.
- `docs/key-files.md` — detailed file-by-file inventory (core contracts, ciphers, UI stores, components, tests).
- `docs/gotchas.md` — the full "Things to avoid" list, topic-grouped.
- `docs/versioning.md` — versioning policy for the three independent surfaces: app semver, step-type `@N` suffix bumps, document `schemaVersion` migration path. Read before any change that touches a step-type contract, the document schema, or the release process.
- `src/steps/CLAUDE.md` — step-type-specific guidance.
- `src/version.ts` — `APP_VERSION` constant re-exported from `package.json`. Consumed by the UI footer and the session-on document export.
- `docs/help/graph-view.md` — user-facing reference for the graph view (edges, drag/drop, palette, warning glyphs, toolbar). Bundled into the app via Vite `?raw` and rendered inside the in-app help modal (`?` button in the graph toolbar). Keep this file the single source of truth — both GitHub readers and the in-app modal display the same prose.

**Plans:**
- Original architectural plan: `~/.claude/plans/i-want-to-build-tender-spark.md`
- Approved UX/feature plan (phases 1–4: frame preservation, run history + diff, byte format toggle, deferred 2D viz): `docs/plans/suggestions-1-4.md`
- Plaintext input + visible padding plan (PKCS#7 + zero-pad + ISO 7816-4 shipped May 2026): `docs/plans/pkcs7-padding.md`
- Speck32/64 plan (shipped May 2026 — second cipher family, ARX, both BE-paper + LE-NSA byte conventions): `docs/plans/speck.md`
- Multi-block AES with ECB/CBC/CTR plan (Phases 1+2 — AES-128 ECB+CBC — shipped May 2026; Phases 3+4 superseded by the universal cipher-shape plan): `docs/plans/multi-block-aes-modes.md`
- Serpent cipher plan (all three key sizes, standard form with explicit IP/FP, single-block — shipped May 2026): `~/.claude/plans/i-want-serpent-cipher-indexed-finch.md`
- 2D/DAG visual cipher editor + JSON document export plan (all 11 slices shipped May 2026): `~/.claude/plans/peppy-knitting-fairy.md`. Memory: `project_2d_editor_plan.md`. Option B (click-to-expand with `LayoutSpec.expandedLabels`) is an optional V2 follow-up; pick up only on explicit user ask.
- Trace-coupling editor bug fix plan (shipped 2026-05-14): `docs/plans/trace-coupling-bug-fix.md`. Root cause was the `hasRunOnce` gate blocking auto-rerun. Option 3b (static spec validator) deferred until Feistel branching data model settles.
- Duplicate-round plan (shipped 2026-05-14): `docs/plans/duplicate-round.md`. Renumber + extend schedule (`aes.key-expansion@2` with relaxed `Nk+6` assertion) + auto-mirror to decrypt. AES today; Speck/Serpent + Feistel-aware rerouting + non-round-group duplication are out of scope.
- Port-spreading at consumer head plan (shipped May 2026): `docs/plans/port-spreading-consumer-head.md`. Mechanisms 1+2 + visual-target bucketing + horizontal-regime extension all closed. Mechanism 3 (off-chip clamp at chip-vs-leaf width) deferred — not visible on smoke fixture.
- Linear-mode pedagogy plan (all 3 phases shipped 2026-05-18 + BytesView follow-up): `~/.claude/plans/immutable-doodling-quokka.md`. Memory: `project_linear_mode_pedagogy_plan.md`. Three additions: `<RoundKeyPanel />` (cipher-agnostic ribbon), `<KeyScheduleExplorer />` (per-cipher simulators in `src/ui/key-schedule-sim/`), cell-level provenance overlay (parallel registry at `src/ui/provenance/`). Contract test `tests/provenance-registry-contract.test.ts` enforces coverage.
- DES + branching primitive plan (Phase 6 complete under legacy contract; **superseded by the B4 port-native rebuild 2026-05-30**): `docs/plans/des-feistel.md`. Memory: `project_des_feistel_plan.md`. Introduced `FeistelRoundGroup` + `tracks: BranchTrack[]` + named `combineKind` (schema bump 1→2). **DES no longer uses `feistel-round`** — universal-port Phase 4d / scaffolding-suppression B4 rebuilt it from native `split-bytes`/`xor`/`concat` (the Feistel swap is the concat argument order). `FeistelRoundGroup`/`BranchTrack`/`CombineKind` survive only for the toy fixture (`src/ciphers/feistel-toy.ts`) + the linear/graph Feistel components, all Phase-5-deprecation-pending. See `docs/plans/scaffolding-suppression.md` "## B4".
- **Universal port-based dataflow plan (2026-05-21 — APPROVED, ACTIVE)**: `docs/plans/universal-port-dataflow.md`. Memory: `project_universal_port_dataflow_proposal.md` (slice-by-slice progress). Every cipher element accepts 0..N Uint8Array inputs / produces 0..N Uint8Array outputs; with explicit mismatch rules, any element can wire to any other. **SUBSUMES** the universal cipher-shape plan and **OBVIATES** the Feistel branching primitive. Key locked design decisions: bytes + advisory layout tag; warn-and-run coercion as visible trace step; for-each-subgraph (no canvas cycles); one frame per (body × iteration) preserving flat trace + `:b{i}` semantics; medium canonical primitives + fine as planned exploration; KAT parity at cipher boundary + `frameMap` for compound decompositions; narration preserved via `narrationOverride: StepDocumentation` field on spec nodes (falls back to registry doc); mirrors stay opt-in. DES rebuild in Phase 4d will use native split/concat/xor; `FeistelRoundGroup` fades with deprecation. **Six phases**: Phase 0 trace-shape spike → Phase 1 adapter + every step lifted + `narrationOverride` field → Phase 2 SHA-2 native (first port-native cipher) → Phase 3 AES rebuild → Phase 4+ rebuilds + fine primitives + compose-and-save → Phase 5 legacy deprecation. **Phase 2 status (as of 2026-05-26)**: Slices 2.0–2.8 all shipped GREEN. SHA-256 decomposed into port-native primitives, KAT byte-equal vs FIPS 180-4 §A.1 + node:crypto, exposed via the hash algorithm selector with default-collapsed groups, narrationOverride on all 1829 leaves. Remaining: Slice 2.9 (provenance overlay) → Slice 2.10/2.11 (KAT parity matrix) closes Phase 2.
- Universal cipher-shape plan (2026-05-16 — **SUBSUMED by universal-port-dataflow plan**, kept only for historical reference): `~/.claude/plans/silly-brewing-sutton.md`. Memory entry `project_universal_cipher_shape_plan.md`. Registry consolidation falls out for free under unified ports.
- SHA-256 density polish plan (2026-05-26 — **DONE/CLOSED 2026-05-28**): `docs/plans/sha-256-density-polish.md`. Memory: `project_sha_256_density_polish_plan.md`. All named slices shipped (S1 ParamEditor blocks, S2 graph layout/focus-dim fixes, S3 narration density). Deferred polish (Case C, route B curve-altitude) not pursued — residual crowding palliated by the orientation-driven offsets layout (default-ON 2026-05-28, `?offsets=0` disables).

**Future:**
- **Feistel: rebuilt port-native (B4, 2026-05-30)**: DES was the first (and only) Feistel cipher, originally built on the branching primitive (`FeistelRoundGroup` + `tracks: BranchTrack[]` + named `combineKind`, Phase 2 of `docs/plans/des-feistel.md`). **B4 (universal-port Phase 4d) rebuilt DES port-native** — it now uses a port-mode `group` per round wiring `split-bytes`/`des.expand-R`/`des.xor-with-K`/`des.s-boxes`/`des.p-permutation`/`xor`/`concat`, proving the universal-port thesis that **Feistel needs no special primitive** (the swap is the `concat` argument order). No shipped spec uses `feistel-round` anymore. The primitive + its runtime walk (`runFeistelRound`, `:rejoin` synthesis) + the linear/graph Feistel components + the toy fixture survive **Phase-5-deprecation-pending**; the track-bounded state-edge inference rule still applies to them. **OBLIGATORY follow-up (user-required):** rebuild a port-native-aware Feistel/swap visualization (the old `feistel-round`-keyed mini-diagram/track-context/rejoin-view go dark for port-native DES) — see memory `project_scaffolding_suppression_plan.md`.

**External:**
- User preferences (commit cadence, comment density, AES pitfalls, frame preservation, crypto-verification): `C:\Users\boiko\.claude\projects\M--claud-projects-Cryptographer\memory\`
- GitHub repo: https://github.com/BoykoNeov/Cryptographer
