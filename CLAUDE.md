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
- 2D/DAG visual cipher editor + JSON document export plan (all 11 slices shipped May 2026): `~/.claude/plans/peppy-knitting-fairy.md`. Memory entry `project_2d_editor_plan.md` tracks per-slice progress. Slice 8 (palette + graph insertion — `StepPalette.tsx` sidebar inside `.graph-view-layout`, HTML5 DnD via the `application/x-cryptographer-step-type` MIME, drop on a leaf calls `insertStepAfter(leafId)`, drop on a container header calls `insertStepAfter(containerId)` (after-the-container-in-its-parent, NOT into-container — explicit Slice 8 semantic), drop on empty canvas root-appends; padding overlay step types excluded from the palette so the next selector flip can't silently strip user inserts) shipped on `main` hand-rolled — a parallel solid-flow spike on branch `explore/solid-flow` is being driven by a separate session to evaluate the library route; don't touch that branch from here. Slice 7 (URL hash share — `[share…]` button, `#doc=<base64url-deflate-raw>`, browser-native `CompressionStream`, no new deps) shipped 2026-05-13 (commit `0bf381e`); the boot decode + share both route through the shared `applyDocument` boundary in `App.tsx`, factored out of `handleLoadFromText`. Slice 9 (edge-aware validation — `GraphWarning[]` from `core/graph.ts` for orphaned reads, unused writes, cycles, surfaced as overlay dots) shipped as part of the 11-slice arc. Option B (click-to-expand with `LayoutSpec.expandedLabels`) is an optional V2 follow-up for the readability sequence; pick up only on explicit user ask.
- Trace-coupling editor bug fix plan (shipped 2026-05-14): `docs/plans/trace-coupling-bug-fix.md`. Three editor-flow bugs (orphan-warning glyphs, ParamEditor selection, replicate fan-out) shared one root cause: the `hasRunOnce` gate blocked auto-rerun before first manual Run, so the trace was null. Shipped option 1 (`onMount(() => run())`) + option 3a (ParamEditor takes `stepId`, not `frame`). Option 3b (static spec validator) deferred until Feistel branching data model settles. Bug 4 (drop UX feedback gap — verified not a logic bug) deferred as separate UX polish.
- Duplicate-round plan (shipped 2026-05-14): `docs/plans/duplicate-round.md`. Renumber + extend schedule (`aes.key-expansion@2` with relaxed `Nk+6` assertion) + auto-mirror to decrypt counterpart. All six phases landed (two-spec store + auto-mirror + UI button + e2e tests). Scope is AES today; Speck/Serpent + Feistel-aware rerouting + non-round-group duplication are out of scope.
- Port-spreading at consumer head plan (shipped across three rounds May 2026): `docs/plans/port-spreading-consumer-head.md`. Mechanisms 1+2 (kind-agnostic per-consumer slot assignment) + visual-target bucketing follow-up + horizontal-regime extension (commit `8604236`, `targetYOffset` on left/right entries) all closed. Mechanism 3 (off-chip clamp at chip-vs-leaf width) deferred — not visible on the smoke fixture. Downstream chain (Slice 7b state-edge replication, arrow bundling) also shipped. Next blocker is the Feistel plan + first Feistel cipher implementation.
- Linear-mode pedagogy plan (all 3 phases shipped 2026-05-18 + BytesView follow-up): `~/.claude/plans/immutable-doodling-quokka.md`. Memory entry `project_linear_mode_pedagogy_plan.md`. Three additions to linear mode: (1) `<RoundKeyPanel />` reads `trace.finalAux` and renders every `prefix.N` Uint8Array sequence as a labelled ribbon, with the current frame's consumed K_i outlined — cipher-agnostic (AES → 11/13/15 grids, Serpent → 33, Speck → 22 two-byte strips). (2) `<KeyScheduleExplorer />` replaces FrameStateView for key-expansion frames; per-cipher simulators in `src/ui/key-schedule-sim/` re-run the algorithms yielding per-stage decomposition (AES per-word RotWord→SubWord→Rcon→XOR chain; Serpent pad→prekey→S-box→IP pipeline). Re-simulate-in-viz chosen over executor refactor; parity tests pin byte-equality. (3) Cell-level provenance overlay — hovering an `after` cell in MatrixView (or BytesView for Serpent) lights up the source cells in `before` AND in the consumed K_i's TinyMatrix. Parallel registry at `src/ui/provenance/`; param-driven so forward AND inverse direction use one fn per generic step type. Highlight precedence (`.provenance-source` > `.round-key-cell-current` > `.diff-vs-prev` > `.changed`) enforced by single-class composition in classList. Contract test (`tests/provenance-registry-contract.test.ts`) walks the core registry and fails if a matrix-shape or bytes-shape stepType is neither provenance-registered nor on `PROVENANCE_NO_OP_ALLOWLIST` — turns audit into CI gate. Manual browser smoke completed 2026-05-18, with four polish commits landing the same day (latest `516b522` — AES key-schedule type+value prose).
- DES + branching primitive plan (drafted 2026-05-19, not started): `docs/plans/des-feistel.md`. Memory entry `project_des_feistel_plan.md`. First Feistel cipher; introduces `FeistelRoundGroup` spec node + `tracks: BranchTrack[]` + named `combineKind` (4-arg `(L_in, L_out, R_in, R_out) → (new_L, new_R)`). Path C chosen — design true branching against DES's harder constraints rather than ship TEA first with a representation that doesn't carry to DES. 6 phases: oracle → primitive in core (validated against asymmetric-F toy) → DES step types → UI wiring + Param/Narration/Provenance → six linear-mode components (track context, mini Feistel diagram SVG, rejoin view, DES 48-bit ribbon, key-schedule explorer, timeline badges) → graph view branched layout (top/bottom tracks, dedicated rejoin chip, single-chip collapse, per-track gutters) + smoke. Schema bump `CipherDocument.schemaVersion` 1 → 2 in phase 2. Iterative slice review pattern adopted — re-consult advisor before each phase. TEA/XTEA/3DES become cheap follow-ups; Twofish/Blowfish need separate plans (n-way + key-dependent S-boxes are orthogonal concerns).
- **Universal port-based dataflow plan (2026-05-21 — APPROVED after 2 advisor consults, held until DES Phase 6e complete): `docs/plans/universal-port-dataflow.md`. Memory entry `project_universal_port_dataflow_proposal.md`. Every cipher element accepts 0..N Uint8Array inputs, produces 0..N Uint8Array outputs; with explicit mismatch rules, any element can wire to any other. SUBSUMES the universal cipher-shape plan and OBVIATES the Feistel branching primitive. Design decisions locked in: Q1 hybrid (bytes + advisory layout tag), Q2 warn-and-run with deterministic right-pad/truncate-from-right coercion surfaced as visible trace step, Q3 for-each-subgraph (no canvas cycles), Q3-frame (i) one frame per (body × iteration) preserving flat trace + `:b{i}` semantics (hierarchical trace (iii) deferred as own future plan), Q-A medium canonical + fine as planned exploration construct, Q-A-parity (β) frame-equivalence at primitive boundaries + `frameMap` for compound decompositions + KAT parity at cipher boundary, Q-B both `byte-substitute` (a, first) and `lookup-substitute` (b, next) coexist, Q-C strict order (a) parameters → (b) compose-and-save → (c) TBD code/formula form. Narration preserved under rebuild via `narrationOverride: StepDocumentation` field on spec nodes (folded into Phase 1 contract design, falls back to registry doc when absent — shipped AES carries cipher-specific overrides per leaf, palette-dropped primitives get generic). Mirrors stay opt-in/suggested, never auto-applied. Feistel types fade with gradual deprecation; DES rebuild in Phase 4d uses native split/concat/xor. Six phases with explicit pass/fail gates: Phase 0 widened ~3-day trace-shape spike on `aes.sub-bytes` + `aes.add-round-key` + one ECB iteration (validates load-bearing claim across pure step + aux read + iterate boundary), Phase 1 adapter + every step lifted + `narrationOverride` field added (1–2 weeks), Phase 2 SHA-2 native (first port-native cipher), Phase 3 AES rebuild from medium primitives with `frameMap` test infrastructure, Phase 4+ rebuilds + fine primitives + compose-and-save, Phase 5 legacy deprecation. Phase 2 status (2026-05-25): Slices 2.0a/b-i/b-ii/c, 2.1a/b, 2.2, 2.3, 2.4, 2.5, 2.6a, 2.6b, 2.6c, **2.6d all GREEN**. 2.6d shipped SHA-256 decomposed into port-native primitives across 6 commits: 3 new primitives (`aux-load-bytes@1`, `byte-slice@1`, `split-bytes@1`) + a bytes-shape sibling registration `generic.state-to-aux-bytes@1` + spec rewrite using only the universal vocabulary + parity test pinning legacy ≡ decomposed ≡ node:crypto. User picks locked pre-slice (advisor consult): Q1 = (b) "W in aux entirely" (eliminates 2.6c's zero-width split-bytes + W_0..W_{t-1} loss bugs), Q2 = keep `sha2.*` helpers registered + allowlisted for saved-doc backward compat. Frame count grew 123 → 2487 (~20× pedagogy payoff — every ROTR/XOR/add-mod is visible). KAT byte-equal vs FIPS 180-4 §A.1 + node:crypto across all 6 single-block messages. Suite 2255 → 2262 (+7 in same-day advisor follow-up), bundle 627.46 KB (+13.8 KB). **Same-day 4-item follow-up landed 2026-05-25** (commit `2df4987` + docs): (1) coverage asymmetry closed — 7 dedicated `tests/state-to-aux-bytes.test.ts` tests + documented decision NOT to write legacy-vs-ported frame parity for the bytes sibling (raw layout decodes to bare Uint8Array on the ported path but BytesState on legacy — no shipped spec observes the asymmetry; aux-load-bytes is port-native and forces flag-on); (2) param-name gotcha → `docs/gotchas.md` Port-native primitives section with full table (rotate-bits-right/shift-bits-right use `bits` not `shift`, no `byteLength`; add-mod-32/xor/and/concat use `inputCount`, no `byteLength`; not@1 takes empty params; split-bytes uses `widths`) + CLAUDE.md highlights bullet + memory entry — errors NAME the missing param the executor wanted, not the wrong one supplied; (3) sequencing pin: default-collapse for the 64 round groups MUST land BEFORE Slice 2.10 (else the user sees a 1792+ chip wall on first SHA-256 render) — order is default-collapse → 2.7 → 2.10; (4) Q-A-parity β re-labelled as DELIBERATE scope cut (not "deferred") — KAT catches divergence, frameMap mostly catches structural noise. Recorded so it doesn't resurface as "2.6d wasn't finished." Next: default-collapse (UI polish, layout-store change) THEN Slice 2.7 (`requiresPortedDispatch` plumbing) THEN Slice 2.10 (SHA-256 in cipher selector). `narrationOverride` content lands in Slice 2.8.**
- Universal cipher-shape plan (2026-05-16 — **SUBSUMED by universal-port-dataflow plan**, kept only for historical reference): `~/.claude/plans/silly-brewing-sutton.md`. Memory entry `project_universal_cipher_shape_plan.md`. Registry consolidation falls out for free under unified ports.

**Future:**
- **Feistel future (interim under legacy contract)**: DES is the first Feistel cipher under the legacy executor contract, with the branching primitive (`FeistelRoundGroup` + `tracks: BranchTrack[]` + named `combineKind`) introduced in Phase 2 of `docs/plans/des-feistel.md`. This is **interim** — the approved universal-port-dataflow plan obviates the special primitive. DES Phase 6e completes under legacy; the universal-port plan's Phase 4d rebuilds DES from native `split`/`concat`/`xor` and `FeistelRoundGroup` fades with deprecation. Until rebuild ships, today's track-bounded state-edge inference rule applies: within a track DFS-consecutive leaves share state; across tracks no state edge.

**External:**
- User preferences (commit cadence, comment density, AES pitfalls, frame preservation, crypto-verification): `C:\Users\boiko\.claude\projects\M--claud-projects-Cryptographer\memory\`
- GitHub repo: https://github.com/BoykoNeov/Cryptographer
