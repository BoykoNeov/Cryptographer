# Cryptographer

Interactive cryptography explorer. The user enters plaintext + key, sees every intermediate state of every step of every round, and can experiment by editing the cipher's parameters (swap the S-box, reorder steps, change the MixColumns matrix) and watch the trace re-run within ~200ms. Built as a learning tool, not a production crypto library.

## Quick reference

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server at `http://localhost:5173`. Hot-reloads on file changes. |
| `npm test` | Vitest, single run. Currently 117 tests across 11 files, ~1.4s total (jsdom UI tests dominate). |
| `npm run typecheck` | `tsc --noEmit`, strict. |
| `npm run check` | The gate: `biome ci . && tsc --noEmit && vitest run && vite build`. Runs in ~6s on this machine. |
| `npm run build` | Production build into `dist/`. ~23KB gzipped JS. |

The pre-commit hook in `.githooks/pre-commit` runs `npm run check`. GitHub Actions in `.github/workflows/ci.yml` runs the same on push. Don't bypass with `--no-verify` unless you have a specific reason; both gates exist for a reason.

## Architecture

The whole app is built around one idea: **a cipher is JSON, not code.**

```
CipherSpec (JSON tree)  ──►  Runtime  ──►  Trace (immutable frames)  ──►  UI (Solid)
                              ▲
                              │ looks up by stepType
                           Registry: stepType → { executor, doc }
```

A `CipherSpec` (`src/core/types.ts`) is a tree of `StepNode`s. Leaves are `{ kind: "step", id, type, params }`; groups are `{ kind: "group", id, label, children }`. The `Runtime` (`src/core/runtime.ts`) walks the tree, looks each leaf's `type` up in the `StepRegistry` (`src/core/registry.ts`), and calls its executor with `(state, params, ctx)`. Each executor is pure — `(state, params) → state` — and the runtime is the only place that knows about tracing.

Each step type registers an executor *and* a `StepDocumentation` block (`name`, `summary`, `detail` markdown, `params`, `references`). The UI looks up the same key for both. Adding a new cipher = registering its step types in `src/ciphers/default-registry.ts` plus authoring a `CipherSpec` JSON file. **No UI changes needed for new step types** unless their params can't be edited by the existing `ParamEditor` blocks.

State is a discriminated union: `BytesState`, `MatrixState` (4×4 byte matrix, column-major), `BitVecState`, `BigIntState`. AES uses `MatrixState`; future ciphers will use the others.

The future "binary export" feature is what *forced* the spec-as-data choice: a code generator can consume JSON, not closures.

## Conventions

**Commits:** push to GitHub after every batch of related changes. Don't accumulate. Each commit message: 1 short title + a "why this exists" paragraph + bullet list of the substantive parts. Co-author trailer: `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`.

**Comments:** *override the default "no comments" rule for this project.* Comment frequently — file headers explaining purpose, JSDoc on step executors, FIPS-197 references where the code implements a published algorithm, "why" rather than "what." User explicitly requested this. Educational project; the user reads the code to learn.

**Tests:** new step types and new ciphers ship with tests **in the same commit** as the implementation. Test names should explain the property being checked, not just "it works." Known-answer tests against published vectors (FIPS-197 Appendix C, etc.) are the gold standard for cryptographic correctness. The pre-commit hook enforces "if a new file lands in `src/steps/`, at least one `tests/` file must also be modified."

**Type safety:** `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax` are on. Use `import type` for type-only imports (biome enforces). Cast through `Record<string, Json>` when you need to spread JSON params.

**Param editing in the UI:** when the user edits a step's params, the spec store creates a new spec via the helpers in `src/core/spec-mutations.ts` (which preserve reference equality on untouched branches). A `createEffect(on(spec, ...))` then debounces 200ms before re-running the cipher and producing a new trace.

**Frame preservation across re-runs:** `src/ui/stores/trace.ts::setTrace` is the single boundary that swaps in a new trace. It captures the current `stepId` and tries to land the scrubber back on the same step in the new trace; if that stepId is gone, it clamps the previous numeric index. Universal — every cipher's traces flow through this same boundary, so a future Speck/ChaCha20/RSA inherits the behavior for free.

**Byte format toggle:** `src/core/format.ts` defines `ByteFormat = "hex" | "decimal" | "ascii"` plus the `formatByte`/`parseByte` round-trip pair. `src/ui/stores/format.ts` holds the active format (persisted in `localStorage`). Every byte-rendering site reads the store; the App-level toggle does an in-place re-render of the input/key fields (parse with old → format with new) so the user's data survives. S-box axis labels stay hex regardless — they're addresses, not values.

**UI testing:** Most tests run in vitest's `node` environment (fast, no DOM). UI component tests opt into jsdom with a `// @vitest-environment jsdom` directive at the top of the file, then use `@solidjs/testing-library`. The Solid plugin needs `resolve.conditions: ["development", "browser"]` and `server.deps.inline: [/solid-js/]` in `vite.config.ts` — without those, `createSignal` throws "Client-only API called on the server side." Module-scope signals in stores produce a harmless "computations created outside createRoot" warning during tests; ignore.

## Key files (load-bearing)

**Core (load-bearing contracts):**
- `src/core/types.ts` — `CipherSpec`, `StepNode`, `State` variants, `TraceFrame`, `StepDocumentation`. Saved JSON references these shapes forever; changes here are breaking.
- `src/core/runtime.ts` — the walk-and-trace engine. Pure given a registry.
- `src/core/registry.ts` — `StepRegistry`. Maps stepType → `{ executor, doc }`.
- `src/core/spec-mutations.ts` — `findStep`, `updateStepParams`, `updateAllStepsByType`, `compareSpecs`. Pure spec-in/spec-out.
- `src/core/format.ts` — `ByteFormat`, `formatByte`/`parseByte`/`formatBytes`/`parseBytes`/`parseBytesWithLength`. Consumed by every byte-rendering site.

**Ciphers:**
- `src/ciphers/default-registry.ts` — wires every step type. Adding a new step means editing this.
- `src/ciphers/aes-128.ts`, `src/ciphers/aes-128-decrypt.ts` — the two real cipher specs.
- `src/ciphers/aes-constants.ts` — AES_SBOX, AES_INV_SBOX, AES_RCON, AES_MIX_MATRIX, AES_INV_MIX_MATRIX, AES_SHIFT_ROWS, AES_INV_SHIFT_ROWS.

**UI stores (singletons; module-scope signals on purpose):**
- `src/ui/stores/trace.ts` — current trace + frame index, `setTrace` preserves focus by stepId across re-runs.
- `src/ui/stores/format.ts` — active byte format, persisted in `localStorage`.
- `src/ui/stores/spec.ts` — current spec + cipher mode (encrypt/decrypt). `setMode`, `resetSpec`, and `setPadding` all funnel through `applyPaddingScheme` so the active padding scheme survives mode flips and resets.
- `src/ui/stores/history.ts` — 5-deep run snapshot ring buffer + `pushSnapshot` (auto-dedups identical re-runs), `findPreviousRunFrameByStepId`, and the `showPreviousRun` overlay toggle.
- `src/ui/stores/padding.ts` — active padding scheme (`none` / `pkcs7`), persisted in `localStorage`. `paddingLimits(mode, scheme)` returns the allowed raw-input byte-length range so the Run handler can produce friendly errors.
- `src/ui/components/ByteCellInput.tsx` — format-aware editable byte cell. Width adapts (hex=2/dec=3/ASCII=4 chars). Used by SboxEditor (16x16) and MatrixEditor (4x4).
- `src/ui/components/BytesView.tsx` — variable-length sibling to MatrixView. Renders BytesState frames (pkcs7-pad / pkcs7-unpad) as a 1×N wrapping row with length-delta "missing" cell placeholders when the row's compareTo side is longer.
- `src/ui/components/RunExplorerModal.tsx` — side-by-side run comparison modal (uses native `<dialog>` for backdrop + escape handling). Pure delta-string formatter lives in `run-delta-format.ts` so node-env tests can pin its output without spinning up jsdom.

**Tests:**
- `tests/aes-vectors.test.ts` — FIPS-197 Appendix C.1 and B known-answer tests for forward AES.
- `tests/aes-decrypt.test.ts` — round-trip + decryption tests.
- `tests/spec-mutations.test.ts` — spec mutation helpers + the headline "swap S-box → ciphertext changes" modularity test.
- `tests/markdown.test.ts` — parser tests for the step-doc renderer.
- `tests/format.test.ts` — byte format core (round-trip, validation, length errors).
- `tests/trace-frame-preservation.test.ts` — `setTrace` keeps the scrubber on the same stepId across re-runs.
- `tests/byte-cell-input.test.tsx`, `tests/matrix-view.test.tsx`, `tests/app-format-toggle.test.tsx` — jsdom component tests for the format toggle (the `.tsx` files run in jsdom; see Conventions). `matrix-view` also covers the Phase 2b previous-run overlay.
- `tests/run-history.test.ts`, `tests/run-explorer-delta.test.ts` — Phase 2 store + delta formatter tests (node-env; the modal's pure helper was split out so it can be tested without DOM).
- `tests/pkcs7-pad.test.ts`, `tests/load-store-block.test.ts`, `tests/spec-mutations-padding.test.ts` — Phase 4 step + overlay tests (node-env).
- `tests/bytes-view.test.tsx`, `tests/app-padding-roundtrip.test.tsx` — Phase 4 jsdom integration tests. The headline round-trip drives the App from "apple" through encrypt → ciphertext → decrypt → "apple".

For step-type-specific guidance (adding new ones), see `src/steps/CLAUDE.md`.

## Things to avoid (Claude tends to get these wrong)

- **FIPS-197 has multiple appendices with DIFFERENT keys.** Appendix B uses key `2b7e1516…`, Appendix C.1 uses `000102…0e0f`, Appendix C.2 uses a 24-byte AES-192 key. *Don't quote a value from one appendix to test a vector from another.* Verify the key matches before asserting an intermediate state.
- **SubBytes and ShiftRows commute.** Both are byte-wise permutations; swapping their order in a round produces *identical* ciphertext. This is a real algebraic property, exploited by efficient AES implementations. If you're writing a "reordering changes the output" test, swap **ShiftRows ↔ MixColumns** instead.
- **The AES state matrix is column-major.** Byte at row `r`, col `c` lives at `bytes[r + 4*c]`. The first 4 bytes of the input go into column 0 (top-to-bottom), not row 0 (left-to-right). Visualization conventions sometimes invert this.
- **GF(2^8) uses the polynomial `x^8 + x^4 + x^3 + x + 1` (0x11b).** Don't use 0x1b alone (that's the reduction-when-MSB-is-set part of `xtime`).
- **Key expansion uses the FORWARD S-box, even when decrypting.** The inverse cipher consumes the same round keys in reverse order; it does not re-derive them with the inverse S-box. Both `aes-128.ts` and `aes-128-decrypt.ts` share the same `key-expansion` step verbatim.
- **Don't redirect native command stderr in PowerShell with `2>&1`.** PowerShell 5.1 wraps stderr lines in `NativeCommandError` records and sets `$?` to false even on success exit code 0. Capture stdout only, or merge in a different way.
- **Solid components must use `createMemo` for derived values** read multiple times in JSX. A plain function gets evaluated independently per access; that's three trace lookups per render in the worst case.
- **Solid `For` callbacks aren't reactive scopes** — a `const value = formatByte(..., props.format)` captured outside the JSX is computed once when the item is added. Inline the dynamic call into the JSX (`{formatByte(..., props.format)}`) so prop changes propagate. We've hit this in `MatrixView.tsx`: refactoring cell-value computation into a const broke the format-toggle reactivity.
- **Don't set `display:` on the bare `.modal` rule for a native `<dialog>`.** The UA stylesheet's `dialog:not([open]) { display: none }` is what hides the closed modal; overriding with `display: flex` makes the dialog visible at ALL times, obscuring the rest of the page. Put flex layout on an inner wrapper (`.modal-inner`) and let the UA rule handle visibility. The backdrop is the native `::backdrop` pseudo, not a separate element.
- **In integration tests, click the format-toggle BUTTON; don't call `setByteFormat` directly.** The store call only updates the format signal — the App's `changeFormat` handler also re-renders the input AND key fields in place. Calling the setter alone leaves the key in the old format → the Run handler then rejects it as the wrong byte count. We hit this when wiring the PKCS#7 round-trip test.
- **PKCS#7 always adds at least one byte of padding.** When the raw input is already a clean block multiple, canonical PKCS#7 appends a FULL extra block of `blockSize`. The single-block UI caps input at `blockSize - 1` to avoid this case; the step itself implements the canonical behavior. Don't "optimize" by skipping padding when `input.length % blockSize === 0` — you'll break unpad.
- **`applyPaddingScheme` walks the TOP level of `spec.steps` only.** The four overlay step types (pkcs7-pad/unpad, load-block/store-block) are always inserted at the top level so a top-level filter cleanly strips them without descending into per-round groups. If a future scheme needs to insert leaves inside groups, the helper needs a deeper walk — don't sneak overlay leaves into nested groups.

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

- Original architectural plan: `~/.claude/plans/i-want-to-build-tender-spark.md`
- Approved UX/feature plan (phases 1–4: frame preservation, run history + diff, byte format toggle, deferred 2D viz): `docs/plans/suggestions-1-4.md`
- User preferences (commit cadence, comment density): saved as feedback memories under `C:\Users\boiko\.claude\projects\M--claud-projects-Cryptographer\memory\`
- GitHub repo: https://github.com/BoykoNeov/Cryptographer
