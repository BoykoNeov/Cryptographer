# Cryptographer

Interactive cryptography explorer. The user enters plaintext + key, sees every intermediate state of every step of every round, and can experiment by editing the cipher's parameters (swap the S-box, reorder steps, change the MixColumns matrix) and watch the trace re-run within ~200ms. Built as a learning tool, not a production crypto library.

## Quick reference

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server at `http://localhost:5173`. Hot-reloads on file changes. |
| `npm test` | Vitest, single run. Currently 235 tests across 23 files, ~2s total (jsdom UI tests dominate). |
| `npm run typecheck` | `tsc --noEmit`, strict. |
| `npm run check` | The gate: `biome ci . && tsc --noEmit && vitest run && vite build`. Runs in ~6s on this machine. |
| `npm run build` | Production build into `dist/`. ~32KB gzipped JS. |

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

State is a discriminated union: `BytesState`, `MatrixState` (4×4 byte matrix, column-major), `BitVecState`, `BigIntState`. AES uses `MatrixState`; Speck32/64 uses `BytesState` of length 4 (the two-word ARX interpretation lives inside the executor via a byte ↔ word codec). `BitVecState` and `BigIntState` are declared but not yet exercised by a shipped cipher.

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
- `src/core/spec-mutations.ts` — `findStep`, `updateStepParams`, `updateAllStepsByType`, `compareSpecs`. Pure spec-in/spec-out. `compareSpecs` returns `SpecParamDiff[]` where each entry optionally carries `scalar` (before/after for primitive params) or `cells` (per-cell `ParamCellDiff`, 1D index or 2D row/col; flat-256 arrays auto-decompose to 16×16 like the S-box editor). Bare diffs with neither field intentionally pass through — `describeDelta` falls back to "X changed" for them.
- `src/core/format.ts` — `ByteFormat`, `formatByte`/`parseByte`/`formatBytes`/`parseBytes`/`parseBytesWithLength`. Consumed by every byte-rendering site.

**Ciphers:**
- `src/ciphers/default-registry.ts` — wires every step type. Adding a new step means editing this.
- `src/ciphers/aes-128.ts`, `src/ciphers/aes-128-decrypt.ts` — AES-128 forward + inverse specs.
- `src/ciphers/aes-192.ts`, `src/ciphers/aes-192-decrypt.ts` — AES-192 (Nk=6, Nr=12). Reuses every AES-128 step type; only `ROUNDS` and `inputs.key.byteLength` differ.
- `src/ciphers/aes-256.ts`, `src/ciphers/aes-256-decrypt.ts` — AES-256 (Nk=8, Nr=14). Same shape as AES-192; the `aes.key-expansion@1` step has an Nk>6 branch that fires only here.
- `src/ciphers/aes-constants.ts` — AES_SBOX, AES_INV_SBOX, AES_RCON, AES_MIX_MATRIX, AES_INV_MIX_MATRIX, AES_SHIFT_ROWS, AES_INV_SHIFT_ROWS. Rcon table is long enough for all three key sizes.
- `src/ciphers/speck-32-64-builder.ts` + `speck-32-64-{be,le}{,-decrypt}.ts` — Speck32/64 spec factory + four canonical specs (BE encrypt, BE decrypt, LE encrypt, LE decrypt). The four files differ only by the `(byteOrder, direction)` pair passed to the builder; the builder bakes the per-leaf params and the decrypt round-key reversal. Block size is 4 bytes, key is 8 bytes, 22 rounds, no padding overlay support.

**UI stores (singletons; module-scope signals on purpose):**
- `src/ui/stores/trace.ts` — current trace + frame index, `setTrace` preserves focus by stepId across re-runs.
- `src/ui/stores/format.ts` — active byte format, persisted in `localStorage`.
- `src/ui/stores/spec.ts` — current spec + (cipher, mode) selector. `defaults` is a `Record<Cipher, Record<Mode, CipherSpec>>` table. `setMode`, `setCipher`, `resetSpec`, and `setPadding` all funnel through `applyPaddingScheme` so the active padding scheme survives mode / cipher flips and resets.
- `src/ui/stores/cipher.ts` — active AES variant (`aes-128` / `aes-192` / `aes-256`), persisted in `localStorage`. Also exports `DEFAULT_KEY_BYTES_BY_CIPHER` (FIPS-197 §A.1/§A.2/§A.3 canonical keys) used by the App's cipher-change handler to swap the key field only when it still holds the previous cipher's default.
- `src/ui/stores/history.ts` — 5-deep run snapshot ring buffer + `pushSnapshot` (auto-dedups identical re-runs), `findPreviousRunFrameByStepId`, and the `showPreviousRun` overlay toggle.
- `src/ui/stores/padding.ts` — active padding scheme (`none` / `pkcs7`), persisted in `localStorage`. `paddingLimits(mode, scheme)` returns the allowed raw-input byte-length range so the Run handler can produce friendly errors.
- `src/ui/stores/auto-rerun.ts` — two signals: `autoRerun` (user preference, persisted in `localStorage`, default true) and `dirty` (session-only flag set when manual mode receives a spec edit). The App's `createEffect(on(spec, ...))` branches on `autoRerun()` — true keeps the 200ms debounced re-run; false just calls `setDirty(true)` so the inline "edits pending" banner appears. Flipping `autoRerun` back ON clears `dirty` so the banner doesn't go stale.
- `src/ui/components/ByteCellInput.tsx` — format-aware editable byte cell. Width adapts (hex=2/dec=3/ASCII=4 chars). Used by SboxEditor (16x16) and MatrixEditor (4x4).
- `src/ui/components/BytesView.tsx` — variable-length sibling to MatrixView. Renders BytesState frames (pkcs7-pad / pkcs7-unpad) as a 1×N wrapping row with length-delta "missing" cell placeholders when the row's compareTo side is longer.
- `src/ui/components/RunExplorerModal.tsx` — side-by-side run comparison modal (uses native `<dialog>` for backdrop + escape handling). Pure delta-string formatter lives in `run-delta-format.ts` so node-env tests can pin its output without spinning up jsdom.

**Tests:**
- `tests/aes-vectors.test.ts` — FIPS-197 Appendix C.1 and B known-answer tests for forward AES-128.
- `tests/aes-decrypt.test.ts` — round-trip + decryption tests (AES-128).
- `tests/aes-192-vectors.test.ts` — NIST AES Core 192 KAT + FIPS-197 §A.2 roundKey.12 assertion + round-trip with `aes-192-decrypt`.
- `tests/aes-256-vectors.test.ts` — NIST AES Core 256 KAT + FIPS-197 §A.3 roundKey.3 (pins the Nk>6 SubWord-only branch in key-expansion) + roundKey.14 + round-trip + Nk+6==rounds assertion error.
- `tests/app-cipher-selector.test.tsx` — jsdom integration. Drives the App through the actual `<select>` change events to prove the cipher dropdown wires up the key-field auto-swap, dynamic key length, and that AES-192 / AES-256 produce the NIST canonical ciphertexts end-to-end.
- `tests/spec-mutations.test.ts` — spec mutation helpers + the headline "swap S-box → ciphertext changes" modularity test.
- `tests/markdown.test.ts` — parser tests for the step-doc renderer.
- `tests/format.test.ts` — byte format core (round-trip, validation, length errors).
- `tests/trace-frame-preservation.test.ts` — `setTrace` keeps the scrubber on the same stepId across re-runs.
- `tests/byte-cell-input.test.tsx`, `tests/matrix-view.test.tsx`, `tests/app-format-toggle.test.tsx` — jsdom component tests for the format toggle (the `.tsx` files run in jsdom; see Conventions). `matrix-view` also covers the Phase 2b previous-run overlay.
- `tests/run-history.test.ts`, `tests/run-explorer-delta.test.ts` — Phase 2 store + delta formatter tests (node-env; the modal's pure helper was split out so it can be tested without DOM). `run-explorer-delta` also pins the per-cell rendering — scalar diffs, 1D/2D cell diffs, the 8-line overflow cap, and the bare-diff fallback.
- `tests/app-auto-rerun-toggle.test.tsx` — jsdom integration for the auto/manual rerun toggle. Drives the App through an initial Run, flips the toggle off, edits the spec via `editStepParams`, and asserts no new snapshot lands until the user clicks Run again (the whole point of manual mode — preserving the prior snapshot for the Run Explorer).
- `tests/pkcs7-pad.test.ts`, `tests/load-store-block.test.ts`, `tests/spec-mutations-padding.test.ts` — Phase 4 step + overlay tests (node-env).
- `tests/bytes-view.test.tsx`, `tests/app-padding-roundtrip.test.tsx` — Phase 4 jsdom integration tests. The headline round-trip drives the App from "apple" through encrypt → ciphertext → decrypt → "apple".

For step-type-specific guidance (adding new ones), see `src/steps/CLAUDE.md`.

## Things to avoid (Claude tends to get these wrong)

- **FIPS-197 has multiple appendices with DIFFERENT keys.** Appendix B uses key `2b7e1516…`, Appendix C.1 uses `000102…0e0f`, Appendix C.2 uses a 24-byte AES-192 key. *Don't quote a value from one appendix to test a vector from another.* Verify the key matches before asserting an intermediate state.
- **SubBytes and ShiftRows commute.** Both are byte-wise permutations; swapping their order in a round produces *identical* ciphertext. This is a real algebraic property, exploited by efficient AES implementations. If you're writing a "reordering changes the output" test, swap **ShiftRows ↔ MixColumns** instead.
- **The AES state matrix is column-major.** Byte at row `r`, col `c` lives at `bytes[r + 4*c]`. The first 4 bytes of the input go into column 0 (top-to-bottom), not row 0 (left-to-right). Visualization conventions sometimes invert this.
- **GF(2^8) uses the polynomial `x^8 + x^4 + x^3 + x + 1` (0x11b).** Don't use 0x1b alone (that's the reduction-when-MSB-is-set part of `xtime`).
- **Key expansion uses the FORWARD S-box, even when decrypting.** The inverse cipher consumes the same round keys in reverse order; it does not re-derive them with the inverse S-box. Both `aes-128.ts` and `aes-128-decrypt.ts` share the same `key-expansion` step verbatim.
- **AES-256 has an extra `i % Nk == 4` SubWord-only branch in key expansion.** When `Nk > 6`, every word at `i % Nk == 4` passes through SubWord WITHOUT RotWord and WITHOUT an Rcon XOR. Only AES-256 (Nk=8) triggers it — AES-128/192 never reach the branch. If you assert only the final round key, an end-to-end KAT can pass with a wrong intermediate by coincidence. `tests/aes-256-vectors.test.ts` asserts `roundKey.3` directly (= w[12..15], where w[12] is the first index that fires the branch) as the specific guard.
- **AES key length and `rounds` must agree: `rounds === Nk + 6`.** Key-expansion asserts this — a 24-byte key with `rounds: 10` (or any mismatched pair) throws "rounds (X) must equal Nk+6 (Y)". When writing a new AES-variant spec, both the `inputs.key.byteLength` and the key-expansion `rounds` param must move together.
- **Don't redirect native command stderr in PowerShell with `2>&1`.** PowerShell 5.1 wraps stderr lines in `NativeCommandError` records and sets `$?` to false even on success exit code 0. Capture stdout only, or merge in a different way.
- **Solid components must use `createMemo` for derived values** read multiple times in JSX. A plain function gets evaluated independently per access; that's three trace lookups per render in the worst case.
- **Solid `For` callbacks aren't reactive scopes** — a `const value = formatByte(..., props.format)` captured outside the JSX is computed once when the item is added. Inline the dynamic call into the JSX (`{formatByte(..., props.format)}`) so prop changes propagate. We've hit this in `MatrixView.tsx`: refactoring cell-value computation into a const broke the format-toggle reactivity.
- **Solid signal setters return the value they set.** Writing `export const setDirty = (v: boolean): void => setDirtySignal(v);` fails typecheck under `exactOptionalPropertyTypes` because `setDirtySignal(v)` returns `boolean`, not `void`. Wrap in a block (`(v) => { setDirtySignal(v); }`) to drop the return value. Hit this when wiring `stores/auto-rerun.ts`.
- **Don't set `display:` on the bare `.modal` rule for a native `<dialog>`.** The UA stylesheet's `dialog:not([open]) { display: none }` is what hides the closed modal; overriding with `display: flex` makes the dialog visible at ALL times, obscuring the rest of the page. Put flex layout on an inner wrapper (`.modal-inner`) and let the UA rule handle visibility. The backdrop is the native `::backdrop` pseudo, not a separate element.
- **In integration tests, click the format-toggle BUTTON; don't call `setByteFormat` directly.** The store call only updates the format signal — the App's `changeFormat` handler also re-renders the input AND key fields in place. Calling the setter alone leaves the key in the old format → the Run handler then rejects it as the wrong byte count. We hit this when wiring the PKCS#7 round-trip test.
- **PKCS#7 always adds at least one byte of padding.** When the raw input is already a clean block multiple, canonical PKCS#7 appends a FULL extra block of `blockSize`. The single-block UI caps input at `blockSize - 1` to avoid this case; the step itself implements the canonical behavior. Don't "optimize" by skipping padding when `input.length % blockSize === 0` — you'll break unpad.
- **`applyPaddingScheme` walks the TOP level of `spec.steps` only.** The four overlay step types (pkcs7-pad/unpad, load-block/store-block) are always inserted at the top level so a top-level filter cleanly strips them without descending into per-round groups. If a future scheme needs to insert leaves inside groups, the helper needs a deeper walk — don't sneak overlay leaves into nested groups.
- **The padding overlay is AES-only.** `load-block` is hardcoded for blockSize=16 (the 4×4 byte matrix). `applyPaddingScheme` early-returns for any spec whose `stateShape !== "matrix4x4-bytes"`, and the UI disables the padding `<select>` for non-AES ciphers. A future block-size-aware load/store rework can unlock the overlay for Speck and friends, but right now: don't try to apply padding to non-AES specs, and don't write tests that assume the overlay fires for them.
- **Speck byte ordering: two conventions, neither is "wrong."** The Beaulieu et al. paper gives *word-level* test vectors only. We ship two cipher specs (`speck-32-64-be` paper-faithful, `speck-32-64-le` NSA reference) sharing the same step code; they differ only in the `byteOrder` param on each leaf. Same word-level KAT, different byte serializations. Don't quote a BE byte sequence to test an LE spec or vice versa — the codec in `src/steps/speck-word-codec.ts` is the boundary that absorbs the convention.
- **Speck's key bytes are NOT in `k_0`-first order for BE-paper.** In `K = (l_{m-2}, l_{m-3}, …, l_0, k_0)`, the visual order (and BE-paper byte order) puts `l_{m-2}` first in memory and `k_0` last. For LE-NSA it's the reverse (k_0 first). If you write a test that assumes "first 2 bytes are k_0," that's wrong for BE — `decodeKey` in the codec handles this asymmetry. Verify against the KAT before pinning intermediate-word assertions.
- **JS bitwise ops are 32-bit.** Speck's ARX kernel uses word sizes parameterized by `wordBits`. The rotations multiply by `(1 << bits) - 1` for the mask. `1 << 16 = 65536` works fine, but `1 << 32 = 1` (the shift count is taken mod 32). The `wordMask` helper special-cases 32 and uses `0xffffffff`. Larger Speck variants (Speck128/* uses 64-bit words) will need BigInt; today we only test 16-bit Speck32/64 and the code asserts up to 32.
- **Speck modular subtraction (decrypt round) can go negative in JS.** The inverse round computes `(x' XOR k) - y` which mathematically wraps mod 2^n. In JS, the `-` operator can return negative numbers; mask back to `wordBits` *after* adding `(mask + 1)` to bring the value non-negative first. Otherwise the trailing `& mask` works on a signed int32 and produces garbage for some inputs.

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
- Plaintext input + visible padding plan (PKCS#7 shipped May 2026; zero-pad + ISO 7816-4 follow-up shipped May 2026; multi-block deferred): `docs/plans/pkcs7-padding.md`
- Speck32/64 plan (shipped May 2026 — second cipher family, ARX, both BE-paper + LE-NSA byte conventions): `docs/plans/speck.md`
- User preferences (commit cadence, comment density): saved as feedback memories under `C:\Users\boiko\.claude\projects\M--claud-projects-Cryptographer\memory\`
- GitHub repo: https://github.com/BoykoNeov/Cryptographer
