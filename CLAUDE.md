# Cryptographer

Interactive cryptography explorer. The user enters plaintext + key, sees every intermediate state of every step of every round, and can experiment by editing the cipher's parameters (swap the S-box, reorder steps, change the MixColumns matrix) and watch the trace re-run within ~200ms. Built as a learning tool, not a production crypto library.

## Quick reference

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server at `http://localhost:5173`. Hot-reloads on file changes. |
| `npm test` | Vitest, single run. Currently 278 tests across 29 files, ~2s total (jsdom UI tests dominate). |
| `npm run typecheck` | `tsc --noEmit`, strict. |
| `npm run check` | The gate: `biome ci . && tsc --noEmit && vitest run && vite build`. Runs in ~6s on this machine. |
| `npm run build` | Production build into `dist/`. ~42KB gzipped JS. |

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

**Multi-block modes via the `iterate` primitive.** Block-cipher modes of operation (ECB shipped Phase 1; CBC/CTR queued for Phase 2/3) run AES's per-block body once per plaintext block by wrapping it in an `iterate` group. The runtime reads `aux[countFromAux]` (a number) and `aux[blocksFromAux]` (a `MatrixState[]`), sets `state = blocks[i]` per iteration, walks the children body, suffixes every emitted frame's `stepId` with `:b{i}` so the flat trace stays uniquely keyed, stamps each frame with `blockIndex: i`, and appends the iteration's final state into `aux[outBlocksAux]`. The two boundary steps `generic.split-blocks@1` (`BytesState → MatrixState[]` into aux) and `generic.concat-blocks@1` (reverse, after the loop) are what make this composable across modes — the iterate node itself doesn't slice bytes. See `docs/plans/multi-block-aes-modes.md` for the design rationale and Phases 2–4 still on paper.

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
- `src/ciphers/aes-round-builder.ts` — extracted forward/inverse AES round body (`buildAesEncryptBody(rounds)` and `buildAesDecryptBody(rounds)`). Used by single-block `aes-128.ts` and the multi-block ECB factory; CBC/CTR factories will call it too when Phase 2/3 land. The single point of truth for the per-block round-group construction.
- `src/ciphers/aes-ecb-builder.ts` + `aes-128-ecb.ts` + `aes-128-ecb-decrypt.ts` — Phase 1 multi-block ECB. The builder is variant-aware (`aes-128`/`192`/`256` × `encrypt`/`decrypt`) but only the AES-128 spec files exist today; AES-192/256 ECB are a one-line spec each, waiting on Phase 4. The spec shape is `[key-expansion, split-blocks, compute-block-count, iterate{...round-body...}, concat-blocks]`; `applyPaddingScheme` prepends `pkcs7-pad` (or sibling) on encrypt and appends `pkcs7-unpad` on decrypt around the outside.
- `src/ciphers/speck-32-64-builder.ts` + `speck-32-64-{be,le}{,-decrypt}.ts` — Speck32/64 spec factory + four canonical specs (BE encrypt, BE decrypt, LE encrypt, LE decrypt). The four files differ only by the `(byteOrder, direction)` pair passed to the builder; the builder bakes the per-leaf params and the decrypt round-key reversal. Block size is 4 bytes, key is 8 bytes, 22 rounds, no padding overlay support.

**UI stores (singletons; module-scope signals on purpose):**
- `src/ui/stores/trace.ts` — current trace + frame index, `setTrace` preserves focus by stepId across re-runs.
- `src/ui/stores/format.ts` — active byte format, persisted in `localStorage`.
- `src/ui/stores/spec.ts` — current spec + (cipher, cipherMode, mode) selector. `defaults` is a **3D** `Record<Cipher, Partial<Record<CipherMode, Record<Mode, CipherSpec>>>>` table — each cipher's inner record only carries the modes-of-operation it supports (Speck has only `single-block`; AES-128 has `single-block` + `ecb` today). `resolveDefault` falls back to `single-block` when the requested cipherMode isn't registered, so picking ECB on AES-128 and then flipping to Speck just lands you back on single-block Speck without crashing. `setMode`, `setCipher`, `setCipherMode`, `resetSpec`, and `setPadding` all funnel through `applyPaddingScheme` so the active padding scheme survives every selector flip.
- `src/ui/stores/cipher.ts` — active AES variant (`aes-128` / `aes-192` / `aes-256`), persisted in `localStorage`. Also exports `DEFAULT_KEY_BYTES_BY_CIPHER` (FIPS-197 §A.1/§A.2/§A.3 canonical keys) used by the App's cipher-change handler to swap the key field only when it still holds the previous cipher's default.
- `src/ui/stores/cipher-mode.ts` — block-cipher mode of operation (`single-block` / `ecb` / `cbc` / `ctr`), persisted in `localStorage`. `SUPPORTED_CIPHER_MODES` carries only the modes the current code can actually run (Phase 1: `single-block`, `ecb`); CBC/CTR are present in the type/dropdown but disabled until Phases 2/3. A persisted value pointing at an unsupported mode falls back to `single-block` on load — keeps the app from breaking when a half-shipped mode lands in localStorage.
- `src/ui/stores/history.ts` — 5-deep run snapshot ring buffer + `pushSnapshot` (auto-dedups identical re-runs), `findPreviousRunFrameByStepId`, and the `showPreviousRun` overlay toggle.
- `src/ui/stores/padding.ts` — active padding scheme (`none` / `pkcs7` / `zero-pad` / `iso7816-4`), persisted in `localStorage`. `paddingLimits(mode, scheme, cipher, cipherMode?)` returns the allowed raw-input byte-length range so the Run handler can produce friendly errors. Cipher-mode is a fourth arg with a `"single-block"` default — multi-block ECB/CBC widen the range to `MAX_BLOCKS_UI × 16` (16 blocks = 256 bytes today), CTR uses the same cap but skips padding, single-block keeps today's 0..15 / 1..16 / 16..16 ranges per scheme. The cap is a UI guard (trace browsability), not a runtime limit — bump the `MAX_BLOCKS_UI` constant to encrypt a paragraph at the cost of a noisier scrubber.
- `src/ui/stores/auto-rerun.ts` — two signals: `autoRerun` (user preference, persisted in `localStorage`, default true) and `dirty` (session-only flag set when manual mode receives a spec edit). The App's `createEffect(on(spec, ...))` branches on `autoRerun()` — true keeps the 200ms debounced re-run; false just calls `setDirty(true)` so the inline "edits pending" banner appears. Flipping `autoRerun` back ON clears `dirty` so the banner doesn't go stale.
- `src/ui/components/ByteCellInput.tsx` — format-aware editable byte cell. Width adapts (hex=2/dec=3/ASCII=4 chars). Used by SboxEditor (16x16) and MatrixEditor (4x4).
- `src/ui/components/BytesView.tsx` — variable-length sibling to MatrixView. Renders BytesState frames (pkcs7-pad / pkcs7-unpad) as a 1×N wrapping row with length-delta "missing" cell placeholders when the row's compareTo side is longer.
- `src/ui/components/BlockBadge.tsx` — small "Block i of N" chip rendered above the per-frame state view when the current frame belongs to an iterate loop (i.e. `frame.blockIndex !== undefined` and the trace has more than one block). Pure visual — no scrubber surgery. Driven by App-level `blockCount` memo that scans `trace.frames` for the max `blockIndex`.
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
- `tests/runtime-iterate.test.ts` — Multi-block Phase 1: loop-primitive unit tests. Per-iteration `stepId:b{i}` suffixing, `blockIndex` frame stamps, accumulation into `aux[outBlocksAux]`, `aux["blockIndex"]` exposed to executors during iteration, count=0 no-op, and the two malformed-aux throw paths.
- `tests/aes-128-ecb-kat.test.ts` — Multi-block Phase 1: NIST SP 800-38A §F.1.1 encrypt + §F.1.2 decrypt against the 4-block published vector. Cross-checked against `node:crypto` during implementation (caught a single-character typo in my own copy of the standard — block 4 ends `…6c3710` not `…6c2710`). Also asserts the 164-frame total count and pins specific `:b0` / `:b3` step ids.
- `tests/multi-block-padding-boundary.test.ts` — Multi-block Phase 1: round-trip across input lengths 0/1/15/16/17/31/32/64 under PKCS#7 + ECB; pins the canonical "16-byte input pads to a full extra block" behaviour; and pins the `paddingLimits` ranges for every (encrypt/decrypt, scheme, cipherMode=ecb) combination.
- `tests/app-multi-block-roundtrip.test.tsx` — Multi-block Phase 1 jsdom integration. Drives the App through ECB + PKCS#7 + ASCII format, types "the quick brown fox jumps over" (30 bytes / 2 blocks), encrypts, switches to decrypt mode, pastes ciphertext, recovers the original. Also pins the cipher-mode dropdown's disabled-state on CBC/CTR.

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
- **The padding overlay is AES-only.** `load-block` is hardcoded for blockSize=16 (the 4×4 byte matrix). `applyPaddingScheme` early-returns for any spec whose `stateShape !== "matrix4x4-bytes"` AND has no iterate node (the single-block-AES detection), and the UI disables the padding `<select>` for non-AES ciphers. Multi-block AES specs reach the iterate branch instead — see next bullet. A future block-size-aware load/store rework can unlock the overlay for Speck and friends, but right now: don't try to apply padding to non-AES specs, and don't write tests that assume the overlay fires for them.
- **`applyPaddingScheme` has three branches now, not two.** Multi-block specs (detected by `kind: "iterate"` at the top level) get just `pkcs7-pad` prepended on encrypt or `pkcs7-unpad` appended on decrypt — NO `load-block` / `store-block` at the boundary, because the iterate body's `split-blocks` / `concat-blocks` steps handle the BytesState ↔ MatrixState transition internally. Single-block AES (`stateShape === "matrix4x4-bytes"`, no iterate) keeps today's `[pad, load-block]` / `[store-block, unpad]` shape. Non-AES (Speck) skips the overlay entirely. The branch order in `spec-mutations.ts::applyPaddingScheme` matters — iterate detection comes first.
- **The iterate node delegates byte slicing to step executors.** The runtime never reads `state.bytes.subarray(i*16, (i+1)*16)` itself. Instead, a `split-blocks@1` step BEFORE the iterate writes `aux["plaintext-blocks"]: MatrixState[]`, and the iterate reads from that aux array each iteration. This keeps the executor signature `(state, params, ctx) → state` intact — no special "runtime can slice bytes" carve-out for iterate. When Phase 3 lands CTR, the same pattern: a step does the work, the iterate just walks the aux array. Don't put byte-slicing logic in the runtime.
- **Per-iteration step ids get a `:b{i}` suffix automatically.** A `round.1.sub-bytes` leaf inside an iterate emits `round.1.sub-bytes:b0`, `round.1.sub-bytes:b1`, … per iteration. The trace store's `setTrace` is stepId-anchored, so this is what makes "preserve focus across re-runs" work on a multi-block trace. Don't write step ids with literal `:b` substrings in them — they'd collide with the suffix convention. The runtime also stamps `frame.blockIndex` so renderers (`BlockBadge`) can show context without parsing the stepId.
- **`paddingLimits` got a fourth `cipherMode` arg with a default.** Existing call sites that don't pass it get `cipherMode = "single-block"` and behave identically to before — same ranges, same scheme-specific caps. The new arg is what widens the range for multi-block (0..255 PKCS#7-encrypt, 16..256 decrypt, etc.) up to `MAX_BLOCKS_UI × 16`. If you add a new call site in code that's mode-aware, plumb the cipherMode through; if you're calling from a single-block test, the default is the right answer.
- **Run handler's alignment check belongs in App.tsx, not deep in `split-blocks`.** Multi-block decrypt + multi-block encrypt-with-`none` both require input length % 16 == 0. `split-blocks` throws a generic "not a multiple of blockSize" error if alignment is off, which surfaces to the user as a deep-internals message. App.tsx has a friendly pre-check that fires before runSpec — keep it there so the error names the input field, not the step.
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
- Plaintext input + visible padding plan (PKCS#7 shipped May 2026; zero-pad + ISO 7816-4 follow-up shipped May 2026; multi-block extension lifted in the multi-block-aes-modes plan below): `docs/plans/pkcs7-padding.md`
- Speck32/64 plan (shipped May 2026 — second cipher family, ARX, both BE-paper + LE-NSA byte conventions): `docs/plans/speck.md`
- Multi-block AES with ECB/CBC/CTR plan (Phase 1 — loop primitive + AES-128 ECB — shipped May 2026; Phases 2–4 on paper: CBC + IV, CTR + keystream, AES-192/256 generalization): `docs/plans/multi-block-aes-modes.md`
- User preferences (commit cadence, comment density): saved as feedback memories under `C:\Users\boiko\.claude\projects\M--claud-projects-Cryptographer\memory\`
- GitHub repo: https://github.com/BoykoNeov/Cryptographer
