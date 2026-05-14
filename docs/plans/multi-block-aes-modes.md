# Multi-block AES with ECB / CBC / CTR

**Status:** Phase 1 (loop primitive + AES-128 ECB) ✅ shipped May 2026 (commit `1e144c0`). Phase 2 (CBC + IV) ✅ shipped 2026-05-14 (commits `4a91462` chaining primitives, `e9cc510` CBC factory + dropdown, `46f7ccc` IV store + IvInput + document round-trip). Implementation deviated from this plan's CBC-specific step names (`xor-with-chain`, `store-chain`, …) in favor of generic primitives (`generic.iv-load@1`, `generic.xor-aux-into-state@1`, `generic.state-to-aux@1`) that compose into CBC and will reuse for OFB/CFB without rewrites; the decrypt chain-advance reuses the existing `generic.aux-copy@1`. Phases 3 (CTR + keystream) and 4 (AES-192/256 generalization) remain on the plan; the runtime + spec-store + cipher-mode-dropdown infrastructure they need is already in place.

## Context

Today Cryptographer caps the user's input at exactly one block. `paddingLimits` (`src/ui/stores/padding.ts:94-130`) forces 0–15 bytes for PKCS#7 and exactly 16 for `none`; the friendly error at `src/ui/App.tsx:787` explicitly says *"multi-block modes are not yet supported."* That cap was set when single-block padding shipped (May 2026) — the deferral has now come due.

The user wants to type **whole sentences**, watch them flow through AES, and **see what differentiates the three classic modes**:

- **ECB**: blocks encrypt independently → identical plaintext blocks produce identical ciphertext blocks (the Tux-image leak). Best pedagogical "what NOT to do."
- **CBC**: each plaintext block is XORed with the previous ciphertext block (or the IV for block 0) before the AES round. Demonstrates *chaining*.
- **CTR**: AES encrypts a counter block to produce a keystream that is XORed with plaintext. Turns AES into a stream cipher — **no padding needed**, the keystream is truncated to plaintext length.

The user picked (per `/plan` answers):

1. **Hybrid iteration**: a loop node lives in JSON, runtime expands it into flat per-iteration frames so the UI / trace store / Run Explorer keep treating traces as flat arrays.
2. **All three modes** ship in this slice (phased across commits).
3. **IV input is both** — a user-typed 16-byte field plus a "randomize" button.

This plan keeps the AES-128 round groups intact (FIPS-197 regression stays green), wraps them in a runtime loop, and layers chaining / keystream / IV machinery on top via four small new step types plus a per-mode spec factory.

## Approach

### 1. Loop primitive in the spec tree (runtime-expanded)

Add a third `StepNode` variant to `src/core/types.ts`:

```ts
type IterateGroup = {
  kind: "iterate";
  id: string;
  label?: string;
  countFromAux: string;   // aux key holding the iteration count (a number)
  blocksFromAux: string;  // aux key holding MatrixState[] (the per-iter input)
  outBlocksAux: string;   // aux key to accumulate MatrixState[] outputs
  children: StepNode[];
};
```

**Why aux-driven count, not a literal `count: 3`:** the block count is `ceil(paddedInputLen / 16)`, computed at run time from the input. A pre-step (`generic.compute-block-count@1`) writes `aux["blockCount"]` from the current input BytesState; the iterate node reads it. Same shape as today's `aux["key"]` flow — no new mechanism.

**State-shape transition contract** (resolves advisor concern #1): the iterate node **does not slice bytes itself** — that violates the principle that "executors are pure, runtime knows only about tracing." Two new "boundary" step types do the shape-shifting, and the iterate node only reads pre-built MatrixState arrays from aux:

- **Pre-loop**: `generic.split-blocks@1` (`BytesState → BytesState` passthrough state, but writes `aux["plaintext-blocks"]: MatrixState[]` as a side effect). The aux array is built once.
- **Inside loop iteration `i`**: the runtime reads `state = aux[blocksFromAux][i]` (a MatrixState), runs children with that state, and **after the last child** appends the resulting MatrixState to `aux[outBlocksAux]`.
- **Post-loop**: `generic.concat-blocks@1` (state was the last iteration's MatrixState — runtime resets it to a fresh BytesState built from `aux[outBlocksAux]`, then this step passes it through with a trace frame showing the concatenated output).

This keeps the executor signature `(state, params, ctx) → state` intact. The runtime's job inside `iterate` is purely: set `state` from `aux[blocksFromAux][i]`, recurse children, append final `state` to `aux[outBlocksAux]`. No byte slicing in the runtime.

**Runtime contract** (`src/core/runtime.ts`): when the walker encounters an `iterate` node, it:

1. Reads `count = aux[countFromAux]` (a number) and `blocks = aux[blocksFromAux]` (`MatrixState[]`).
2. Initializes `aux[outBlocksAux] = []`.
3. For `i = 0..count-1`: sets `aux["blockIndex"] = i`, sets `state = blocks[i]`, **recurses through `children` exactly as today's group walker does** (each child sees its predecessor's output as input — the existing executor contract is unchanged), **suffixes every emitted frame's `stepId` with `:b${i}`** so the flat trace stays uniquely keyed, **stamps each emitted frame with `blockIndex: i`** for the BlockBadge to consume, and after children finish appends the final `state` to `aux[outBlocksAux]`.
4. After the loop, leaves `state` as the *last iteration's last MatrixState* — the subsequent `concat-blocks` step is responsible for producing the BytesState output (so the trace has a visible "concat" frame, not a hidden runtime transition).

The `:b{i}` suffix preserves the existing trace-store invariant — `setTrace` in `src/ui/stores/trace.ts` keeps focus by stepId across re-runs; per-block suffixes mean each loop iteration is a distinct landing point. The `History` snapshot ring and Run Explorer's delta formatter are agnostic to the suffix (`tests/run-history.test.ts`'s expectations stay valid).

The `:b{i}` suffix preserves the existing trace-store invariant — `setTrace` in `src/ui/stores/trace.ts` keeps focus by stepId across re-runs; per-block suffixes mean each loop iteration is a distinct landing point. The `History` snapshot ring and Run Explorer's delta formatter are agnostic to the suffix (`tests/run-history.test.ts`'s expectations stay valid).

**Frame metadata**: add an optional `blockIndex?: number` to `TraceFrame` in `core/types.ts`. The runtime stamps it inside the loop; renderers can opt-in later (the `BlockBadge` in §6 is the first consumer).

### 2. New step types

In `src/steps/` + registered in `src/ciphers/default-registry.ts`. The boundary steps (`split-blocks`, `concat-blocks`) are the new shape-shifters that the iterate node depends on:

| Step                                | Shape transform                                  | What it does                                                                                                                       |
| ----------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `generic.split-blocks@1`            | `BytesState → BytesState` (passthrough)          | Writes `aux["plaintext-blocks"]: MatrixState[]` by slicing input into 16-byte chunks. Asserts `length % 16 === 0` (padding has run). |
| `generic.concat-blocks@1`           | `MatrixState → BytesState`                       | Reads `aux["ciphertext-blocks"]: MatrixState[]`, concatenates into a single BytesState (the trace frame shows the assembled result). |
| `generic.compute-block-count@1`     | `BytesState → BytesState` (passthrough)          | Writes `aux["blockCount"] = bytes.length / 16`. Runs after `split-blocks`.                                                         |
| `generic.iv-load@1`                 | `MatrixState → MatrixState` (passthrough)        | Reads `aux["iv"]` (16 bytes), stores it in `aux["chain"]` for CBC's first XOR. CTR uses it as the initial counter block.            |
| `generic.xor-with-chain@1`          | `MatrixState → MatrixState`                      | Inside the CBC encrypt loop: `state ⊕= aux["chain"]`. After: `aux["chain"] = state` (the just-produced ciphertext block).          |
| `generic.store-prev-ciphertext@1`   | `MatrixState → MatrixState` (passthrough)        | CBC decrypt: copies the *input* ciphertext block into `aux["next-chain"]` BEFORE the AES inverse runs (so it survives the round). |
| `generic.xor-with-prev-ciphertext@1` | `MatrixState → MatrixState`                      | CBC decrypt: after AES inverse, `state ⊕= aux["chain"]`. Then sets `aux["chain"] = aux["next-chain"]` for the next iteration.       |
| `generic.build-counter-block@1`     | `MatrixState → MatrixState`                      | CTR: increments `aux["chain"]` (interpreted as a 128-bit big-endian counter) by 1 and sets `state = aux["chain"]`. On `blockIndex=0` it uses the initial IV as-is (no pre-increment). |
| `generic.xor-with-plaintext-block@1`| `MatrixState → MatrixState`                      | CTR: after AES encrypts the counter, XOR result with `aux["plaintext-blocks"][blockIndex]`. Produces the ciphertext block. **The last iteration's partial-block truncation is handled by `concat-blocks` reading `aux["original-plaintext-length"]`** (see CTR partial-block note below). |
| `generic.truncate-to-length@1`      | `BytesState → BytesState`                        | CTR-only post-loop step: reads `aux["original-plaintext-length"]`, truncates the concatenated BytesState. Resolves the partial-last-block contract (advisor concern #3). |

Each step gets `StepDocumentation` per the `src/steps/byte-substitution.ts` convention. The doc detail for `xor-with-chain` explains the chaining invariant + cites NIST SP 800-38A §6.2; the CTR step docs cite §6.5 and call out the full-128-bit counter interpretation (see CTR Counter Format below).

**CTR counter format** (resolves advisor concern #6): we use the **full-128-bit big-endian counter** interpretation — `aux["chain"]` is the initial value (set from the 16-byte IV by `iv-load`), and each iteration increments the entire 128-bit value by 1. This matches NIST SP 800-38A §F.5.1's vector (`IV = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff` → next block uses `…fdfeff` + 1 = `…feff00`). **No 12-byte nonce / 4-byte counter split** — that is the AES-GCM convention, not generic CTR. Document this distinction in the `build-counter-block` step's doc detail since users will recognize it from GCM contexts.

**CTR partial-last-block** (resolves advisor concern #3): the loop always produces full 16-byte blocks. A post-loop `truncate-to-length@1` step reads the original (pre-padding) plaintext length, which `split-blocks` records into `aux["original-plaintext-length"]` before any padding. Since CTR doesn't use the padding overlay, the input to `split-blocks` is the raw user input; for the loop to operate on whole blocks, `split-blocks` zero-pads internally up to the next multiple of 16 (a *non-PKCS#7* internal pad — purely a buffer for the keystream XOR) and records the original length. `truncate-to-length` drops the surplus bytes back off. The trace shows: input(20B) → split (writes 2 blocks of plaintext + records length=20) → loop produces 2 ciphertext blocks → concat (32B) → truncate (20B output).

### 3. Per-mode spec factories

Mirrors the Speck `byteOrder` factory pattern (`src/ciphers/speck-32-64-builder.ts`). A new `src/ciphers/aes-cbc-builder.ts` (and `aes-ecb-builder.ts`, `aes-ctr-builder.ts`) produces specs of the form:

```
[
  pkcs7-pad (BytesState → BytesState)        // ECB / CBC only; CTR skips
  compute-block-count (sets aux.blockCount)
  iv-load (CBC only: seeds aux.chain = IV)
  key-expansion (once total, OUTSIDE the loop)
  iterate count=aux.blockCount {
    load-block (BytesState[i] → MatrixState)
    xor-with-chain (CBC only)
    initial-round-key
    round.1..N
    final-round
    store-chain (CBC only: aux.chain = current MatrixState)
  }
  // After loop: state = BytesState (concatenated ciphertext blocks)
]
```

CTR uses a different inner body — `build-counter-block → AES rounds → xor-with-plaintext-block` — and skips padding entirely.

Decrypt variants mirror (CBC uses `xor-with-prev-ciphertext` after inverse rounds; CTR encrypt == decrypt structurally).

Files added per cipher (phased — see Phasing below):

```
src/ciphers/aes-128-ecb.ts            aes-128-ecb-decrypt.ts
src/ciphers/aes-128-cbc.ts            aes-128-cbc-decrypt.ts
src/ciphers/aes-128-ctr.ts            (CTR encrypt == decrypt)
```

Same shape for AES-192 / AES-256 in the final phase.

### 4. Mode selector store + UI

New `src/ui/stores/cipher-mode.ts`:

```ts
type CipherMode = "single-block" | "ecb" | "cbc" | "ctr";
```

- `"single-block"` is the existing path — **kept as a distinct mode** even though ECB-with-count=1 produces equivalent output. Rationale (disagreeing with advisor concern #4 on test-stability grounds): collapsing into ECB-count-1 forces every emitted frame's stepId to acquire a `:b0` suffix, which would break the four existing FIPS-197 / NIST-KAT test files (`tests/aes-vectors.test.ts`, `tests/aes-decrypt.test.ts`, `tests/aes-192-vectors.test.ts`, `tests/aes-256-vectors.test.ts`) that assert on specific stepIds and frame counts. Keeping `"single-block"` as a non-iterated canonical-spec mode preserves those tests untouched and matches the project's "you can study a single block without ceremony" pedagogical intent. The cost is one if-branch in `setCipherMode` selecting between `aes-128.ts` (single-block) vs `aes-128-{ecb,cbc,ctr}.ts` (multi-block).
- New `<select>` slots into `src/ui/App.tsx` next to the existing cipher dropdown.
- `setCipherMode(next)` reloads the active spec via the mode-aware factory + re-applies `applyPaddingScheme` (which gets a CTR-aware early-return added).
- Persists in `localStorage`.

### 4a. Round-group extraction (Phase 1 sub-step)

The canonical `src/ciphers/aes-128.ts` is currently a monolithic spec literal (the `steps` array is built inline). Phase 1 includes a refactor: extract the round-group construction into `src/ciphers/aes-round-builder.ts`:

```ts
buildAesRoundGroups(variant: "aes-128" | "aes-192" | "aes-256"): StepGroup[]
```

Returns the array of round groups + the initial-round-key leaf. Both `aes-128.ts` (single-block) and the new `aes-128-ecb.ts` / `cbc.ts` / `ctr.ts` factories call it. The encrypt / decrypt direction is a parameter. **Critical**: the existing FIPS-197 test must still pass byte-identical with the extracted helper — verify by running `tests/aes-vectors.test.ts` after the refactor and before any new functionality lands.

### 5. IV input field + randomize toggle

New `src/ui/stores/iv.ts` (parallels `format.ts`'s simple-signal pattern):

- `ivBytes()` / `setIvBytes(Uint8Array)` — 16 bytes, persisted in `localStorage`.
- `randomizeIv()` — fills from `crypto.getRandomValues`.

New `src/ui/components/IvInput.tsx`:

- Format-aware 16-byte input row (reuses `ByteCellInput`).
- Disabled when `cipherMode === "single-block"` or `"ecb"` (ECB has no IV).
- "🎲 Randomize" button next to the field.

The Run handler in `App.tsx` reads `ivBytes()` and seeds `aux["iv"]` alongside the key.

### 6. Trace UI: block context

`TraceFrame.blockIndex` is the hook. Two small additions:

- **`src/ui/components/BlockBadge.tsx`** (new): a small chip rendered above MatrixView / BytesView showing *"Block 3 of 5"* whenever `frame.blockIndex !== undefined`. Pure CSS-styled, no scrubber surgery.
- **`src/ui/components/TraceTimeline.tsx`**: secondary tick marks at iteration boundaries (every K frames where K = frames-per-iteration). Pure visual; the slider stays a single linear range. No behavior change needed in the trace store.

The Run Explorer's delta formatter (`run-delta-format.ts`) is agnostic — multi-block traces are still flat. The history ring (5 snapshots × ~800 frames each = 4000 frame objects in memory worst-case) is well within limits.

### 7. Padding overlay: CTR-aware skip + multi-block PKCS#7 ranges

In `applyPaddingScheme` (`src/core/spec-mutations.ts:471-560`): add an early-return when the active cipher mode is `"ctr"` *or* `stateShape !== "matrix4x4-bytes"` (the existing Speck guard). The padding `<select>` in the UI is disabled-and-greyed when `cipherMode === "ctr"`, with a tooltip "*CTR does not require padding.*"

**Multi-block PKCS#7 length ranges** (resolves advisor concern #2): with the multi-block loop, PKCS#7 follows the **canonical "always adds a block" rule**. The new `paddingLimits(mode, scheme, cipherMode)` returns:

| (mode, scheme, cipherMode) | min | max | Notes |
| --- | --- | --- | --- |
| encrypt, none, single-block | 16 | 16 | unchanged |
| encrypt, pkcs7, single-block | 0 | 15 | unchanged |
| encrypt, pkcs7, ecb/cbc | 0 | 256 | the multi-block cap — 16 blocks = 256 bytes keeps the trace browsable in the UI (≈1600 frames for AES-128). Bigger inputs will work but the scrubber gets unwieldy. |
| encrypt, none, ecb/cbc | multiple of 16, 16..256 | (same upper cap) | rejects non-aligned input with a friendly error citing the chosen padding scheme. |
| encrypt, \*, ctr | 0 | 256 | no padding; the cap exists purely for trace size. |
| decrypt, \*, ecb/cbc | multiple of 16, 16..256 | (ciphertext must align to the block) |
| decrypt, \*, ctr | 0 | 256 | matches encrypt — no padding to strip. |

The 256-byte upper cap is **soft and configurable** via a constant in `padding.ts` (e.g., `MAX_BLOCKS_UI = 16`). Larger inputs can be supported by raising the constant; the runtime has no hard limit. The UI error wording: `"PKCS#7 encrypt supports 0–256 bytes (16 blocks max for trace browsability). Got 273. Raise MAX_BLOCKS_UI to extend."` This makes the cap discoverable.

**Canonical "always adds a block"**: an input of exactly 16 bytes under PKCS#7 produces a *second* block of `0x10 × 16` after padding — the user sees a `pkcs7-pad` frame that **adds 16 bytes**, then two ECB/CBC iterations. This is the textbook PKCS#7 contract; the existing `pkcs7-pad.ts` step already implements it (the single-block cap was a UI guard, not a step-level limitation — confirmed in the exploration agent's report on `src/steps/pkcs7-pad.ts:31`).

## Phasing

Each phase = one commit per the project's commit cadence rule. Pause-points are explicit so the user can stop after any phase.

**Phase 1 — Loop primitive + ECB (AES-128)**
- Sub-step 1a: extract `buildAesRoundGroups` into `src/ciphers/aes-round-builder.ts`. Re-point `aes-128.ts` at it. Run existing FIPS-197 tests — must stay green. Commit-able on its own as a pure refactor.
- `core/types.ts`: add `IterateGroup`, `TraceFrame.blockIndex`.
- `core/runtime.ts`: loop expansion + stepId suffix + per-frame `blockIndex` stamp.
- 3 new steps: `split-blocks@1`, `concat-blocks@1`, `compute-block-count@1`.
- `aes-128-ecb.ts` + `aes-128-ecb-decrypt.ts` factories (call `buildAesRoundGroups`).
- Mode selector dropdown wired (only `single-block` and `ecb` enabled).
- Padding overlay extended to wrap iterated specs; `paddingLimits` learns the multi-block ranges and `MAX_BLOCKS_UI` constant.
- KAT: NIST SP 800-38A §F.1.1 (AES-128 ECB encrypt) + F.1.2 (decrypt).
- BlockBadge minimal version.
- Tests: loop expansion unit test, ECB KAT, stepId suffix + blockIndex stamp test, multi-block PKCS#7 boundary tests (input length 0, 1, 15, 16, 31, 32, 256 — each produces the right block count and the right ciphertext length), headline round-trip "the quick brown fox jumps over a lazy dog" encrypt+decrypt.

**Phase 2 — CBC + IV input**
- 4 new steps: `iv-load@1`, `xor-with-chain@1` (encrypt), `store-prev-ciphertext@1` + `xor-with-prev-ciphertext@1` (decrypt — the two-step dance preserves the input block across the AES inverse for the post-round XOR).
- IV store (`src/ui/stores/iv.ts`) + `IvInput` component + 🎲 randomize button.
- `aes-128-cbc.ts` + `aes-128-cbc-decrypt.ts`.
- KAT: NIST SP 800-38A §F.2.1 (AES-128 CBC encrypt) + F.2.2 (decrypt).
- Tests: CBC KAT, IV propagation through the loop, randomize-button reproducibility (a second click changes the trace), CBC-with-identical-blocks produces *different* ciphertext halves (the half of the ECB-leak demo to be completed in Phase 3).

**Phase 3 — CTR**
- 3 new steps: `build-counter-block@1`, `xor-with-plaintext-block@1`, `truncate-to-length@1`.
- `aes-128-ctr.ts` (encrypt == decrypt structurally — same factory, both directions produce the same spec).
- Padding overlay CTR-aware skip + UI tooltip.
- KAT: NIST SP 800-38A §F.5.1 (AES-128 CTR encrypt) + F.5.2.
- Tests: CTR KAT including the full-128-bit counter increment (assert the 2nd block's counter is `IV+1`), CTR partial-last-block round-trip (20-byte input → 20-byte output, byte-identical), padding-selector-disabled integration test, **ECB-leak demo test** (two identical 16-byte plaintext blocks → identical ciphertext halves under ECB, different halves under CBC — closes the pedagogical loop with the CBC-half added in Phase 2).

**Phase 4 — AES-192/256 generalization**
- Spec factories for AES-192/256 in each of the three modes.
- Cipher selector × mode selector grid produces 9 spec combinations.
- KATs from SP 800-38A §F.{1,2,5}.{3,4,5,6}.
- Tests: cross-product matrix.

After Phase 1 the user can already encrypt arbitrary-length plaintext under ECB. Each subsequent phase is independently valuable.

## Critical files

**Modified:**
- `src/core/types.ts` — new `IterateGroup`, `TraceFrame.blockIndex`. **Schema change**: any saved-spec JSON without `kind: "iterate"` continues to work; new specs add the kind. No migration needed.
- `src/core/runtime.ts` — loop expansion + stepId suffix.
- `src/core/spec-mutations.ts` — `applyPaddingScheme` learns CTR / iterated-spec shape; new `compareSpecs` walk into iterate children.
- `src/ciphers/default-registry.ts` — register the 4–6 new step types across phases.
- `src/ui/App.tsx` — mode selector, IV input row, byte-length validation reads `paddingLimits(mode, scheme, cipherMode)`.
- `src/ui/stores/padding.ts` — `paddingLimits` learns multi-block ranges (no upper cap for ECB/CBC; CTR has no padding so no length constraint).
- `src/ui/stores/spec.ts` — `setCipherMode` reloads the right factory + re-applies padding overlay.
- `src/ui/components/TraceTimeline.tsx` — iteration tick marks (Phase 1).
- `src/ui/components/MatrixView.tsx` / `BytesView.tsx` — optionally consume `blockIndex` (zero behavior change if absent).

**Added:**
- `src/steps/split-blocks.ts`, `src/steps/concat-blocks.ts`, `src/steps/compute-block-count.ts`, `src/steps/iv-load.ts`, `src/steps/xor-with-chain.ts`, `src/steps/store-prev-ciphertext.ts`, `src/steps/xor-with-prev-ciphertext.ts`, `src/steps/build-counter-block.ts`, `src/steps/xor-with-plaintext-block.ts`, `src/steps/truncate-to-length.ts` (10 step files total across all phases).
- `src/ciphers/aes-round-builder.ts` — extracted in Phase 1; the round-group construction shared between `aes-128.ts` and all multi-block factories.
- `src/ciphers/aes-{128,192,256}-{ecb,cbc,ctr}{,-decrypt}.ts` (with CTR encrypt == decrypt: 15 files total across all phases).
- `src/ciphers/aes-ecb-builder.ts`, `aes-cbc-builder.ts`, `aes-ctr-builder.ts` — mode-specific spec factories.
- `src/ui/stores/cipher-mode.ts`, `src/ui/stores/iv.ts`.
- `src/ui/components/IvInput.tsx`, `src/ui/components/BlockBadge.tsx`.

**Reused (no changes):**
- `src/ciphers/aes-128.ts` and `aes-128-decrypt.ts` — the canonical FIPS-197 single-block specs stay untouched; the new mode factories *re-use* their round groups via shared helpers (extract once when building Phase 1).
- `src/ciphers/aes-constants.ts` — same S-box / Rcon / mix matrices.
- `src/steps/byte-substitution.ts` (and other AES round-step files) — entirely reused.
- `src/ui/components/ByteCellInput.tsx` — IvInput composes it.
- `src/core/format.ts` — IV input uses the same format toggle.

## Tests

**Phase 1:**
- `tests/runtime-iterate.test.ts` (node-env) — loop expansion: child stepIds gain `:b{i}` suffix; per-iteration aux state isolation; empty count (0 blocks) is a no-op; `blockIndex` set correctly.
- `tests/aes-128-ecb-kat.test.ts` (node-env) — NIST SP 800-38A §F.1.1 + F.1.2.
- `tests/app-multi-block-roundtrip.test.tsx` (jsdom) — type a 32-byte plaintext (two full blocks), encrypt under ECB, decrypt, recover the plaintext.

**Phase 2:**
- `tests/aes-128-cbc-kat.test.ts` (node-env) — §F.2.1 + F.2.2.
- `tests/iv-store.test.ts` (node-env) — randomize produces distinct bytes; localStorage persistence round-trip.
- `tests/app-cbc-iv-flow.test.tsx` (jsdom) — type plaintext + IV, encrypt, randomize IV, re-encrypt, assert ciphertext changes.

**Phase 3:**
- `tests/aes-128-ctr-kat.test.ts` (node-env) — §F.5.1 + F.5.2.
- `tests/ecb-leak-demo.test.ts` (node-env) — two identical 16-byte plaintext blocks → identical ciphertext halves under ECB, *different* halves under CBC. The headline pedagogical test.
- `tests/app-ctr-padding-disabled.test.tsx` (jsdom) — selecting CTR disables the padding selector with the right tooltip; the spec contains no pkcs7-pad node.

**Phase 4:**
- `tests/aes-{192,256}-{ecb,cbc,ctr}-kat.test.ts` — SP 800-38A §F appendix matrix.

## Verification (end-to-end manual)

After each phase:

1. `npm run check` passes (biome + tsc + vitest + vite build).
2. **FIPS-197 regression**: default cipher (AES-128, single-block, no padding, hex input) → ciphertext matches Appendix C.1 byte-for-byte. Untouched.
3. **Phase 1 headline**: cipher = AES-128, mode = ECB, padding = PKCS#7, format = ASCII, input = `"the quick brown fox jumps "` (26 bytes), key = 16 bytes anything. Run. Scrub — see two `:b0` and `:b1` block sequences in the trace, each with full AES rounds. Switch to decrypt with the resulting ciphertext + PKCS#7. Recover the original string.
4. **Phase 2 headline**: same input, switch mode to CBC. Type IV `00000000000000000000000000000000` (hex). Encrypt. Note ciphertext. Click 🎲. Encrypt again. **Ciphertext changes** even though plaintext + key are identical — the visible demonstration of IV.
5. **Phase 3 ECB-leak demo**: type a 32-byte input where the two halves are identical (e.g., `"sixteen byteszzzssixteen byteszzz"` ASCII — adjust to make halves match). Encrypt under ECB. Observe ciphertext halves are identical. Switch to CBC with same IV. Encrypt. Observe halves are now different. *This is the pedagogical money shot.*
6. **Run Explorer** captures snapshots across modes correctly (delta formatter unchanged, history ring not blown).
7. **Format toggle** still flips the input + key + IV in place across all modes.

## Open questions / risks

- **Spec round-trippability across mode changes**: today's `setCipherMode` would reload a fresh canonical spec, *losing* any per-step edits the user made (e.g., a swapped S-box). This is consistent with how `setMode` (encrypt↔decrypt) works today — flagging it here for awareness; the workaround if needed is the existing per-step diff in `compareSpecs`.
- **TraceTimeline tick marks** assume each iteration has the same number of leaves. True for AES (every block runs the same round group). If a future cipher has variable-length blocks, the marks become a guideline rather than ground truth — fine for v1.
- **Multi-block input field UX**: the existing input field is a single `<textarea>` already; format toggle handles ASCII vs hex vs decimal. The byte-length range validation just relaxes its upper bound. No new input widget needed — confirmed by reading the App.tsx Run handler.
- **MAX_BLOCKS_UI = 16 ceiling** is a UX guard, not a runtime limit. If a user wants to encrypt a paragraph, they raise the constant in `padding.ts`. Acceptable for v1 since the scrubber/timeline degrades visually past ~16 blocks. A future enhancement could collapse iteration bodies in `StepList` when expanded count is high.
- **`aes-round-builder.ts` extraction safety**: the Phase 1 refactor of `aes-128.ts` must produce a byte-identical spec to the current monolithic literal. The existing FIPS-197 tests (`tests/aes-vectors.test.ts`, `tests/aes-decrypt.test.ts`) are the safety net — they pin exact intermediate states by stepId. If the refactor changes any stepId or ordering, those tests fail loudly. Treat that as a hard gate before any new functionality lands in Phase 1.
- **Snapshot serialization stability**: existing snapshots in `localStorage` from prior sessions will be loaded against the new `CipherSpec` shape (which now includes `IterateGroup`). Since old specs never had `kind: "iterate"`, deserialization is forward-compatible. Verify by loading an old snapshot in dev after Phase 1.
