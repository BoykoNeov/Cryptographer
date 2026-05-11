# Plaintext input + visible padding for AES (single-block)

**Status:** ✅ Shipped in commit `cbaba6a` (May 2026) for PKCS#7; ✅ extended with zero-pad + ISO 7816-4 in a follow-up (May 2026). Multi-block + ECB/CBC/CTR/GCM modes remain deferred per the "Deferred" section below; the three single-block schemes are all in.

## Context

The Cryptographer currently forces the user to type exactly 16 bytes of input. Anything shorter — like the word `apple` (5 bytes) — fails at `parseBytesWithLength(..., 16)` in `src/ui/App.tsx:97`. The user wants to type plaintext words and watch them flow through AES.

The wall is not the format (ASCII already renders printable bytes as literals) — it is the length check. Removing the check requires *padding* the short input up to a 16-byte block. To stay aligned with the project's "you can see everything" ethos, padding becomes a **visible step in the cipher spec**, not a silent UI-layer transform. When the user types `apple`, the trace will show a `pkcs7-pad` frame producing `apple\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b` before AES touches it. Decrypt mirrors with a `pkcs7-unpad` step at the tail, recovering exactly `apple`.

PKCS#7 was chosen because it round-trips losslessly, is universal across block ciphers (parametrize on `blockSize` → drops into future DES/3DES/Speck/Twofish/Serpent), and is the canonical scheme taught alongside AES. Zero-pad and ISO 7816-4 are sketched as future work but **not implemented in this change**.

Stream ciphers (ChaCha20, RC4) need no padding; RSA uses its own padding (PKCS#1 v1.5, OAEP) tied to modulus size — these are out of scope for this feature and will be handled per-cipher when added.

## Design decisions (committed)

1. **Conditional pad insertion, not always-through-BytesState.** When the padding scheme is `none` (default, fresh load), the spec is unchanged from today — input enters as `MatrixState` via `matrixFromBytes`, and the FIPS-197 Appendix C.1 test vector renders identically (no extra frames). When the scheme is `pkcs7`, two new steps are prepended to the encrypt spec: `generic.pkcs7-pad@1` (BytesState → BytesState, length-expanded) then `generic.load-block@1` (BytesState → MatrixState). Decrypt mirrors with `generic.store-block@1` (MatrixState → BytesState) then `generic.pkcs7-unpad@1` (BytesState → BytesState, length-shrunk) appended at the tail. This preserves the canonical first-impression trace and keeps the pad/unpad chain a discrete, reversible "prefix/suffix" toggle.

2. **Padding scheme lives in a small UI store** (`src/ui/stores/padding.ts`), persisted in localStorage like `format.ts`. Not part of `CipherSpec` itself — the spec records the *result* of the choice (whether the pad/load steps are present) and round-trips that as JSON via snapshots. The store + spec sync via a `setPaddingScheme` mutator that rebuilds the current spec with/without the padding prefix on each change. Mode changes (encrypt↔decrypt) re-apply the current scheme to the freshly-loaded canonical spec.

3. **Single-block scope only.** Multi-block + cipher modes (ECB/CBC/CTR/GCM) are explicitly deferred. The Run handler enforces a per-scheme byte-length range:

   | Scheme | Allowed raw input length |
   |---|---|
   | `none` | exactly 16 |
   | `pkcs7` | 0–15 (PKCS#7 always adds ≥1 byte) |
   | `zero-pad` (future) | 0–16 |
   | `iso7816-4` (future) | 0–15 |

   The friendly error cites the scheme: e.g. `"PKCS#7 input must be 0–15 bytes; got 16. (A 16-byte input would need a second padding block — multi-block modes are not yet supported.)"` Key input stays strict-16 regardless of padding scheme (keys are not padded).

4. **No fourth byte format.** ASCII already renders printable bytes as literals — the user's "in plaintext" request is satisfied by ASCII + padding. The `hex / dec / ASCII` toggle stays as-is.

## New step types

Four new entries in `src/ciphers/default-registry.ts`, each with executor + `StepDocumentation` colocated per the existing convention (`src/steps/byte-substitution.ts` is the template):

1. **`generic.pkcs7-pad@1`** — `(BytesState, { blockSize }) → BytesState`. Appends `N` bytes of value `N` where `N = blockSize - (input.length % blockSize)`. Always adds at least 1 byte (so when input is already a block multiple, it adds a full extra block — and in single-block scope, our length cap prevents that case at the UI level). Lives in `src/steps/pkcs7-pad.ts`.

2. **`generic.pkcs7-unpad@1`** — `(BytesState, { blockSize }) → BytesState`. Reads the last byte `N`, validates that the trailing `N` bytes all equal `N` and that `1 ≤ N ≤ blockSize`, then strips them. Throws on malformed padding (educational: the user should see the failure if they edit ciphertext and break padding). Lives in `src/steps/pkcs7-unpad.ts`.

3. **`generic.load-block@1`** — `(BytesState, { blockSize: 16 }) → MatrixState`. Validates `bytes.length === blockSize`, then constructs the AES column-major 4×4 via the existing `matrixFromBytes` helper. Lives in `src/steps/load-block.ts`.

4. **`generic.store-block@1`** — `(MatrixState, {}) → BytesState`. Inverse of `load-block`: copies the 16 bytes out as a `BytesState`. Lives in `src/steps/store-block.ts`.

Each step's `StepDocumentation.detail` markdown explains the scheme with a worked example, cites the relevant standard (RFC 5652 §6.3 for PKCS#7), and — for the pad/unpad pair — notes the "reusable across block ciphers, not for stream/RSA" generalization so the educational angle is captured in the in-app docs, not just here.

## State-shape rendering: `BytesView`

`MatrixView` is matrix-only; the existing fallback at `src/ui/App.tsx:339` shows `"non-matrix state — view not yet implemented"`. Add a sibling `src/ui/components/BytesView.tsx` that renders a `BytesState` (before/after) as a 1×N row of byte cells using the same color palette and the active byte format. The wrapper in App.tsx dispatches by `frame.stateBefore.shape`:

- both sides `matrix4x4-bytes` → `<MatrixView>` (today's path)
- both sides `bytes` → `<BytesView>` (new)
- mixed shapes (pad's BytesState → load-block's MatrixState transitions) → render two adjacent panels, one BytesView for `stateBefore` and one MatrixView for `stateAfter` (or vice versa for store-block / unpad).

The previous-run overlay (`previousAfter`) on the new mixed-shape boundary is guarded: if the historical run had a different shape at this stepId (e.g., user changed padding scheme between runs), the overlay is suppressed for that frame rather than crashing. This guard is added to `MatrixView` too as a defensive read of `previousAfter?.shape` before use.

The `outputText` memo at `src/ui/App.tsx:169` widens to accept both `matrix4x4-bytes` and `bytes` final-state shapes, extracting `.bytes` from either. `formatBytes` already handles arbitrary length.

## UI: padding scheme selector

A `<select>` slots into the inputs `<section>` (`src/ui/App.tsx:206`) right after the mode select, before the bytes-format fieldset:

```
mode: [encrypt ▾]   padding: [none ▾]   bytes: [hex|dec|ASCII]
```

Options for v1: `none`, `PKCS#7`. (Zero-pad and ISO 7816-4 ship later — leave the select extensible.) The change handler calls `setPaddingScheme(next)` which:

1. Persists to localStorage (via the new `src/ui/stores/padding.ts`).
2. Rebuilds the current spec via a new `applyPaddingScheme(spec, mode, scheme)` helper in `src/core/spec-mutations.ts` — pure, takes spec-in/spec-out, prepends/appends pad+load (or unpad+store) leaves as appropriate, or removes them if scheme is `none`.
3. Writes the new spec into the spec store, which triggers the existing debounced auto-rerun.

When `setMode(next)` runs in `src/ui/stores/spec.ts`, it re-applies the active padding scheme to the freshly-loaded canonical spec so the chain stays symmetric across encrypt↔decrypt switches.

The Run handler in `App.tsx` consults the padding store to pick its parse path: with `none`, today's `parseBytesWithLength(..., 16)` and `matrixFromBytes` flow; with `pkcs7`, a new `parseBytesUpTo(text, fmt, 15)` (or a small `paddingLimits(scheme)` lookup that returns `{min, max, initialState}`) parses to a `BytesState` and seeds `runSpec` with that instead.

## Spec-mutation surface

New helper in `src/core/spec-mutations.ts`:

```ts
applyPaddingScheme(spec: CipherSpec, mode: "encrypt"|"decrypt", scheme: "none"|"pkcs7"): CipherSpec
```

Pure. Strips any existing pad/unpad/load-block/store-block leaves first (so calling it twice is idempotent), then prepends/appends the new ones based on (mode, scheme). The canonical specs in `src/ciphers/aes-128.ts` and `src/ciphers/aes-128-decrypt.ts` are **not modified** — they remain the matrix-direct FIPS-197 form, and the padding chain is layered on top by this helper. This keeps the canonical spec round-trippable against the FIPS-197 test vectors without modification (the vector tests don't go through `applyPaddingScheme`).

`CipherSpec.stateShape` — verify what this field constrains at implementation time. If it documents the *initial* state shape, the helper updates it to `"bytes"` when scheme ≠ `none`. If it's currently unused at runtime, leave it alone and note in the plan that it may need a follow-up.

## Run history / Run Explorer impact

Spec snapshots in `src/ui/stores/history.ts` already capture the full spec, so two runs with different padding schemes will surface as a spec-shape diff. Skim the diff-building code in `history.ts` once before wiring — if it iterates step lists by index, patch it to walk by `stepId` (the canonical way). `run-delta-format.ts` itself consumes a pre-computed `paramsChanged` keyed by stepId and is already robust.

## Tests

New test files under `tests/`:

- **`tests/pkcs7-pad.test.ts`** (node-env) — pad/unpad round-trip across the full input length range 0..15; canonical pad bytes (`apple` → 11×0x0b); malformed-unpad throws (last byte 0, last byte > blockSize, inconsistent trailing bytes); idempotent applyPaddingScheme.
- **`tests/load-store-block.test.ts`** (node-env) — `BytesState(16) → MatrixState → BytesState` round-trips byte-identical; load-block throws on wrong length.
- **`tests/spec-mutations-padding.test.ts`** (node-env) — `applyPaddingScheme` is idempotent, strips before adding, leaves canonical AES spec unchanged when scheme = `none`, produces the right step-id ordering for encrypt vs decrypt.
- **`tests/bytes-view.test.tsx`** (jsdom) — minimal rendering smoke: `BytesView` shows N cells for an N-byte input, format toggle propagates, previous-run overlay no-ops on shape-mismatch.
- **`tests/app-padding-roundtrip.test.tsx`** (jsdom) — **the headline test**: select PKCS#7 in encrypt mode, type `apple` + a 16-byte key, run, assert the trace contains a `pkcs7-pad` frame whose `stateAfter.bytes` ends in `0x0b * 11`, then switch to decrypt mode with the resulting ciphertext, run, assert `outputText()` is `apple`.

Existing tests stay untouched (FIPS-197 vectors test the canonical spec; `applyPaddingScheme` is layered on top).

## Critical files

**Modified:**
- `src/core/spec-mutations.ts` — add `applyPaddingScheme`
- `src/ciphers/default-registry.ts` — register 4 new step types
- `src/ui/App.tsx` — padding selector in inputs row; widen `outputText` memo; route Run through scheme-aware parsing; render dispatch by state shape
- `src/ui/stores/spec.ts` — `setMode` re-applies active padding scheme
- `src/ui/components/MatrixView.tsx` — guard `previousAfter` against shape mismatch

**Added:**
- `src/steps/pkcs7-pad.ts`, `src/steps/pkcs7-unpad.ts`, `src/steps/load-block.ts`, `src/steps/store-block.ts`
- `src/ui/stores/padding.ts`
- `src/ui/components/BytesView.tsx`
- 5 test files listed above

**Not modified** (intentionally): `src/ciphers/aes-128.ts`, `src/ciphers/aes-128-decrypt.ts`, `src/core/runtime.ts`, `src/core/types.ts` (BytesState already exists), `src/core/format.ts`.

## Phasing

**One commit.** Per advisor: splitting "infrastructure (BytesView + load/store-block)" from "padding + UI" would land dead code in commit 1 that doesn't change any user-visible behavior — exactly the kind of churn `CLAUDE.md` warns against. All four step types, the BytesView, the selector, the spec helper, and the headline round-trip test ship together. Subsequent commits cover zero-pad / ISO 7816-4 / multi-block modes as separate features.

## Deferred (explicitly out of scope)

- ~~**Zero-pad and ISO 7816-4 schemes**~~ — ✅ shipped in the follow-up commit. Added as a generic.zero-pad@1 / generic.zero-unpad@1 pair (lossy on trailing zeros — that's the lesson) and a generic.iso7816-4-pad@1 / generic.iso7816-4-unpad@1 pair (0x80 sentinel + zeros). Each pair's `StepDocumentation.detail` calls out the trade-offs vs. the other two schemes so the educational story is captured in-app. Limits: zero-pad accepts 1..16 bytes on encrypt (length 0 excluded because the canonical formula gives N=0 → empty block → fails load-block); iso7816-4 accepts 0..15 like PKCS#7 (always adds ≥1 byte).
- **Multi-block + modes** (ECB / CBC / CTR / GCM) — requires a loop construct in the spec (the current runtime is linear). Listed as a future architecture phase.
- **RSA / stream-cipher padding** — handled when those ciphers are added; the PKCS#7 module is not reused for them.
- **Plaintext on output for *encrypt*** — ciphertext is pseudorandom, ASCII rendering of it would be garbage. The "see plaintext on output" benefit is realized in decrypt mode (which this plan already covers via the unpad step + widened `outputText` memo).

## Verification

1. `npm run check` passes (biome + tsc + vitest + vite build).
2. **FIPS-197 regression**: open the app fresh, padding scheme = `none`, default hex input → ciphertext matches Appendix C.1 byte-for-byte. (The canonical specs are untouched, so this is a sanity check, not a hard test.)
3. **Round-trip headline** (matches the `tests/app-padding-roundtrip.test.tsx` flow but done by hand in the browser):
   - Encrypt mode, scheme = PKCS#7, input = `apple` (ASCII), key = 16 bytes of anything.
   - Run. Scrub the trace — confirm a `pkcs7-pad` frame appears showing `apple` (5 bytes) → `apple\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b` (16 bytes). Confirm a `load-block` frame transitions to the 4×4 matrix. AES rounds proceed as today.
   - Copy the ciphertext hex.
   - Switch mode → decrypt. Paste the ciphertext as input. Confirm the scheme stays PKCS#7 (selector value persists). Run.
   - Confirm the trace ends with a `store-block` frame (matrix → 16 bytes) followed by a `pkcs7-unpad` frame (16 bytes → 5 bytes). Confirm the result row shows `apple`.
4. **Scheme switch mid-session**: with the trace from step 3 visible, flip scheme to `none`. Confirm the trace re-runs with the padding steps removed and a length-mismatch error appears (`apple` is now too short for `none`). Flip back to PKCS#7 — error clears, trace returns.
5. **Run Explorer**: open compare-runs after capturing snapshots with both schemes. Confirm the modal renders both without crashing and the delta legend identifies the spec-shape change.
6. **Format toggle interaction**: in PKCS#7 mode with `apple` typed, flip hex↔dec↔ASCII. Confirm the input field reformats in place and the trace still shows the expected padding bytes in the active format.
