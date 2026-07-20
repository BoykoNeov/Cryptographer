# Honest CTR: partial final blocks, no padding

**Status:** ✅ SHIPPED 2026-07-20 — plan CLOSED
**Supersedes:** the "v1 caveat: whole blocks only" deferral in `src/ciphers/modes/ctr.ts`

## Context

CTR (shipped 2026-07-20) turns a block cipher into a **stream** cipher: it
encrypts a counter to make keystream and XORs that keystream with the message.
Nothing is ever fed *through* the cipher, so a 5-byte message needs exactly 5
keystream bytes and CTR — unlike ECB/CBC — **requires no padding at all**. That
is one of the three headline facts the mode exists to teach.

This build does not honour it. CTR v1 requires a whole-block message and keeps
the padding overlay engaged, so the app currently teaches the opposite of what
its own narration says. Two mechanisms enforce that:

1. `runtime.ts:302` — the port-mode `iterate` throws when `seedInput.length` is
   not a multiple of `blockByteLength`.
2. `xor@1` requires equal-length operands (`src/steps/xor.ts:126-135`), so even
   if a short final block reached the body, the full-width keystream would not
   XOR against it.

**Outcome:** CTR accepts a message of any length ≥ 1, emits ciphertext exactly
as long as the plaintext, and shows the padding selector disabled with an
honest reason. `L < B` — a whole message shorter than one cipher block —
becomes representable for the first time.

## The mechanism is one thing, not two additions

The runtime relaxation and the truncation step are two halves of a single
change, and the coupling is what makes the design work:

- Relaxing the iterate makes the **final `in` block short**.
- So the trim must live **inside the body**, between the keystream and the XOR,
  trimming the *keystream* down to the `in` block's width.
- Trimming the final concatenated output instead would be a different design
  (see Rejected alternatives).

**The cipher body is untouched, and stays cipher-agnostic, because the counter
rides `chain`, not `in`.** `chain` is bootstrapped from `fetch-iv` (one block
wide) and advanced by `increment-counter@1` (width derived from its input), so
it is full-width `B` on every iteration including the last. The core therefore
always encrypts a full counter block and always produces full-width keystream.
Only `in` goes short. No `BlockCipherCore` changes; no per-cipher work.

## Changes

### 1. Runtime — `src/core/types.ts` + `src/core/runtime.ts`

New **optional, additive** field on `IterateNode`, honoured only in the port-mode
branch:

```ts
/** Port mode only. When true, `seedInput` need not be a whole multiple of
 *  `blockByteLength`: the final iteration receives a SHORT `in` block…  */
readonly allowPartialFinalBlock?: boolean;
```

No `schemaVersion` bump — same additive posture as `seedInput` / `chainInput`
(`types.ts:199-205`). Absent ⇒ today's behaviour byte-identically, so ECB and
CBC are provably unaffected. The field is independent of the chain carry.

In `runtime.ts` (~line 302), gate the modulo throw on the flag and switch the
count to `Math.ceil(len / blockLen)`. Two things already work and must be
*confirmed*, not written:

- the per-block slice at line 327 (`subarray(i*B, (i+1)*B)`) **already clamps**,
  so the short last block falls out for free;
- the output concat at 362-368 is length-generic, and the port-mode branch has
  **no per-iteration `bodyOutput` width assertion** (unlike
  `for-each-subgraph`'s at ~970). Verified — do not add one.

Keep a guard: with the flag set, a zero-length `seedInput` still yields zero
iterations, which the App's `min: 1` bound prevents reaching.

### 2. New step type — `src/steps/truncate-to-reference.ts` (`truncate-to-reference@1`)

Port-native, **no params**, width derived from wiring. Two inputs, one output:

| port | role |
|---|---|
| `input` | the full-width keystream block |
| `reference` | the `in` block, whose length is the target |
| `output` | `input[0 .. reference.length]` |

Throws when `reference.length > input.length`. `byte-slice@1` cannot serve —
its `length` is a **param**, and here the length is only known at run time.

`increment-counter@1` is the exact template: same mode, same authoring
conventions, same "the width is not a param, it is the wiring" rationale — and
its file header is the model for the doc prose. **Registration strategy: grep
`increment-counter` across the repo and add a parallel entry at every hit.**
That currently enumerates `src/ciphers/default-registry.ts`,
`src/ui/components/ParamEditor.tsx` (`NO_PARAMS_PORT_NATIVE_TYPES` +
`portNativeNoParamsLabel`), `src/core/port-provenance.ts`, and
`tests/port-provenance-coverage.test.ts`.

Two coverage gates (see `CLAUDE.md` "Things to avoid") must clear:

- **Provenance** — write an **exact** provenance fn (identity prefix: output
  byte `i` ← input byte `i`), not an allowlist entry. It is pedagogically
  load-bearing here: the hover shows precisely which keystream bytes survived.
- **Narration** — write a real `NarrationFn`, not a `NARRATION_NO_OP_ALLOWLIST`
  entry. On a full block it says the block passed through whole; on the ragged
  tail it says *"kept the first N keystream bytes and discarded the other B−N —
  this is why the ciphertext is exactly as long as the plaintext."* That
  sentence is the feature.

### 3. `src/ciphers/modes/ctr.ts`

Insert `ctr-trim` between the keystream body and `ctr-xor`, set the flag, and
rewrite the "v1 caveat" header section into a description of how the ragged
tail actually works:

```ts
const ctrTrim = { id: "ctr-trim", type: "truncate-to-reference@1", params: {},
                  portInputs: { input: keystream.output, reference: blockIn }, … };
// ctr-xor operand1 now reads port(ctr-trim, "output")
// iterateNode gains: allowPartialFinalBlock: true
```

`ctr-increment` is unaffected — it reads `port(it,"chain")`, which is still
full width. Encrypt and decrypt stay structurally identical.

### 4. Disengage padding for CTR — five sites

"No padding" is the point, and it is enforced in more places than the runtime
throw. All five must move together or the feature silently never triggers:

| # | file | change |
|---|---|---|
| 1 | `src/core/runtime.ts:302` | the throw, gated on the new flag (§1) |
| 2 | `src/ui/App.tsx:464` | drop `ctr` from the `needsAlignment` condition |
| 3 | `src/ui/stores/padding.ts:180` | pull `ctr` out of the `ecb`/`cbc` branch into its own: `{ min: 1, max: MAX_BYTES }`, both directions, no alignment |
| 4 | `src/ciphers/block-cipher-core.ts:133` | the `BlockMode.requiresPadding` doc/flag now reads true for CTR — set `false` |
| 5 | **`src/ui/stores/spec.ts:515`** | `buildCanonicalPair` passes `blockBytes` for every mode, so the overlay splices a pad into CTR. Pass `undefined` when `cipherMode === "ctr"` — reusing `overlayApplies`'s existing "no block width ⇒ no overlay" semantics rather than adding a second gate inside `applyPaddingScheme`. |

Site 5 is the one most likely to be missed: if a user-selected pad step still
wraps CTR it re-fills the last block and the partial path never runs.

Plus UI: disable the padding `<select>` when `cipherMode() === "ctr"` with the
tooltip *"CTR is a stream mode — it needs no padding."*, and adjust
`formatLengthError`'s CTR wording.

## Verification

**Oracle.** `node:crypto`'s `aes-128-ctr` handles the ragged tail natively and
is the gold reference for AES. Reuse whatever oracle
`tests/ctr-all-cores-kat.test.ts` already uses for the non-AES cores — do **not**
assume node exposes DES-CTR; fall back to encrypt→decrypt round-trip identity
for those, which is a sound check because CTR decrypt runs the same forward path.

New/changed tests:

- `tests/ctr-partial-block-kat.test.ts` — AES-128 CTR vs `node:crypto` at
  `L % B !== 0`, and at **`L < B`** (the headline case: ciphertext shorter than
  one block, previously unrepresentable). Assert `ciphertext.length === L`.
- Round-trip identity across `L = 1 … 3B+1` for every core in
  `BLOCK_CIPHER_CORES` — the block-size-generic sweep, which is where a stray
  `>= B` assumption would surface (the Speck 4-byte-block lesson).
- `tests/increment-counter.test.ts` sibling for the new step: exact-width
  passthrough, strict prefix, `reference` longer than `input` throws.
- Runtime unit: a port-mode iterate with a non-multiple seed throws **without**
  the flag and yields `ceil` iterations **with** it; ECB/CBC specs unchanged.
- **Existing whole-block CTR KATs** still pass at the output level but now emit
  an extra `ctr-trim:b{i}` frame per block — any frame-ID or frame-count
  assertions in `tests/ctr-all-cores-kat.test.ts` need updating.
- `tests/cipher-mode-fallback.test.ts` (the three-table canary) — no core is
  added, so `BLOCK_CIPHER_CORES` is untouched; confirm it stays green.

**Manual** (`npm run dev`): AES-128 → CTR → enter a 5-byte plaintext → Run.
Expect one block of trace, a visible `ctr-trim` frame whose narration names the
discarded bytes, 5 bytes of ciphertext, the padding selector greyed with its
tooltip. Flip to decrypt, paste the ciphertext back, confirm the plaintext.
Then repeat on Speck32/64 (B=4) with a 6-byte message. Finally spot-check that
ECB and CBC still reject a ragged input with the friendly length error.

**Gate:** `npm run check` (allow >3 min cold — a killed pre-commit hook aborts
the commit and silently leaves everything staged).

## Rejected alternative

**Zero-pad inside the spec, trim the final concatenated output against
`$input`.** Needs no runtime change and no new `core/types.ts` field. Rejected
on pedagogy: it makes a padded plaintext block visibly enter the XOR, which
directly contradicts both the mode's own narration and the reason the feature
exists. The runtime relaxation is the honest depiction.

## Docs to update in the same commit

`CLAUDE.md` (the CTR paragraph's "v1 caveat" sentence and the `paddingLimits`
side-effect note), `CHANGELOG.md`, `docs/gotchas.md` (multi-block/iterate
section — the new flag), `docs/key-files.md` (the new step),
`docs/plans/foamy-prancing-wren.md` (CTR's `requiresPadding` row), and memory
`project_cipher_agnostic_block_modes.md`.

## Critical files

- `src/core/types.ts` — `IterateNode.allowPartialFinalBlock` (**the plan-mode trigger**)
- `src/core/runtime.ts:296-368` — the port-mode iterate branch
- `src/steps/truncate-to-reference.ts` — new; `src/steps/increment-counter.ts` is the template
- `src/ciphers/modes/ctr.ts` — `ctr-trim` + the flag + header rewrite
- `src/ui/stores/spec.ts:507-531` — `buildCanonicalPair`, the overlay gate
- `src/ui/stores/padding.ts:162-207` — `paddingLimits`
- `src/ui/App.tsx:445-475` — length + alignment validation
- `src/ciphers/default-registry.ts`, `src/ui/components/ParamEditor.tsx`,
  `src/core/port-provenance.ts`, `src/ui/narration/index.ts` — the four
  registration gates for the new step type
