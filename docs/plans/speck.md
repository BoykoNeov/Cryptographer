# Speck32/64 — second cipher

A first non-AES cipher, to validate the spec-as-data architecture beyond a single
algorithm family.

## Context

**Why this cipher first.** Speck32/64 was chosen over the larger Speck variants,
ChaCha20, or RSA because:

- It's an **ARX** cipher (Add-Rotate-XOR). Zero overlap with AES's S-box +
  GF(2^8) machinery. If our generic step infrastructure can host both, the
  "spec is data, not code" claim has teeth.
- The block is 4 bytes, the state is two 16-bit words, the key is 8 bytes,
  22 rounds. Small enough to fit a single-step round in the trace clearly —
  one round per frame, no nested groups needed.
- A published KAT exists (Beaulieu et al. 2013, Table 4.1) so correctness is
  pinnable on day one.
- It avoids changing `core/types.ts`. We re-use `BytesState` with length 4;
  the two-word interpretation lives entirely inside the round executor.
  Per CLAUDE.md, new state shapes are a mandatory-planning load-bearing
  change we'd rather defer.

**Why only one Speck variant (with two byte-order specs).** AES grew
variant-by-variant (128 → 192 → 256, each in its own commit) and each step
found bugs in the previous one. Speck has ten declared variants
(Speck32/64 through Speck128/256); ship the smallest first, settle the
integration story, leave the rest as follow-ups.

Per the user's clarification, **both byte-ordering conventions ship as
selectable cipher options in the dropdown** rather than as a separate
toggle. Two specs (`speck-32-64-be` paper-faithful, `speck-32-64-le`
NSA-reference) sit alongside the AES entries. The step code is shared;
only the per-leaf `byteOrder` param differs, which is pedagogically
strong: same cipher, same words computed, different byte serialization
visible side-by-side in the trace. The cipher dropdown grows by two
entries (BE + LE), four specs total (encrypt + decrypt for each).

**Scope of the change.** This is *not* a refactor of the AES code. The AES
specs, step types, tests, and UI all stay untouched. The work breaks down as
~30% new step files (round + key-schedule + spec + decrypt-spec), ~30% UI
integration (`Cipher` union, `DEFAULT_*` tables, `paddingLimits`, the App's
initial-state seeding), ~40% tests (KAT, round-trip, a structural-modularity
test, an end-to-end cipher-selector test).

## Approach

### Byte-ordering — two conventions, both shipped

The Beaulieu et al. paper gives **word-level** test vectors. Two
byte-serialization conventions are popular and pedagogically interesting:

**BE-paper** (big-endian within word, `l_{m-2}` … `k_0` in memory):

- Key bytes left-to-right = words in `(l_{m-2}, …, l_0, k_0)` order, each
  word big-endian. For Speck32/64 (m=4): bytes 0..1 are `l_2`, bytes 2..3
  are `l_1`, bytes 4..5 are `l_0`, bytes 6..7 are `k_0`.
- Plaintext bytes left-to-right = (x, y), each word big-endian.
- Paper-faithful: user pastes hex `1918111009080100` for the key and
  `6574694c` for the plaintext and sees the same hex digits the paper
  prints (`Key: 1918 1110 0908 0100`).

**LE-NSA** (little-endian within word, `k_0` … `l_{m-2}` in memory):

- Key bytes left-to-right = words in `(k_0, l_0, …, l_{m-2})` order, each
  word little-endian. Same example: bytes 0..1 are `k_0` low-byte-first.
- Plaintext bytes left-to-right = (y, x), each word little-endian.
- Matches NSA reference implementation / SUPERCOP convention.

KAT (Speck32/64, Beaulieu et al. 2013 Table 4.1, identical word-level):

| Variant   | Key bytes          | Plaintext bytes | Ciphertext bytes |
|-----------|--------------------|-----------------|------------------|
| BE-paper  | `1918111009080100` | `6574694c`      | `a86842f2`       |
| LE-NSA    | `0001080910111819` | `4c697465`      | `f24268a8`       |

Both variants compute the *same* word-level KAT
(`(x,y)=(0x6574,0x694c) → (0xa868,0x42f2)`); they differ only in how
those words are laid out as bytes. The verification script proved this
before the plan was finalized.

The `byteOrder` param lives on each Speck step type. The cipher dropdown
exposes both ("Speck 32/64 (BE, paper)" and "Speck 32/64 (LE, NSA)") so
users can flip and compare. The DEFAULT_KEY/PT tables carry both
convention's bytes so the canonical KAT plaintext lands on the input
field for each variant.

### New step types (two)

`speck.key-schedule@1` — params `{ keyAuxName, outputPrefix, rounds, wordBits,
m, alpha, beta, byteOrder }`. Reads the key from `aux[keyAuxName]` as
`2*m` bytes, decodes per `byteOrder` into `m` words, runs the iterative
schedule, and writes `outputPrefix.0` … `outputPrefix.rounds-1` to aux as
**`Uint8Array(wordBits/8)`** (the round-key word in the SAME `byteOrder`
encoding, so the round step decodes consistently). State unchanged.

`speck.round@1` — params `{ roundKeyAux, alpha, beta, wordBits, byteOrder }`.
Decodes state bytes per `byteOrder` into two words, reads
`aux[roundKeyAux]` as one word (same encoding), applies the ARX round,
re-encodes the new two-word state back to bytes per the same convention.

`speck.round-inverse@1` — same params, inverse math (ROR/ROL swapped,
modular subtraction). Reads keys in the SAME way as the forward round; the
decrypt spec orders the leaves so the round keys are consumed in reverse
(`roundKey.21` first, `roundKey.0` last). Mirrors the AES decrypt-spec
pattern where `aes.key-expansion@1` is shared verbatim and the decryption
ordering lives in the spec leaves.

The shared `byteOrder` param across all three step types is **the** way
the spec encodes the convention. Two cipher specs differ ONLY by this
param value; the step code is identical.

Both round step types share the same `wordBits / alpha / beta` params so
*one* Speck64/128 follow-up will only need to change those numbers and the
round count — no executor changes.

### New cipher specs (four total — encrypt × decrypt × BE × LE)

- `src/ciphers/speck-32-64-be.ts` — forward, BE-paper.
- `src/ciphers/speck-32-64-be-decrypt.ts` — inverse, BE-paper.
- `src/ciphers/speck-32-64-le.ts` — forward, LE-NSA.
- `src/ciphers/speck-32-64-le-decrypt.ts` — inverse, LE-NSA.

A shared builder (`src/ciphers/speck-32-64-builder.ts`) exports a function
`buildSpeck32_64Spec(byteOrder, direction)` that emits the spec; the four
files call it with their corresponding `(byteOrder, direction)` pair. This
keeps the four specs from drifting and signals that they're four
instances of one cipher, not four ciphers.

Top-level leaves (no per-round group wrapper — each round is one step,
so the extra nesting would just add UI noise). The forward spec:

```
key-schedule              (writes roundKey.0..21)
round.1   (uses roundKey.0)
round.2   (uses roundKey.1)
…
round.22  (uses roundKey.21)
```

The decrypt spec runs the same `key-schedule`, then `round-inverse.1` using
`roundKey.21`, down to `round-inverse.22` using `roundKey.0`.

### UI / store integration

The following AES-shaped assumptions become parametric:

1. **`stores/cipher.ts::Cipher`** — union grows to include `"speck-32-64-be"`
   and `"speck-32-64-le"`. Labels: `"Speck 32/64 (BE, paper)"` and
   `"Speck 32/64 (LE, NSA)"`. `DEFAULT_KEY_BYTES_BY_CIPHER` gains two
   8-byte entries with the per-convention KAT key bytes
   (`1918111009080100` for BE, `0001080910111819` for LE).
2. **NEW `DEFAULT_PT_BYTES_BY_CIPHER`** (mirror of the key map). AES gets
   the 16-byte FIPS vector; Speck-BE gets `6574694c`; Speck-LE gets
   `4c697465`. Replaces the single `DEFAULT_PT_BYTES` constant currently
   hardcoded in `App.tsx`. `DEFAULT_SHORT_PT_BYTES` ("apple") stays as the
   pkcs7/iso7816-4 fallback for AES — Speck doesn't need a short variant
   since its block is already 4.
3. **`stores/spec.ts::defaults`** — gains two rows: `"speck-32-64-be"` and
   `"speck-32-64-le"`, each mapping `encrypt → <var>Spec`,
   `decrypt → <var>DecryptSpec`.
4. **`stores/padding.ts::paddingLimits`** — currently keyed on `(mode,
   scheme)` only. The signature stays but the caller passes the *active
   spec*; the helper reads `spec.inputs.plaintext.shape` and the block size
   to decide the range. For Speck (block 4, no padding) it returns
   `{min:4, max:4}`.
5. **`core/spec-mutations.ts::applyPaddingScheme`** — early-return
   `{ ...spec, steps: stripped }` (and keep the spec's own `stateShape` /
   `inputs`) whenever `spec.stateShape !== "matrix4x4-bytes"`. The AES
   overlay's `load-block` step is hardcoded for blockSize=16, so silently
   skipping for non-AES specs is correct and idempotent. The padding store
   keeps the user's preference; switching back to AES re-applies it.
6. **`App.tsx`** — three call sites change:
   - Initial-state seeding (`mode === "encrypt" && padding !== "none"`) is
     replaced with `spec.inputs.plaintext.shape === "bytes"`. The padding
     check was a proxy for "use BytesState"; the spec's own input shape is
     the source of truth.
   - `DEFAULT_PT_BYTES` → `DEFAULT_PT_BYTES_BY_CIPHER[cipher()]`.
   - `changeCipher` swaps both the key field **and** the plaintext field
     when they hold the *previous cipher's* known defaults (mirrors
     `changePadding`'s "only clobber if it's a canonical default" policy).
7. **`App.tsx` padding UI** — the padding `<select>` becomes `disabled` when
   the active cipher's `stateShape !== "matrix4x4-bytes"`, with a `title`
   tooltip explaining "padding is AES-only in this build." Future block
   ciphers wanting padding will need block-size-aware `load-block` / `store
   -block` (out of scope for this commit).

The encrypted+decrypted round trip and the "swap a value, watch the trace
update" UX continue to work for Speck unchanged — the runtime, trace store,
history store, step description, and param editor are all step-type-driven
and pick the new step types up by their registry keys.

### ParamEditor

Both new step types fall back to the raw-JSON view by default. That's a
known un-shipped state per CLAUDE.md (`src/steps/CLAUDE.md`). To meet the
"new step types ship with a ParamEditor block" rule we add:

- `SpeckRoundBlock` — small `<dl>` showing `roundKeyAux`, `alpha`, `beta`,
  `wordBits` as read-only scalars. None of these are user-tunable in a
  pedagogically useful way: alpha/beta are cipher-defining; `roundKeyAux`
  pins the leaf to a specific round; `wordBits` is a state-shape parameter.
  Same shape as the existing `AddRoundKeyBlock`.
- `SpeckKeyScheduleBlock` — `<dl>` with `keyAuxName`, `outputPrefix`,
  `rounds`, `m`, `wordBits`, `alpha`, `beta`. Same shape as
  `KeyExpansionBlock`.
- `BLOCK_SIZE_PARAM_TYPES` already-existing extension point in ParamEditor:
  Speck's steps don't use `blockSize`, so they get their own `Match` arms.

These are intentionally minimal — the modularity-demo headline for Speck is
"swap an unrelated cipher in alongside AES," not "tune Speck's S-box" (Speck
has no S-box). Future versions could add an `alpha`/`beta` slider as a
playground feature.

### Tests

- `tests/speck-32-64-vectors.test.ts` — node env. Three assertions:
  1. The KAT: encrypt `6574694c` under the KAT key, expect `a86842f2`.
  2. All 22 round keys exist in aux with the right length.
  3. A frame is emitted for every leaf — 23 total (1 key-schedule + 22 rounds).
- `tests/speck-32-64-decrypt.test.ts` — node env. Two assertions:
  1. Decrypt `a86842f2` under the KAT key, expect `6574694c`.
  2. Round-trip: encrypt(decrypt(arbitrary)) == arbitrary, over a handful
     of random 4-byte inputs.
- Extend `tests/app-cipher-selector.test.tsx` — jsdom. A fourth selector
  option ("Speck 32/64") drives the App through the dropdown and asserts
  the end-to-end ciphertext on the displayed output.
- `tests/spec-mutations-padding.test.ts` — add one assertion:
  `applyPaddingScheme` on a non-matrix4x4-bytes spec is a no-op (returns
  the spec with overlay leaves stripped but no AES overlay inserted).

No new tests are needed for the step-doc registration: the existing
"runtime throws on unknown step type" surface gives loud feedback if a
spec ships before its types are registered.

### Commit shape

Two commits to keep blast radius reviewable:

1. **Speck32/64 step types + spec + KAT/round-trip tests.** The cipher
   itself, with executors, docs, ParamEditor blocks, and node-env tests.
   No UI integration yet — the spec is registered but no `Cipher` union
   entry exists, so the user can't reach it through the dropdown.
2. **Wire Speck into the cipher selector.** `Cipher` union, `DEFAULT_*`
   tables, `App.tsx` plaintext default + initial-state-shape logic,
   padding selector disabling, `applyPaddingScheme` non-AES guard,
   `paddingLimits` spec-aware refactor, jsdom selector test.

If the first commit's tests all pass, the second is mechanical and small.
If they fail, the second commit doesn't ship.

## Critical files

**New:**

- `src/steps/speck-round.ts`
- `src/steps/speck-round-inverse.ts`
- `src/steps/speck-key-schedule.ts`
- `src/steps/speck-word-codec.ts` — shared BE/LE encode/decode helper.
- `src/ciphers/speck-32-64-builder.ts` — shared spec factory.
- `src/ciphers/speck-32-64-be.ts`
- `src/ciphers/speck-32-64-be-decrypt.ts`
- `src/ciphers/speck-32-64-le.ts`
- `src/ciphers/speck-32-64-le-decrypt.ts`
- `tests/speck-32-64-vectors.test.ts` — covers both BE and LE.
- `tests/speck-32-64-decrypt.test.ts` — covers both BE and LE round-trips.

**Modified (registration / wiring):**

- `src/ciphers/default-registry.ts` — register the three new step types.
- `src/ui/stores/cipher.ts` — extend `Cipher` union + labels + default key.
- `src/ui/stores/spec.ts` — add Speck row to `defaults`.
- `src/ui/stores/padding.ts` — `paddingLimits` becomes spec-aware.
- `src/core/spec-mutations.ts` — `applyPaddingScheme` non-AES early return.
- `src/ui/App.tsx` — plaintext default per cipher, initial-state shape
  from spec, `changeCipher` swaps plaintext too, padding-select disabled
  for non-AES.
- `src/ui/components/ParamEditor.tsx` — two new `Match` arms.

**Modified (tests):**

- `tests/app-cipher-selector.test.tsx` — fourth option.
- `tests/spec-mutations-padding.test.ts` — non-AES no-op assertion.

## Out of scope

- **Other Speck variants** (Speck64/128, Speck128/128, etc.). Trivial
  extension once Speck32/64 is in; deferred to its own commit so the
  diff stays clean.
- **Padding for non-AES block ciphers.** Requires a block-size-aware
  `load-block` / `store-block` rework. Not blocking; AES users still get
  the full padding chain.
- **Speck-specific visualizations** (two-word labeled view). BytesView
  renders the 4-byte block as four hex cells, which is correct and
  readable for a first cut.
- **Binary export / codegen.** The architecture supports it; this
  commit doesn't exercise it.

## Pitfalls flagged for this work

- **Don't add a "two-word" state shape.** BytesState(4) is enough; the
  word interpretation lives in the executor. CLAUDE.md flags `core/types.ts`
  changes as mandatory-planning load-bearing — we don't need it.
- **Modular addition is `(a + b) & 0xffff` for 16-bit words.** Don't use
  full 32-bit JS addition without masking; the rotation operators rely on
  the value being in `[0, 0xffff]`.
- **Rotations on a 16-bit word: shift mask is `(16 - n)`, not `(32 - n)`.**
  `ROR16(x, n) = ((x >>> n) | (x << (16 - n))) & 0xffff`. The mask is
  load-bearing because JS bitwise ops are 32-bit.
- **The decrypt round consumes keys in REVERSE.** The math is asymmetric
  (the encrypt round XORs `k_i` after the add; decrypt XORs it before the
  subtract). Round keys themselves are produced in forward order by the
  same `key-schedule` step; only the leaf ordering in the spec changes.
- **`applyPaddingScheme` must keep the original `inputs.plaintext.shape`
  on non-AES specs.** The AES overlay overwrites `inputs.plaintext.shape`;
  for Speck we need it to stay `"bytes"`.
- **The `changeCipher` swap policy is "only clobber if it's a canonical
  default."** When swapping AES→Speck, an AES 16-byte FIPS vector should
  be replaced by the Speck 4-byte KAT plaintext, but a user-typed
  arbitrary value should be left alone (they'll see a friendly length
  error on the next Run). Mirrors `changePadding`.
