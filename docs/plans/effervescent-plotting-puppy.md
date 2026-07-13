# cSHAKE + KMAC (NIST SP 800-185)

## Context

The app ships SHA3-256 + SHAKE128/256 (FIPS 202) as its sponge/Keccak
foundation, explicitly chosen as the honest base for NIST post-quantum work.
**cSHAKE** (the customizable SHAKE) and **KMAC** (the Keccak keyed MAC) are the
next SP 800-185 layer on that base — and the direct precursors NIST's PQC
standards reach for. This plan adds both.

The key insight (advisor-confirmed) that keeps this small: **cSHAKE/KMAC are not
new sponge machinery.** They build a *prefixed* (and for KMAC, *suffixed*)
message string, flip one domain byte, then run the **exact same** absorb fold +
squeeze already shipped. Everything genuinely new lives **upstream** of
`keccak.pad@1 → sponge → squeeze`:

- the SP 800-185 §2.3 byte-string encodings (`encode_string`, `bytepad`,
  `right_encode`), and
- for KMAC, the **first keyed hash** (the `key` input is `byteLength:0` for
  every hash today; the UI hides the key field for the whole hash category).

### Decisions locked (user)
- **Slicing:** cSHAKE first (Slice A), then KMAC (Slice B). One plan, two
  independently-verifiable commits.
- **Customization inputs editable in-app** (cSHAKE `N`/`S`; KMAC key + `S`) via
  structural rebuild, mirroring the existing SHAKE output-length control.
- **Variants:** `cshake128`, `cshake256`, `kmac128`, `kmac256`, **plus**
  `kmacxof128`, `kmacxof256` (the arbitrary-length MAC, `right_encode(0)`).

## The byte constructions (SP 800-185) — with the footguns baked in

Rates unchanged: 128-variants **168** bytes, 256-variants **136**.

**`encode_string(S)` = `left_encode(8·len(S)) || S`** — the length is in **BITS**
(`8·len`). This is the single most common cSHAKE/KMAC bug; it passes every
structural check and silently produces a wrong digest. `left_encode(x)` =
`byte(n) || x` big-endian in `n` bytes (`n` = min bytes to hold `x`, ≥1);
`right_encode(x)` = the same with the length byte **last**. `bytepad(X, w)` =
`left_encode(w) || X`, zero-padded to a multiple of `w` bytes (`w` = rate in
**bytes**). Sanity anchors: `left_encode(0)=01 00`, `right_encode(0)=00 01`,
`encode_string("")=01 00`, `left_encode(168)=01 A8`, `right_encode(256)=01 00 02`.

**cSHAKE128(X, L, N, S):**
- If `N=="" && S==""` → **≡ SHAKE128(X, L)**, domain `0x1F`. The cSHAKE builder
  **delegates to `buildShakeSpec`** in this case (correct by construction).
- Else → `KECCAK[cap]( bytepad(encode_string(N) || encode_string(S), rate) || X, 00…, L )`
  with the `00` two-bit domain suffix ⇒ **`keccak.pad@1` domain byte `0x04`**
  (merge case `0x84`). The pad step is *already* generic over `domainByte` — no
  new pad step.

**KMAC128(K, X, L, S)** `= cSHAKE128(newX, L, "KMAC", S)` where
`newX = bytepad(encode_string(K), rate) || X || right_encode(L)`:
- `N` is the **fixed** ASCII `"KMAC"` (4B `4B 4D 41 43`) for *both* 128 and 256 —
  never user-editable. Only `S` is user customization (so domain is always
  `0x04`; no SHAKE fallback branch).
- `L` in `right_encode(L)` is the output length **in bits** (`outputBytes·8`).
- **KMACXOF** = identical pipeline but `right_encode(0)` instead of
  `right_encode(L)`.
- **KMAC breaks prefix-stability** (L is bound into the input) — KMAC@32 is *not*
  a prefix of KMAC@64. Each output length must be verified independently.

## Design — three new steps, everything else reused

### New step types (`src/steps/`, registered in `default-registry.ts`)
All port-native (`kind:"ported"`, no `legacy`/`meta`/`shapeContract`), raw-layout
ports (variable byteLength, computed at runtime from the actual input):

1. **`encode-string@1`** (SP 800-185 §2.3.2) — one input `input`, output
   `left_encode(8·len(input)) || input`. Computes the bit-length at runtime, so it
   is robust to any input length. Used for `N`, `S`, and the KMAC key.
2. **`bytepad@1`** (§2.3.3) — param `w` (block bytes), input `input`, output
   `left_encode(w) || input` zero-padded up to a multiple of `w`.
3. **`right-encode@1`** (§2.3.1) — param `value` (non-negative integer), zero
   inputs, output `right_encode(value)`. A param'd constant emitter so the
   builder can pass `outputBytes·8` (KMAC) or `0` (KMACXOF), keeping the
   "this binds the output length into the tag" relationship visible + editable.

`left_encode` needs no standalone step — it appears only *inside* `encode-string`
and `bytepad`.

### Reused unchanged
`constant-load@1` (raw `N`/`S` literals — `params.bytes`), `aux-load-bytes@1`
(the KMAC key from `aux["key"]`, and `S0` init state), `concat@1`,
`keccak.pad@1` (domain `0x04`/`0x84`), and the whole downstream sponge:
`buildAbsorbSteps`, `buildKeccakRounds`, `buildKeccakPermGroup`, and the squeeze
unroll — all family-neutral in `keccak-f.ts` / `shake.ts`.

**Small refactor (provably-inert):** the sponge-absorb-`iterate` + unrolled
squeeze currently live inside `buildShakeSpec` (`shake.ts`). Extract them into a
shared `buildSpongeSqueeze(rate, outputLength, padOutputPort, narration)` helper
(new `src/ciphers/sponge.ts`, or exported from `shake.ts`) so cSHAKE/KMAC reuse
the identical tail. **Guard with a `JSON.stringify` byte-diff** of
`buildShakeSpec(...)` before/after (per the SHAKE-refactor lesson: a re-run KAT
checks the digest, not step ids/params/narration → layout-pin + URL-hash drift
would pass silently).

### Spec pipelines (per builder)

**cSHAKE** (`src/ciphers/cshake.ts`, non-empty case):
```
constant-load N ─┐                         constant-load S ─┐
                 encode-string ─┐                           encode-string ─┐
                                concat(2) → bytepad(w=rate) → prefix ─┐
                                             plaintext X ─────────────┤
                                                          concat(2) = prefix‖X
                                                          → keccak.pad(0x04)
                                                          → sponge → squeeze
```
Empty `N` && empty `S` → `return buildShakeSpec(variant, L)`.

**KMAC / KMACXOF** (`src/ciphers/kmac.ts`):
```
constant-load "KMAC" → encode-string ─┐
constant-load S      → encode-string ─┤ concat(2) → bytepad(w=rate) → cShakePrefix ─┐
aux-load-bytes "key" → encode-string → bytepad(w=rate) → keyBlock ──────────────────┤
plaintext X ────────────────────────────────────────────────────────────────────── ┤
right-encode(value = XOF? 0 : L·8) ──────────────────────────────────────────────── ┤
                                            concat(4) = cShakePrefix‖keyBlock‖X‖rightEnc
                                            → keccak.pad(0x04) → sponge → squeeze
```

Every leaf carries a `narrationOverride: StepDocumentation` with the SP 800-185
prose (rate/domain/bit-length specifics — parameterized per variant, per the
SHAKE lesson that hardcoding "136" on a 168-rate is an unguarded defect).

## Store + UI wiring

### `src/ui/stores/cipher.ts` (the hash "tables" — SHA3 lesson)
Extend `Hash` union + `isHash` + `ALL_HASHES`/`HASH_OPTIONS` + `HASH_LABELS` +
description/origin blurbs + `DEFAULT_KEY_BYTES_BY_HASH` + `DEFAULT_PT_BYTES_BY_HASH`
with the six new ids. Hashes are mode-less ⇒ **no `cipher-mode.ts` change**.
`DEFAULT_KEY_BYTES_BY_HASH` gets its first **non-empty** entries (KMAC — the
NIST 32-byte sample key); cSHAKE/KMACXOF stay empty/sample as appropriate.

### `src/core/document-schema.ts`
Add the six ids to `HASH_IDS` (the compile-time `MissingHash` assertion catches
an omission at `tsc`).

### `src/ui/stores/spec.ts` (build-on-demand, like SHAKE)
- New signals mirroring `shakeOutputLength`: `cshakeN`, `cshakeS`, `kmacS`
  (customization strings) — plus `kmacKeyLength` if we make key length editable
  (see Open question). Setters do a **structural rebuild** through the same
  `withBoundaryReset` / `setSpecs(buildCanonicalHash(...))` path.
- `resolveHashDefault(hash)` branches: cSHAKE/KMAC/KMACXOF built **on demand** at
  the current signal values (SHA-256/SHA3 stay static in `hashDefaults`; SHAKE
  already on-demand).

### `src/ui/App.tsx`
- **Key field gate:** change the key-field `<Show when={isCipher(algorithm())}>`
  (App.tsx:1573) to `<Show when={activeSpecConsumesKey()}>` where that reads
  `spec().inputs.key.byteLength > 0`. Equivalent to `isCipher` today (all ciphers
  keyed, all hashes keyless) and naturally lights up for KMAC — the honest test
  is "does the spec consume a key," not "is it a cipher."
- **Customization panel:** a `<Show>` block (active hash ∈ cSHAKE/KMAC family)
  with text inputs for the editable strings (ASCII → UTF-8 bytes), committing on
  change via structural rebuild (reuse `changeShakeOutputLength`'s
  `withBoundaryReset` shape). The existing SHAKE output-length stepper is reused
  as-is (all six variants are variable-length). KMAC's `N` is shown read-only
  ("KMAC"); KMACXOF shows the `right_encode(0)` note.

### ParamEditor + narration (per `src/steps/CLAUDE.md` checklist)
- `src/ui/components/ParamEditor.tsx`: read-only scalar blocks for the three new
  step types (`bytepad` `w`, `right-encode` `value`; `encode-string` has no
  params) — avoid the raw-JSON fallback.
- Narration: add per-frame `NarrationFn`s (or allowlist entries) for
  `encode-string@1` / `bytepad@1` / `right-encode@1` so
  `tests/narration-registry-contract.test.ts` stays green; and a
  `port-provenance-coverage` allowlist entry + set-pin bump for the bare-name
  steps (per the SHA3 `rotate-lanes@1` precedent).

## Verification — **highest risk: no `node:crypto` oracle**

`node:crypto` has `shake128/256` but **NOT** cSHAKE or KMAC. Per
`feedback_crypto_verification`, pin the first KAT against an external reference
**before** writing any test:
1. **NIST SP 800-185 official example-value docs** (gold standard — cSHAKE
   Samples, KMAC Samples incl. the XOF variants).
2. **pycryptodome** (`Crypto.Hash.cSHAKE128/256`, `KMAC128/256`) as an
   independent implementation.

Build a scratch JS reference of the whole `encode → prefix (→ keyBlock →
rightEncode) → pad → sponge → squeeze` chain in
`M:\claud_projects\temp\cshake-kmac-ref\`, check it against **both** sources,
*then* decompose into steps.

Then:
- `tests/cshake-kat.test.ts` / `tests/kmac-kat.test.ts` — full spec through the
  real runtime, byte-equal to the pinned vectors; **sweep message length AND
  output length**, and for KMAC assert **each output length independently** (no
  prefix-stability). Include the empty-`N`-and-`S` ⇒ SHAKE-equivalence check.
- `tests/sp800-185-encodings.test.ts` — per-step `encode-string`/`bytepad`/
  `right-encode` against the §2.3 formulas incl. edge cases (empty string, the
  bit-vs-byte length, `bytepad` already-a-multiple).
- **Inertness byte-diff** for the `buildShakeSpec` refactor.
- Browser smoke (`npm run dev`): correct cSHAKE + KMAC digests vs the pinned
  vectors; clean default-collapsed graph; the customization panel rebuilds on
  edit; the key field appears for KMAC and drives the tag.

Gate: `npm run check`. Docs (README "What's in the box", CHANGELOG, gotchas) +
memory updated in the shipping commits.

## Open question (call during Slice B, not blocking Slice A)
KMAC **key length** editability. v1 leans: editable key **bytes** via the key
field (default = NIST 32-byte sample) at a spec-declared `inputs.key.byteLength`;
variable key *length* is the same structural-rebuild mechanism as output length
but adds a control — include it if cheap, else defer with a note. `encode-string`
computes the key's bit-length at runtime, so a fixed declared length is only a
validation choice, not a correctness one.

## Files (representative)
- New: `src/steps/encode-string.ts`, `src/steps/bytepad.ts`,
  `src/steps/right-encode.ts`; `src/ciphers/cshake.ts`, `src/ciphers/kmac.ts`;
  (opt) `src/ciphers/sponge.ts`.
- Edit: `src/ciphers/default-registry.ts`, `src/ciphers/shake.ts` (extract
  shared tail), `src/core/document-schema.ts`, `src/ui/stores/cipher.ts`,
  `src/ui/stores/spec.ts`, `src/ui/App.tsx`, `src/ui/components/ParamEditor.tsx`,
  narration + provenance-coverage registries.
- Tests: `tests/sp800-185-encodings.test.ts`, `tests/cshake-kat.test.ts`,
  `tests/kmac-kat.test.ts`, plus the shake-refactor inertness diff.
