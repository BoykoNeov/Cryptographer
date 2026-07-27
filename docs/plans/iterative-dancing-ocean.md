# Pseudo-random generators — a fourth algorithm family

**Status:** **P1 SHIPPED 2026-07-27** (family surface + MINSTD ×2).
**P2 SHIPPED 2026-07-27** (ANSI C LCG + `add-mod@1`). P3 in scope and not
started; P4 (MT19937) deferred to its own decision.

### P2 shipped — what changed against the plan

1. **`add-mod@1` has NO params, so it needed the `NO_PARAMS_PORT_NATIVE_TYPES`
   entry the plan explicitly said it would not.** The plan reasoned "both new
   leaves have params, so the no-params set is not involved" while its own
   signature for the step was `add-mod@1 { }` — and the shipped `mod-mul@1` it
   is templated on takes `params: {}`. Without the entry it drops to the
   raw-JSON fallback and renders `{}`, which is what `mod-mul@1` does today.
   (That sibling was left alone: fixing it changes RSA's editor, a different
   feature's defect.)
2. **`isPrng` became membership over `ALL_PRNGS` rather than gaining a third
   `===` arm.** The `isCipher` landmine the plan documented as a per-*family*
   hazard is re-armed by every new *variant*: a forgotten arm makes `isPrng`
   false, `isCipher` true, and the compiler believes it. Reading the same list
   the dropdown reads removes the drift permanently.
3. **The plan's five ANSI-C reference states were correct, and a stronger
   second anchor came free.** Dividing them by 65536 mod 32768 gives
   `16838, 5758, 10113, 17515, 31051` — the published opening of C's `rand()`.
   Both sequences are pinned, and the second is derived from the runtime's
   output so it cannot degenerate into a tautology if the app's emitted value
   ever changes.
4. **A byte-identity hash pin on the MINSTD specs was added, which the plan only
   prescribed for P3's ChaCha20 export.** The same hazard applies here: spec-only
   saves feed the URL-share hash, so reflowing one narration sentence while
   generalizing the builder would repoint every previously shared MINSTD link
   without changing a byte of output. Digests were taken from the shipped P1
   builder before the refactor.
5. **Emitting the raw state rather than C's top-15-bit extraction was a real
   decision, not an omission.** The extraction is C's workaround for the low-bit
   weakness; performing it would hide the defect the variant exists to show. The
   cost is a prose obligation — the `emit` narration states the relationship and
   prints both sequences — and the plan did not anticipate it.

### P1 shipped — what changed against the plan

Two things the plan got wrong, both corrected in the code and worth carrying
forward:

1. **P1 ships TWO generators, not one.** MINSTD's two published multipliers are
   the same builder with a different constant, so `minstd_rand` came free with
   `minstd_rand0` — and both carry an ISO conformance value, so the anchor
   doubled for nothing. The plan's "one generator keeps the diff focused"
   reasoning was about the *builder*, not the variant count.
2. **The `chainFeedback` untrimmed-vs-trimmed choice is byte-indistinguishable
   here, not load-bearing.** The plan (and the advisor pass behind it) treated a
   trimmed feedback as a live bug that a non-multiple output length would expose.
   It would not: only the FINAL block is ever short, and the final iteration's
   feedback is discarded. This is precisely OFB's situation. The wiring is still
   untrimmed — the recurrence is defined on whole words and the trace should say
   so — but the KAT now *perturbs the binding and asserts the streams match*,
   rather than asserting a failure mode that does not exist.

Also shipped beyond the plan's list: the graph's endpoint pills
(`GraphView.tsx`'s `endpointLabels`) needed a PRNG arm — **found by browser
smoke, not by any test**, since nothing in the type system objects to a wrong
string. `App.tsx`'s mode-toggle gate was rephrased from `!isHash(...)` to a
positive `hasDirection()` so the next direction-less family is one arm rather
than a third negation. `tests/app-rsa.test.tsx` pins the exact category-option
list and correctly failed on the new entry.

## Context

The app explores three families today — `cipher` (13 variants), `hash` (10), and
`asymmetric` (RSA). The user asked for **pseudo-random generators to be included
and explorable**. PRNGs are the missing third leg of applied symmetric
cryptography: every cipher in the app consumes randomness it does not itself
produce, and "where do the random bytes come from, and how badly can that go
wrong" is a first-class teaching subject that the current app cannot show at all.

The intended outcome is a fourth `Category` reachable from the algorithm
selector, whose specs run through the same runtime, produce the same
`TraceFrame`s, and are explorable with the same linear view, graph view, and
param editors as every other algorithm. **No new viewer, no new state shape, no
runtime change.**

The pedagogical centre is the LCG. Because its multiplier `a`, increment `c`, and
modulus `m` are ordinary `constant-load@1` params, the user can edit them in
place and watch the generator degrade in the trace — set `a` to an even number
and the low bits go constant within a few words. That experiment is the answer to
"explorable"; it needs no visualization work, only the affordances the app
already has.

### Decisions already taken (user, 2026-07-27)

- **v1 generators:** LCG family — MINSTD (Lehmer) + the ANSI-C / `rand_r` LCG.
- **Plus one CSPRNG:** ChaCha20-based, reusing the shipped ChaCha20 machinery.
- **MT19937:** deferred to its own phase, depth decided against a working app.
- **Out of scope:** xorshift, PCG32, randomness-quality visualizations (spectral
  test, bit-plane plots). "Explorable" is already satisfied by trace + graph +
  param editing; quality tooling is a separate plan if wanted.

## The shape: a fourth family, hash-shaped

A PRNG has **no encrypt/decrypt direction**, so it copies `HashSpecsByMode`, not
the cipher shape:

```ts
type PrngSpecsByMode = { readonly kind: "prng"; readonly prng: Prng; readonly single: CipherSpec };
```

**Explicitly rejected: modelling PRNGs as `Cipher`s with `cipherMode: "stream"`.**
Tempting, because ChaCha20-as-CSPRNG *is* the existing keystream path. But a PRNG
has no message input, and `isCipher`-true would drag in
`SUPPORTED_CIPHER_MODES_BY_CIPHER`, `defaultCipherModeFor`, `paddingLimits` and
`ivByteLengthFor` — precisely the surface a fourth category costs zero on.

**Seed → `inputs.plaintext`; `inputs.key.byteLength = 0`.** Both existing
direction-less/keyless families (hash, RSA) put the variable-length user input in
`plaintext` and zero the key, and the App hides the key field on that basis. The
input field is relabelled "seed", the output "random bytes".

**Output length → a sibling of the SHAKE mechanism**, not a reuse of it.
`shakeOutputLength` (`stores/spec.ts:345`) is hash-keyed and clamped by
`MAX_SHAKE_OUTPUT`. A `prngOutputLength` signal + `setPrngOutputLength` copies
`setShakeOutputLength` (`spec.ts:849`) verbatim — including that it is a
**structural rebuild** (`setSpecs(buildCanonicalPrng(...))`), because the length
changes the spec's contents, which `editStepParams` cannot express. It needs a
`readPrngOutputLength(spec)` counterpart modelled on `readShakeOutputLength`
(`ciphers/shake.ts:244`), or document round-trip silently loses the length.

## How a generator runs N times — the spine

Verified against `core/runtime.ts:268-390`: the shipped port-mode `iterate`
already does everything needed, with **no runtime change**.

- `seedInput` length ÷ `blockByteLength` is what sets the iteration count.
- `allowPartialFinalBlock: true` → `Math.ceil`, and the final `in` block is short
  (the `subarray` at line 337 already clamps).
- `chainInput` / `chainFeedback` carry the generator state across iterations —
  exactly OFB's shape.
- The body may simply **ignore** the injected `in` port; it is offered, not
  required (line 340).
- Per-iteration `bodyOutput`s are concatenated into the container's output.

The one missing piece is a length-N buffer to drive the loop. That is the new
`zero-fill@1` leaf below. The result: **spec size is constant in N** (one copy of
the body, looped by the runtime), unlike SHAKE's unrolled squeeze.

### New step types (2)

**`zero-fill@1 { byteLength }`** — zero inputs, one output port carrying
`byteLength` zero bytes. It is the *request for randomness*: its width is what
makes the generator run `⌈N/w⌉` times, and that fact is the honest thing for the
trace to show. Rejected alternative: `constant-load@1` with an N-element zero
array — no new step type, but its documentation says "cryptographic round
constant", so using it as a length-carrier is a category lie in the trace, and it
puts a 256-element array into every saved/shared document.

**`add-mod@1 { }`** — three input ports `a`, `b`, `modulus`; output
`(a + b) mod modulus` at `modulus.length` width. The exact sibling of the shipped
`mod-mul@1` (`steps/mod-mul.ts`), which already supplies `(a · b) mod m`.
Rejected alternative: `add-mod-32@1` followed by `and@1` with a `0x7FFFFFFF`
mask — works, uses only shipped primitives, and teaches "mod 2^k is a bitmask",
but it is correct *only* for power-of-two moduli. In an app whose entire premise
is editing params, a modulus the user can edit into silent wrongness is a
footgun.

Both leaves must clear the two coverage gates named in `CLAUDE.md`: an exact fn
in `core/port-provenance.ts` **or** an entry in `PROVENANCE_NO_OP_ALLOWLIST`
(pinned in **two** files — `tests/port-provenance-coverage.test.ts` *and*
`tests/port-provenance.test.ts`'s exact-mapping count), plus
`tests/narration-registry-contract.test.ts`. `zero-fill@1` and `add-mod@1` both
have params, so `NO_PARAMS_PORT_NATIVE_TYPES` is not involved, but both need a
`ParamEditor` blurb.

### The LCG spec (~6 leaves per output word)

```
seed-source   ← inputs.plaintext (4 bytes)
request       zero-fill@1 { byteLength: outputLength }
iterate "words"  seedInput=request, blockByteLength=4, allowPartialFinalBlock=true
                 chainInput=seed-source, chainFeedback=state, bodyOutput=trim
  mult   constant-load@1 { bytes: a }      ← editable: the multiplier
  incr   constant-load@1 { bytes: c }      ← editable: the increment (MINSTD omits)
  modu   constant-load@1 { bytes: m }      ← editable: the modulus
  prod   mod-mul@1 (a=iterate.chain, b=mult, modulus=modu)
  state  add-mod@1 (a=prod, b=incr, modulus=modu)      ← MINSTD: state = prod
  trim   truncate-to-reference@1 (input=state, reference=iterate.in)
outputFrom = iterate.out
```

`truncate-to-reference@1` is the shipped leaf CTR/CFB/OFB/ChaCha/Salsa already use
for a short final block — so a non-multiple output length works for free.

### The ChaCha20 CSPRNG

Same iterate shape at `blockByteLength: 64`, `chainInput` = a zero counter,
`chainFeedback` = `increment-counter@1`, body = ChaCha20's block function
**without the final XOR** (there is no message; the keystream *is* the output).
Seed (32 bytes) is the key; the nonce is fixed all-zero, supplied by a
`constant-load@1` — so no IV field is introduced.

**Compose it from an exported double-round group builder rather than
refactoring `buildChaCha20Spec`.** `chacha20.ts` exports only
`buildChaCha20Spec` today; exporting the double-round group builder lets the
CSPRNG build its own head (state assembly) and tail (add + serialize) while the
shipped ChaCha20 spec stays **byte-identical and untouched** — lower risk than
parameterizing `buildBlockBody` with a `keystreamOnly` flag. Guard it with a
structural-equality test on the shipped spec.

Payoff worth verifying in the browser: because the double-round *groups* are
built by the same code, `analyzeChaChaDoubleRound` (`core/chacha-shape.ts`), the
canonical ARX layout cell, `arxRoundNeverModes` (`core/arx-group.ts`), and the
`<ChaChaQuarterRoundDiagram />` should all light up for the CSPRNG with no extra
work. If they do, that is direct evidence the ARX generalization landed in
`41aa16e` cut the seam in the right place.

## Critical files

**New:**
- `src/steps/zero-fill.ts`, `src/steps/add-mod.ts`
- `src/ciphers/lcg.ts` (both variants via one builder), `src/ciphers/chacha20-csprng.ts`
- `tests/lcg-kat.test.ts`, `tests/chacha20-csprng-kat.test.ts`, `tests/prng-family-surface.test.ts`

**Modified — the family surface (the pattern, applied once per file):**
- `src/ui/stores/cipher.ts` — `Prng` union, `ALL_PRNGS` / `PRNG_OPTIONS` /
  `PRNG_LABELS`, `PRNG_DESCRIPTIONS`, `PRNG_HISTORY`, `DEFAULT_KEY_BYTES_BY_PRNG`
  (empty) + `DEFAULT_PT_BYTES_BY_PRNG` (seed), widen `Algorithm` + `Category`,
  add `isPrng`, route `describeAlgorithm` / `historyOfAlgorithm`, extend
  `__resetCipherForTests`.
- `src/ui/stores/spec.ts` — `PrngSpecsByMode`, `buildCanonicalPrng`,
  `resolvePrngDefault`, `prngOutputLength` signal + `setPrngOutputLength`,
  `setPrng`, `setAlgorithm` routing (`spec.ts:935`), and the `.kind` branches the
  compiler will walk you through: `activeSpec`, `updateActive`, `updateBoth`,
  `resetSpec`, `isCustomSpec`, `setSpecFromDocument`, `restoreSpecsForHistory`,
  cross-mode-mirror guards.
- `src/core/document-schema.ts` — `PRNG_IDS`, fold into `ALGORITHM_IDS`, add
  `assertPrngCoverage` alongside the existing `assertHashCoverage` /
  `assertAsymmetricCoverage` (line 141-145). A miss surfaces as the cryptic
  `Type 'true' is not assignable to type 'never'`.
- `src/ui/App.tsx` — ~12 family-gated sites: the category selector (line 1365),
  a `category() === "prng"` panel beside the hash/asymmetric ones (1530/1637),
  `inputLabel`/`outputLabel` (1331/1337) → "seed" / "random bytes", the Run-path
  input validation branch (501), the default-bytes routers (2368/2380), and the
  output-length stepper modelled on the SHAKE one (1561).
- `src/ciphers/default-registry.ts` — register the two new step types.
- `src/ciphers/chacha20.ts` — export the double-round group builder. Nothing else.
- `tests/cipher-mode-fallback.test.ts` — a fourth class beside cored /
  coreless-awaiting-a-core / stream. A PRNG has no `CipherMode` at all.

## Two landmines

**1. `isCipher` must explicitly subtract `Prng`.** The `SpecsByMode` union sites
are compiler-enforced — adding a `kind: "prng"` variant with no `encrypt`/
`decrypt` makes `activeSpec`'s `s[mode()]` a type error, so TS walks you through
every one. **`isCipher` gets no such protection**: it is a hand-written
`a is Cipher` predicate (`cipher.ts:220`), so `!isHash(prng) && !isAsymmetric(prng)`
returns `true` and *the compiler believes it*, silently routing PRNGs down the
cipher path. This is the RSA bug already recorded in memory; the file's own
comment says every new non-cipher family MUST be subtracted here. Highest-value
line in the change.

**2. Seeding convention is the oracle trap.** PRNGs have excellent external
oracles, but their *seeding* differs in ways that produce a perfectly plausible
wrong stream — the same failure class as ChaCha counter=1 vs Salsa counter=0,
which this repo got bitten by twice. Write down *which* routine produced each
vector, next to the bytes.

**The v1 oracle is standards-track and already verified in this session** (run
with `BigInt`, both matched exactly):

| generator | recurrence | conformance value |
|---|---|---|
| `minstd_rand0` | `x ← 16807·x mod (2³¹−1)`, seed 1 | 10000th = **1043618065** |
| `minstd_rand` | `x ← 48271·x mod (2³¹−1)`, seed 1 | 10000th = **399268537** |

Both are required by ISO/IEC 14882 §rand.predef — a FIPS-197-grade anchor. The
ANSI-C LCG (`x ← (1103515245·x + 12345) mod 2³¹`) has no standard conformance
value; pin it against a reference run and record the source. From seed 1 the
first five states are `1103527590, 377401575, 662824084, 1147902781, 2035015474`.
Note it is **not** glibc's default `rand()` (a TYPE_3 additive-feedback
generator) — name it for `rand_r` / the C-standard example, or the label lies.

ChaCha20-CSPRNG has a live oracle: `node:crypto`'s `chacha20` over a zero buffer
yields the keystream directly.

## Phases

**P1 — the family surface, with MINSTD only.** Fourth category end-to-end:
selector, store, `zero-fill@1`, the LCG builder, document round-trip,
seed/output labels, output-length control. One generator keeps the diff focused
on the surface. Gate: `npm run check` + browser smoke.

**P2 — ANSI-C LCG + `add-mod@1`.** Second variant and the editable-(a, c, m)
experiment that is the plan's pedagogical point. Ships with its KAT.

**P3 — ChaCha20 CSPRNG.** Export the double-round builder, compose the
keystream-only spec, verify the ARX cell + quarter-round diagram light up in the
browser. Ships with the `node:crypto` KAT.

**P4 — MT19937 (deferred, not authorized).** 624-word state, 624-step twist per
refill — three to four orders of magnitude more frames than the others, which
will blow the ~200ms re-run budget and the trace-legibility ceiling SHA-256
already forced (its 512-byte input cap). The repo's sanctioned escape hatch is
the deliberate-monolith-with-rich-narrator (`blowfish.key-schedule@1`,
`twofish.h-expand@1`). Decide depth against a working app, not on paper. Note
the seeding trap here specifically: `init_genrand(s)` and `init_by_array([s])`
produce different streams, and numpy/Python use the latter for integer seeds
while the classic published vector uses `init_genrand(5489)`.

## Verification

Per phase, in this order:

1. **KAT first, against the external oracle, before anything else** — the repo
   rule (`feedback_crypto_verification`). P1: the two C++ conformance values
   above. P2: the recorded reference run. P3: `node:crypto` `chacha20` over
   zeros, plus a structural-equality assertion that the shipped ChaCha20 spec is
   byte-identical to before the export refactor.
2. **Family-surface test** (`tests/prng-family-surface.test.ts`) — save → reset →
   load round-trips a PRNG document *including its output length*; the fourth
   class in `tests/cipher-mode-fallback.test.ts` holds; `isPrng`/`isCipher`/
   `isHash`/`isAsymmetric` partition `Algorithm` exactly.
3. **Perturbation, not assumption** — flip the LCG multiplier to an even number
   and assert the low bits go constant; that both proves the KAT is live and
   *is* the teaching claim. (Precedent: the CFB/OFB perturbation runs.)
4. `npm run check` — the full gate. Cold runs can exceed 3 minutes; background
   it or give the hook a generous timeout.
5. **Browser smoke** — visual features need it (`feedback_visual_smoke_vs_property_tests`).
   Select each generator, confirm the key/IV/padding/mode selectors are hidden
   and the seed + output-length fields render; scrub the trace; edit `a` in the
   graph view and watch the re-run. For P3 specifically, confirm the ARX
   canonical cell and the quarter-round diagram appear.
6. **Docs + memory + commit, in that order** (`feedback_session_end`) — README's
   "What's in the box", `CHANGELOG.md`, `docs/key-files.md`, `docs/gotchas.md`
   (a PRNG section: seeding conventions, the `isCipher` subtraction), and this
   plan's status line.
