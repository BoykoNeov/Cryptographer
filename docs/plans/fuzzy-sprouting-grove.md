# SHAKE128 / SHAKE256 — the variable-length XOF (FIPS 202)

Status: **SHIPPED 2026-07-13.** Both SHAKE variants join the Hash selector,
byte-equal to `node:crypto` across message *and* output lengths, with a
live-editable output length that grows/shrinks the visible squeeze loop.
Delivered in four commits (keccak-f extraction → SHAKE builder + wiring + KAT →
editable control + graph fix → docs). Reuses the shipped Keccak-f[1600]
permutation + sponge absorb **unchanged**; the one new element is the
**variable-length squeeze** (unrolled — see below). Memory:
`project_sha3_keccak_plan`. One deviation from the plan below: a graph bug the
new group→group squeeze carry exposed (a redundant "no frame found" container
edge) was fixed in commit 3 (`resolveSeedChain` in the loop-input pass) with
`tests/shake-graph-resolution.test.ts` as its guard.

## Context

The user is building toward the NIST post-quantum standards (ML-KEM / ML-DSA /
SLH-DSA), **all of which consume SHAKE**. SHA3-256 landed the Keccak-f[1600]
permutation, the pad10\*1 padding, the round constants, and the sponge *absorb*
fold. SHAKE is the natural next slice: same permutation, same absorb, but its
output is **arbitrarily long** — you *squeeze* `rate` bytes out of the state, run
Keccak-f, squeeze `rate` more, and repeat until you have enough, then truncate.

The user chose (AskUserQuestion) the **editable output length** model: a live UI
control to change the digest length and watch squeeze blocks appear/disappear —
the spec rebuilds structurally on edit, bounded by a legibility cap. This is the
richest pedagogy and matches this user's consistent "show the mechanism" choices
(traced EEA, visible PHT blocks). Intended outcome: two new dropdown entries,
**SHAKE128** and **SHAKE256**, byte-identical to `node:crypto`'s `shake128` /
`shake256` across message lengths *and* output lengths, with the squeeze loop
visible on the canvas by default and interactively resizable.

## Two facts that shape everything

1. **Squeeze = unrolled, NOT an iterate** (advisor-confirmed). The port-mode
   `iterate` derives `count = seedInput.length / blockByteLength` — there is no
   explicit-count path, so an iterate squeeze would need a dummy loop-counter
   seed (dishonest in a "the trace is honest" tool) or a `types.ts`+`runtime.ts`
   extension (scope creep). Unrolled needs neither and is **more faithful**: FIPS
   202 Algorithm 8 breaks the loop *before* the final permutation → **N extracts
   / N−1 Keccak-f's, no trailing wasted permute** (an iterate's per-iteration
   `chainFeedback` would always run, leaving a dangling permutation). The
   absorb=iterate / squeeze=unrolled asymmetry is honest: absorb's count comes
   from the input (a natural seed); squeeze's from the desired output length.

2. **Zero new step types.** SHAKE reuses *every* existing primitive:
   - pad → `keccak.pad@1` with `domainByte: 0x1F` (the executor already computes
     `domainByte ^ 0x80` generically — merge case `0x1F ^ 0x80 = 0x9F` — verified
     in `src/steps/keccak-pad.ts`, no hardcoded 0x06/0x86).
   - absorb + Keccak-f round (θ/ρ/π/χ/ι) → the shipped SHA3-256 machinery.
   - squeeze → `byte-slice@1` (extract first `rate` bytes) + Keccak-f (existing
     rounds) + `concat@1` (join blocks) + `byte-slice@1` (truncate to length).

## Design

### A. Extract the shared Keccak-f machinery — `src/ciphers/keccak-f.ts` (NEW)

Move out of `src/ciphers/sha3-256.ts` (verbatim, so SHA3-256 stays byte-stable):
the geometry + constants (`RHO_OFFSETS`, `PI_INDICES`, `CHI_SHIFT1/2`,
`RC_VALUES`/`RC_BYTES`, `S0_BYTES`, `laneStart`, `STATE_BYTES`, `ROUNDS`,
`LANE_BYTES`), the round-level narration (`NARR_THETA`…`NARR_IOTA`), the absorb
narration + `buildAbsorbSteps`, and a **generalized round builder**:

```ts
// roundId = prefix ? `${prefix}.round.${r}` : `round.${r}`
//   → empty prefix reproduces SHA3-256's EXACT ids (`round.0`…`round.23`),
//     so saved SHA3-256 docs + layout pins keep working.
buildKeccakRound(prefix: string, r: number, seedRound0: PortBinding): StepNode
buildKeccakF(prefix: string, seedRound0: PortBinding): StepNode[]  // 24 round groups
buildAbsorbSteps(rate: number): StepNode[]                          // rate now a param
```

`sha3-256.ts` (MODIFIED) then imports these, keeps only its sponge-specific
constants (`RATE=136`, `DOMAIN=0x06`, `DIGEST=32`, squeeze narration) and calls
`buildKeccakRound("", r, port("absorb","output"))` for round 0 /
`port("round.{r-1}","out")` for later — **ids unchanged**. Guard: re-run
`tests/sha3-256-kat.test.ts` after the extraction, before writing any SHAKE code.

### B. SHAKE spec builder — `src/ciphers/shake.ts` (NEW)

```ts
buildShakeSpec(variant: "shake128" | "shake256", outputLength: number): CipherSpec
```

Constants: `rate = 168` (SHAKE128) / `136` (SHAKE256); `domain = 0x1F` (both);
`cipherConstants = { RC: RC_BYTES, S0: S0_BYTES }`. Topology:

```
pad  keccak.pad@1 { rate, domainByte: 0x1F }
iterate "sponge"  (absorb — IDENTICAL to SHA3-256, rate-parameterized)
    seedInput = pad.output ; chainInput = init-state ; blockByteLength = rate
    chainFeedback/bodyOutput = round.23.out ; chainOutput = "state"
    children: buildAbsorbSteps(rate) + buildKeccakF("", port("absorb","output"))

# ── Squeeze (unrolled): numBlocks = ceil(outputLength / rate) ──
squeeze.extract.0  byte-slice(state,        offset 0, length rate)   # block 0
for j in 1..numBlocks-1:
    squeeze.perm.{j}   buildKeccakF(`squeeze.perm.{j}`, <prev state>) # a Keccak-f, collapsed group
    squeeze.extract.{j} byte-slice(perm{j}.out, 0, rate)             # block j
squeeze.concat     concat(extract.0 … extract.{numBlocks-1})         # numBlocks*rate bytes
squeeze.truncate   byte-slice(concat, 0, outputLength)               # = the XOF output
outputFrom = squeeze.truncate.output
```

State fed to each extract: block 0 ← absorbed state; `perm.1` = Keccak-f(absorbed
state), block 1 ← perm.1; `perm.{j}` = Keccak-f(perm.{j-1}), block j ← perm.{j}.
**No permute after the last extract.** When `numBlocks === 1` (outputLength ≤
rate) the squeeze collapses to a single extract + truncate — same shape as
SHA3-256, correct. Each `squeeze.perm.{j}` is wrapped in a `defaultCollapsed`
group so the extra Keccak-f's don't flood the canvas. SHAKE-specific
`narrationOverride` on the squeeze leaves (extendable-output prose); rounds inherit
the shared `NARR_*`.

### C. Editable output length — the signal mechanism

Output length is **spec data** (it changes what runs + the digest, and travels
via Save/Share) — the signal is just the "current desired length" input, exactly
analogous to the `cipherMode` signal feeding `buildCanonicalPair`.

- **`src/ui/stores/spec.ts` (MOD):** add `shakeOutputLength` signal (default
  **200** → 2 squeeze blocks for *both* variants, loop visible on first paint;
  floor 1; cap `MAX_SHAKE_OUTPUT`). `resolveHashDefault` special-cases the two
  SHAKE ids to build on demand — `buildShakeSpec(hash, shakeOutputLength())` —
  while `sha-256`/`sha3-256` stay in the static `hashDefaults` table. Add
  `setShakeOutputLength(n)`: clamp to `[1, MAX_SHAKE_OUTPUT]`, set the signal,
  and **rebuild the active spec synchronously** via `setSpecs(buildCanonicalHash(hash()))`
  when a SHAKE is active (a *structural* rebuild — NOT `editStepParams`, which
  can't change `numBlocks`). Signal + spec move in lockstep so `isCustomSpec`'s
  `canonical(currentLength)` never sees a mismatched pair (a pure length change
  reads "not custom"; only real edits read "custom").
- **`src/ui/App.tsx` (MOD):** render a small numeric **stepper** (±rate, or
  commit-on-blur/Enter — avoid rebuilding ~650 leaves per keystroke) near the
  message/digest area, gated on `hash() === "shake128" || hash() === "shake256"`.
  Reads `shakeOutputLength()`, calls `setShakeOutputLength`. The existing
  `MAX_HASH_INPUT = 512` *input* cap is unaffected (separate axis). In
  `applyDocument`'s hash short-circuit, **sync the signal from the loaded spec**
  by reading the `squeeze.truncate` step's `length` param (the exact output
  length; numBlocks alone loses it) so the control shows the right value and a
  later `resetSpec` rebuilds at the right length.

Cap: **`MAX_SHAKE_OUTPUT = 512`** → up to 4 squeeze blocks (3 extra Keccak-f ≈
648 leaves; with a short message ≈ 870 total, well under SHA-256's 2486). Gives
headroom above the 200-byte default to demonstrate the loop growing.

### D. Selector + persistence wiring (mirror `sha3-256`; the compiler enforces it)

- **`src/core/document-schema.ts`:** add `"shake128"`, `"shake256"` to
  `HASH_IDS`. The `MissingHash = Exclude<Hash, HASH_IDS[number]>` assert (line
  117) catches any map you forget when widening the union.
- **`src/ui/stores/cipher.ts`:** widen `type Hash`; **update `isHash`** (critical
  — `isCipher = !isHash && !isAsymmetric`, so a missed SHAKE id would be
  mis-run as a cipher, per the RSA `isCipher` lesson); add to `ALL_HASHES`,
  `HASH_LABELS` ("SHAKE128"/"SHAKE256"), the description + history maps, and the
  default plaintext/key maps (`"abc"` / 0-byte, like the other hashes).
- **No `cipher-mode.ts` change** — hashes are mode-less (verified; the "two
  tables" cipher gotcha does not apply to hashes).
- Constants panel: SHAKE reuses `keccak.iota@1` + `aux["RC"]`, so the RC legend +
  ι-consumer scan light up automatically — verify, don't rebuild.

## Critical files

| File | Change |
|---|---|
| `src/ciphers/keccak-f.ts` | **NEW** — shared Keccak-f round machinery + constants + narration + absorb, extracted from sha3-256.ts |
| `src/ciphers/sha3-256.ts` | **MOD** — import the shared machinery; keep ids byte-identical |
| `src/ciphers/shake.ts` | **NEW** — `buildShakeSpec(variant, outputLength)`: absorb + unrolled squeeze |
| `src/ui/stores/spec.ts` | **MOD** — `shakeOutputLength` signal + `setShakeOutputLength`; `resolveHashDefault` builds SHAKE on demand |
| `src/ui/App.tsx` | **MOD** — output-length stepper (SHAKE-gated); `applyDocument` syncs the signal from the loaded spec |
| `src/ui/stores/cipher.ts` | **MOD** — widen `Hash`, `isHash`, labels/descriptions/history/defaults |
| `src/core/document-schema.ts` | **MOD** — `HASH_IDS` += both SHAKE ids |
| `tests/shake-kat.test.ts` | **NEW** — KAT sweep vs `node:crypto` |
| docs / memory | README "What's in the box", CHANGELOG, `docs/gotchas.md` (SHAKE domain/rate + editable-length rebuild note), memory update |

No new step types → **no** `default-registry.ts` / `ParamEditor.tsx` / narration-
registry changes (all reused primitives already have those). No schema bump
(SHAKE specs are ordinary port-native JSON; output length is captured
structurally in the spec).

## Verification

1. **Oracle already pinned** (this session): `node:crypto` `shake128`/`shake256`
   with `{ outputLength }`. `shake128("abc",32)=5881092d…`, empty/32=`7f9c2ba4…`;
   `shake256("abc",32)=48336660…`, empty/32=`46b9dd2b…`. The 168/169-byte
   boundary shows the second squeeze block (trailing `…6a`).
2. **`tests/shake-kat.test.ts`** — byte-equal vs `node:crypto`, for **both**
   variants, sweeping output lengths **including > rate** (or the squeeze loop is
   literally untested): e.g. `{1, rate−1, rate, rate+1, ~2·rate, cap}` × messages
   `{empty, "abc", len ≡ rate−1 mod rate (the single-0x9F pad-merge case), a
   multi-block message}`. Build each spec via `buildShakeSpec(variant, outLen)`
   and run through the real runtime.
3. **SHA3-256 regression guard** — re-run `tests/sha3-256-kat.test.ts` *after*
   the keccak-f extraction, before writing SHAKE, to prove no digest/id drift.
4. **`npm run check`** stays green (biome + tsc + vitest + build);
   `tests/cipher-mode-fallback.test.ts` (mode-less hashes) unaffected.
5. **Browser smoke** (`npm run dev`): select SHAKE128, enter "abc" → digest
   matches the KAT; the squeeze shows extract → permute → extract by default
   (200-byte output = 2 blocks); crank the output-length control up → a new
   `squeeze.perm.{j}` group + extract appear and the digest lengthens; crank down
   to 32 → collapses to a single extract; Save → reset → Load round-trips the
   output length (the control shows the loaded value, digest matches);
   `isCustomSpec` reads "not custom" after a pure length change but "custom" after
   a param edit. Note: `expand all` on the 24-round groups crashes headless
   Chromium (same as SHA-256/SHA3) — expand ONE round via the container chevron.
   (Playwright stays dormant per `feedback_playwright_dormant` unless a visual
   regression needs pinning.)

## Suggested commit sequence

1. Extract `keccak-f.ts`; rewire `sha3-256.ts`; re-run its KAT (proves the
   refactor is inert). **One commit, no behaviour change.**
2. `shake.ts` builder + selector/persistence wiring + `tests/shake-kat.test.ts`.
3. Editable output-length control (spec-store signal + App.tsx stepper +
   `applyDocument` sync) + browser smoke.
4. Docs (README / CHANGELOG / gotchas) + memory.

## Deferred (out of scope)

SHA3-224/384/512 (rate/output re-parameterization on this same base); cSHAKE /
KMAC / TupleHash (SHAKE-derived, need the `N`/`S` customization-string encoding);
canonical sponge graph layout (SHA3 memory already defers it — don't gold-plate);
the PQC algorithms themselves. SHAKE with a *live-editable rate/capacity* (fixed
per-variant here) is not a goal.
