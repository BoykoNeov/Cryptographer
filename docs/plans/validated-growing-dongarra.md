# MT19937 — the PRNG family's P4, and the generator that is neither weak nor safe

**Status: SHIPPED 2026-08-09 — CLOSED.** P4a (primitives + oracle), P4b (the
spec + surface) and P4c (narration, browser smoke, docs) all landed; the family
plan `docs/plans/iterative-dancing-ocean.md` is closed with it.

**What the plan got wrong, recorded because both were caught by doing rather
than reasoning.** (1) The output ceiling: the plan expected to have to measure
before ruling out a per-variant arm. Measured, 42 → 1024 settles in **~325 ms**
— roughly six times inside the CSPRNG's budget — so `maxPrngOutputFor` gained
no arm. The reason is that the step strip renders one entry per SPEC NODE and
tempering is twelve leaves whatever the block count, so MT19937's UI cost is
nearly flat in output length. (2) The plan assumed the family-surface guard
would catch a missing variant. Perturbing it showed the suite passes
**vacuously** — every assertion iterates `PRNG_OPTIONS`, so deleting MT19937
took the file from 28 tests to 26, all green. Now pinned against
`Record<Prng, string>`'s compiler-enforced keys, and re-perturbed to watch it
fail. A third near-miss is recorded in `docs/gotchas.md`: a mask perturbation
that was a no-op *because* `y << 7` zeroes the bits it touched.

## Context

The PRNG family shipped three generators on 2026-07-27: two MINSTD variants and
the ANSI C LCG (all trivially predictable, and *visibly* so), plus a ChaCha20
CSPRNG (unpredictable, and structurally a stream cipher with the message
deleted). Between those two poles sits the generator that actually runs in
production language runtimes — Python's `random`, C++'s `std::mt19937`, MATLAB,
Ruby — and it belongs to **neither** category the family currently teaches.

That is the reason to ship it. MT19937 has a period of 2¹⁹⁹³⁷−1, passes the
statistical batteries the LCGs fail outright, and is still completely
predictable: its output function is invertible, so 624 consecutive outputs
recover the entire internal state and hand over the whole future *and* past of
the stream. It is the family's only member that separates **"passes statistical
tests"** from **"unpredictable"** — the LCGs fail both, the CSPRNG passes both.
A learner who has only met those two will reasonably conclude the properties are
the same property. MT19937 is the counterexample, and it sits one dropdown entry
away from the CSPRNG that does not share its flaw.

Intended outcome: a fifth `Prng` variant reachable from the algorithm selector,
running through the same runtime, trace, graph and param editors as everything
else. No new viewer, no new state shape, **no runtime change.**

## The depth decision (user, 2026-08-09)

Two of MT19937's three stages are **structurally inexpressible** as port-mode
iterates, and this is a finding, not a preference:

- `init_genrand(s)` is `mt[i] = 1812433253·(mt[i−1] ^ (mt[i−1]>>30)) + i`. The
  `+ i` is the loop index, and **no leaf produces the iteration index** — the
  runtime does not expose one.
- The twist reads `mt[i]`, `mt[i+1]` and `mt[i+397]`. A port-mode iterate hands
  its body **only that iteration's own block plus the cross-iteration carry**,
  so the body cannot reach two other words of the array. (It is also genuinely
  sequential: from `i = 227` the `mt[i+397]` read hits an *already twisted*
  word, so it does not vectorize into slice arithmetic either.)

So: **two monoliths + visible tempering** (user-selected). `mt19937.seed@1` and
`mt19937.twist@1` are single frames carrying rich value-prose narrators — the
sanctioned escape hatch, precedent `blowfish.key-schedule@1` (runs the cipher on
itself 521×) and `twofish.h-expand@1` (4 disclosure rows of real per-key values).
The **tempering is decomposed into 12 visible leaves per output word**, because
tempering is the invertible part and therefore the whole teaching point.

**Default seed: 5489** (user-selected) — `std::mt19937`'s `default_seed`, so
first paint reproduces a published stream, the property AES-128 gets from
FIPS-197 §C.1 and ChaCha20 from RFC 8439 §2.4.2.

## The spec

```
$input (4-byte seed, default 5489)
  seed-state  mt19937.seed@1   ($input)            → 2496 B    ← MONOLITH
  twist       mt19937.twist@1  (seed-state.output) → 2496 B    ← MONOLITH
  request     zero-fill@1 { byteLength: N }                    ← the length, as always
  words       byte-slice@1 { offset: 0, length: 4·ceil(N/4) } (twist.output)
  temper      iterate  seedInput = words.output, blockByteLength = 4
                sh1  shift-bits-right@1 {bits:11, wordBits:32}  (temper.in)
                y1   xor@1                                       (temper.in, sh1)
                m2   constant-load@1 { bytes: 9d 2c 56 80 }
                sh2  shift-bits-left@1  {bits:7,  wordBits:32}  (y1)
                a2   and@1                                       (sh2, m2)
                y2   xor@1                                       (y1, a2)
                m3   constant-load@1 { bytes: ef c6 00 00 }
                sh3  shift-bits-left@1  {bits:15, wordBits:32}  (y2)
                a3   and@1                                       (sh3, m3)
                y3   xor@1                                       (y2, a3)
                sh4  shift-bits-right@1 {bits:18, wordBits:32}  (y3)
                y4   xor@1                                       (y3, sh4)
              bodyOutput = y4.output
  emit        truncate-to-reference@1 (input = temper.out, reference = request.output)
outputFrom: emit.output
```

Four structural facts worth stating in the file header, because each is a first:

1. **The temper loop has no cross-iteration carry at all** — no `chainInput`, no
   `chainFeedback`. Every other port-mode iterate in the app threads state
   through the loop (CBC's chain, CTR's counter, SHA-256's running H, the LCGs'
   `x`). MT's extraction is a pure **map over the state array**: word `i` of the
   output depends on word `i` of the twisted state and nothing else. Confirm the
   runtime accepts a chain-free port-mode iterate (`runtime.ts` guards
   `chainFeedback` with `!== undefined`, and ECB is the existing precedent).
2. **The state is the iterate's `seedInput`, read over a port.** Do *not* route
   it through aux out of P3 reflex — the CSPRNG's lesson was that a seed cannot
   cross *into* a body's scope, and nothing crosses a scope here. Ports show the
   flow; aux would hide the app's single most interesting wire.
3. **Round-up-slice + post-iterate trim is forced, not stylistic.** Every
   shipped trim (CTR/CFB/OFB/ChaCha/Salsa/LCG) lives *inside* the body, keyed on
   the iterate's `in` port. That is unavailable here: `in` is always a full
   4-byte state word, so no short reference exists to trim against. Hence
   `byte-slice@1` rounds *up* to a whole number of words and a **sibling**
   `truncate-to-reference@1` cuts the concatenated result down to `N`.
   `runtime.ts:390` publishes the iterate's outputs into the same `nodeOutputs`
   map sibling leaves resolve against, so `port(temper,"out")` resolves exactly
   as the LCG's `outputFrom` already does — **verified by reading, still to be
   verified by running.** This is the one novel wiring in the design; spike it
   before writing a single narrator.
4. **One twist, no refill.** MT refills every 624 words = 2496 bytes; the
   output ceiling is 1024, so the refill path is unreachable. The builder
   **throws** above 2496 rather than silently emitting a wrong stream, and the
   twist narrator says what *would* happen. This is the one place the app is a
   strict subset of the algorithm, so it gets said out loud rather than implied.

**Seeding: `init_genrand` only.** `init_by_array` is a test-only second oracle,
never a product option — two seeding modes would *be* the mismatch trap rather
than a demonstration of it. Note this diverges from the family convention
`lcg.ts`'s header states ("x_0 is the seed verbatim, no scrambling, no
`init_by_array`"): MT19937 **cannot** honor it, since `init_genrand` is a
mandatory scramble. Say so in the new file's header or the family reads as
self-contradictory.

## Ceiling: expected to need no new arm

12 leaves/word × 256 words at the LCGs' **existing** `MAX_PRNG_OUTPUT` of 1024
≈ 3.1k frames — inside the CSPRNG's measured 3,958 frames / ~2.0 s. So the
working assumption is **no `maxPrngOutputFor` arm and no new clamp site**.
Measure in the browser at 1024 before concluding; if it misses budget, the
missable clamp site is the **variant switch**, not the stepper
(`stores/spec.ts` `setPrng`).

## Slices

**P4a — primitives.** `shl8/16/32/64` in `core/word-codec.ts` (only `shr*`
exists today); `src/steps/shift-bits-left.ts` copied from `shift-bits-right.ts`
verbatim in shape (`{bits, wordBits}`, `layout:"raw"`, the `bits >= wordBits`
zero short-circuit); `src/steps/mt19937-seed.ts` + `src/steps/mt19937-twist.ts`;
all three registered. Executor-level KAT against the captured oracle.

> `shift-bits-left@1` over the ROL-plus-mask trick: `(y<<7)&0x9d2c5680` does
> equal `ROL(y,7)&0x9d2c5680` (the mask's low 7 bits are clear, and its low 15
> for the second constant), but that is a numerical coincidence, not the
> algorithm. This is the `rotate-bits-left@1` precedent inverted — the trace
> should read as the reference code writes it.

**P4b — the generator.** `src/ciphers/mt19937.ts` (builder + node ids +
`readPrngOutputLength` reuse from `ciphers/prng-request.ts`) and the surface
tables. Runtime KAT + family-surface test.

**P4c — narration, smoke, docs.** Rich value-prose on the two monoliths; the
tempering narrators carrying the invertibility lesson; browser smoke; the
ceiling measurement; README / CHANGELOG / `docs/key-files.md` /
`docs/gotchas.md`; memory; commit.

## Critical files

**New:** `src/steps/shift-bits-left.ts`, `src/steps/mt19937-seed.ts`,
`src/steps/mt19937-twist.ts`, `src/ciphers/mt19937.ts`,
`tests/mt19937-kat.test.ts`, `tests/shift-bits-left.test.ts`.

**Modified:**
- `src/core/word-codec.ts` — the `shl*` family beside `shr*`.
- `src/ciphers/default-registry.ts` — three registrations.
- `src/core/port-provenance.ts` — `shift-bits-left@1` into
  `PROVENANCE_NO_OP_ALLOWLIST` beside `shift-bits-right@1`, same
  "bit-level → byte-approximate" rationale. The two `mt19937.*` types are
  **prefixed**, so they are outside that gate's bare-name scope by design.
- `tests/port-provenance-coverage.test.ts` **and** `tests/port-provenance.test.ts`
  — the allowlist set-pin lives in *two* files; run the full suite, not one.
- `src/ui/components/ParamEditor.tsx` — add `shift-bits-left@1` to the existing
  bit-shift block (`:263` guard + the label switch at `:2332`).
- `src/ui/stores/cipher.ts` — `Prng` union, `ALL_PRNGS`, plus the six per-variant
  tables (`PRNG_LABELS`, the two description tables, `DEFAULT_KEY_BYTES_BY_PRNG`,
  `SEED_BYTES_BY_PRNG` = 4, `PRNG_UNIT_BYTES_BY_PRNG` = 4,
  `PRNG_UNIT_NOUN_BY_PRNG` = "word", `DEFAULT_PT_BYTES_BY_PRNG` = `00 00 15 71`).
- `src/ui/stores/spec.ts` — `resolvePrngDefault` arm.
- `src/core/document-schema.ts` — the `algorithm` enum. **No `schemaVersion`
  bump**: per `docs/versioning.md` a new legal value is not a wrapper-layer
  change (RSA added a whole family at v3 without one).
- `tests/prng-family-surface.test.ts` — keep the `isPrng`/`isCipher`/`isHash`/
  `isAsymmetric` partition exact. `isPrng` is membership over `ALL_PRNGS`, so a
  new *variant* re-arms the `isCipher` landmine; perturb the predicate to prove
  the guard is live rather than assuming.
- `docs/plans/iterative-dancing-ocean.md` — flip the P4 status line.

## Verification

Order matters — KAT against the external oracle **first**
(`feedback_crypto_verification`).

1. **The oracle is already captured**, at `M:\claud_projects\temp\mt19937\oracle.py`,
   with two independent anchors so a disagreement says *which* half is wrong:
   - **A** — our hand-written `init_genrand` pushed into
     `np.random.MT19937.state` (`pos = 624` forces the twist), read via
     `random_raw()`: numpy's C twist+temper under our seeding.
   - **B** — CPython's `random.Random(int)` (which seeds via `init_by_array`
     over the int's little-endian 32-bit words) reproducing the published
     `mt19937ar.out` vector, with **no trust in our seeding at all**. Anchors B
     and B′ (same key array through numpy) agree exactly.

   Pins for the test file, all measured rather than recalled:

   | | |
   |---|---|
   | `init_genrand(5489)` first words | `3499211612, 581869302, 3890346734, 3586334585, …` |
   | …as the bytes the app emits (BE) | `d091bb5c 22ae9ef6 e7e1faee d5c31f79 …` |
   | 10000th output | **4123659995** — ISO/IEC 14882 §rand.predef, independently reproduced |
   | `init_by_array([0x123,0x234,0x345,0x456])` | `1067595299, 955945823, 477289528, …` |

   Reach the 10000th value through the **executors**, not the traced runtime
   (40 KB / ~10,000 iterations of frames), asserting the two agree on short
   lengths — exactly `tests/lcg-kat.test.ts`'s posture. **If the app and the
   reference disagree, suspect the seeding convention before the twist.**

2. **Perturbation, not assumption** (the CFB/OFB/LCG precedent). Drop the final
   `y ^= y>>18`, and separately corrupt the `0x9d2c5680` mask; each must fail the
   KAT loudly. Then the **teaching claim asserted against emitted bytes**: invert
   the four tempering steps, recover `mt[i]` from an emitted word, and pair it
   with the contrast that the same attack does not exist for
   `chacha20-csprng` — so invertibility is attributed to the *output function*
   rather than to "this generator is old".
3. **Family surface** — save → reset → load round-trips an MT19937 document
   *including* its output length; the partition test stays exact.
4. `npm run check` — cold runs exceed 3 minutes; background it or give the hook a
   generous timeout (a killed hook aborts the commit and leaves everything
   staged).
5. **Browser smoke** (`feedback_visual_smoke_vs_property_tests`). Select
   MT19937: seed + output-length fields render, key/IV/padding/mode selectors
   hidden, labels read "seed" / "random bytes" in **both** the sidebar and the
   graph endpoint pills (nothing type-checks a label string — that arm was found
   by smoke in P1). Scrub the trace; edit a temper constant and watch the re-run.
   Two things to look at specifically:
   - **the sibling trim's graph edge** — a container→leaf port edge is the shape
     SHAKE's squeeze-carry bug lived in (a redundant "no frame found" container
     edge, fixed in `resolveSeedChain`);
   - **a 2,496-byte value on a port** is the largest the app has ever carried
     (Blowfish's 4 KB rides aux, not ports) and the linear view renders it twice
     — confirm it does not tank the render.
   - measure a 42 → 1024 length change end to end for the ceiling call.
6. **Docs → memory → commit → push, in that order** (`feedback_session_end`).

## Explicitly out of scope

- `init_by_array` seeding as a product option (test-only oracle — see above).
- The refill path (> 2496 bytes); the builder throws and the narrator explains.
- MT19937-64, and any randomness-quality visualization (spectral test, bit-plane
  plots) — the family plan already ruled the latter a separate plan.
- A canonical graph cell / linear-view diagram for the temper chain. The 12
  leaves are a straight line, which the generic stack already renders honestly.
