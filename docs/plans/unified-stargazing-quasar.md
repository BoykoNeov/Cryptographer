# ML-KEM — the lattice layer, and the app's first post-quantum algorithm

**Status: P1 + P2 SHIPPED 2026-08-09; P3 + P4 SHIPPED 2026-08-10. P5 open.** Five phases; the NTT is
selectable under a fifth `Category`, `"lattice"`. Scope decided with
the user at plan time: **ML-KEM only** (ML-DSA deferred to its own plan),
**Keccak calls are monolith frames that cross-reference the already-visible
SHAKE**, and **P1 ships the NTT as its own selectable algorithm**.

## Context

Three shipped plans state outright that the Keccak sponge was built as the
honest foundation for post-quantum work: `docs/plans/joyful-sauteeing-turtle.md`
(SHA3-256), `docs/plans/fuzzy-sprouting-grove.md` (SHAKE128/256), and
`docs/plans/effervescent-plotting-puppy.md` (cSHAKE + KMAC). ML-KEM consumes
SHAKE128, SHAKE256, SHA3-256 and SHA3-512 — every one of which already ships and
already reuses the same `keccak-f.ts` permutation. What is unbuilt is the
**lattice layer**: arithmetic in the ring `R_q = Z_q[X]/(X²⁵⁶+1)` with
`q = 3329`, the number-theoretic transform that makes multiplication in that
ring cheap, and the KEM assembled on top.

Every plan in `docs/plans/` is closed or shipped except `graph-vertical-flow.md`
(drafted, never started), so this competes with nothing in flight.

**Intended outcome:** a learner can select **NTT** and watch a polynomial
transform layer by layer with the twiddle factors visibly advancing, then select
**ML-KEM-768** and watch a real post-quantum key encapsulation run — key
generation, encapsulation, decapsulation — with the lattice arithmetic fully
traced and each Keccak call one frame away from the sponge that ships under the
Hash selector.

## The measurements this plan is built on

Three numbers, read from code rather than estimated. They decide every depth
decision below, so they are stated first.

1. **Groups emit no frames.** `runtime.ts` has exactly one `frames.push(frame)`
   (line 858) and it sits inside the leaf branch. So one Keccak-f[1600] is
   **exactly 216 frames and 240 spec nodes** (24 round groups + 24×9 leaves).
2. **Spec-node count dominates wall clock, by ~17×.** Fitting CLAUDE.md's two
   published measurements — ChaCha20-CSPRNG ~991 nodes / 3,958 frames ≈ 2.0 s,
   MT19937 ~20 nodes / ~3,072 frames ≈ 325 ms — gives **≈1.6 ms per spec node
   and ≈0.095 ms per frame**. An `iterate` is therefore cheap in the expensive
   currency and expensive in the cheap one; an unroll pays both.
3. **`runtime.ts:336` sets `aux["blockIndex"] = i`** on every port-mode iterate,
   and `ctx.aux` reaches every executor. An iterate body *can* be
   iteration-index-aware. This is the opposite of the MT19937 `+ i` wall
   (`validated-growing-dongarra.md`), and it is recorded here because the design
   below deliberately **does not use it** — see "Twiddle factors ride the chain".

**These are the model, not the truth.** The two data points come from different
work on different days. P1's first task is a measurement spike that re-derives
the two coefficients on this machine; if they move materially, revisit the depth
decisions before P2.

## The three decisions the user made

### 1. ML-KEM only

ML-DSA's signing loop repeats an **unbounded** number of times until the
signature passes its bounds checks, and the iteration count depends on
*intermediate values*, not on inputs. The app's spec is JSON built before the
run, so expressing that needs a simulate-then-rebuild pass — a different
architectural problem from ML-KEM's, and one that deserves its own plan and its
own advisor pass. Not in scope here.

### 2. Keccak calls inside ML-KEM are single frames

Measured cost of the alternative: ML-KEM-768 makes ~17 sponge invocations
(9 matrix polynomials, 6 PRF calls, G, H). At 240 spec nodes each that is
**~4,080 nodes ≈ 6.7 s of re-run and a canvas nobody can read**, before a single
coefficient is multiplied. Full expansion is not affordable.

So `ml-kem.sample-ntt@1`, `ml-kem.prf@1`, `ml-kem.hash-g@1`, `ml-kem.hash-h@1`
and `ml-kem.kdf-j@1` are single-frame steps that call the shared `keccak-f.ts`
code internally. Precedent for the shape: `blowfish.key-schedule@1`,
`twofish.h-expand@1`, `mt19937.twist@1`.

**Say the right thing in each step's own description.** MT19937's lesson was
that a monolith must declare *which kind* it is. These are not the "structurally
inexpressible" kind and not the "no legible decomposition" kind — they are a
**third kind, new to this app: a cross-reference.** The sponge is not hidden; it
is one dropdown away, fully decomposed, under Hash → SHAKE128. Each monolith's
`detail` must name the exact function and rate it invokes and point the learner
at that selector entry. A description that reads like `blowfish.key-schedule@1`'s
("no legible decomposition") would be a lie here.

### 3. P1 ships the NTT as its own algorithm

The butterfly is the actual teaching content of the lattice layer, and inside a
KEM it would be a collapsed group under six other collapsed groups. It gets its
own selector entry, its own oracle, and its own layout work — and it gives P1 a
shippable end rather than a drawer of primitives.

## Architecture

### Representation

A polynomial is **256 coefficients × 2 bytes = 512 bytes** on a port, one
coefficient per big-endian `u16`. Big-endian per element matches the app's
standing "every port is a non-negative BE integer" convention (Twofish, RSA,
ChaCha's rails); ML-KEM's own 12-bit packed `ByteEncode`/`ByteDecode` is
little-endian, so the crossing is localized to those two leaves exactly the way
ChaCha20 localizes its four `permute@1` LE↔BE crossings. Endianness is a
**param** (`littleEndian: false`) on the vector steps, following
`rotate-lanes@1`, so it is visible and editable rather than baked in.

No new `State` shape and no new `PortLayout` variant is required; a `"zq-poly"`
advisory layout tag may be added in P5 purely for rendering.

**`q` arrives on a port, not as a param.** `add-mod@1` exists precisely because
"the modulus is a design decision, not a register width" — the same argument
applies with more force here, since `q = 3329` being prime and `≡ 1 mod 512` is
what makes the NTT exist at all. It rides `cipherConstants["q"]`, so it is one
editable source of truth that moves every consumer in lockstep (`types.ts`'s
`cipherConstants` doc states exactly this property).

### The NTT: seven layer-iterates, twiddle factors on the chain

FIPS 203's NTT is seven layers; layer *j* has `2^j` groups, each group pairing
coefficient *i* with *i+len* under its own twiddle factor ζ. Vectorized, one
group is:

```
split(in) → [lo | hi]            widths [len·2, len·2]
zeta   = byte-slice(chain, 0, 2)         ← this group's ζ
t      = zq-vec-mul-scalar(hi, zeta, q)
lo'    = zq-vec-add(lo, t, q)
hi'    = zq-vec-sub(lo, t, q)
concat(lo', hi')
chainFeedback = permute(chain, rotate-left-2-bytes)   ← advance the ζ cursor
```

**The 128 twiddle factors ride the iterate's cross-iteration chain as a rotating
256-byte table, and pass from layer to layer via `chainOutput` → the next
layer's `chainInput`.** This is CBC's chain machinery and OFB's carry, unchanged;
it needs **no runtime change and no new mechanism**. It was chosen over reading
`aux["blockIndex"]` and indexing a ζ table (which measurement 3 shows is
*possible*) for two reasons: the aux route hides the app's single most
interesting wire behind an executor, and nested iterates clobber `blockIndex`,
which would silently break the moment an NTT is placed inside another loop —
exactly the class of latent breakage the port-scope rules exist to prevent.

**This is a choice, not a forcing — and the cost of the alternative is the
Context section's promise.** The aux form computes the same coefficients and
would pass every KAT in this plan; what it would not do is let the learner
*watch the twiddle factors advance*, which is the one thing the NTT view exists
to show. Say exactly that in the builder's header, so a future reader who finds
the rotating table baroque knows what "simplifying" it deletes.

Cost per polynomial: 7 iterates × ~7 leaves ≈ **50 spec nodes**, and
`1+2+4+…+64 = 127` groups × 7 leaves ≈ **890 frames** — about 0.16 s under the
model. An unrolled equivalent would be ~890 nodes ≈ 1.4 s *per polynomial*,
which is what makes the iterate form the only affordable one once six
polynomials are in play.

`blockByteLength` per layer is `512, 256, 128, 64, 32, 16, 8`. The inverse NTT
is the same seven iterates run in reverse order with the Gentleman–Sande
butterfly and a final multiply by `n⁻¹ mod q`.

### Budget for the whole KEM

With monolithic Keccak, iterate-based NTT, and **vectorized pointwise
multiplication** (one frame per polynomial pair rather than 128 base-case
frames), ML-KEM-768 encapsulation costs roughly **350 spec nodes and ~6,000
frames ≈ 1.1 s** — inside the budget the CSPRNG already occupies. Key generation
is comparable. **ML-KEM-768 (k=3) is therefore the shipped parameter set**, not
the cheaper 512.

The degree-1 base-case multiplication is the one thing vectorization hides. It
gets its own small demo in P5 rather than 1,152 frames in the main trace.

### Where each algorithm lives in the UI

- **P1 adds a fifth `Category`, `"lattice"`**, with `Lattice = "ntt-3329-256"`.
  Forward NTT is the "encrypt" direction, inverse the "decrypt" — the transform
  is genuinely a direction pair, so it uses the existing two-slot model. It is
  not a cipher (no key, and `isCipher` would drag in modes, padding and an IV),
  not a hash (invertible), not a PRNG (it has a message), and not public-key.
  Measured cost of the `prng` precedent: 18 sites across 4 files.
- **P4 adds `"ml-kem-768"` to the existing `Asymmetric` family.** RSA already
  established that surface — no symmetric key field, no cipher mode, no padding,
  encrypt/decrypt toggle retained — and encapsulation/decapsulation maps onto it
  directly. Key material is derived inside the spec from a 64-byte seed `d‖z` in
  a default-collapsed key-generation group, exactly as RSA derives `n`/`d` from
  editable `p, q, e`.

Revisit this split at P3's advisor consult; if the lattice category has by then
grown a second member, housing ML-KEM there instead is a live option.

### `isAsymmetric` must become membership

`isAsymmetric` is today `a === "rsa"` — a hand-written disjunction the compiler
trusts. CLAUDE.md records that this landmine is "re-armed by every new
*variant*, not just every new family", and that `isPrng` was rewritten as
membership over `ALL_PRNGS` for exactly this reason. Adding `"ml-kem-768"` to
the `Asymmetric` union without widening the predicate makes `isCipher` return
**true** for ML-KEM, silently handing it a key field, a mode selector and
padding. Convert to membership over an `ALL_ASYMMETRIC` list **in P4, in the
same edit that widens the union.**

## Phases

Each phase ends green on `npm run check` and is browser-smoked before the next
begins. Per `feedback_iterative_slice_review`, **re-consult the advisor before
starting each phase** — this plan has five.

### P1 — the ring, the NTT, and a measurement spike

1. **Spike first, code second.** Build a throwaway seven-layer iterate chain
   with existing primitives only and confirm:
   - (a) `chainOutput` → the next iterate's `chainInput` resolves across
     **sibling** iterates;
   - (b) a chain rotated by `permute@1` survives 127 iterations **at a width
     that differs from `blockByteLength`** — the chain is a fixed 256 bytes
     while blocks run 512→8. Every shipped iterate has chain width *equal* to
     block width (CBC's IV, CTR's counter, SHA-256's running H), so this is the
     first divergence. `runtime.ts` reads as permissive (`prevChain` is plain
     bytes with no length check), but that is read-verified, not run-verified —
     the exact posture MT19937's plan flagged before its novel wiring;
   - (c) the node/frame cost model from "Measurements" reproduces on this
     machine;
   - (d) **what a ~381-consumer `cipherConstants["q"]` does to the canvas.**
     `replicateHighFanoutSources` splits sources above a threshold of 3, and
     CLAUDE.md's ChaCha gotcha records a 16-consumer split being **deleted and
     scattered into 16 chips** without a never-replicate guard. `q` on a port
     means every one of 127 groups × 3 vector leaves reads one source. Either
     it needs a never-replicate guard from the start or `q` rides a per-layer
     `aux-load-bytes@1`. Decide here, not after the first browser look;
   - (e) that the two-slot `SpecsByMode` path accepts a non-cipher family.
     `hasDirection()` in `App.tsx` and `isSingleSlotSpecs` in `stores/spec.ts`
     were shaped by hash/PRNG being direction-*less*; the two-slot path may
     carry cipher-shaped assumptions (mode, padding, IV) that a direction-ful
     non-cipher trips. Cheap here, expensive at integration.

   This mirrors the MT19937 plan's discipline of spiking novel wiring before
   writing any algorithm code.
2. Three new port-native step types: **`zq-vec-add@1`**, **`zq-vec-sub@1`**,
   **`zq-vec-mul-scalar@1`**. Each takes `q` on a port, `{ coeffBytes: 2,
   littleEndian: false }` as params, and is element-wise over the vector.
3. `src/ciphers/ntt-3329-256.ts` — the forward/inverse builders, plus
   `src/ciphers/mlkem-constants.ts` holding the 128 ζ values and `q` as **module
   constants, never spec params** (the Blowfish π-table precedent).
4. Fifth `Category` + `Lattice` union + selector entry + `LATTICE_IDS` and
   `assertLatticeCoverage` in `core/document-schema.ts`.

**Oracle (before any test is written, per `feedback_crypto_verification`).**
Two independent checks, and the second is the strong one:
- FIPS 203 Appendix A's published ζ table, pinned value-by-value.
- **The convolution theorem**: for random `f, g`, `NTT⁻¹(NTT(f) ∘ NTT(g))` must
  equal the schoolbook product `f·g mod (X²⁵⁶+1)` computed independently in the
  test. This checks the transform against something that is not itself the
  transform, unlike `NTT⁻¹(NTT(f)) = f`, which a pair of matched-wrong
  implementations passes — the same trap CFB's round-trip test documents.

**P1 OUTCOME (2026-08-09).** Shipped as planned, with five corrections worth
carrying into P2:

1. **`q` on a port was not achievable as written, and the plan's spike item (d)
   was asking the wrong question.** The vector leaves live INSIDE a layer's
   iterate, and `runtime.ts` seeds a body scope with only that iterate's own
   `in`/`chain` ports — so a top-level `cipherConstants["q"]` cannot reach them
   by port at all. It rides aux (`aux-load-bytes@1`) inside each body, which is
   forced rather than a canvas preference. This also dissolves the 381-consumer
   replication worry: the plan conflated frame count with spec-node count, and
   per body it is ONE aux-load feeding THREE consumers — at, not above, the
   threshold.
2. **The final scale is `128⁻¹ = 3303`, not `n⁻¹` read as `256⁻¹`.** The plan's
   phrase "a final multiply by `n⁻¹ mod q`" invites exactly the wrong constant.
   Seven layers ⇒ 2⁷.
3. **The convolution-theorem oracle needs the degree-1 base-case multiply,
   which the plan assigned to P2.** `NTT⁻¹(NTT(f) ∘ NTT(g))` with an
   element-wise `∘` is simply wrong. It is ~10 lines written inside the test.
   The stronger and cheaper rank-1 oracle turned out to be **direct CRT
   evaluation** against FIPS 203 §2.4.4's definition, which shares no code with
   the butterflies at all.
4. **The measurement model is ~20× pessimistic for the runtime alone.** The
   spike measured 43 spec nodes + 636 frames at **5.5 ms**, against 129 ms
   predicted. The 1.6 ms/node coefficient is therefore dominated by the UI
   pipeline (graph derivation, layout, Solid render), not by `runSpec`. Node
   count is still the driver and the depth decisions stand — but do not quote
   the model as wall-clock for anything that does not re-render.
5. **The coverage gates were cleared in P1, not P5** (the plan's own sequencing
   bug: the steps register in P1 and P1 must end green). The three `zq-vec-*@1`
   steps are on `PROVENANCE_NO_OP_ALLOWLIST` rather than carrying exact
   provenance fns — element-wise looks like `xor@1`'s exact column mapping but
   is not, because the dependency WITHIN one 2-byte element is value-dependent
   (carry plus the reduction), so no value-independent index fn can be exact.
   Same rationale as `add-mod@1`.

Deferred from P1, deliberately, and both worth picking up in P5:

- **`littleEndian` is read-only in the ParamEditor.** Flipping it on ONE leaf
  while its siblings keep the other convention is not a different transform, it
  is not a transform at all — a real experiment needs a scoped apply-all (the
  Speck α/β precedent).
- **The cipher-constants panel renders 258 editable byte cells** (`q`, the
  256-byte ζ table, `128⁻¹`). The shape is precedent — SHA-256's K is 256 bytes
  — but "break one ζ and watch one butterfly go wrong" is a headline experiment
  in the shipped narration, and finding the right pair among 128 unlabelled ones
  is not the two-keystroke edit MINSTD's `a` is. The table wants index labels,
  or a ζ-aware editor block.

### P2 — the rest of the lattice layer — SHIPPED 2026-08-09

Pointwise/base-case multiplication (`zq-vec-mul-pointwise@1`), polynomial
add/sub reuse P1's steps, `zq-compress@1` / `zq-decompress@1`,
`zq-byte-encode@1` / `zq-byte-decode@1` (the 12-bit packing, and the LE
crossing), and centered-binomial sampling `zq-cbd@1`. No new selector entry —
P2's surface is the test suite plus the palette.

Compression is the one place ML-KEM is *lossy*, and it is why decapsulation can
be correct without the ciphertext being invertible. That fact belongs in
`zq-compress@1`'s own `detail`, not only in a plan file.

**Oracle: FIPS 203's published intermediate values where they exist, and
otherwise transitive through P3.** Be honest about which is which — compression,
12-bit packing and CBD are three independent places to be subtly wrong, and P3's
`ek` comparison catches them only *in aggregate*, so a compensating pair of
errors survives it. Pin `Compress`/`Decompress` and `ByteEncode`/`ByteDecode`
directly against the FIPS 203 §4.2.1 formulas over the full coefficient range
(they are total functions on `[0, q)` — exhaustive testing is cheap at
`q = 3329`), and pin CBD against the reference bit-counting definition. Only
then lean on P3.

**P2 OUTCOME (2026-08-09).** Shipped as five step types across four commits
(`f4239d3`, `0ac8159`, `f521b91`, `96847ef`), with six corrections worth
carrying into P3.

1. **The step is NOT "pointwise", and the plan's own name for it is the trap.**
   Multiplying two transformed polynomials element-wise is what every other
   transform buys you and is simply wrong here — the transform stops at 128
   degree-1 polynomials, so a product is a per-PAIR multiply in
   `Z_q[X]/(X²−γ)`. Shipped as **`zq-base-case-mul@1`**, deliberately breaking
   the `zq-vec-` family prefix, because a learner meets the name in the palette
   before the description. It is **polymorphic over `k` pairs**: `k = 128` with
   the whole γ table is `MultiplyNTTs`, `k = 1` is one `BaseCaseMultiply` — so
   P3 drops this same executor inside an iterate rather than needing a second
   step type. A test pins that the two forms agree.
2. **The γ exponent in this plan is WRONG and is corrected in code.** The
   Critical-files line said "the 128 ζ² base-case values"; FIPS 203 Alg 11 uses
   `ζ^(2·BitRev7(i) + 1)`. The missing `+ 1` gives `1, 3328, 1729, 1600, …`
   where the true table is `17, 3312, 2761, 568, …`. `GAMMAS` derives it as
   `ZETAS[i]²·17` so the relation to the published table stays visible. Note
   P1's *test* oracle already had the exponent right — only the prose was wrong,
   which is exactly why the code was checked against FIPS rather than against
   the plan. **Second independent check, worth reusing:** `γ[2i] = ZETAS[64+i]`
   and `γ[2i+1] = q − ZETAS[64+i]`, so the upper half of the published ζ table
   re-verifies this one.
3. **`Compress(Decompress(y)) = y` holds only while `2^d ≤ q`.** The plan said
   "verify it, don't assume" and the verification paid: at `d = 12` it fails,
   because 4096 bucket indices cannot survive a trip through 3329 values. That
   is pigeonhole rather than a rounding slip, and it is why FIPS 203 defines
   `Compress_d` for `d < 12` only. Also measured: `q` being odd means
   compression can never hit a rounding tie, so **the tie rule is observable
   only in decompression** — a truncating compressor passes every tie-focused
   spot check anyone would write.
4. **Write FIPS 203's `m` as `min(2^d, q)`, never as a `d === 12` branch.** The
   rule exists because 12 bits can carry 4095, which is not a ring element, and
   every narrower `d` cannot. The min reproduces it exactly at `q = 3329` and
   keeps behaving sensibly if a learner edits `q`, where a literal 12 goes
   quietly wrong.
5. **An external oracle existed in P2 that this plan said would only be
   transitive through P3.** `tests/zq-byte-encode-decode.test.ts` carries a real
   ML-KEM-768 `ek` from Node 24's OpenSSL: decoding it FIPS-fashion yields 768
   coefficients all inside `[0, q)` (where ~19% of random 12-bit values are
   not), and re-encoding reproduces it byte for byte. **Captured as a byte
   fixture, not generated** — CI runs Node 22 and has no ML-KEM, so a live call
   would skip there, which is the vacuous-suite hole. See the CORRECTION block
   in P3 for why it could not be seed-reproducible anyway.
6. **`insertStepIntoSpec` gives a palette-dropped leaf `params: {}`.** Any
   ParamEditor row gated on a value being *present* therefore vanishes exactly
   when the user needs it — a dropped `zq-compress@1` could never be given its
   `d`. Rows must be keyed on the step TYPE. Found by writing
   `tests/zq-param-editor-coverage.test.tsx`, which exists because the standing
   `param-editor-coverage.test.tsx` walks only types appearing in a SHIPPED
   spec — a scope that does not cover a palette-only family. This generalises
   past the lattice layer and is now in `docs/gotchas.md`.

Deliberately deferred, and each is a P3 obligation rather than an omission:

- **No narration.** All five omit `shapeContract`, so
  `tests/narration-registry-contract.test.ts` passes them silently — the hole
  CLAUDE.md names. Correct for P2, since no spec uses them. **The moment K-PKE
  wires them in, five leaves render with zero narration and CI stays green.**
  Register real `NarrationFn`s in P3 and scrub to the frames in a browser.
- **No browser pass.** The only surfaces P2 touches are the ParamEditor block
  and the palette chip; the jsdom coverage test above drives the real
  drop-then-edit path and is strictly more durable than a look, and the palette
  chip plus doc panel are registry-driven. Stated rather than left unsaid.
- **`d` and `η` are editable; `coeffBytes` and `littleEndian` stay read-only**,
  per P1's deferral. `d`'s two families label it differently ("Bits kept" vs
  "Bits per coeff") because one discards and the other does not.

### P3 — K-PKE (the IND-CPA core) — SHIPPED 2026-08-10

`KeyGen`, `Encrypt`, `Decrypt` per FIPS 203 §5, with the five `ml-kem.*` Keccak
monoliths. No selector entry yet — shipping a half-algorithm to users would
miseducate; P3's proof is its KAT.

**`ml-kem.sample-ntt@1` must loop until acceptance — the monolith hides the
loop, it does not remove the obligation.** `SampleNTT` squeezes SHAKE128 and
rejects candidates `≥ q`; with acceptance ≈ `3329/4096`, the number of squeeze
blocks needed is a **random variable with no fixed bound**, and a matrix is nine
independent draws, so the relevant quantity is the maximum over nine. Hardcoding
"squeeze three blocks" inside the executor produces a **silently wrong matrix on
some seeds** — a wrong `ek` that only fails the Node comparison for the seeds
you happened to test. This is the same failure class as RSA's unroll bound
(`K = eeaMaxIterations(W)`), which CHANGELOG records as "a *silent* wrong `d`
for some user-entered key"; the difference is that here the loop is inside an
executor and so has no bound to prove — it just has to actually be a loop.
Make the accepted-coefficient count the loop condition, never the block count.

**Oracle: `node:crypto` on Node 24, verified available at plan time.**
`crypto.generateKeyPairSync("ml-kem-768", { seed })` accepts a caller-supplied
64-byte seed and is **deterministic**, so our K-PKE key generation from `d‖z`
must produce the encapsulation key byte-identically. Extracting it: the SPKI DER
export is a fixed 22-byte header followed by the raw 1184-byte `ek`, and
re-importing a hand-assembled SPKI works (probed at plan time). Encrypt/decrypt
are pinned transitively in P4.

> **CORRECTION, measured during P2 (2026-08-09) — the seed is IGNORED.** On
> **Node v24.14.1**, `generateKeyPairSync("ml-kem-768", { seed })` accepts the
> option without complaint and returns a **different key on every call**: three
> successive runs with `Buffer.alloc(64, 7)` produced three different `ek`s. So
> the "deterministic from `d‖z`" oracle above **does not exist as written**, and
> P3 must not be planned around it. What was verified at plan time was
> availability and the SPKI layout, both of which hold (`spki.length` 1206, the
> trailing 1184 bytes being `ek`); the determinism half was assumed. Three
> options for P3, in the order worth trying: (a) import a private key from a
> hand-assembled PKCS#8 carrying the **seed** choice of the ML-KEM `PrivateKey`
> CHOICE, then derive `ek` from it — the exported PKCS#8 here is 2498 bytes, so
> this build stores an expanded form and the seed form needs checking; (b) drop
> to published FIPS 203 intermediate values / the ACVP vectors; (c) pin against a
> second independent implementation. Resolve this **before** writing P3's KAT,
> not after — it decides what P3 can claim.
>
> Also worth carrying forward: a `node:crypto` `ek` is still a perfectly good
> oracle for anything that does not need reproducibility. P2 used one to pin the
> 12-bit packing (`tests/zq-byte-encode-decode.test.ts`), which the plan had
> assumed would only be checkable transitively through P3 — **captured as a byte
> fixture**, because CI runs Node 22 and has no ML-KEM at all.

> **RESOLVED at the start of P3 (2026-08-10) — option (a) works, and gives more
> than `ek`.** A hand-assembled PKCS#8 carrying the `seed` arm of the ML-KEM
> `PrivateKey` CHOICE imports cleanly on v24.14.1 and is fully deterministic, so
> the seed → key oracle exists after all — we choose the seed, rather than being
> handed one. Four measured facts:
>
> - **The `[0]` tag must be IMPLICIT** (`0x80 0x40 <64 bytes>` inside the outer
>   `OCTET STRING`). The EXPLICIT spelling (`0xa0`) and a bare `OCTET STRING`
>   are both rejected with `error:1E08010C:DECODER routines::unsupported`.
> - **`generateKeyPairSync`'s own export uses the *both* arm** — `SEQUENCE {
>   OCTET STRING (64) seed, OCTET STRING (2400) expandedKey }`, hence the 2498
>   bytes the correction above noticed. So the seed is recoverable from any
>   generated key, and re-importing it reproduces that key exactly. That is how
>   the two halves were cross-checked rather than assumed.
> - **The expanded `dk` is FIPS 203 §7.1's layout, verified byte for byte**:
>   `dk_PKE (1152) ‖ ek (1184) ‖ H(ek) (32) ‖ z (32)`. This is the part that
>   beats the original plan: P3 gets a direct oracle for K-PKE keygen's **secret**
>   half (`ByteEncode_12(ŝ)`), not merely for `ek`, so a wrong CBD or a wrong NTT
>   on `s` is caught where it happens instead of only through `t̂`.
> - **P4's oracle works through a seed-imported key too**: `encapsulate` /
>   `decapsulate` round-trip, and a corrupted ciphertext decapsulates without
>   throwing to a deterministic, different secret.
>
> Captured as `tests/fixtures/ml-kem-768-seed-vectors.json` (18 seeds → `ek`,
> `dk_PKE`, `H(ek)`; 4 encapsulations; one cross-decapsulation pair), because CI
> is on Node 22. Every seed is derived from its own label so the fixture is
> rebuildable; the harvest script is `M:\claud_projects\temp\p3-oracle\harvest.mjs`
> and its essentials are documented in `tests/ml-kem-oracle-fixture.test.ts`'s
> header. Two of the eighteen seeds share `d` and differ in `z`, which is the only
> way the fixture can assert §7.1's split — same `ek`, same `dk_PKE`, different
> implicit-rejection secret. That pins P4's hardest-to-see branch before P4 starts.

**P3 OUTCOME (2026-08-10).** Shipped as planned. Six things worth carrying into
P4:

1. **Encrypt and Decrypt had a direct oracle after all, and it is the FO loop
   run test-side.** The plan expected them to be "pinned transitively in P4",
   because the fixture's encapsulations are ML-KEM's — `crypto.encapsulate`
   picks `m` internally, so no seed → `(m, r)` → `c` row exists. But decrypting
   OpenSSL's ciphertext gives `m′`, `(K′, r′) = G(m′ ‖ H(ek))` is computable in
   the test, and re-encrypting must reproduce `c` **byte for byte**. That single
   assertion pins Decrypt against OpenSSL's Encrypt, Encrypt against it, and `G`
   — and it front-loads P4's hardest machinery. Round-trip still ranks last.
2. **The plan's SampleNTT block-count assertion was VACUOUS as worded.**
   "Enough seeds that at least one polynomial demonstrably needs an extra squeeze
   block" — but acceptance is ~3329/4096, so 256 coefficients need ~315
   candidates ≈ 473 bytes and **every** draw already spends three 168-byte
   blocks. Measured over the fixture's 162 draws: **160 take three, 2 take
   four.** The live assertion is that the count *varies*; the executor exposes it
   on a `squeezes` output port so it is observable rather than argued.
3. **Three published facts checked against the fixture before any spec code, and
   each wrong variant is self-consistent.** `G(d ‖ k)` not `G(d)` (the draft's
   spelling; breaks ρ). `A[i][j] = SampleNTT(ρ ‖ j ‖ i)` in KeyGen and `ρ ‖ i ‖ j`
   in Encrypt — the byte swap IS the transpose (breaks `ek`, leaves ρ and
   `dk_PKE` green). `N` = 0,1,2 for `s` then 3,4,5 for `e` (breaks `dk_PKE`,
   leaves ρ green). All three failure signatures are pinned as perturbations, so
   a future breakage announces which layer it is in.
4. **The three checkpoints work exactly as hoped, and they are why KeyGen is its
   own spec.** ρ → `dk_PKE` → `ek`, in that order, each failing where its cause
   lives. This is the whole argument against a single combined spec.
5. **Measured budget, and the 1.6 ms/node model is again ~8× pessimistic for
   `runSpec` alone**: keygen 485 nodes / 6,197 frames / **146 ms**; encrypt 572 /
   7,236 / **129 ms**; decrypt 293 / 4,101 / **22 ms**. P1's finding restated —
   that coefficient is the UI pipeline, not the runtime. At the UI rate P4's
   encapsulation lands near ~1.0 s, inside the budget the CSPRNG occupies, so
   **no depth decision needs revisiting**.
6. **Node-id prefixing is load-bearing and was made explicit.** Six transforms in
   one spec means six `layer1.split`; the flat trace keys frames by `stepId`, so
   a collision breaks the scrubber and the graph derivation **without an error**.
   `buildNttNodes`/`buildNttGroup` take a prefix and a test asserts two embedded
   groups have disjoint id sets. Any future "embed an existing spec N times" work
   inherits this obligation.

### P4 — ML-KEM encapsulation and decapsulation — SHIPPED 2026-08-10

The Fujisaki–Okamoto wrapper: `G`, the re-encryption check, and implicit
rejection via `J`. Adds `"ml-kem-768"` to `Asymmetric`, widens `isAsymmetric` to
membership (see above), and adds the id to `ASYMMETRIC_IDS` /
`ALGORITHM_IDS` — the latter surfacing as a cryptic
`Type 'true' is not assignable to type 'never'` if missed.

**Oracle.** `crypto.decapsulate(dk, ct)` on a `dk` grown from our own seed must
return our shared secret — which pins K-PKE's encrypt path transitively, since a
wrong ciphertext cannot decapsulate to the right key. And `crypto.encapsulate`
on our `ek` produces a `(ct, K)` our decapsulation must reproduce. **Test the
implicit-rejection path explicitly**: a corrupted ciphertext must yield a
*different but deterministic* shared secret, never an error. That branch is
invisible to every round-trip test and is the whole difference between the
IND-CPA core and the IND-CCA KEM.

Watch the **vacuous-suite hole** (`validated-growing-dongarra.md`): any surface
test that iterates an options list passes green when a variant is missing. Pin
against `Record<Asymmetric, string>`'s compiler-enforced keys.

#### Settled before any code (2026-08-10 — measurements + two user decisions)

**Measured**, by running the three SHIPPED P3 builders (throwaway test, deleted):

| spec | nodes | frames | `runSpec` |
|---|---|---|---|
| K-PKE.KeyGen | 485 | 6,197 | 145 ms |
| K-PKE.Encrypt | 572 | 7,236 | 173 ms |
| K-PKE.Decrypt | 293 | 4,101 | 28 ms |

So an ML-KEM spec's size is a matter of which K-PKE bodies it embeds, and the
one open design question was whether key generation is one of them.

1. **Key material: the key pair is BORN INSIDE BOTH SPECS** (user decision;
   the plan's original design, chosen over the two cheaper alternatives). The
   64-byte seed `d ‖ z` is the editable source of truth — RSA's `p, q, e`
   precedent — and a default-collapsed key-generation group derives `ek`,
   `dk_PKE`, `h = H(ek)` and `z` from it in both directions. Cost: encaps
   ≈ 1,065 nodes, decaps ≈ 1,355 nodes / ~17.5k frames, against a fitted
   ~1.6 ms/node + ~0.095 ms/frame UI pipeline that predicts 3–4 s per re-run —
   ABOVE the ~2.0 s ceiling the CSPRNG occupies. **The prediction is a model,
   not a measurement, and this plan has twice recorded that model as ~8–20×
   pessimistic for `runSpec`.** Browser-measure the real decaps re-run and
   report it; if it is genuinely unusable, the fallback (already costed) is
   `dk` through aux the way K-PKE Encrypt/Decrypt already take it, at
   ≈ 870 nodes.
2. **Implicit rejection is ONE leaf**, `ml-kem.select-shared-secret@1` (user
   decision, one teaching point ⇒ one leaf, the `twofish.h-expand@1`
   precedent). FIPS 203 §7.3's `if c ≠ c′ then K′ = J(z ‖ c)` cannot be a
   branch — the spec model is straight-line step/group/iterate — and a select
   is the honest depiction anyway: both secrets are computed every time, and
   one is chosen without leaking which. The verdict is what its narrator
   prints. Gates it must clear: `tests/port-provenance-coverage.test.ts` AND
   `tests/port-provenance.test.ts`'s own count, `NO_PARAMS_PORT_NATIVE_TYPES`
   + `portNativeNoParamsLabel`, and the narration contract — which now
   **auto-enrols it** through P3's `ml-kem.` prefix walk, so it fails loudly
   instead of passing silently. That is the P3 narration work paying off in
   the very next phase.
3. **Family placement stays `Asymmetric`.** The plan's revisit condition
   ("if the lattice category has by then grown a second member") is NOT met —
   lattice still has exactly one selectable member — and the placement puts
   ML-KEM beside RSA, which is the comparison that teaches.
4. **The encaps oracle is already direct**, which the plan expected to need
   building: `tests/k-pke-kat.test.ts` runs the FO recovery today
   (`m′ = Decrypt(dk, c)` on the fixture ciphertext, then `(K′, r′) = G(m′ ‖ H(ek))`
   test-side). So encaps is pinned byte-for-byte on BOTH `ciphertext` and
   `sharedSecret` with no new oracle work.

**Order of operations**, with the one step that is easy to get backwards first:

1. **Capture digests of the three shipped K-PKE specs BEFORE touching
   `k-pke.ts`**, then extract prefixable node-list builders from it and assert
   byte-identity after. This is the CSPRNG `buildDoubleRoundGroups` extraction
   verbatim — take the digests afterwards and the test pins the new bytes to
   themselves. **Node-id prefixing is load-bearing in a way P3 only half
   exercised**: decaps embeds THREE K-PKE bodies, each carrying `layer1.*`
   iterate ids, and a collision produces no error at all — just a broken
   scrubber, broken frame preservation and a wrong graph.
2. `ml-kem.select-shared-secret@1` + its gates.
3. `src/ciphers/ml-kem-768.ts` — the two builders.
4. The family surface. Widen the `Asymmetric` union, add to `ALL_ASYMMETRICS`
   and convert `isAsymmetric` to membership **in the same edit**, then perturb
   the predicate to prove the guard test is live. The three
   `Record<Asymmetric, …>` tables are compiler-enforced; the option list is
   not — that is the landmine.
5. `tests/ml-kem-768-kat.test.ts`, ranked by what discriminates: `hEk` →
   `ek` / `dk_PKE` → encaps `c` + `K` → decaps `K` → **`rejectedSharedSecret`**
   (the strongest assertion in P4, and already sitting in the fixture) →
   round-trip LAST.
6. The browser scrub (below), then docs + memory.

**Published facts to check against FIPS 203 itself, not against this plan, and
to ship as perturbations so the failure signature is pinned** — each has a
wrong version that is entirely self-consistent, which is how P2 and P3 both
caught this plan stating a constant wrongly:

- `J(z ‖ c)` takes the **received** `c`, never the re-encrypted `c′`. With a
  valid ciphertext the two are equal, so this is invisible to every test that
  does not corrupt one.
- Which 32 bytes out of `G`'s 64 are `K` and which are `r`.
- Decapsulation uses the `h` **stored inside `dk`**, not a freshly recomputed
  `H(ek)`. With keygen inside the spec these are equal by construction, so say
  so where the spec computes it.
- The `dk` parse offsets of §7.1's `dk_PKE ‖ ek ‖ H(ek) ‖ z`.

#### OUTCOME (2026-08-10) — what P4 actually cost, and what it found

**Shipped in four commits**: the K-PKE extraction (prefixable node lists +
pre-refactor spec digests), `ml-kem.select-shared-secret@1`, the two specs plus
the family surface, and the browser scrub.

**Measured, all three predictions wrong in the same direction.** Encapsulation is
1,066 nodes / 13,441 frames; decapsulation 1,359 / 17,542. `runSpec` takes 1.5 s
and 0.9 s. In the browser a decapsulation re-run settles in **~0.9 s** — the
fitted 1.6 ms/node + 0.095 ms/frame model predicted 3–4 s and would have argued
for taking `dk` through aux and never showing the key being born. That is the
third phase running where the coefficient is pessimistic; treat it as an upper
bound on the UI pipeline, never as a design constraint on its own.

**Five things worth carrying forward.**

1. **A group has exactly ONE input port**, and that is what decided which bodies
   are collapsed. Key generation takes only the seed, so it groups for free; the
   encryption and decryption bodies take two and three inputs and could only be
   boxed by concatenating outside and splitting back inside — plumbing serving
   the box rather than the algorithm. The group's single output is `ek ‖ dk`,
   which is exactly what FIPS 203's KeyGen returns, so the split outside it is
   the standard's own `(ek, dk)` rather than an artefact of the constraint.
2. **`q` and `gamma` appear twice** because port flow cannot cross a group
   boundary. Third time this constraint has decided a design (after the CSPRNG's
   seed and the NTT's modulus); `kPkeConstantNodes` now takes a prefix.
3. **The wrong version of `J(z ‖ c)` is unrepresentable without moving nodes.**
   Same-scope wiring is forward-only, so binding `j-in` to `re.c` where it stands
   throws rather than computing the wrong answer. A weak structural guard, but a
   real one — and the perturbation test had to relocate two nodes to write the
   mistake at all.
4. **The browser scrub found a bug no headless test could.** Switching from RSA
   to ML-KEM left RSA's 2-byte message in the field and the trace died on
   `zq-vec-add: ports "a" (512 bytes) and "b" (32 bytes)`. The public-key
   dropdown wired straight to `setAsymmetric` with no smart input swap — because
   RSA was the only member, so a variant switch was **unreachable and therefore
   untested**. Generalised in `docs/gotchas.md`: a one-member family's
   variant-switch handler is dead code until the second member lands.
5. **The fixture's corruption is `c[0] ^= 0x01`.** It records the flag
   `corruptedCiphertextFlipsByte0` but not the value; a different flip gives a
   different decoy that reads as a broken implementation. Found by trying `0xff`.

**Two coverage gaps found by the closing advisor pass, both now closed.** (a) The
plan asked for `isAsymmetric` to be perturbed and it had not been. Deleting
`"ml-kem-768"` from `ALL_ASYMMETRICS` passes `tsc` cleanly — the list is
`readonly Asymmetric[]`, and the `Record<Asymmetric, …>` tables stay green — and
was caught only incidentally, by a UI test noticing the dropdown had lost an
option. Nothing asserted `isCipher` staying false. `tests/asymmetric-family-surface.test.ts`
now does, in the shape `prng-family-surface.test.ts` established, with the
anti-vacuity list pin FIRST because every other assertion iterates the list.
(b) `document-roundtrip.test.ts` does not enumerate algorithms, so it passed
throughout P4 without ever touching an ML-KEM document; the new file round-trips
each variant.

**One graph observation, deliberately not acted on.** `dk-split` has four
consumers against the replication threshold of three, so it scatters into ghost
chips beside them — `replicateHighFanoutSources` counts consumers per source
NODE, not per output port. Rendered and looked at: it is the same treatment `q`
and `gamma` already get, there are no warning glyphs, and unlike Twofish and
ChaCha there is no canonical layout cell for it to break. **Revisit when P5 adds
the butterfly cell** — that is when a `neverModes` guard becomes the question it
was for those two.

**The narration debt is CLOSED.** All twelve narrated lattice types were read on
screen at the parameters this section names — `zq-compress@1` at d = 10 / 4 / 1,
`zq-decompress@1` at all three, `ml-kem.hash-g@1` at both call sites,
`ml-kem.sample-ntt@1` reporting a real block count, and `ml-kem.hash-h@1` /
`ml-kem.kdf-j@1` rendered outside a test spec for the first time. The select was
read in BOTH verdicts: flipping one ciphertext bit in the field turns "the
ciphertexts MATCH" into "the ciphertexts DIFFER in 1 of 1088 bytes", names the
divergent byte, and changes the output without raising an error.

#### The narration debt — PAID 2026-08-10, with one half deliberately left open

P3 recorded that the P2/P3 step types omit `shapeContract`, so
`narration-registry-contract.test.ts` passed all fourteen of them silently, and
that this would bite the moment P4 made ML-KEM selectable. That was paid ahead of
P4 rather than inside it:

- **Eleven narrators** in `src/ui/narration/lattice.tsx`, one per lattice step
  type whose teaching point is per-frame; **three allowlisted**
  (`zq-vec-add|sub|mul-scalar@1` — 128–256 identical coefficients per frame, so
  the only honest conceptual unit would mean hundreds of `<details>`).
- **The gate hole is closed for this family** by a prefix-derived walk over
  `registry.types()` (`zq-` / `ml-kem.`) rather than a hand-list, so a
  fifteenth lattice step enrols automatically. Verified live by perturbation.
- Driven through **real frames from the shipped K-PKE specs** in
  `tests/lattice-narration.test.tsx`; `ml-kem.hash-h@1` / `ml-kem.kdf-j@1`, which
  no shipped spec emits until the FO wrapper, get a purpose-built two-leaf spec
  so their narrators are still exercised by the real runtime.

**The open half, and it is P4's to close.** *None of the eleven is reachable in a
browser yet.* The only user-selectable lattice spec is the NTT, and it emits
**exactly** the three ALLOWLISTED types — so no amount of clicking today renders
a single one of these narrators. They are pinned by jsdom render assertions over
real frames, which is strictly weaker than looking:
`feedback_visual_smoke_vs_property_tests` is on the record twice in this plan
already. Layout, disclosure-row density on a 256-coefficient frame, and whether
the `<details>` labels are legible at all are precisely the properties these
tests are blind to.

**Scrub ACROSS frames of the same step type at different params — not one frame
per type.** One-per-type is the weaker pass and would have missed the worst bug
this work produced. Minimum coverage: `zq-compress@1` at **d = 10, 4 AND 1**,
`zq-decompress@1` at **d = 1 vs 10**, `ml-kem.hash-g@1` at **all THREE call
sites** (keygen's `d ‖ k`, encaps' `m ‖ H(ek)`, decaps' `m′ ‖ h` — it was two
when this was written; the FO wrapper adds the third), and several
`ml-kem.sample-ntt@1` draws (the block count is the whole point). Add
`ml-kem.hash-h@1` and `ml-kem.kdf-j@1`, which no shipped spec has ever emitted:
their narrators have been rendered ONLY inside a purpose-built two-leaf test
spec, so nobody has looked at them at all.

Two narrator bugs are already on the record from this work, and they are the
argument that the scrub is not a formality:

1. `zqCompressNarration` printed FIPS 203's error bound with an integer floor,
   so at `d = 10` it rendered "worst error 2 of a possible 1". The bound is
   `⌈q/2^(d+1)⌋` — round to **nearest**. Caught only because the test derives
   the bound independently instead of reusing the narrator's expression.
2. The same narrator's third row called a **`d = 1` compression a ciphertext
   size optimisation** — but that leaf is Decrypt *recovering the message*, the
   one place compression is applied to the message rather than a ciphertext. The
   test asserting `(d = ${d})` appears for every `d` was blind to it by
   construction: it only exercises the first row's headline. Fixed with a
   `d === 1` arm mirroring the decompress narrator's, plus a negative test.
   **`zq-compress@1` runs at `d ∈ {10, 4, 1}` — assuming `{10, 4}` is wrong.**

Both are the same failure mode: prose that is correct for the frame the author
had in mind and false for a sibling frame of the same step type. That is what
scrubbing across params catches and what a per-type spot check does not.

### P5 — pedagogy — SHIPPED 2026-08-10

Canonical NTT butterfly layout (the fourth member of the
`feistel-shape` / `twofish-shape` / `arx-group` family), a linear-view diagram
of one butterfly and one degree-1 base-case multiplication, per-leaf narration
for every new step type, and the docs sweep: `README.md`'s feature table,
`CHANGELOG.md`, `docs/key-files.md`, `docs/gotchas.md`, CLAUDE.md's architecture
notes, and a memory update.

Every new bare-name port-native step must clear **both** coverage gates —
`tests/port-provenance-coverage.test.ts` (whose set-pin lives in *two* files)
and `tests/narration-registry-contract.test.ts` — plus a `ParamEditor` block and,
for the no-params steps, entries in `NO_PARAMS_PORT_NATIVE_TYPES` and
`portNativeNoParamsLabel`.

#### OUTCOME (2026-08-10) — what P5 actually cost, and what it found

**Shipped in two commits**: the canonical butterfly cell (`core/ntt-shape.ts` +
`core/ntt-layout.ts` + the `GraphView` threading), and the two linear-view
diagrams (`core/ntt-diagram.ts` + `NttButterflyDiagram` +
`ZqBaseCaseMulDiagram`). **Zero new step types**, as the phase's own brief
required — every part of P5 is derivation over leaves that already existed, so
it cleared no coverage gate. The per-leaf narration the brief also listed was
paid ahead of P4 and was not reopened.

**Eight things worth carrying forward.**

1. **The cell is the family's FIRST keyed on an `iterate` rather than a group.**
   All three predecessors (`feistel` / `twofish` / `arx`) analyze a `StepGroup`,
   and `layoutNode`'s three canonical branches each gate on
   `container.kind === "group"`. A layer body is a port-mode `iterate`, so this
   one gates on `kind === "iterate"`. It is safe for a reason worth stating
   rather than trusting: `expandCollapsedIterates` replaces a body with
   per-block chips only when the iterate is COLLAPSED, so a cell and a chip row
   are mutually exclusive **by construction**.
2. **The grid was derived from an EDGE-ROUTER fact, and the audit that found it
   generalises.** The router draws a cubic holding the SOURCE's y for the first
   half of its x-span and settling onto the TARGET's y for the second. The
   consequence that decided two placements: a source outside two same-row boxes
   cannot reach the far one without entering the near one, because the far
   box's y *is* the near box's y-band. So the modulus sits BETWEEN the rails,
   and the ζ pair takes a row of its own with the rotation rightmost.
   Both were found by **sampling every rendered path against every leaf box** in
   a real browser and asking which boxes it passes through that are not its
   endpoints — a check strictly stronger than looking, and the first time this
   project has run it.
3. **The measurement.** Wires crossing a box they do not terminate at:
   forward 34 → 1, inverse 47 → 1; canvas ~12,800 → ~6,600 px wide. The two
   survivors are pre-existing and outside any cell, **confirmed by re-running
   the audit with the recognizer stubbed out** rather than by reasoning about
   which were whose.
4. **One slot table serves both butterflies, and that is not a shortcut.** The
   analyzer resolves the direction into ROLES before the layout sees anything,
   and the role sets differ exactly where the shapes do — a Cooley–Tukey body
   has `{twist, hi}` and never a `diff`, a Gentleman–Sande one the reverse. A
   test pins that disjointness, because losing it would silently collide two
   leaves into one position.
5. **The replication guard here is INSURANCE, not a fix — the opposite of ARX's,
   and the test says so.** Nothing crosses the default threshold of 3: the
   Cooley–Tukey split and the modulus feed exactly three consumers each and the
   check is a strict `>`. But the threshold is a user control that goes to 1,
   and at 2 the cell loses both hubs. Recording which kind of guard it is
   matters more than having it.
6. **The butterfly diagram is the first DIRECTION-AWARE one since Twofish.**
   ChaCha20's and Salsa20's diagrams are direction-blind because those specs are
   structurally identical; the NTT's are not, so the twiddle box moves to the
   other side of the crossing. Two geometry bugs in it were invisible to every
   unit test and found only by looking: the crossing's two diagonals were
   computed onto a single x (the X rendered as one vertical line), and the
   inverse's longest output line ran past the viewBox and vanished.
7. **`zq-base-case-mul@1` IS browser-reachable** — the plan left that open. It is
   emitted by K-PKE's matrix-vector product, so it reaches a user through
   ML-KEM-768. Its test drives the frame through **the spec store at
   `ml-kem-768`**, not a locally built K-PKE spec, which is both the honest path
   and the fix for the first version rendering nothing: these components read
   the ACTIVE spec, so a locally built one is invisible to them. The same
   mistake had the butterfly tests asserting against the forward diagram twice.
8. **`dk-split` — the P4 revisit, resolved: NO ACTION, deliberately.** P4
   conditioned it on this phase ("that is when a `neverModes` guard becomes the
   question it was for those two"). The answer is no, and the reason is that the
   condition turned out not to apply: `dk-split` is not a butterfly member, so
   no canonical cell contains it and none can be broken by its replication. It
   keeps the treatment `q` and `gamma` already get, with no warning glyphs. The
   guard added in this phase is scoped to recognized butterflies and does not
   name it.

**Verified in a real browser, both contexts.** The cell and both diagrams were
read on screen in both directions of the standalone NTT, and the geometric audit
was run against both. The cell **rendered inside ML-KEM-768** — where the layers
sit two scopes deeper inside default-collapsed transform groups — was closed by a
**throwaway Playwright spec** after the browser extension dropped mid-phase; the
workaround existed, so leaving it open would have been a choice rather than a
blocker. The real question there was never the cell's geometry (the layout branch
reads only `container.kind` and the shape map, both already tested at depth) but
whether a collapsed transform group expands to show layer boxes at all. It does:
with everything expanded, the butterfly leaves land in consecutive groups of
eight on exactly **five distinct y values at a 60 px pitch** — the cell's grid,
where the generic ribbon would give one or two. The spec was run once, recorded,
and deleted, per the dormant-Playwright posture.

Two mechanics worth reusing if another throwaway spec is needed: the view
switcher is a **`tab` role, not a button** (read off the failure's
error-context YAML rather than guessed), and clicking a container header
directly is defeated by neighbouring leaf rects intercepting the pointer on a
~14,000 px canvas — drive the toolbar's own `expand all` instead, which
exercises the same expansion path.

## Critical files

**New:**
- `src/ciphers/mlkem-constants.ts` — `q`, the 128 ζ values, the 128 base-case γ
  values, `128⁻¹ mod q`. Module constants, never spec params. **The γ values are
  `ζ^(2·BitRev7(i) + 1)`, NOT `ζ²`** — this line said `ζ²` until P2 corrected it,
  and the missing `+ 1` yields a table that agrees with nothing (see the P2
  OUTCOME block). Likewise `128⁻¹`, not `n⁻¹` read as `256⁻¹`.
- `src/ciphers/ntt-3329-256.ts` — forward/inverse layer-iterate builders (P1).
- `src/ciphers/k-pke.ts` (P3, SHIPPED) — three separate builders, not one
  combined spec, because the oracle gives **checkpoints** and a combined spec
  would throw them away. `ek`/`dk_PKE`/`r` reach Encrypt and Decrypt through
  `cipherConstants` + `aux-load-bytes@1`, the channel `q` and ζ already use.
  `src/ciphers/ml-kem-768.ts` — the KEM spec (P4).
- `src/steps/zq-*.ts` — the vector primitives. P1: `zq-vec-add@1`,
  `zq-vec-sub@1`, `zq-vec-mul-scalar@1`. P2: `zq-compress@1`,
  `zq-decompress@1`, `zq-byte-encode@1`, `zq-byte-decode@1`, `zq-cbd@1`,
  `zq-base-case-mul@1`.
- `src/steps/ml-kem-*.ts` — the five Keccak monoliths (P3).
- `src/ciphers/keccak-compute.ts` — the sponge in one call, for those monoliths
  (P3). **Not a second Keccak**: it drives the same nine step executors
  `buildKeccakRound` emits as spec nodes, with the same constants, so the
  one-frame hash inside ML-KEM cannot drift from the sponge the Hash selector
  shows. Measured at ~48 ms for a keygen-sized workload, and pinned against both
  `node:crypto` and the app's own traced `buildSha3256Spec()`.

**Modified:**
- `src/ui/stores/cipher.ts` — fifth `Category`, `Lattice` union, `Asymmetric`
  widening, **`isAsymmetric` → membership**.
- `src/ui/stores/spec.ts` — `defaults` table, a `LatticeSpecsByMode` slot
  (two-slot, like ciphers), `setAlgorithm` routing.
- `src/core/document-schema.ts` — `LATTICE_IDS`, `ASYMMETRIC_IDS`,
  `ALGORITHM_IDS`, and their `assert*Coverage` compile-time pins.
- `src/ciphers/default-registry.ts` — register every new step type + doc.
- `src/ui/components/ParamEditor.tsx` — a block per new step type.
- `src/ui/App.tsx` — category-gated surfaces (the `"lattice"` arm).
- `src/ui/narration/` — a narrator module for the lattice family.

**Read, not modified — the patterns being reused:**
- `src/core/runtime.ts:257-395` — the port-mode iterate the NTT layers ride.
- `src/ciphers/keccak-f.ts` + `src/ciphers/sponge.ts` — what the monoliths call.
- `src/ciphers/rsa.ts` — the `asymmetric` surface and in-spec key generation.
- `src/ciphers/modes/cbc.ts` — `chainInput`/`chainFeedback`/`chainOutput`.
- `src/steps/add-mod.ts` — why a modulus belongs on a port.

## Verification

- **Per phase:** `npm run check` green (biome + tsc + vitest + build), and a
  real-browser smoke via `npm run dev` — select the algorithm, confirm the trace
  renders, scrub a frame, expand a layer, read the narration, zero console
  errors. `feedback_visual_smoke_vs_property_tests` is on the record here:
  ~60 green tests once hid a shape failure that one browser look caught.
- **P1:** ζ table pinned against FIPS 203 Appendix A; convolution-theorem test
  against an independent schoolbook multiply; `INTT(NTT(f)) = f` ranked **last**
  because it is the weak one.
- **P3:** our `ek` byte-equal to `crypto.generateKeyPairSync("ml-kem-768",
  { seed })` for all-zero, all-`0xff`, **and enough fixed random seeds that at
  least one matrix polynomial demonstrably needs an extra squeeze block.** Two
  hand-picked seeds are blind to the one branch that varies; assert the
  extra-block case was actually hit rather than hoping for it.
- **P4:** `crypto.decapsulate` agrees with our shared secret; `crypto.encapsulate`
  on our `ek` decapsulates correctly through our spec; the implicit-rejection
  branch asserted explicitly on a corrupted ciphertext.
- **Perturbation, on every KAT that matters.** Run it, don't assume it: break one
  ζ, swap a butterfly's add and sub, drop the `n⁻¹` scaling, flip the LE↔BE
  crossing in `ByteEncode`, and record how many assertions fail. Two of this
  project's plans record perturbations that turned out to be **no-ops** for
  reasons worth knowing (MT19937's mask below a shift; OFB's untrimmed
  feedback). If a perturbation changes nothing, find out why before weakening
  the test.
- **Frame/node budget re-measured at P1 and again at P4.** The depth decisions
  above are only as good as the 1.6 ms / 0.095 ms model.
