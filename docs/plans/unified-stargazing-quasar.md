# ML-KEM — the lattice layer, and the app's first post-quantum algorithm

**Status: P1 SHIPPED 2026-08-09. P2–P5 open.** Five phases; the NTT is
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

### P2 — the rest of the lattice layer

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

### P3 — K-PKE (the IND-CPA core)

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

### P4 — ML-KEM encapsulation and decapsulation

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

### P5 — pedagogy

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

## Critical files

**New:**
- `src/ciphers/mlkem-constants.ts` — `q`, the 128 ζ values, the 128 ζ² base-case
  values, `n⁻¹ mod q`. Module constants, never spec params.
- `src/ciphers/ntt-3329-256.ts` — forward/inverse layer-iterate builders (P1).
- `src/ciphers/k-pke.ts`, `src/ciphers/ml-kem-768.ts` — the KEM specs (P3/P4).
- `src/steps/zq-*.ts` — the vector primitives (P1/P2).
- `src/steps/ml-kem-*.ts` — the five Keccak monoliths (P3).

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
