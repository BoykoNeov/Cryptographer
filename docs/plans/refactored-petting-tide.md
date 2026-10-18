# ML-DSA-44 — the post-quantum signature, and the app's first loop that stops on its own

**Status: P1 + P2 + P3 SHIPPED 2026-10-18; P4 SHIPPED 2026-10-19; P5 open.** Five phases. Successor to
`docs/plans/unified-stargazing-quasar.md` (ML-KEM, CLOSED), which deferred
ML-DSA to "its own plan and its own advisor pass" because signing retries an
unbounded number of times. This is that plan.

## Context

The user asked for "another post-quantum cipher". NIST's post-quantum standards
are key exchanges and signatures rather than ciphers. ML-KEM (the key exchange)
already ships, so the user picked **ML-DSA-44** (FIPS 204, "Dilithium").
ML-DSA-44 is the lattice signature that is ML-KEM's sister standard, in its
smallest parameter set.

What it teaches that nothing else in the app does:

- **Signing is a rejection loop.** Every attempt makes a candidate signature
  and checks it against four bounds. Any candidate that would leak information
  about the secret key is thrown away. The number of attempts depends on
  intermediate values: FIPS 204 Table 1 gives an expected **4.25** attempts for
  ML-DSA-44. A learner should *see* the rejected attempts and *which* bound each
  one failed. That is the content.
- **The transformed domain is element-wise here.** q = 8380417 ≡ 1 mod 512, so
  the NTT runs all **8** layers down to 256 single coefficients. Multiplication
  is then plain element-wise, which is the exact opposite of ML-KEM's "per
  pair, never element-wise" lesson. The contrast is the point.
- **Hints.** A signature can drop the low bits of a value because a few hint
  bits let the verifier recompute the high bits. This is lossy compression done
  on purpose, the sibling of ML-KEM's compress/decompress pair.

**Intended outcome:** under **Lattice**, a learner selects **NTT mod 8380417**
and watches the full 8-layer transform. Under **Asymmetric**, they select
**ML-DSA-44**, sign a message (encrypt slot), and see a key pair born from a
32-byte seed. The rejected attempts are visible one per loop pass, each naming
the bound it broke. In the verify slot (decrypt), the signature is accepted or
rejected.

## The three decisions the user made (2026-10-18)

1. **The retry loop is a repeat-until loop in the engine**, with a hard cap. We
   rejected "count the attempts in advance, then build that many" for three
   reasons:
   - The count goes stale the moment a learner edits γ1, β or a bound, and
     editing is the app's whole purpose.
   - It bakes the message into the spec, which breaks the byte-stable,
     spec-only share links.
   - It costs a whole extra simulated run.
2. **Each NTT inside ML-DSA is ONE frame**, a cross-reference monolith pointing
   at the new fully traced **NTT mod 8380417** selector entry. This follows the
   precedent ML-KEM set for its Keccak calls. The cost of the alternative was
   measured, not guessed:
   - One signing attempt runs 5 forward + 16 inverse NTTs: NTT(y) ×4,
     INTT(Â∘ŷ) ×4, NTT(c) ×1, and c·s1, c·s2, c·t0 ×4 INTT each.
   - Each transform is 255 butterfly groups × ~7 leaves ≈ 1,800 frames.
   - That gives ≈ **38k frames per attempt and ≈ 160k per signature**, against
     ML-KEM decapsulation's 17.5k at ~0.9 s.
3. **The byte-exact signing oracle is a one-off `@noble/post-quantum` script**,
   run in `W:\temp\claude\ml-dsa-oracle\` and never added to `package.json`. It
   writes a committed byte fixture. Node 24 cannot be that oracle: its signing
   is randomized (hedged), and it ignores `deterministic`/`dsaDeterministic`
   (probed 2026-10-18).

## The oracle situation (probed on this machine, Node v24.14.1)

- **Key generation: deterministic, two checkpoints.**
  - A hand-assembled PKCS#8 for OID `2.16.840.1.101.3.4.3.17` with the
    **IMPLICIT `[0]` seed arm** (`0x80 0x20 ‖ ξ`) imports cleanly. The public
    key it derives is stable across imports. This is the same trick as ML-KEM
    P3.
  - Exported PKCS#8 is 2626 bytes, the "both" form: seed + the **2560-byte
    expanded sk**. So `sk` is pinned as well as `pk` (1312 B). Confirm by
    parsing in P3.
- **Verification: Node is a direct oracle.** Node-made (randomized) signatures
  must verify true under our spec, and a one-bit flip must verify false. Node
  also accepts `context`.
- **Signing: Node verifies OURS** (an independent verifier, which is strong), and
  noble's deterministic signing (`rnd = 0³²`) pins the exact bytes. Before
  trusting noble, the fixture script asserts that noble's `pk` from a seed
  equals Node's, so the two implement the same final FIPS 204 and not the
  round-3 draft.
- **CI is Node 22**, so every Node-derived value is captured as a byte fixture.
  This is the ML-KEM precedent: `tests/fixtures/ml-kem-768-seed-vectors.json`.

## Architecture

### Representation

A polynomial is **256 × 4-byte big-endian coefficients = 1024 bytes** in
`[0, q)`. q needs 23 bits. The shipped `zq-vec-add/sub/mul-scalar@1` steps
already take `coeffBytes` up to 8 with `q` on a port (`src/core/zq-vector.ts`),
so they work **unchanged** at `coeffBytes: 4`. Centred values (`mod± q`) exist
only inside the steps that need them (norm checks, Decompose, bit-packing) and
never on a wire. A vector of k polynomials is their concatenation, so
element-wise steps act on a whole vector in one frame.

### The repeat-until loop (P4, the crux)

The change is one optional field on the **port-mode** `iterate`, which touches
`core/types.ts`, `core/runtime.ts`, `core/document-schema.ts` and the document
validator:

- `stopWhen?: PortBinding` names a body port carrying a 1-byte accept flag.
  After each iteration, if that byte is non-zero, the runtime stops.
- **The hard cap is the existing count**: the seed width / `blockByteLength`,
  fed by a `zero-fill@1` whose bytes are never read. This is the PRNG "length
  enters as a width" precedent, so the cap is an ordinary editable param.
- The signature leaves the loop on the **chain**, which carries
  `κ ‖ accepted ‖ σ-candidate`. `chainOutput` harvests it and a sibling split
  separates the parts. Do not slice the collected output, because its width now
  varies. NTT P1 already proved that chain width can differ from block width.
- If the cap is hit without acceptance, nothing throws: the harvested
  `accepted = 0` drives a verdict leaf. FIPS 204 §3.4 allows an implementation
  to bound the loop. Pick the cap from measured per-attempt cost:
  0.765^32 ≈ 2e-4, 0.765^64 ≈ 4e-8.
- **Every check runs on every attempt** (dataflow, no branching). The four flags
  are `‖z‖∞ < γ1−β`, `‖r0‖∞ < γ2−β`, `‖ct0‖∞ < γ2` and `#h ≤ ω`, combined with
  the shipped `and@1`. FIPS skips the later work after an early reject; ours
  shows it, and the narrator says so.
- **Scope rule (third time it decides a design):** an attempt body sees only its
  own `in`/`chain`. So Â, ŝ1, ŝ2, t̂0, μ and ρ″ are published to **aux** before
  the loop and read inside it with `aux-load-bytes@1`, the way the CSPRNG seed
  and the NTT modulus are.
- **Audit spec-side count readers before building.** `spec-shapes.ts`,
  `ntt-diagram.ts`, the collapsed-iterate chip rows (`expandCollapsedIterates`),
  and the "Block i of N" badge must show **κ, not the cap**. Readers that go
  through the trace and `iterateScopeKey` (`core/step-id.ts`) are already safe.

### UI surface

ML-DSA-44 joins **`Asymmetric`** beside RSA and ML-KEM-768. The encrypt slot is
**Sign** and the decrypt slot is **Verify**. That surface already has no
symmetric key field, no mode, no padding and a direction toggle. `isAsymmetric`
is already membership over `ALL_ASYMMETRICS`; extend the list **in the same edit
that widens the union**, because of the `isCipher` landmine.

The 32-byte seed ξ is the key input, as ML-KEM's 64-byte seed is. Key
generation is a default-collapsed group inside **both** specs; the verify spec
takes the public half. The rest:

| | Sign | Verify |
|---|---|---|
| Inputs | message | message + signature (2420 B) |
| Output | signature | a verdict |

- `ctx` (default empty) is a param on a `ml-dsa.format-message@1` leaf
  (`M′ = 0 ‖ |ctx| ‖ ctx ‖ M`). Miss that prefix and Node rejects every
  signature. `rnd` defaults to 32 zero bytes (the deterministic variant) and is
  a visible constant.
- **Default inputs must make κ ≥ 2 attempts** so a rejection is on screen at
  first paint. Choose them with the oracle script, which records the attempt
  count from a test-side reference.
- Label arms to update, all string-typed, so only browser smoke finds them:
  sidebar, graph endpoint pills, `describeAlgorithm`, `historyOfAlgorithm`.

## Phases

Each phase ends green on `npm run check`, is browser-smoked, and gets an advisor
consult before it starts (`feedback_iterative_slice_review`).

### P1 — NTT mod 8380417, the lattice category's second member

1. **Capture digests first** of the shipped NTT (both directions), the three
   K-PKE specs and both ML-KEM-768 specs, before touching any builder. The
   CSPRNG / ML-KEM P4 rule: digests taken after a refactor pin the new bytes to
   themselves.
2. Parameterize `src/ciphers/ntt-3329-256.ts` by a constants record:
   `q, root, layers, coeffBytes, zetas, nInv`, plus the narration strings that
   quote numbers. ML-KEM stays byte-identical, pinned by the digests.
3. New `src/ciphers/mldsa-constants.ts`, holding module constants and never
   spec params:
   - q = 8380417, ζ = 1753, 256⁻¹ = 8347681.
   - The 256-entry ζ table in **BitRev8 consumption order** (FIPS 204
     Appendix B, verbatim), giving a 1024-byte rotating chain.
   - d = 13, τ = 39, γ1 = 2¹⁷, γ2 = 95232, β = 78, ω = 80, (k, l) = (4, 4),
     η = 2, λ = 128.
4. New `Lattice` variant `ntt-8380417-256`. `isLattice` membership, plus
   `LATTICE_IDS` / `assertLatticeCoverage` in `document-schema.ts`.
5. Check `src/core/ntt-shape.ts`, `ntt-layout.ts` and `ntt-diagram.ts` for
   7-layer / 3329 / 2-byte assumptions. The canonical butterfly cell and the
   diagram should come free; verify by the rendered-path-vs-box audit (ML-KEM
   P5), not by eye.

**Oracle:**
- The definition first: evaluation at ζ^(2·BitRev8(i)+1), an independent double
  loop.
- The convolution theorem with **element-wise ∘**, correct here and wrong in
  ML-KEM. Keep both suites; the contrast is a test.
- Appendix B's table, value by value.
- Round-trip last.

**Perturbations:**
- 256⁻¹ swapped for ML-KEM's 128⁻¹ shape.
- An ascending-exponent table.
- 7 layers instead of 8.

**P1 OUTCOME (2026-10-18).** Shipped as planned. Five things to carry forward:

1. **The parameterization is a PROFILE, and prose is part of it.** `NttProfile`
   holds n, layers, coeffBytes and zetaTableBytes plus an `NttNarration`.
   Templating ML-KEM's sentences would have had to reproduce them byte for byte
   to keep the spec digests (and therefore shared links) stable, so each
   transform owns its own prose for every leaf that quotes a number. The
   sum, difference and rejoin prose is shared. Digests captured before the
   change: `tests/ml-kem-768-spec-digests.test.ts` is new; the NTT and K-PKE
   digests already existed. All came out identical.
2. **FIPS 204 Appendix B lists entry 0 as 0, not 1753⁰ = 1.** Nothing reads it.
   Entries 1…255 are re-derived in the KAT, and a perturbation changes entry 0
   and asserts that nothing moves.
3. **My own narration had a wrong number, caught before shipping:** 8380416² ≈
   7·10¹³ is 46 bits, well inside a double's exact range (2⁵³), not past it.
   The real point is that it exceeds 32 bits. The KAT reference arithmetic stays
   in `number` for exactly that reason.
4. **The same stale-input bug ML-KEM P4 found, one family over, found again by
   the browser.** The lattice dropdown called `setLattice` directly, because a
   variant switch was unreachable with one member. Fixed with a mode-aware
   `changeLattice`, pinned by `tests/app-lattice-switch.test.tsx` (both
   directions plus typed-input survival) and perturbation-verified.
   **Generalization: every family dropdown needs a change handler the moment it
   gains a second member.** Families with one member today: none left that
   have a direction.
5. **The butterfly diagram hardcoded "FIPS 203 Algorithm 9/10".** It now reads
   the citation from the twiddle multiply's `narrationOverride.references[0]`
   (spec-derived, not inferred from width or modulus), falling back to FIPS 203
   for palette-built butterflies. Pinned by `tests/ntt-diagram.test.tsx` and
   perturbation-verified.

**The graph cell, measured (P1 step 5, done after the first commit on the
advisor's catch).** With everything expanded, all eight layers lay out as the
canonical butterfly cell: 67 leaves (3 heads + 8 × 8), each layer's eight on
**exactly five rows at a 60 px pitch**, the same grid ML-KEM's transform gets.
Opening the graph tab cost one 66 ms long task; `expand all` cost none.

**The first-session freeze is NOT the stale input.** Replayed with the
input-swap fix temporarily removed, the exact original sequence (lattice →
ML-DSA with ML-KEM's 512-byte polynomial left in the field) ran in 5 ms + 10 ms
with zero long tasks and showed the friendly length error. An EDITED 512-byte
polynomial surviving the switch (the advisor's concern: the sacred-input
policy re-creates the stale state) behaves the same. The freeze happened only
on the first page loads after the new files appeared, so a cold dev server
compiling modules on demand is the likeliest cause. That is unproven; it never
recurred. Chrome-extension screenshots timed out for the whole session even
while the page ran at ~60 fps, so the capture failures were the extension, not
the app.

**The jsdom stall.** One run of `app-lattice-switch.test.tsx` stalled for 5+
minutes while it used `toBe` on multi-kilobyte hex strings and a fixed 500 ms
sleep. Both are gone (`expectHex` and a `waitFor` on the shown result), and
it has passed in ~15 s on every run since. Also fixed: the `kind` dropdown's
tooltip named only Z_3329 and only RSA.

### P2 — the ML-DSA arithmetic layer (palette only, no selector entry)

**Two rules decided at P2's start (2026-10-18, on the advisor's catch):**

1. **Ports vs params.** Every constant a learner might edit reaches every
   step that uses it on a wire. That covers q, γ1, γ2, ω, the norm bounds and
   the packing ranges. Params hold only structural sizes: d, k, l, η, τ and
   output lengths. The audit that forced the rule: γ1 also fixes ExpandMask's
   width and z's packing range, γ2 also fixes w1's packing width, and ω also
   fixes the packed hint's length. A param copy of any of those would break
   P4's "edit γ1, watch κ change" with a crash or an unreadable signature.
   So FIPS's `w1Encode` becomes its own step, which reads γ2.
2. **The packers stay strict, and P4 selects before packing.** The signing
   loop does not branch, so it encodes a candidate on every attempt. A
   rejected `z` can sit up to β outside BitPack's range, and a rejected `h`
   can hold more than ω ones. Rather than making the packers accept anything,
   P4 swaps a rejected attempt for zeros before encoding: a select, the
   ML-KEM precedent. That matches FIPS, which never encodes a rejected
   candidate. Nothing in P2 changes.

New steps, each with tests in the same commit:
- **Generic `zq-` steps:**
  - `zq-vec-mul@1`: element-wise, the NTT-domain product. It is deliberately a
    sibling of `zq-base-case-mul@1`, and its doc says why one is per-pair and
    this one is not.
  - `zq-inf-norm-below@1`: centred ‖v‖∞ < bound, giving a 1-byte flag. The bound
    arrives on a port so γ1−β stays one editable source.
- **`ml-dsa.` arithmetic:** `power2round@1` (t → t1, t0), `decompose@1`
  (w → w1, r0, via `HighBits`/`LowBits` with FIPS's `r⁺ − r0 = q − 1` special
  case), `make-hint@1`, `use-hint@1`, `hint-count@1`.
- **Cross-reference monoliths:** `ml-dsa.ntt@1` and `ml-dsa.intt@1`, for any
  whole number of polynomials, each naming the selector entry.
- **Sampling monoliths over the shared `keccak-f.ts`:** `ml-dsa.expand-a@1`
  (SHAKE128, RejNTTPoly, seed `ρ ‖ j ‖ i`), `expand-s@1` (SHAKE256,
  RejBoundedPoly), `expand-mask@1` (κ on a port), `sample-in-ball@1`,
  `hash-h@1` (SHAKE256, `outBytes` param). Each `detail` names its function and
  rate and points at Hash → SHAKE (the ML-KEM "third kind" wording).
- **Packing:** first check whether `zq-byte-encode@1` already *is*
  SimpleBitPack. Its LSB-first stream is the same rule. Add `ml-dsa.bit-pack@1`
  / `bit-unpack@1` (the `[−a, b]` form) and `hint-pack@1` / `hint-unpack@1`
  only for what it cannot express. `hint-unpack` must reject a malformed hint
  (FIPS's ⊥) as a flag, not a throw.
- **`ml-dsa.format-message@1`.**

**Gates:**
- Provenance (exact fn or allowlist, in **both** files).
- Narration: a **prefix walk over `ml-dsa.`** in
  `narration-registry-contract.test.ts`, like the `zq-` / `ml-kem.` block.
- A palette-only ParamEditor coverage test, because `insertStepIntoSpec` gives
  dropped leaves `params: {}`.

**Oracles:**
- Exhaustive over the domain where it is cheap: Decompose, Power2Round,
  MakeHint/UseHint over all r. Assert the FIPS identity
  `UseHint(MakeHint(z, r), r) = HighBits(r + z)` for ‖z‖ ≤ γ2.
- The samplers byte-matched against the noble fixture's intermediates.

**P2 OUTCOME (2026-10-18).** Shipped in three commits: rounding, samplers,
packers. That is twenty steps: eighteen `ml-dsa.*` plus `zq-vec-mul@1` and
`zq-inf-norm-below@1`. Seven things to carry forward:

1. **The strongest check was a composition, not a per-step test.**
   `tests/ml-dsa-44-oracle.test.ts` builds FIPS 204's KeyGen, Verify and Sign
   out of nothing but the registered executors. Key generation reproduces
   Node's pk and the 2560-byte expanded sk from three seeds. Verification
   agrees with Node on 18 valid signatures and on one malformed hint per
   refusal rule. Deterministic signing reproduces noble's bytes. All three
   matched on the first run. Noble and Node were cross-checked both ways before
   the fixture was written: same pk and sk from the same seed, and each
   accepts the other's signatures, with and without a context. P3's specs
   inherit this as a ready-made oracle at every checkpoint.
2. **ExpandA covers the whole matrix, a deliberate departure from ML-KEM's
   visible index join.** ML-DSA never builds the transpose, so the
   `ρ ‖ s ‖ r` order is one convention, not a distinction between call sites.
   The order is pinned by Node's pk, and the test keeps a runnable transpose
   perturbation whose signature is recorded: ρ and s1/s2 stay green, while t1,
   tr and t0 break.
3. **The fixture's nine signatures took 1, 1, 1, 2, 2, 7, 8, 9 and 12
   attempts. Every rejection came from the z or the r0 check, none from ct0 or
   the hint count.** So the byte-exact signing match pins two of the four
   checks directly. The other two are pinned only by the ±1 unit tests. P4's
   "a case per rejection reason" therefore needs the planned search, and
   should not assume the fixture already contains one.
4. **Perturbations, run not assumed:** each breaks one rule and is restored byte for byte.
   - Drop Decompose's wrap-round case: 27 failures (the exhaustive test and
     the signing match).
   - Big-endian ExpandS index: 4. Transposed ExpandA: 23.
   - Big-endian ExpandMask counter: 9. That counter only differs from its
     correct form from attempt 2 on, which the fixture's multi-attempt
     signatures reach.
   - Forget HintBitUnpack's rule 3: 2 (one oracle case and one unit test).
   - `<` for hint-count's `≤`: 2. `≤` for the norm check's `<`: 1. These two
     edge flips are caught ONLY by the ±1 unit tests. No real signature in
     the fixture lands on an edge, so the oracle is blind to them, which is
     why those tests exist.
5. **The unsigned packer needed no new step.** `zq-byte-encode@1` already *is*
   SimpleBitPack (the same LSB-first stream), and the oracle uses it for the
   public key's t1 at d = 10. `w1Encode` became its own step only because its
   width must follow the wired γ2.
6. **Three wrong numbers of my own, caught before commit:** the uncompressed
   public key is 2,976 bytes, not 2,336. ExpandA rejects about 1 candidate in
   1,024, not 1 in 500. And the paragraph on spare bit patterns in BitUnpack
   had it backwards: only the 3-bit secret fields have spare patterns, while
   z's and t0's ranges fill their fields exactly.
7. **Process gotchas.** `tests/byte-native-ports-contract.test.ts` resolves
   every function-form port contract under a shared `KITCHEN_SINK` params
   object, so a new param name that sizes a port (`outBytes`, `k`, `l`) must
   be added there. Only the full gate found this. Separately,
   `npm --prefix X init -y` ignores the prefix and rewrites the CURRENT
   directory's `package.json`. The rewrite was caught in `git status` and
   reverted.

**Browser smoke (P2 exit).**
- All twenty steps appear in the graph palette under their names.
- `format-message` dropped onto a real canvas shows its block. Typing `61 62`
  through real keystrokes saved two context bytes, and the field read back
  `61 62`.
- The description renderer (`markdown.tsx`) supports neither tables nor
  single-star italics, and both showed up in the new step descriptions as raw
  punctuation. They are rewritten as lists and bold. A test now bans both in
  every ML-DSA description. Two older steps (`rotate-bits-left`,
  `ml-kem.hash-g`) still carry a table and are left as they are.
- **Not seen on screen: the narrators.** A palette-dropped step has no
  coefficient width set and nothing wired, so it never runs and never makes
  a frame. The narrators are tested on real runtime frames in jsdom only, and
  reading them in the browser stays a P5 item.
- The graph tab's first render took over 45 s on a cold dev server while
  another project's test suite held the CPU. That is the P1 freeze pattern
  again, and it is not caused by P2.

### P3 — key generation + verification specs (still no selector entry)

- `src/ciphers/ml-dsa-44.ts` with **prefixable builders** from day one,
  embedding key generation in both specs. Node ids must be prefixed or the flat
  trace silently collides (K-PKE P3, lesson 6). Assert this on the SHIPPED specs.
- Key generation: `(ρ, ρ′, K) = H(ξ ‖ k ‖ l, 128)`. The **`‖ k ‖ l` domain
  separator is final-FIPS-only**: the round-3 draft omits it and is
  self-consistent, so it is a perturbation that must break `pk`. Then
  Â, ExpandS, t, Power2Round, pkEncode, tr = H(pk, 64), skEncode.
- Verification: decode, Â, μ = H(tr ‖ M′, 64), SampleInBall, the w′approx
  combination, UseHint, recompute c̃′, then a verdict leaf that compares and
  checks the norm.

**Checkpoints:**
- ρ pins H.
- `sk` pins ExpandS + Power2Round.
- `pk` pins Â and the matrix product.
- Node signatures verify true; a flipped bit in each of c̃, z and h verifies
  false; a malformed hint is rejected.
- The `ExpandA` byte order `ρ ‖ j ‖ i` vs `ρ ‖ i ‖ j` (a transpose) is a
  perturbation that leaves ρ and `sk` green and breaks `pk`. Pin that
  signature.

**P3 OUTCOME (2026-10-18).** Shipped as `src/ciphers/ml-dsa-44.ts` (the
verification spec, plus the key-generation body, group and matrix-product
builders P4 will reuse) and one new step, `ml-dsa.verdict@1`. Every check
passed on the first run. Eight things to carry forward:

1. **Verification's input is the signature; the message is an editable
   leaf.** A spec has one input, and `split-bytes@1` has no open-ended slot,
   so a variable-length message and a fixed 2420-byte signature cannot share
   it. The signature is fixed-width, so it takes the input, which is also
   ML-KEM decapsulation's shape. How a learner types the message in P4's UI is
   a user-facing question to ask then; the body is binding-driven
   (`mlDsaVerifyNodes(ctx, constants, { pk, mPrime, signature })`), so either
   answer only changes the wrapper.
2. **No standalone key-generation spec.** K-PKE had one; here the checkpoints
   (ρ, `sk`, `pk`) are read off the trace inside the shipped verify spec's
   `keygen.` group, which tests the embedding that ships rather than a second
   copy of it.
3. **Constants:** q, γ1, γ2, β and ω live in `cipherConstants` (editable in
   the Constants panel). γ1 − β (the norm bound) and γ1 − 1 (z's packing low
   end) are `sub@1` leaves, never second constants. Values fixed by a
   structural param (η, the t0 range, 2^d) are `constant-load@1` leaves. Key
   generation's group loads only its own q.
4. **All k·l matrix products are ONE `zq-vec-mul@1` frame**: Â against
   `concat(v̂ × k)`, then a split and a per-row add chain (`matVecNodes`,
   shared with P4). Element-wise multiplication makes that possible, and it is
   the contrast with ML-KEM's per-pair multiply.
5. **The verdict reads three flags, and the tests read its INPUTS.** A
   malformed hint arrives as an all-zero hint with `valid = 0`, which also
   breaks the challenge, so the output byte alone cannot tell whether the hint
   flag is wired. The malformed-signature test asserts the verdict's
   `hintValid` input, and a perturbation that rewires it shows the output
   stays 0 while that assertion fails. The narrator names EVERY failed check
   for the same reason.
6. **A new fixture case, `p3.overNorm`, makes the norm check load-bearing.**
   It is the default pair's first signing attempt (rejected for z), packed
   anyway: z exceeds γ1 − β but still fits the packing range, ct0 and the
   hint count pass, so the challenge matches and only the norm flag rejects
   it. Node and noble both reject it (recorded). Without it, nothing in
   verification needs the norm check, because a flipped z bit fails on the
   challenge first.
7. **Defaults (fixture `p3.defaultPair`):** the counting seed, the message
   "Hello, world!" (deterministic signing takes three attempts: z, then r0,
   then accepted) and noble's deterministic signature, which Node verifies.
   P4's signing must reproduce exactly those bytes.
8. **Perturbations run:** drop ‖ k ‖ l (ρ breaks); compare c̃ with itself (every
   positive case still verifies, only a negative case catches it); drop the
   norm flag (only the over-norm case catches it); drop the hint flag (output
   still 0, the input assertion catches it). ExpandA's index order is NOT a
   spec-level edge (the step is a monolith); `tests/ml-dsa-44-oracle.test.ts`
   keeps that perturbation.

**Cost.** One verification is 91 frames and ~0.2–0.5 s in `runSpec`, almost
all of it the two ExpandA calls' incremental SHAKE128 (the shared byte-level
Keccak). P4's attempt loop runs ExpandA once, outside the loop, so this does
not multiply by κ. `tests/ml-dsa-44-spec.test.ts` memoizes runs.

**Browser smoke.** No selector entry yet, so the spec was loaded through a
share link (`#doc=`) into ML-KEM-768's decrypt slot, which is the only way to
reach it. The default signature showed `01` and, at frame 91 of 91, "VALID:
all three checks pass". One flipped challenge bit showed `00` and "INVALID:
c̃′ ≠ c̃" with the other two checks ticked. The graph drew with key
generation as one collapsed box and no console errors. A hand-built document
without `keyBytes: []` kept the previous algorithm's 16-byte key and refused
to run ("key: expected 0 bytes, got 16"). That is an artefact of the
hand-built document only: the app's own session save turns an empty key
field into `keyBytes: []` (`parseBytes("")` is an empty array, not a
failure), and load restores it, so real share links are unaffected.

**Gotchas for P4, found the hard way here.** A new `ml-dsa.` step must bump
the lattice inventory pin in `tests/narration-registry-contract.test.ts`
(35 → 36 for the verdict). It is a deliberate set-size pin, and only the full
gate runs it. And run `tsc` after writing the TESTS, not just the source: a
`readonly` return type in a test file cost one commit attempt. The default
pair's three-attempt shape (z, r0, accepted) is pinned in
`tests/ml-dsa-44-oracle.test.ts`, where attempt reasons are observable.

### P4 — signing, the loop, and the selector entry

1. **Spike with existing primitives only**, before any ML-DSA signing code. Use
   a toy body whose accept flag fires on iteration 3 of a cap of 8, and confirm:
   - the loop stops;
   - `chainOutput` carries the last attempt;
   - the trace has exactly 3 iterations;
   - the graph, chip rows and badge show 3, not 8;
   - save → load and share round-trips;
   - a spec that hits the cap gets a verdict, not a throw.

   Measure the per-attempt cost with the monolith NTTs, and set the cap from it.
2. Add `stopWhen` to types/runtime/schema/validator. Also add it to
   `cloneGroupWithFreshIds`'s binding rebase and to the port-wiring editor's
   legal-source set if it is user-editable; check both.
3. Sign spec: precompute ŝ1, ŝ2, t̂0, Â, μ, ρ″ = H(K ‖ rnd ‖ μ, 64) → aux. Then
   the attempt loop (ExpandMask(ρ″, κ), w, w1, c̃, c, z, r0, ct0, h, four flags,
   `and@1`, sigEncode; chainFeedback `κ + l`). Then harvest.
4. Selector entry `ml-dsa-44` in `Asymmetric`. Extend `ALL_ASYMMETRICS` in the
   same edit, and update `describeAlgorithm`, `historyOfAlgorithm` and the
   labels.
5. Narrator for the attempt verdict. Like ML-KEM's select, it is a VERDICT
   headline: "attempt 1 rejected: ‖z‖∞ = 131,029 ≥ γ1−β = 130,994; ‖r0‖∞ = …".

**P4 STEP 1 OUTCOME — the repeat-until loop (2026-10-18).** `stopWhen` shipped on
the port-mode `iterate` (types, runtime, schema, static checker), proven by a toy
built from shipped primitives only (`tests/runtime-iterate-stop-when.test.ts`).
Its chain is `counter ‖ accepted`, so the value differs on every pass and the
accept flag rides out of the loop — a pass count alone cannot tell "accepted on
the last allowed attempt" from "hit the cap" (both 8 passes). Five things:

1. **The check sits after `chainFeedback`.** Moved above it, the harvest reads
   the attempt BEFORE the winning one; that perturbation fails 4 tests. Removing
   the schema entry fails the behavioural Save/Load test (the reloaded loop runs
   all 8 attempts, no error anywhere). Both run, then restored.
2. **A pre-existing checker gap, fixed:** `spec-shapes.ts` never recorded an
   iterate's `chainOutput` port, so a SIBLING reading the harvest got a false
   `port-input-unresolvable`. Invisible until now because every shipped harvest
   is read only through `outputFrom`, which that walk does not check. Signing's
   `κ ‖ accepted ‖ σ` split is the first sibling reader.
3. **No change needed, checked:** `cloneGroupWithFreshIds` rejects iterates
   outright (`assertCompositeSubtreeSupported`); the port-wiring editor rewires
   LEAF ports only; `duplicateRound`'s `bodyOutput` remap touches groups only.
4. **Every count reader derives from the trace**, so 3 of 8 shows 3 with no
   change: the graph's `blockSpan` (`graph.ts`, max `blockIndex` + 1) and the
   "Block i of N" badge (`App.tsx`'s `blockCounts`, scoped by `iterateScopeKey`).
   Pinned at unit level against the real `deriveAuxGraph` /
   `expandCollapsedIterates`; the BROWSER check of chips and badge moves to the
   signing spec, which is where a learner will see it.
5. **A flag must be exactly one byte** (a wider one throws — an accept flag wired
   to a polynomial is a mistake a truthy check would hide), and `stopWhen` in aux
   mode throws.

**Measured rejection statistics (instrumented noble copy, 1,500 random keys,
6,639 attempts).** 4.43 attempts per signature (FIPS 204 Table 1 says 4.25). By
FIRST failed check in noble's order: z 46%, r0 31%, hint count 0.5%, **ct0
never** — the largest ‖ct0‖∞ seen was 72,641 against γ2 = 95,232, about 6σ short.
So the plan's "a case per rejection reason" is reachable for three of four:

- **hint:** "Hello, world! #17" under the default seed: attempts z, z, **hint
  (81 ones, ω + 1)**, z, r0, z, r0, accepted. Noble reaches the hint count only
  after every other check passes, so the app's failed SET on that attempt must
  be exactly {hint}.
- **first try:** "Hello, world! #0" — accepted on attempt 1.
- **context:** "Hello, world!" with ctx "cryptographer" — 12 attempts.
- **ct0 has no external case.** Lowering γ2 would also move Decompose's buckets,
  w1's width and the r0 bound, so no reference would agree. Instead a test-side
  copy of the spec tightens ONLY the ct0 check's bound and asserts the flag, the
  narrator and the retry — a wiring pin, which is all a spec test can pin.

Noble records the FIRST failure; the app computes all four flags every attempt.
So a fixture "z" means z is AMONG the app's failures — assert containment there,
set equality only where noble's order makes it exact (the hint case).

**P4 STEPS 2–4 OUTCOME — signing, and the selector entry (2026-10-18/19).**
`buildMlDsa44SignSpec` (sign: message in, signature out) joins the verify spec;
ML-DSA-44 is the third `Asymmetric` member (sign = encrypt slot, verify =
decrypt). Byte-exact against noble on the first run for all four cases. Three
new steps, and the decisions that shaped them:

1. **`ml-dsa.publish@1`** — the B-minimal aux tail (RSA's posture): Â, ŝ1, ŝ2,
   t̂0, μ, ρ″ are computed once and filed under `ml-dsa.sign.*`, because the
   attempt body sees only its own `in`/`chain`. The prefix keeps them clear of
   the editable constants in the same global map. Narration-allowlisted with the
   other publish tails.
2. **`ml-dsa.attempt-verdict@1`** takes THREE ports per check: the flag (which
   alone decides — the `<` / `≤` rules stay in the check steps), the measured
   value and the limit. The last two are display ports (the `twofish.h-expand`
   precedent), forced by the fact that a `NarrationFn` sees only its own frame:
   without them the headline could name the failed check but not the number,
   and adding ports later would mean an `@2`. P2 had already given
   `zq-inf-norm-below@1` a `norm` port and `hint-count@1` a `count` port for
   exactly this. Outputs: `accepted` (the `stopWhen` flag and the select
   multiplier) and `failed` (a bitmask, the loop's `bodyOutput`, so `out` is a
   free one-byte-per-attempt log).
3. **`ml-dsa.release-signature@1`** — the signature if accepted, EMPTY at the
   cap. A capped loop's chain still holds 2,420 well-formed bytes (the last
   candidate, z and h zeroed); handing that out would look real and fail to
   verify. Its narrator reads the log: "SIGNED: accepted on attempt 3", then each
   rejected attempt's reasons.

**The select is multiply-by-the-accept-bit**, not a new step: `concat(0,0,0,
accepted)` is the flag as one coefficient, and `zq-vec-mul-scalar@1` applies it
to z and h before packing. **Correction to the P2 rule's premise, measured:** a
rejected z rarely overshoots its PACKING range — z exceeds γ1 − β far more often
than γ1, and the default pair's rejected z fits (as P3's over-norm signature
already showed). The case that needs the select is the HINT: the #17 attempt's
81 ones cannot be packed into ω = 80 slots, and removing the h select throws
there (pinned).

**The default pair, read off the trace:** attempt 1 fails z (131,029 ≥ 130,994)
AND r0 (95,166 ≥ 95,154) — noble records only "z"; attempt 2 fails r0 (95,190);
attempt 3 passes with z two under its limit (130,992). ct0 peaked at 57,327 of
95,232.

**Perturbations, run:** ω = 81 makes the #17 case stop at attempt 3 with
different bytes (the edit-a-bound experiment, on the fixture's only real edge
case); advancing κ by 1 instead of l changes every byte; dropping the h select
throws. Plus the ct0 wiring pin (a test-only bound of 1 rejects every attempt by
ct0, the loop retries to its cap, release emits nothing).

**The user's decision on Verify's message (2026-10-18): an opt-in copy button.**
Verify checks a message held in its own spec (a `constant-load@1` leaf, P3's
shape); the mode flip carries the signature across but never the message. A
Verify-only sidebar row (`MlDsaVerifyMessage`) shows the message being checked
and "Use the message from Sign", fed by a session-only `signed-message` store
that records Sign's input. Nothing copies on its own (the cross-mode rule), and
the app test asserts INVALID before the click and VALID after it.

**One source for endpoint labels.** `endpointLabelsFor` (stores/cipher.ts) now
feeds both the sidebar and the graph pills. The two were hand-kept copies, and
ML-KEM-768's pills had read "message → ciphertext" against the sidebar's
"message m (random) → ciphertext" — fixed by the same change.

**The cap is 32, set from measurement.** One attempt costs ~31 ms of `runSpec`
and 71 frames, on top of ~190 ms fixed (key generation's two ExpandA calls and
the precomputation's third). So a run that reaches 32 attempts takes ~1.2 s and
~2,300 frames, about ML-KEM decapsulation's budget; 64 would take ~2.2 s. With
the standard bounds an attempt passes with p ≈ 0.226 (1,500 / 6,639 measured),
so 32 straight rejections hit ≈ 1 message in 3,700 (64: ≈ 1 in 13 million).
The cap is chosen for the case it exists for — a learner who tightened a bound,
where every run reaches it — not for the default odds. It is the length of a
`zero-fill@1` leaf, so it is editable like any other width.

**A signature has a fixed width**, so Verify's input gets its own App
validation arm (2,420 bytes, said in a sentence) — also keeping ML-DSA out of
the RSA arm, which reads `cipherConstants.q` for an unrelated check.

**Oracle:**
- Noble's deterministic fixture, byte-exact. A wrong rejection rule changes κ,
  hence y, hence every byte, so the attempt count is pinned implicitly.
- Node verifies our signatures, with and without `ctx`.
- **A case per rejection reason**: the fixture script searches (seed, message)
  pairs until each of the four bounds is the first to fail at least once, and
  records which. The narrator's claim is asserted against that.
- Perturb each bound by one and confirm the fixture breaks.

### P5 — pedagogy

- A linear-view **rejection-loop panel**: one row per attempt, its four bound
  values against their limits, the accepted row highlighted, click to scrub.
- A **Decompose / hint diagram**: the number line cut into 2γ2-wide buckets, the
  value, its high/low parts, and how one hint bit moves the verifier's
  rounding.
- Read every P2 narrator on screen (the ML-KEM narration-debt lesson). Browser
  smoke throughout; the extension may drop, and the throwaway Playwright recipe
  is in memory.
- **Relabel the attempt loop's chips** — the graph's collapsed-iterate chips and
  the badge say "block N"/"Block i of N"; for signing they are attempts.
- **Found after P4, fixed there; the sibling left for here:** the mode flip
  copies the output into the input in BOTH directions, so Verify → Sign put the
  one-byte verdict where the message was (and the signed-message recorder then
  remembered it). P4's follow-up restores the recorded message for ML-DSA
  (`tests/app-ml-dsa.test.tsx`, perturbation-verified: without it the field
  reads `00`). ML-KEM-768 has the same older pattern — decapsulation → back to
  encapsulation puts the 32-byte shared secret in the "message m (random)"
  field. Harmless (32 bytes is a valid m) but wrong-looking; decide here.

## Critical files

- **Runtime contract:** `src/core/types.ts`, `src/core/runtime.ts`,
  `src/core/document-schema.ts` (+ the document validator),
  `src/core/spec-mutations.ts`.
- **NTT:** `src/ciphers/ntt-3329-256.ts` (parameterize),
  `src/ciphers/mlkem-constants.ts` (template), new
  `src/ciphers/mldsa-constants.ts`, `src/core/ntt-shape.ts`,
  `src/core/ntt-layout.ts`, `src/core/ntt-diagram.ts`.
- **Reuse:** `src/core/zq-vector.ts` (`readZqVecParams` / `readZqModulus` /
  `readCoeff` / `writeCoeff`), `src/ciphers/keccak-f.ts`, `src/steps/zq-*.ts`,
  `src/ciphers/k-pke.ts` and `src/ciphers/ml-kem-768.ts` (the prefixable-builder
  and key-gen-group templates), the `ml-kem.*` monoliths (the "cross-reference"
  doc template).
- **Registration:** `src/ciphers/default-registry.ts`.
- **UI:** `src/ui/stores/spec.ts`, `src/ui/App.tsx`, the Asymmetric selector, and
  the algorithm description/history tables.
- **Gates:** `tests/port-provenance-coverage.test.ts`,
  `tests/port-provenance.test.ts`, `tests/narration-registry-contract.test.ts`.

## Verification (end to end)

- `npm run check` at below-normal priority, per phase:
  `cmd //v:on //c "start /belownormal /b /wait npm run check & exit !errorlevel!"`.
- The KAT suites above. Each ranks the definition / external oracle first and
  round-trip last, and each has its perturbation run, not assumed.
- Browser:
  - Select NTT mod 8380417 and watch 8 layers.
  - Select ML-DSA-44 → Sign: default inputs show ≥ 2 attempts, the rejected one
    names its bound, and the badge and chip rows show κ, not the cap.
  - Switch to Verify: valid.
  - Flip a signature byte: invalid.
  - Edit γ1 and watch the attempt count change live. The repeat-until decision
    exists for this.
- Temp scripts and the noble install live under `W:\temp\claude\ml-dsa-oracle\`
  and are deleted when the arc ends. Only the fixture JSON is committed.
