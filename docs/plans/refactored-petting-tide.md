# ML-DSA-44 — the post-quantum signature, and the app's first loop that stops on its own

**Status: PLANNED 2026-10-18.** Five phases. Successor to
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

### P2 — the ML-DSA arithmetic layer (palette only, no selector entry)

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
   headline: "attempt 2 rejected: ‖z‖∞ = 131,040 ≥ γ1−β = 130,994".

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
