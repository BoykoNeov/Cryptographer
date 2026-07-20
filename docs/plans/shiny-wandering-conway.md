# Salsa20 — the second stream cipher, and the ARX shape generalization

Status: **APPROVED, in progress.** Created 2026-07-20.
**S1 SHIPPED 2026-07-20** — the ARX family is extracted; S2 (the cipher) is next.

## Context

ChaCha20 shipped 2026-07-20 (`docs/plans/fluffy-orbiting-shannon.md`) as the app's
first stream cipher and first coreless cipher. Salsa20 is its direct ancestor —
same designer, same ARX family, same 4×4 word state, same keystream-⊕-message
structure — and it is the natural next cipher because it is the cheapest way to
buy two things the app currently asserts but has never demonstrated:

1. **That `"stream"` was correctly modelled as a sixth `CipherMode` rather than a
   per-cipher predicate.** ChaCha20's CLAUDE.md note argues a cipher-keyed
   predicate would have to be OR'd in at seven sites while a sixth mode costs
   zero. Salsa20 is the first chance to *prove* that: a second stream cipher
   should cost **one row** (`salsa20: ["stream"]`) and **zero** new arms on
   `isStreamCipher` / `isStreamCipherMode` / `cipherModeUsesIv` /
   `defaultCipherModeFor`. If it costs more, the abstraction was wrong.
2. **That the canonical-layout family generalizes.** ChaCha's P5 shipped a third
   shape/layout/diagram trio. Salsa20's double round has the *same* 98-leaf
   wall-of-chips problem, so it either forks ~1000 lines or forces the
   generalization. The user chose to generalize.

Salsa20 also adds something ChaCha cannot: **no `node:crypto` oracle exists**, so
it is the first cipher whose verification rests entirely on pinned external
vectors. That is a discipline worth having in the repo.

### Scope decisions (user, 2026-07-20)

- **Visual layer: generalize, do not fork.** Extract the shared ARX machinery so
  both ciphers consume it.
- **Variants: Salsa20/20 with a 256-bit key only.** Salsa20/8, Salsa20/12 and the
  128-bit-key variant (`"expand 16-byte k"`) are deferred.

### Refinement to the approved mechanism (advisor, 2026-07-20)

The option preview proposed parameterizing by an `opOrder: ["add","rot","xor"]`
token. **That does not survive contact with the code and is not what will be
built.** The two quarter rounds differ in their *dependency chain*, not merely in
the order of three tokens:

```
ChaCha  a += b;  d ^= a;  d <<<= 16     in-place accumulate; each op mutates a named rail
Salsa   z1 = y1 ^ ((y0 + y3) <<< 7)     add → rotate → xor into a FRESH rail
```

So the 12-op walk is irreducibly per-cipher. The *direction* the user approved —
maximal honest sharing, one family, no 1000-line fork — is delivered, and in fact
better delivered, by cutting the seam around the walk instead of inside it. The
sharing is still substantial: the entire layout module, the whole double-round
envelope, the word-index threading, and the diagram's rail/station rendering.

## Verified facts (measured, not recalled)

Confirmed byte-exact against `pycryptodome`'s `Crypto.Cipher.Salsa20` over two
blocks before any code was written:

- **Quarter round** — `z1=y1^ROL(y0+y3,7)`, `z2=y2^ROL(z1+y0,9)`,
  `z3=y3^ROL(z2+z1,13)`, `z0=y0^ROL(z3+z2,18)`. Rotation constants 7/9/13/18 are
  distinct, so they discriminate the walk exactly as ChaCha's 16/12/8/7 do.
- **Column round** applies QR to `(0,4,8,12) (5,9,13,1) (10,14,2,6) (15,3,7,11)`;
  **row round** to `(0,1,2,3) (5,6,7,4) (10,11,8,9) (15,12,13,14)`. Ten double
  rounds.
- **State is diagonal, not four regions:**
  `c0 ‖ k0..k3 ‖ c1 ‖ nonce ‖ counter ‖ c2 ‖ k4..k7 ‖ c3` — exactly **eight
  contiguous runs**, so state assembly is a single `concat@1` with
  `inputCount: 8`. (ChaCha's is four regions / `inputCount: 4`. This difference is
  the pedagogical payload of the cipher.)
- **Counter is 64-bit** (words 8–9), **nonce is 8 bytes** (words 6–7).
- **The counter starts at 0**, and pycryptodome offers no API to start it
  elsewhere. Do **not** carry over ChaCha's "RFC test vectors start at 1"
  narration — it is RFC-8439-specific and would silently decouple us from the
  only oracle we have.

## Approach

### Phase S1 — extract the shared ARX family (ChaCha-only, zero behaviour change) — **SHIPPED 2026-07-20**

Pure refactor, no Salsa20 yet. **The gate is that all ~41 existing ChaCha
shape/layout/diagram tests stay green without being edited.**

**Gate met exactly as written:** the five `tests/chacha-*` files pass 43/43 with
zero edits, and the full `npm run check` is green (280 files / 3755 tests).

**One design refinement found in the code.** The plan assumed `ArxOp` /
`ArxQuarterRoundShape` could be plain base types that ciphers intersect with
(`ChaChaQuarterRoundShape = ArxRailedQuarterRound & { ops: readonly ChaChaOp[] }`).
That does not typecheck: intersecting two array types gives
`readonly ArxOpBase[] & readonly ChaChaOp[]`, and element access resolves to the
BASE, so every `op.kind` / `op.bits` read in `chacha-diagram.ts` and
`chacha-shape.test.ts` breaks. The op type is therefore a **generic parameter**
(`ArxQuarterRoundShape<O extends ArxOpBase>`), which is what actually keeps the
cipher's richer descriptor intact through the envelope. Salsa's walk in S3
should declare `SalsaOp` and instantiate the same way.

`tests/arx-round-shape.test.ts` (new, 4 tests) checks what ChaCha's own suite
structurally cannot: that `anchorBits` is a real parameter (the envelope must
DECLINE ChaCha's rounds when told to anchor on Salsa's `<<< 18`), that the walk
is a real seam (a foreign matcher's descriptors ride through untouched), and
that the partition gate judges whatever the walk returns.

- `src/core/arx-round-shape.ts` (new) — the generic types (`ArxRail`, `ArxOp`,
  `ArxQuarterRoundShape`, `ArxDoubleRoundShape`), the narrowing helpers currently
  re-declared in `chacha-shape.ts:141-195` (`asRecord`, `paramNumber`,
  `portInputsOf`, `leafChildren`, `sameBinding`, `rotateBits`, `isBinary`,
  `operandPair`, `partitionOperands`), and the **envelope**:
  `analyzeArxDoubleRound(group, { anchorBits, matchQuarterRound })` — find the
  concat via `bodyOutput`, find the sole 16-way split, collect the 8 rotate
  anchors, run the per-cipher walk, apply the partition gate. Plus the generic
  `findActiveArxQuarterRound(frame, spec, analyze)`.
- `src/core/arx-round-layout.ts` (new) — `chacha-layout.ts` moved essentially
  verbatim. It already reads only `splitId` / `concatId` / `ops[].nodeId`, so this
  is a retype, not a rewrite.
- `src/core/chacha-shape.ts` — keeps `matchQuarterRound` (the ~120-line walk) and
  becomes a thin adapter calling the envelope with `anchorBits: 7`. Re-exports its
  existing type names as aliases so no consumer import changes.
- `src/core/chacha-diagram.ts` — `deriveWordIndices` moves to a shared module
  parameterized by rail list; `opLabel`, `kind`, and `rfcLabel` stay ChaCha's.

### Phase S2 — the cipher

- `src/ciphers/salsa20.ts` (new) — modelled on `chacha20.ts`. Structural notes:
  - **Endianness.** Same convention: words travel big-endian, every LE↔BE crossing
    is a visible `permute@1`. Crossings: key (32 B), nonce (8 B), counter, and the
    keystream (64 B).
  - **The counter is the one genuinely new wrinkle.** It is a 64-bit LE integer,
    so the bootstrap reverses **all eight bytes** (not per-word) to get a BE-64
    value that `increment-counter@1` — big-endian, width derived from the wired
    input — advances correctly. Inside the body the state wants two BE *words*
    (low first), which is one further `permute@1` swapping the two halves
    (`[4,5,6,7,0,1,2,3]`). Worth its own narration: "the counter is one 64-bit
    number; the state holds it as two words, low first."
  - **State assembly** is one `concat@1`, `inputCount: 8`, over the eight runs
    listed above. The four constants are four separate `constant-load@1` leaves;
    the key is split into two 16-byte halves with `byte-slice@1`.
  - **No new step type.** `add-mod-32@1`, `rotate-bits-left@1`, `xor@1`,
    `split-bytes@1`, `concat@1`, `permute@1`, `byte-slice@1`, `constant-load@1`,
    `aux-load-bytes@1`, `truncate-to-reference@1`, `increment-counter@1` all
    already exist. **Therefore zero coverage gates** (`port-provenance-coverage`,
    `narration-registry-contract`) are engaged.
  - Encrypt and decrypt are structurally identical, as with ChaCha/CTR/OFB.

- **Registration.** All compiler-enforced except one:
  `cipher.ts` (union member, `ALL_CIPHERS`, `CIPHER_LABELS`,
  `CIPHER_DESCRIPTIONS`, `CIPHER_HISTORY`, `DEFAULT_KEY_BYTES_BY_CIPHER`,
  `DEFAULT_PT_BYTES_BY_CIPHER`, `DEFAULT_CT_BYTES_BY_CIPHER`, and — **the only
  silent one, a `Partial<Record<…>>`** — `DEFAULT_IV_BYTES_BY_CIPHER`);
  `cipher-mode.ts:93` (`salsa20: ["stream"]`); `spec.ts` (import + `defaults`
  row); `padding.ts:135` (`case "salsa20"`); `document-schema.ts:64`
  (`CIPHER_IDS`).
  `BLOCK_CIPHER_CORES` is correctly left **untouched** — absence is what makes
  `hasBlockCipherCore("salsa20")` false.

### Phase S3 — Salsa20's shape, layout, diagram

- `src/core/salsa-shape.ts` — `matchSalsaQuarterRound`, anchored on the `<<< 18`
  that ends each quarter round, walking backwards through the four lines. Same
  cross-checking discipline as ChaCha's walk: every unknown pinned by an
  already-identified leaf, never by operand position.
- Layout comes free from `arx-round-layout.ts` — Salsa's quarter round is also
  four written lines of three ops, so the 3×4 block and the two-tier arrangement
  apply unchanged. Tier names become **column / row** (Bernstein's terms) rather
  than column / diagonal.
- `src/core/salsa-diagram.ts` + `src/ui/components/SalsaQuarterRoundDiagram.tsx` —
  four rails, twelve stations, same routing rule (a wire may cross a wire, never a
  labelled box). Labels follow Bernstein's written form
  (`z1 = y1 ^ ((y0+y3) <<< 7)`), not ChaCha's `+=` form.
- **Replication guard.** Salsa's 16-way split has ChaCha's high fanout, so it
  needs the same never-replicate treatment in `GraphView`. Fire the guard on any
  recognized ARX-double-round member so it generalizes with the shape rather than
  being a second hardcoded list.

## Verification

**The oracle problem is this plan's biggest risk.** `node:crypto` has no
`salsa20`, so — unlike ChaCha, whose KAT calls `createCipheriv` live — every
vector must be **generated offline from pycryptodome and hardcoded**. A KAT that
runs the app against the app is circular and passes on an entirely wrong cipher.

`tests/salsa20-kat.test.ts`, ranked by strength:

1. **Bernstein's `salsa20` core / `doubleround` / `rowround` / `columnround`
   vectors.** These exercise the round machinery *independent of the diagonal
   state assembly* — precisely where a state-layout bug hides that a full-cipher
   vector can mask.
2. **Pinned full-cipher vectors from pycryptodome** (and cross-checked against the
   published eSTREAM/ECRYPT verified vectors), counter starting at **0**.
3. Keystream continuity across the 64-byte block boundary; counter advances by
   exactly one per block.
4. A non-block-multiple message (ciphertext exactly as long as plaintext, no
   padding, short final block).
5. **Round-trip last, explicitly labelled a tautology** — one spec used both ways
   round-trips by construction even if the quarter round is entirely wrong.

`tests/app-salsa20-stream.test.tsx` — modelled on `app-chacha20-stream.test.tsx`.
The high-value case is the regression at its `:153`: **Salsa20's IV is also 16
bytes**, so switching AES → Salsa20 hits `reconcileIvWidth`'s equal-width
short-circuit exactly as the ChaCha bug did, and the wrong IV would be silently
retained. That bug was found by opening a browser, not by the suite; pin it.

Plus a **perturbation run**, recorded in the commit rather than assumed: swap two
of Salsa's rotation constants and confirm the KAT fails loudly.

**Browser smoke is required, not optional** (`feedback_visual_smoke_vs_property_tests`):
run `npm run dev`, select Salsa20, confirm the double round renders as the
canonical two-tier cell and not a 98-chip ribbon, scrub into a quarter round and
read the linear diagram.

### Cross-table canaries that will fail until updated

- `tests/cipher-mode-fallback.test.ts:71` — `STREAM_CIPHERS` must gain
  `"salsa20"`. **Not compiler-enforced.**
- `tests/ctr-all-cores-kat.test.ts:94,203` — a hardcoded
  `expect(coreless).toEqual(["chacha20"])`. **Breaks the moment Salsa20 lands and
  has nothing to do with stream ciphers by name** — easy to misdiagnose.
- `tests/default-ciphertext-table.test.ts:56` — compiler-enforced map entry.
- `tests/app-cipher-selector.test.tsx:111` — hand-maintained option list.

## Critical files

| File | Change |
|---|---|
| `src/core/arx-round-shape.ts` | **new** — generic types, helpers, double-round envelope |
| `src/core/arx-round-layout.ts` | **new** — `chacha-layout.ts` moved verbatim |
| `src/core/chacha-shape.ts` | keeps its walk; becomes an adapter over the envelope |
| `src/core/chacha-diagram.ts` | `deriveWordIndices` extracted; labels stay |
| `src/core/salsa-shape.ts` | **new** — the `<<< 18`-anchored walk |
| `src/core/salsa-diagram.ts` | **new** — presentation model |
| `src/ui/components/SalsaQuarterRoundDiagram.tsx` | **new** |
| `src/ciphers/salsa20.ts` | **new** — the spec builder |
| `src/ui/stores/cipher.ts` | union + 7 tables (1 silently omittable) |
| `src/ui/stores/cipher-mode.ts` | one row, zero new predicate arms |
| `src/ui/stores/spec.ts`, `padding.ts`, `core/document-schema.ts` | one entry each |
| `src/ui/components/GraphView.tsx` | 4th shape map; generalize the replication guard |
| `src/ui/App.tsx` | diagram render slot only (`:2151`) |

## Explicit non-goals

Salsa20/8 and Salsa20/12; the 128-bit-key variant; XSalsa20 (extended nonce);
Poly1305 / any authenticator; and any change to `BlockCipherCore` — Salsa20, like
ChaCha20, has no core and needs none.
