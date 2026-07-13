# SHA-3 / Keccak — port-native SHA3-256 (FIPS 202)

Status: **SHIPPED 2026-07-13.** SHA3-256 end-to-end, KAT-verified vs
`node:crypto`, browser-smoked. Foundation slice for future PQC work (ML-KEM /
ML-DSA consume SHAKE, which reuses this same Keccak-f[1600] permutation).
Implemented with 4 new steps (`keccak.theta@1`, `rotate-lanes@1`,
`keccak.iota@1`, `keccak.pad@1`) — one deviation from the plan's 3: ι became a
small custom `keccak.iota@1` (not reused `xor-with-aux@1`, whose same-length
operand rule doesn't fit a lane-0-only XOR against a shared RC table). Next
slice: SHAKE (the squeeze-fold XOF loop). Memory: `project_sha3_keccak_plan`.

## Context

The user wants to work toward the NIST Post-Quantum Cryptography standards
(ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA, FN-DSA). **Every one of those builds
on Keccak / SHA-3 / SHAKE**, and the app today only has SHA-256 (Merkle–Damgård).
So the honest first step — chosen by the user — is a port-native **SHA-3**, which
also slots straight into the existing hash selector as a standalone learning
artifact.

Decisions locked with the user:
- **Foundation first:** build SHA-3/SHAKE before any PQC algorithm.
- **Full standard, one param set.**
- **Concrete v1 = SHA3-256** (256-bit digest ≤ 1088-bit rate → single squeeze,
  **no XOF loop**). SHAKE256's variable-length squeeze-fold is deferred to the
  next slice; it reuses the Keccak-f + absorb built here unchanged.

The intended outcome: a new "SHA3-256" entry in the hash dropdown that traces
every step of the sponge (absorb fold + 24-round Keccak-f permutation + squeeze),
byte-identical to `node:crypto`'s `sha3-256` across all message lengths.

## Why the SHA-256 template both helps and misleads

SHA3-256 reuses SHA-256's port-native machinery wholesale: the port-mode
`iterate` fold (`blockByteLength`/`seedInput`/`chainInput`/`chainFeedback`/
`chainOutput`) IS the sponge absorb, with the carried chain being the full
**200-byte Keccak state** (bootstrapped to all-zeros — simpler than SHA-256's H
constants). `cipherConstants` carries the round constants (like SHA-256's `K`),
sliced per-round exactly like `K_t`. The hash selector wiring (`stores/cipher.ts`
+ `stores/spec.ts`) is already generic over the `Hash` union.

Five places the SHA-256 template will **actively mislead** (advisor-flagged,
verified against the code):

1. **Endianness. Keccak lanes are little-endian; the whole SHA-256 template is
   big-endian.** This is the #1 SHA-3 KAT footgun — it passes structural checks
   and silently produces a wrong digest. Verified: `rotate-bits-right@1`'s
   `wordBits===64` branch uses `decodeBE64`/`encodeBE64` (big-endian assembly),
   so feeding it a raw LE lane scrambles ρ. **Design response (below):** keep the
   200-byte state in the *standard LE byte-string form throughout*, and do all
   64-bit lane rotation inside LE-aware steps — so there is **no** boundary
   byte-reversal and `rotate-bits-right@1` is simply **not used** for Keccak.
2. **ρ is a *left* rotate with 25 *distinct* per-lane offsets.** A single
   `rotate-bits-right@1` rotates every word by the *same* amount, so ρ can't be
   one such leaf.
3. **Padding is pad10\*1 + a domain byte, NO length suffix.**
   `append-be64-length@1` is out.
4. **All six FIPS-202 functions share ONE Keccak-f[1600]**, differing only in
   rate/domain/output-length — build the permutation once, parameterize the rest.
5. **Oracle is ready:** `node:crypto` supports `'sha3-256'`. Empty-string
   SHA3-256 = `a7ffc6f8…f8434a`. Pin the first KAT against it before writing
   tests (house rule `feedback_crypto_verification`).

## Primitive strategy (the core design)

Keccak-f round = θ → ρ → π → χ → ι over a 5×5×64 lattice (25 lanes of 64 bits =
200 bytes). Byte layout: lane `(x,y)` occupies bytes `[8·(x+5y) .. +8)` in
standard LE order. Mapping each step to the vocabulary:

| Step | Realization | Notes |
|---|---|---|
| **θ** (theta) | **NEW `keccak.theta@1`** (one leaf) | Column parities XOR non-contiguous lanes + a rotate-by-1; decomposing = ~30 leaves of lane juggling with no payoff → encapsulate, with a rich narrator (h-expand precedent). |
| **ρ** (rho) | **NEW `rotate-lanes@1`** (generic port-native) | Rotates each fixed-width lane by a **per-lane offset**, **little-endian**. Reusable; ρ = the 25 fixed offsets. (θ's internal rotate-by-1 lives inside `keccak.theta@1`.) |
| **π** (pi) | **reuse `permute@1`** | Lane transposition `A[y,2x+3y]=A[x,y]` = one 200-byte lane-granular gather (`indices`). |
| **χ** (chi) | **decompose:** `permute@1` ×2 + `not@1` + `and@1` + `xor@1` | The sole nonlinear step — pedagogically the most valuable, so keep it visible. `A'[x]=A[x]⊕(¬A[x+1]∧A[x+2])`; the mod-5 row shifts are two whole-state permutes. |
| **ι** (iota) | **reuse `xor-with-aux@1`** | XOR RC[round] into lane (0,0); RC on `cipherConstants`, per-round `offset = 8·round` (exactly the `K_t` slice pattern). |

**Why the state stays LE throughout (no reversal permutes):** π/χ/ι are byte-wise
or lane-permuting → endianness-agnostic. The only endianness-sensitive ops (ρ and
θ's rotate) live inside `rotate-lanes@1` (LE-aware) and `keccak.theta@1`
(LE-internal). So the crossing the advisor warned about is *localized inside two
steps*, not spread across the round. RC constants are baked in standard LE.

**Rejected alternatives:** (a) fully decompose ρ into 25 separate rotate leaves —
a wall of table constants with no pedagogical payoff; (b) hold lanes BE-internal
and reverse at the block boundary — works, but pushes an endianness quirk onto the
visible trace when it can be hidden inside two steps.

**New step types (3), each shipped with tests in the same commit** (pre-commit
hook + house rule):
- `rotate-lanes@1` — params `{ wordBits, offsets: number[], littleEndian: true }`.
  Generic; unit test rotates a known lane both directions.
- `keccak.theta@1` — params `{}` (or `{ lanes: 25 }`); operates on 200 bytes.
  Unit test on a small known state.
- `keccak.pad@1` — params `{ rate, domainByte }`. Replaces `append-be64-length@1`.
  Unit test the merge cases: empty message; `len ≡ −1 (mod rate)` where domain +
  `0x80` collapse into one `0x86` byte.

Reused as-is: `permute@1`, `xor@1`, `and@1`, `not@1`, `xor-with-aux@1`,
`split-bytes@1`, `concat@1`, `byte-slice@1`, the port-mode `iterate`.

## Spec topology (`src/ciphers/sha3-256.ts`)

Constants: `rate = 136` bytes (1088 bits), `capacity = 64` bytes, `domain = 0x06`,
24 rounds, digest = 32 bytes. `cipherConstants = { RC: <192 bytes = 24 LE lanes> }`.

```
$input
 └─ keccak.pad@1 { rate:136, domainByte:0x06 }         → padded, multiple of 136
 └─ iterate "sponge"  (absorb fold)
       blockByteLength = 136
       seedInput   = pad.output
       chainInput  = 200 zero bytes  (constant-load, or a "S0" cipherConstant)
       chainFeedback = round.23 permutation output   (200 bytes)
       chainOutput = "state"
       body per block:
         # absorb: XOR the 136-byte block into the first 136 bytes of the state
         split-bytes(chain → [136][64]) + xor(block, rate-part) + concat → 200 B
         # Keccak-f[1600]: 24 rounds, each a (default-collapsed) group
         round.0 … round.23:  theta → rho(rotate-lanes) → pi(permute)
                              → chi(permute×2/not/and/xor) → iota(xor-with-aux, RC@8·r)
 # squeeze (single, since 32 ≤ 136): first 32 bytes of the final state
 └─ byte-slice@1 (state → first 32 bytes)              → digest
outputFrom = digest
```

For "abc" this is a single-block fold (~220 frames total — well under SHA-256's
~2486). Messages > 135 bytes exercise the multi-block absorb automatically.

## Selector + persistence wiring

Mirror the existing `"sha-256"` entries — all maps are keyed by the `Hash` union:
- `src/ui/stores/cipher.ts`: extend `Hash` to `"sha-256" | "sha3-256"`; add to
  `ALL_HASHES`, the label map (`"SHA3-256"`), description map, and the
  default-plaintext map (`"abc"`, matching SHA-256; the empty-string
  `a7ffc6f8…` KAT is covered by tests). `isHash`/`setHash` are already generic.
- `src/ui/stores/spec.ts`: add `"sha3-256": buildSha3256Spec()` to `hashDefaults`.
  `buildCanonicalHash` and the `applyDocument` hash short-circuit are already
  generic — no other change.
- **No** `cipher-mode.ts` change (hashes are mode-less — verified, no matches).

## Per-step-type UI obligations (per `src/steps/CLAUDE.md`)

For each of the 3 new steps: register in `src/ciphers/default-registry.ts`
(executor + doc); add a `ParamEditor.tsx` block (read-only `.param-scalars` `<dl>`
for `rate`/`domainByte`/`wordBits`; collapsed `<details>` for the `offsets`/`RC`
arrays); and either a narration unit fn in `src/ui/narration/` or a
`NARRATION_NO_OP_ALLOWLIST` entry with rationale (θ likely gets a structural
narrator like Twofish h-expand; `rotate-lanes` gets a per-lane drill).
`cipherConstants.RC` gets a constants-panel legend entry (provenance: the LFSR of
FIPS 202 §3.2.5). Per-spec-leaf `narrationOverride` carries the Keccak-specific
prose on every reused-primitive leaf (the SHA-256 `NARR_*` pattern).

## Verification

1. **Oracle first (before tests):** in a scratch script, compare against
   `require('node:crypto').createHash('sha3-256')` for `""`, `"abc"`, and a
   >136-byte message — pin the exact bytes, including empty = `a7ffc6f8…f8434a`.
2. **KAT test** `tests/sha3-256-kat.test.ts`: byte-equal vs `node:crypto` across
   the length range, explicitly including the empty message and a
   `len ≡ −1 (mod 136)` message (the `0x86` pad-merge case) and a multi-block
   message (exercises the absorb fold + `:b{i}` frame suffixing).
3. **Per-step unit tests** (same commits as the steps): `rotate-lanes` (known
   lane, both directions, LE), `keccak.theta` (small state), `keccak.pad` (the
   merge cases above).
4. `npm run check` (biome + tsc + vitest + build) stays green;
   `tests/cipher-mode-fallback.test.ts` (the canary) unaffected.
5. **Browser smoke** (`npm run dev`): select SHA3-256, enter "abc", confirm the
   digest matches the KAT, the 24-round group expands/collapses, θ/ρ/π/χ/ι
   narration renders, and the constants panel shows RC. (Playwright stays dormant
   per `feedback_playwright_dormant` unless a visual regression needs pinning.)

## Suggested commit sequence

1. `rotate-lanes@1` + `keccak.pad@1` + `keccak.theta@1` (steps + registry +
   ParamEditor + narration + unit tests).
2. `src/ciphers/sha3-256.ts` spec (θρπχι round builder + absorb iterate + squeeze)
   + selector/spec wiring + `tests/sha3-256-kat.test.ts`.
3. Constants-panel RC legend + default-collapse layout for the round group +
   docs (README "What's in the box", CHANGELOG, `docs/gotchas.md` Keccak section)
   + memory.

## Deferred (explicitly out of scope for this slice)

SHAKE128/256 (the squeeze-fold XOF loop — next slice, reuses this Keccak-f +
absorb); SHA3-224/384/512 (trivial rate/output re-parameterization once SHA3-256
lands); the PQC algorithms themselves.
