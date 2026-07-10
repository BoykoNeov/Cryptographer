# Blowfish — fourth Feistel-family cipher (second Feistel after DES)

**Status:** APPROVED-pending — plan written 2026-07-10. Awaiting go-ahead to build Phase 1.

## Context

**What & why.** Blowfish (Schneier, 1993) is the user's chosen "new Feistel
cipher." It is the pedagogically richest option: a 16-round Feistel with a
64-bit block, but a *self-referential* key schedule that generates its
key-dependent P-array + four S-boxes by **running Blowfish on itself 521
times**. It contrasts every existing cipher: unlike DES (bit-permutation
Feistel) it is a 32-bit ARX-ish Feistel; unlike AES/Serpent its S-boxes are
*derived from the key*, not fixed tables.

**The central design tension (resolved).** The project spent Phases 2–5
decomposing every monolithic key schedule into visible port-native frames.
Blowfish's schedule *cannot* decompose legibly — 521 self-encryptions with a
hard data-dependency chain would be tens of thousands of frames. The project's
real rule is "decompose what decomposes legibly," and this doesn't. So the
schedule's 521-loop is a **hybrid-ported monolith** (same posture as
`rsa.publish-key-params@1` / the four `*-publish-round-keys@1` tails), which
*also* serves as the KAT oracle (precedent: the kept `*.key-expansion@1`
oracles). This is the consistent call, not a reversal. (Advisor-confirmed.)

**User decision (2026-07-10):** *visible key-mix + opaque loop.* The
`key ⊕ P` mixing (how a variable-length key enters) is shown as real XOR
frames; only the 521-encryption loop is opaque. Chosen over a fully-opaque
monolith.

**Author's decisions (mine, advisor-sanctioned):**
- **F-function is decomposed** (split → 4 aux-fed S-box lookups →
  `((S0[a]+S1[b]) ⊕ S2[c]) + S3[d]`) so the round arithmetic is visible.
- **π tables (P + 4 S-boxes, ~4KB) stay as MODULE CONSTANTS**, never in spec
  params. DES bakes its 64-byte PC tables into params; Blowfish's 4KB of
  incompressible π digits would bloat every `.cipher.json` and share-URL
  (`deflate-raw` can't shrink π). The 72-byte π P-array *is* small enough to
  ride in a `constant-load@1` for the visible key-mix; the 4KB S-boxes are
  consumed inside the monolith executor from module constants.
- **Key fixed at 8 bytes for v1.** Blowfish accepts 4–56-byte keys, but
  `inputs.key.byteLength` is a single fixed number — variable-length keys need
  new work (deferred). 8 bytes matches the standard Eric-Young vector set.
- **KAT oracle = pycryptodome `Crypto.Cipher.Blowfish` (ECB)**, NOT node
  (OpenSSL 3 buries Blowfish in the legacy provider — often unavailable). Per
  `feedback_crypto_verification`, pin the FIRST vector against the reference,
  don't hand-type from recall.

**Scope boundaries.** Single-block only (multi-block ECB/CBC deferred, same as
Speck/Serpent/DES). Encrypt + decrypt. No padding overlay (single-block).
Canonical Feistel two-column graph layout is NOT attempted — Blowfish's pre-F
`L ⊕ P[i]` breaks `analyzeFeistelRound`'s `split→F→xor→concat` shape, so it
falls back to the generic vertical stack (fine for v1, noted deferred).

## The algorithm (reference, to implement exactly)

Block = 8 bytes = two big-endian 32-bit words `xL || xR`. 16 rounds.

**Key schedule** (`blowfishKeySchedule(key) → { P: u32[18], S: u32[4][256] }`):
1. `P ← π P-array` (18 words), `S ← π S-boxes` (4×256 words) — module constants.
2. `for i in 0..17: P[i] ^= keyWord(i)` where `keyWord(i)` = 4 key bytes
   big-endian, cycling with wraparound (8-byte key ⇒ only 2 distinct words,
   alternating). **← the visible key-mix.**
3. `block ← 0x00000000_00000000`; then repeatedly `block ← encrypt(block)` and
   assign its two words into successive slots: `P[0],P[1] ← block`; re-encrypt →
   `P[2],P[3]`; … `P[16],P[17]` (9 encryptions); continue into
   `S[0][0],S[0][1]`, … `S[3][254],S[3][255]` (512 encryptions). **521 total.**
   Each encryption uses P/S as mutated so far. **← the opaque loop.**

**F function:** `F(x) = ((S0[x≫24] + S1[(x≫16)&0xff]) ⊕ S2[(x≫8)&0xff]) + S3[x&0xff]`
(adds mod 2³²).

**Encrypt(xL, xR):**
```
for i in 0..15:  xL ^= P[i];  xR = F(xL) ^ xR;  swap(xL, xR)
swap(xL, xR)        # undo the final loop swap
xR ^= P[16];  xL ^= P[17]
return xL || xR
```
**Decrypt:** identical but P consumed in reverse — loop uses `P[17..2]`,
whitening uses `P[1]` then `P[0]`.

## Spec composition (how it maps to port-native primitives)

**Key-setup group** (default-collapsed, `id: "key-schedule"`):
- `constant-load@1` → the 72-byte π P-array (18 words). *(π P only; S-boxes
  never enter the spec.)*
- `aux-load-bytes@1` → the 8-byte key; two `byte-slice@1` → key words `kw0`,
  `kw1`.
- `split-bytes@1 widths=[4×18]` on the loaded P → 18 word ports.
- 18 × `xor@1 inputCount=2` → `P[i] ⊕ kw(i mod 2)` — **the visible key-mix.**
- `concat@1 inputCount=18` → the 72-byte key-mixed P.
- `blowfish.key-schedule@1` (**the monolith**) — consumes key-mixed P on an
  input port, runs the 521-loop using π S-boxes (module const), publishes via
  `meta.auxWritePorts`: `aux["blowfish.P.0".."blowfish.P.17"]` (4 bytes each) +
  `aux["blowfish.S0".."blowfish.S3"]` (1024 bytes each). **The one opaque frame.**

**Round group** `round.{i}` (port-mode group, DES-style; i = 1..16):
- `split-bytes@1 widths=[4,4]` → `L`, `R`.
- `xor-with-aux@1 auxName="blowfish.P.{i-1}"` on `L` → `L1 = L ⊕ P[i-1]`.
  *(reuses the parameterizable generic step — verified.)*
- **F(L1):** `split-bytes@1 widths=[1,1,1,1]` → `a,b,c,d`; four
  `blowfish.sbox-lookup@1` (**new**, aux-fed word lookup, `sboxName`
  = `blowfish.S0..S3`) → `s0,s1,s2,s3`; `add-mod-32@1(s0,s1)` → `t1`;
  `xor@1(t1,s2)` → `t2`; `add-mod-32@1(t2,s3)` → `Fout`.
- `xor@1(Fout, R)` → `R1`.
- `concat@1` recombine as `R1 || L1` — the Feistel swap IS the concat order
  (DES precedent).

**Post-round whitening** (after `round.16`): `split-bytes@1` its output into
`A || B`; `xor-with-aux@1(B, "blowfish.P.17")`, `xor-with-aux@1(A,
"blowfish.P.16")`; `concat@1 → (B⊕P17) || (A⊕P16)` = ciphertext. *(This is the
final-swap-undo + P16/P17 whitening.)* Decrypt mirrors with `P.1`/`P.0`.

`buildBlowfishSpec(direction)` parameterizes the P-slot wiring so encrypt and
decrypt share one builder (Speck/DES precedent).

## New step types (2)

1. **`blowfish.key-schedule@1`** — hybrid monolith. Input port `keyMixedP`
   (72 bytes); `meta.auxWritePorts` mirrors 18 P words + 4 S-boxes to aux.
   Executor calls a pure `runBlowfishLoop(keyMixedP)` helper (π S-boxes from
   module const). A sibling pure `blowfishKeySchedule(key)` (full: π-init +
   key-mix + loop) lives in `blowfish-constants.ts` as the **test/KAT oracle**.
   Registered `kind: "ported"` + `meta`, no `legacy`. Narration → allowlist
   (aux-only). ParamEditor → read-only scalar block.
2. **`blowfish.sbox-lookup@1`** — aux-fed word lookup. Input port `index`
   (1 byte, wired); `meta.auxReadPorts` projects `aux[sboxName]` (1024 bytes)
   onto port `table`; output `output` (4 bytes = `table[index*4 .. +4]`).
   Param `sboxName`. Registered `kind: "ported"` + `meta`. Narration → small
   fn (or allowlist). ParamEditor → read-only scalar block.

## Phases

**Phase 1 — correctness spine (no UI).** `blowfish-constants.ts` (π tables +
`blowfishKeySchedule` oracle), the 2 step files, `blowfish-spec-builder.ts`,
`blowfish.ts`. Register both steps. `tests/blowfish-vectors.test.ts`: KAT vs a
pycryptodome-generated vector (8-byte key). **Gate: encrypt KAT green.**

**Phase 2 — decrypt + round-trip.** `blowfish-decrypt.ts`,
`tests/blowfish-roundtrip.test.ts` (encrypt→decrypt = identity across several
inputs; reversed-P assertion).

**Phase 3 — UI wiring.** `cipher.ts` (`BlowfishCipher` type, `Cipher` union,
`ALL_CIPHERS`, `CIPHER_LABELS`, `DEFAULT_{KEY,PT,CT}_BYTES_BY_CIPHER`),
`spec.ts` `defaults`, `cipher-mode.ts` `SUPPORTED_CIPHER_MODES_BY_CIPHER`
(+ `tests/cipher-mode-fallback.test.ts` canary), `document-schema.ts`
`CIPHER_IDS` (tsc-forced), ParamEditor blocks, narration allowlist/fn,
`tests/default-ciphertext-table.test.ts` + `tests/document-roundtrip.test.ts`
blowfish entries. Verify App selector is data-driven (likely zero App change).

**Phase 4 — narration + docs + memory.** `narrationOverride` on every spec
leaf (per-round friendly names, Speck/DES idiom). README "What's in the box",
CHANGELOG `[Unreleased]`. Memory: new `project_blowfish_plan.md` + MEMORY.md
pointer. Browser smoke via `npm run dev`.

## Critical files

**New:**
- `src/ciphers/blowfish-constants.ts` — π P + 4 S-boxes (module const);
  `blowfishKeySchedule(key)` + `runBlowfishLoop(keyMixedP)` pure helpers;
  `BLOWFISH_ROUNDS = 16`, `BLOWFISH_BLOCK_BYTES = 8`.
- `src/ciphers/blowfish-spec-builder.ts`, `blowfish.ts`, `blowfish-decrypt.ts`.
- `src/steps/blowfish-key-schedule.ts`, `src/steps/blowfish-sbox-lookup.ts`.
- `tests/blowfish-vectors.test.ts`, `tests/blowfish-roundtrip.test.ts`.

**Edited:**
- `src/ciphers/default-registry.ts` — register the 2 step types.
- `src/ui/stores/cipher.ts` — union + label + 3 default-byte tables.
- `src/ui/stores/spec.ts` — `defaults` table.
- `src/ui/stores/cipher-mode.ts` — `SUPPORTED_CIPHER_MODES_BY_CIPHER`.
- `src/core/document-schema.ts` — `CIPHER_IDS`.
- `src/ui/components/ParamEditor.tsx` — 2 param blocks.
- `src/ui/narration/*` — allowlist / narration fn for the 2 steps.
- `tests/cipher-mode-fallback.test.ts`, `tests/default-ciphertext-table.test.ts`,
  `tests/document-roundtrip.test.ts` — coverage for the new cipher.
- `README.md`, `CHANGELOG.md`, `CLAUDE.md` pointer, memory store.

**Reference (read, don't edit):** `src/ciphers/des.ts` (port-mode round-group +
concat-swap pattern), `src/steps/xor-with-aux.ts` (parameterizable auxName),
`src/steps/add-mod-32.ts` (32-bit BE word add), `src/ciphers/rsa.ts`
(publish-to-aux monolith posture).

## Deferred (v1 non-goals)

Variable-length key (4–56 bytes); multi-block ECB/CBC; canonical two-column
Feistel graph layout (round shape doesn't match `analyzeFeistelRound`);
share-URL cipher-selector flip (pre-existing bug, see
`project_share_url_cipher_selector_bug`); full-visibility of the 521-loop.
