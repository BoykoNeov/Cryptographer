# Twofish — sixth cipher family, third Feistel

**Status:** SHIPPED (2026-07-12) — all 4 phases complete. Verified at three
levels (S-boxes, 40 subkeys, endpoint CT) against Niels Ferguson's reference C
library AND the published spec constants; canonical all-zero vector
`9f589f5cf6122c32b6bfec2f2ae8c35a`. Deferred items in "## Deferred" unchanged.

Twofish (Schneier/Kelsey/Whiting/Wagner/Hall/Ferguson, 1998 — AES finalist)
is the user's chosen sixth cipher and third Feistel after DES and Blowfish. It
is the natural successor to Blowfish in this explorer: another Schneier design
with **key-dependent S-boxes**, but far richer — it adds an **MDS matrix**, a
**pseudo-Hadamard transform (PHT)**, **input/output whitening**, and **1-bit
round rotations** on top of the Feistel skeleton. It exercises machinery no
existing cipher has: a *second and third* GF(2⁸) field (neither AES's), and a
key schedule whose subkey-mixing half decomposes cleanly while its h-function
half does not.

## Context

### User decisions (2026-07-12)

1. **Key size: 128-bit only for v1.** One fixed 16-byte key (`k = 2`). The
   h-function's q-permutation stage count is key-size-dependent (`k = 2/3/4`
   for 128/192/256), so each size is real added work. 128-only is the sane
   first cut (Blowfish fixed-key precedent); 192/256 are deferred follow-ups
   (Serpent-style "one variant per commit").

2. **Key schedule: partial visibility.** The user explicitly wants *more* than
   Blowfish's fully-opaque schedule. The chosen split (see below): the
   **PHT subkey mixing is visible** as real frames; the **h-function machinery
   (RS S-vector + q-permutation S-box construction + the h evaluations) is an
   opaque monolith** that publishes its outputs to aux. The round body (S-box
   lookups, MDS, PHT-in-F, whitening, 1-bit rotations) is fully decomposed
   either way.

   *The user named the RS S-vector first among the two visibility candidates.*
   We surface the **PHT** rather than the RS S-vector because the PHT
   decomposes into clean `add`/`rotate` frames that feed real consumers (the
   subkeys the rounds read), whereas exposing the RS S-vector needs a **4×8**
   GF(0x14D) matrix step that `gf-matrix-multiply` (4×4) does not cover, and
   its only consumer is the opaque S-box construction — a visible frame feeding
   an opaque step is a dangling illustration. RS visibility (as a decomposed
   *frame*) is a deferred deeper-visibility item, not a silent drop.

3. **The opaque block must still be explained + shown in the linear pedagogy
   panel** (user, 2026-07-12). The `twofish.h-expand@1` monolith stays one
   trace frame, but it is **not** an allowlisted narration no-op like Blowfish's
   `key-schedule` tail — it gets a **rich value-prose narrator** with
   disclosable pedagogy rows, one per hidden stage, each annotated with the
   **real per-key values this run produced**. This is the
   `blowfishKeyScheduleNarration` pattern (registry comment: "the monolith stays
   ONE trace frame … the StepNarration `<details>` mechanism gives it
   disclosable pedagogy ROWS … annotated with the REAL published values … not
   static text"), and Twofish is an even better fit: its hidden stages (LE key
   decode → Me/Mo split → RS S-vector → q-permutation S-box construction → the
   40 h-evaluations) are conceptually distinct and legibly *explainable* — they
   just aren't split into separate frames (that is the deferred "full h
   decomposition"). So the reader sees, inside one frame, what the opaque step
   did and the concrete numbers it produced.

### Author's decisions (advisor-sanctioned)

- **Internal word convention is BIG-ENDIAN.** Twofish is little-endian
  throughout, but the generic ARX primitives (`rotate-bits-right@1`,
  `add-mod-32@1`) decode/encode big-endian words. Reusing them (vs authoring
  LE variants) is strictly less work, so every 32-bit word travels the ports
  as BE bytes. The LE↔BE conversion is localized to the two endpoints as a
  **visible `permute@1`** (reverse the 4 bytes of each word) at plaintext-in
  and ciphertext-out — which also teaches Twofish's LE serialization honestly.

- **The g-function's internal LE↔BE crossing is the primary correctness
  risk** (see "The g function" below). We take **option (b): keep the paper's
  MDS matrix as the displayed `matrix` param and add one `permute@1 [3,2,1,0]`
  after the MDS multiply.** Rejected option (a) (row-reversed matrix param, no
  permute) because ParamEditor renders the matrix and a reversed one would
  mislead anyone cross-checking against a Twofish reference. Cost: ~32 extra
  `permute` frames (one per g, 2 g's × 16 rounds). Pedagogical honesty wins.

- **MDS reuses a *generalized* GF step, `gf-matrix-multiply@2`.** The existing
  `@1` hardcodes AES's field (`gfMul`, polynomial 0x11B) with no modulus param.
  Twofish's MDS is over **0x169**. So `@2` adds a `fieldModulus` param backed by
  a new `gfMulPoly(a, b, mod)` helper. **`@1` is left untouched** — AES depends
  on its hardcoded field. `@2` gets its own ParamEditor block + narration entry
  (the `@1` doc is AES-MixColumns-specific).

- **KAT oracle = the official Twofish `ecb_ival.txt` intermediate-values
  file**, NOT an endpoint-only KAT and NOT hand-typed values. `ecb_ival.txt`
  carries the S-vector, all 40 subkeys, and per-round intermediates — the only
  way to localize a bug in a 16-round cipher (an endpoint KAT after a swapped
  subkey index or wrong rotation just says "wrong ciphertext"). The `twofish`
  PyPI package is a convenience end-to-end oracle **after** we verify once that
  it reproduces `ecb_ival.txt`. Per `feedback_crypto_verification`: pin the
  first vector against the reference; don't hand-type from recall. The paper's
  Appendix A is the human-readable cross-reference; do not mix its formulation
  with a differently-indexed implementation's.

### Scope boundaries

Single-block only (multi-block ECB/CBC deferred, as Speck/Serpent/DES/Blowfish).
Encrypt + decrypt. No padding overlay (single-block). Canonical two-column
Feistel graph layout is **not** attempted — Twofish's round (input whitening
into g, PHT, 1-bit rotations) does not match `analyzeFeistelRound`'s
`split→F→xor→concat` shape, so it falls back to the generic vertical stack
(fine for v1, noted deferred — same call as Blowfish).

## The algorithm (reference — implement exactly, verify vs `ecb_ival.txt`)

Block = 16 bytes = four 32-bit words `(P0, P1, P2, P3)`, each a **little-endian**
read of 4 plaintext bytes. Key = 16 bytes → `M0..M3` (LE words), `k = 2`.
16 rounds.

**Constants.** `ρ = 0x01010101`. `q0`, `q1`: the two fixed 256-byte
permutations. `MDS`: 4×4 over GF(2⁸)/0x169. `RS`: 4×8 over GF(2⁸)/0x14D.

**Key schedule.**
- Split the key into `Me = (M0, M2)` and `Mo = (M1, M3)` (even/odd words).
- **S-vector:** for each `i` in `0..k-1`, `S_i = RS · (key bytes 8i..8i+7)`
  (a 32-bit word). The S-box key list is `L = (S_{k-1}, …, S_0)` — **note the
  word-order reversal** (a classic gotcha, invisible to an endpoint KAT).
- **Subkeys (h + PHT), 20 iterations `i = 0..19`:**
  - `A_i = h(2i·ρ, Me)`
  - `B_i = ROL(h((2i+1)·ρ, Mo), 8)`
  - `K_{2i}   = (A_i + B_i) mod 2³²`               ← PHT
  - `K_{2i+1} = ROL((A_i + 2·B_i) mod 2³², 9)`     ← PHT + rotate
  - `2·B_i` is doubling mod 2³² (`B_i + B_i`), **not** GF multiplication.
  - Produces `K0..K39`. `K0..K3` = input whitening, `K4..K7` = output
    whitening, `K8..K39` = round keys (2 per round).

**h function** `h(X, L=(L_0..L_{k-1}))` (with `k = 2`): take the 4 bytes of `X`;
run each byte through a fixed q0/q1 sequence interleaved with XOR of the
corresponding bytes of `L_1` then `L_0`; then multiply the 4 resulting bytes by
the **MDS** matrix → a 32-bit word. The exact per-lane q0/q1 sequence is the
second monolith gotcha — pin it against `ecb_ival.txt`.

**g function** `g(X) = h(X, S)` — the *same machinery* as h, with the S-vector
as the key list. Because `S` is fixed per key, the four key-dependent byte→byte
S-boxes `s0..s3` (q-perms composed with the S bytes) are **precomputed once**
per key and published to aux; g at run time is just `4 sbox lookups → MDS`.

**Round** `r = 0..15`, input `(R0, R1, R2, R3)`:
- `T0 = g(R0)`
- `T1 = g(ROL(R1, 8))`
- `F0 = (T0 +   T1 + K_{2r+8}) mod 2³²`
- `F1 = (T0 + 2·T1 + K_{2r+9}) mod 2³²`
- `R2' = ROR(R2 ⊕ F0, 1)`
- `R3' = ROL(R3, 1) ⊕ F1`
- next round input = `(R2', R3', R0, R1)` — the Feistel swap **is** the
  recombine (concat) argument order.

**Whitening.** Input: `R_i = P_i ⊕ K_i` (`i = 0..3`) before round 0. Output
(after round 15, undoing the last swap): `C_i = R_{(i+2) mod 4} ⊕ K_{i+4}`.
Then each `C_i` serializes little-endian to 4 ciphertext bytes.

**Decrypt** reverses the round order and inverts the 1-bit rotations and subkey
consumption order; whitening swaps K0..K3 ↔ K4..K7. One `buildTwofishSpec(
direction)` parameterizes both (Speck/Blowfish precedent). Correctness is pinned
by encrypt-KAT + round-trip (a symmetric enc/dec bug fails the KAT).

## Spec composition (mapping to port-native primitives)

Rotations as `rotate-bits-right@1` (`wordBits: 32`): `ROL8 = bits 24`,
`ROR1 = bits 1`, `ROL1 = bits 31`, `ROL9 = bits 23`.

### Key-setup group (`id: "key-schedule"`, default-collapsed)

- `aux-load-bytes@1` → the 16-byte key.
- **`twofish.h-expand@1`** (the opaque monolith) — consumes the key on an input
  port; publishes via `meta.auxWritePorts`:
  - `aux["twofish.A.0".."twofish.A.19"]` (4 BE bytes each — the 20 `A_i`)
  - `aux["twofish.B.0".."twofish.B.19"]` (4 BE bytes each — the 20 `B_i`,
    already `ROL 8`)
  - `aux["twofish.S0".."twofish.S3"]` (256 raw bytes each — the key-dependent
    byte→byte S-boxes; no endianness, pure byte→byte)
  Hides RS S-vector, q-permutation S-box construction, and the 40 h evaluations.
  It ALSO exposes the **S-vector words `S_0..S_{k-1}`** (and, if cheap, `Me`/`Mo`)
  on **display-only output ports** — declared in the `PortContract.outputs` but
  deliberately NOT in `meta.auxWritePorts`, so they ride in `frame.portOutputs`
  for the narrator to surface without a spurious unused-write graph warning.
  These values are the concrete per-key numbers the pedagogy panel shows
  (below); nothing downstream consumes them.
- **20 visible PHT blocks** (`i = 0..19`), each:
  - `aux-load-bytes@1` A_i, `aux-load-bytes@1` B_i (4 bytes each).
  - `K_{2i}   = add-mod-32@1(A_i, B_i)`
  - `2B_i = add-mod-32@1(B_i, B_i)`; `t = add-mod-32@1(A_i, 2B_i)`;
    `K_{2i+1} = rotate-bits-right@1(t, bits 23)`
  - `narrationOverride` names each as "PHT: K_{2i} = A+B" / "K_{2i+1} =
    ROL(A+2B, 9)".
- **`twofish.publish-subkeys@1`** (publish tail) — 40 input ports `K0..K39`
  wired from the PHT frames (same group scope → legal port-flow); publishes
  `aux["twofish.K.0".."twofish.K.39"]` via `meta.auxWritePorts`. This tail is
  the scope boundary that moves subkeys to aux for the rounds (port-flow can't
  cross group scopes — the AES/Serpent/DES decomposed-schedule shape exactly).

### Pedagogy for the opaque block (`twofish.h-expand@1`)

The monolith is one frame; its narrator (`twofishHExpandNarration`) turns it
into disclosable `<details>` rows, each annotated with the **real values this
run produced** (read from `frame.portInputs` / `frame.portOutputs` /
`frame.auxWritten` — never recomputed in the narrator). Coarse by design (the
authoring convention forbids per-item disclosure on large data):

1. **Decode the key → words + Me/Mo.** Show `M0..M3` (from the `key` input,
   LE-decoded in prose) and the even/odd split `Me=(M0,M2)`, `Mo=(M1,M3)`.
2. **RS S-vector.** Show the computed `S_0..S_{k-1}` (from the display-only
   ports). Explain the 4×8 GF(0x14D) RS multiply and the word-order reversal
   `L=(S_{k-1}…S_0)` — the gotcha `ecb_ival.txt` pins.
3. **Build the four key-dependent S-boxes.** Show each S-box head (first 16
   bytes, from `aux[twofish.S0..S3]`) — Blowfish's S-fill row precedent.
   Explain the q0/q1 permutation composition with the S bytes, and that g at
   run time is just `4 lookups → MDS`.
4. **h + subkey material (A/B).** Show a legible sample of the 20 `A_i` / 20
   `B_i` (from `aux[twofish.A.*/B.*]`). Explain that these feed the *visible*
   PHT frames below, which combine them into `K0..K39` — i.e. this row is the
   handoff from the opaque half to the visible half.

### Input whitening (before round 0)

- `permute@1` (reverse each word's 4 bytes: `[3,2,1,0, 7,6,5,4, …]`) on the
  16-byte plaintext → internal BE words. **← the visible LE→BE conversion.**
- `split-bytes@1 [4,4,4,4]` → R0..R3.
- 4 × `xor-with-aux@1 auxName="twofish.K.{i}"` → `R_i ⊕ K_i`.
- `concat@1` → the 16-byte round-0 input.

### One round (`round.{r}`, port-mode group, `r = 0..15`)

- `split-bytes@1 [4,4,4,4]` → R0, R1, R2, R3.
- **g(R0):** `split-bytes@1 [1,1,1,1]`; four `twofish.sbox-lookup@1`
  (`sboxName = twofish.S0..S3`, **`sbox_k` reads `split.out(3−k)`** — BE
  storage reversal); `concat@1(s0..s3)`; `gf-matrix-multiply@2
  fieldModulus=0x169 matrix=MDS`; `permute@1 [3,2,1,0]` → T0. *(option b)*
- **g(ROL(R1,8)):** `rotate-bits-right@1 bits 24` on R1, then the same g chain
  → T1.
- **F (PHT + key):** `aux-load-bytes@1` K_{2r+8}, K_{2r+9};
  `F0 = add-mod-32@1(T0, T1, K_{2r+8})`;
  `2T1 = add-mod-32@1(T1, T1)`; `F1 = add-mod-32@1(T0, 2T1, K_{2r+9})`.
  *(if `add-mod-32@1` is 2-input only, chain two 2-input adds — verify.)*
- **Mix:** `R2x = xor@1(R2, F0)`; `R2' = rotate-bits-right@1(R2x, bits 1)`;
  `R3r = rotate-bits-right@1(R3, bits 31)`; `R3' = xor@1(R3r, F1)`.
- **Recombine (swap):** `concat@1(R2', R3', R0, R1)` → 16-byte next state.

### Output whitening (after round 15)

- `split-bytes@1 [4,4,4,4]` the round-15 output into `(y0,y1,y2,y3)`.
- `C_i = xor-with-aux@1(y_{(i+2) mod 4}, "twofish.K.{i+4}")` — the swap-undo +
  output whitening in one wiring choice.
- `concat@1(C0,C1,C2,C3)`; `permute@1` (reverse each word) → **LE ciphertext.**

## New step types (4)

1. **`gf-matrix-multiply@2`** — generalizes `@1` with a `fieldModulus` param
   (default 0x11B for behavioural parity, set 0x169 for Twofish MDS). Backed by
   a new `gfMulPoly(a, b, mod)` in `src/core/state/matrix.ts`. `@1` untouched.
   Ships its own ParamEditor block (matrix + modulus) + narration entry.
2. **`twofish.h-expand@1`** — the opaque monolith. Input port `key` (16 bytes);
   `meta.auxWritePorts` publishes 20 `A`, 20 `B`, 4 S-boxes; display-only output
   ports carry the S-vector (+ Me/Mo). Executor calls pure
   `twofishKeySchedule(key)` from `twofish-constants.ts` (the KAT oracle).
   `kind: "ported"` + `meta`, no `legacy`. **Narration → a rich value-prose
   narrator** (`twofishHExpandNarration`, `blowfishKeyScheduleNarration`
   precedent) with disclosable rows, one per hidden stage, each showing the real
   per-key values (see "Pedagogy for the opaque block" below). NOT allowlisted.
   Its `detail` doc thoroughly explains the internal algorithm (RS S-vector, the
   word-order reversal `L=(S_{k-1}…S_0)`, per-lane q0/q1 sequence, MDS-in-h).
3. **`twofish.sbox-lookup@1`** — aux-fed **byte→byte** lookup (Twofish's are
   byte→byte, unlike Blowfish's byte→word). Input `index` (1 byte, wired) +
   `table` (256 bytes, aux-projected from `aux[sboxName]` via
   `meta.auxReadPorts`) → `output` (1 byte). Param `sboxName`. **Narration →
   value-prose fn** (`blowfishSboxLookupNarration` precedent, adapted byte→byte):
   names the key-derived S-box and shows the resolved byte.
4. **`twofish.publish-subkeys@1`** — publish tail. 40 input ports `k0..k39`
   (4 bytes each) → `aux["{prefix}.K.{n}"]` via `meta.auxWritePorts`. Param
   `outputPrefix` (default `twofish`). Narration → allowlist — parity with the
   four existing `*.publish-round-keys@1` tails; it is an identity passthrough
   whose interesting math is the *visible* PHT frames feeding it, so it is NOT
   an "opaque block" in the user's sense.

**Reused (no change):** `split-bytes@1`, `concat@1`, `xor@1`, `xor-with-aux@1`,
`add-mod-32@1`, `rotate-bits-right@1`, `aux-load-bytes@1`, `permute@1`.

## Phases

**Phase 1 — correctness spine (no UI).** `twofish-constants.ts` (q0/q1, MDS, RS,
ρ; pure `twofishKeySchedule` + `twofishEncryptBlock` oracle + LE codec); the 4
step files; `twofish-spec-builder.ts`; `twofish.ts`. Register the 4 steps.
`tests/twofish-vectors.test.ts`.
**Gate (advisor's explicit ordering):** *first* assert the S-vector + all 40
subkeys + an intermediate g-output match `ecb_ival.txt`; *then* the end-to-end
encrypt KAT. Do not accept a green endpoint KAT without the intermediate checks.

**Phase 2 — decrypt + round-trip.** `twofish-decrypt.ts`,
`tests/twofish-roundtrip.test.ts` (encrypt→decrypt = identity over several
inputs; reversed-subkey/rotation assertions).

**Phase 3 — UI wiring.** `cipher.ts` (type, union, labels, default
key/pt/ct bytes = the `ecb_ival.txt` vector), `spec.ts` `defaults`,
`cipher-mode.ts` `SUPPORTED_CIPHER_MODES_BY_CIPHER` (+ fallback canary),
`document-schema.ts` `CIPHER_IDS`, ParamEditor blocks (the 3 twofish steps +
`gf-matrix-multiply@2`), narration allowlist/fns, `default-ciphertext-table` +
`document-roundtrip` twofish entries. App selector is data-driven (expect ~zero
App change).

**Phase 4 — narration + docs + memory.** `narrationOverride` on every spec leaf
(round + PHT friendly names). The two value-prose narrators —
`twofishHExpandNarration` (the opaque-block pedagogy rows, user requirement) +
`twofishSboxLookupNarration` — in `src/ui/narration/twofish.tsx`, wired in
`narration/index.ts`; `publish-subkeys` on the allowlist.
`tests/narration-registry-contract.test.ts` stays green; add a jsdom test
asserting `h-expand` renders its stage rows with the run's real S-vector /
S-box-head / A-B values (not static text). README "What's in the box", CHANGELOG
`[Unreleased]`. Memory: new `project_twofish_plan.md` + MEMORY.md pointer.
Browser smoke via `npm run dev` — confirm the `h-expand` frame's pedagogy panel
expands into the four stage rows with real numbers. `npm run check` green with
Twofish selectable.

## Critical files

**New:**
- `src/ciphers/twofish-constants.ts` — q0/q1 tables, MDS (0x169), RS (0x14D), ρ;
  `twofishKeySchedule(key)` (→ `{ K: u32[40], S: Uint8Array[4], A/B intermediates }`),
  `twofishEncryptBlock` oracle, LE↔word codec; `TWOFISH_ROUNDS = 16`,
  `TWOFISH_BLOCK_BYTES = 16`.
- `src/ciphers/twofish-spec-builder.ts`, `twofish.ts`, `twofish-decrypt.ts`.
- `src/steps/twofish-h-expand.ts`, `twofish-sbox-lookup.ts`,
  `twofish-publish-subkeys.ts`.
- `src/ui/narration/twofish.tsx` — `twofishHExpandNarration` (opaque-block
  pedagogy rows) + `twofishSboxLookupNarration`.
- `gf-matrix-multiply@2` executor + doc (in `src/steps/gf-matrix-multiply.ts`,
  second export) + `gfMulPoly` in `src/core/state/matrix.ts`.
- `tests/twofish-vectors.test.ts`, `tests/twofish-roundtrip.test.ts`,
  `tests/gf-matrix-multiply-v2.test.ts` (a non-AES field KAT).

**Edited:**
- `src/ciphers/default-registry.ts` — register 4 step types.
- `src/ui/stores/cipher.ts`, `spec.ts`, `cipher-mode.ts`.
- `src/core/document-schema.ts` — `CIPHER_IDS`.
- `src/ui/components/ParamEditor.tsx` — 4 param blocks.
- `src/ui/narration/index.ts` — register the 2 twofish narrators;
  `registry.ts` — add `twofish.publish-subkeys@1` to the allowlist.
- `tests/cipher-mode-fallback.test.ts`, `default-ciphertext-table.test.ts`,
  `document-roundtrip.test.ts`.
- `README.md`, `CHANGELOG.md`, `CLAUDE.md` pointer, memory store.

**Reference (read, don't edit):** `src/ciphers/blowfish-spec-builder.ts`
(key-dependent S-box + aux-fed lookup + publish-monolith posture),
`src/steps/blowfish-sbox-lookup.ts` (aux-fed lookup shape),
`src/steps/blowfish-key-schedule.ts` (publish-to-aux monolith),
`src/steps/gf-matrix-multiply.ts` (`@1` to generalize),
`src/ciphers/aes-key-schedule-builder-native.ts` (visible-frames + publish-tail
decomposed schedule), `src/ciphers/des.ts` (port-mode round-group + concat-swap).

## Deferred (v1 non-goals)

192/256-bit keys (k=3/4 h-function branches); multi-block ECB/CBC; the RS
S-vector as a visible frame (needs a 4×8 GF(0x14D) step); full h-function /
S-box-construction decomposition.

**Closed since:**

- *Canonical graph layout* — SHIPPED 2026-07-12 as a 4-rail cell, not the
  two-column Feistel one this list imagined: the round shape genuinely doesn't
  match `analyzeFeistelRound`, so it got its own `twofish-shape.ts` /
  `twofish-layout.ts` pair rather than a strained union. See
  `docs/plans/polished-imagining-bird.md`.
- *Linear-view abstract diagram* — SHIPPED 2026-07-17. `TwofishRoundDiagram`
  over a pure `core/twofish-diagram.ts` model. It carries the swap-X the graph
  view had to drop for being a 2000px tangle; at single-round scale the wires
  are ~50px and the 4-way rotation reads.
- *Share-URL cipher-selector flip* — was NOT still a bug when checked on
  2026-07-17. Phase 6e of `docs/plans/des-feistel.md` fixed it before Twofish
  shipped, via the document's `algorithm` hint (emitted on both the save and
  share paths, read by `setSpecFromDocument`, which flips the selector and
  smart-swaps the byte defaults). This entry was stale.
