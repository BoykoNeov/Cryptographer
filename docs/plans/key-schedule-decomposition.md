# Key-schedule decomposition (the productive half of "meta retirement")

> **Status: K1 (AES) CLOSED 2026-06-01 — gate GREEN (biome+tsc+vitest
> 2180 pass+2 skip / 189 files + build).** Plan-mode draft approved; design
> refined by an advisor pass that **reversed iterate→unroll**. K1a
> (decomposition, crypto-verified), K1b (duplicate-round via builder rebuild),
> K1c (blast-radius retarget + mirror role-scoping + KeyScheduleExplorer AES
> retirement + graph smoke + A-vs-B gate) all shipped. **K2–K4 (Speck /
> Serpent / DES schedules) NOT STARTED.** Plan-mode source:
> `~/.claude/plans/misty-questing-fairy.md`. Each slice opens an advisor pass
> ([[feedback_iterative_slice_review]]).
>
> **K1-gate OUTCOME (2026-06-01, user-decided via AskUserQuestion, graph smoke
> in hand — 0 console/page errors, correct FIPS ciphertext, collapsed view
> identical to pre-decomposition AES, 214 chips on expand):**
> 1. **Topology = B-minimal.** Keep the meta-bearing `aes.publish-round-keys@1`
>    tail; AddRoundKey consumers untouched. (Smoke confirmed A's explicit
>    per-round-key wires would only relabel the *same* fan-out for no legibility
>    gain — `replicateHighFanoutSources` already tames it.)
> 2. **S-box mirror = re-home Copy (role-scoped by leaf id).** `byte-substitute@1`
>    now has TWO mirror roles: round-body SubBytes keeps class-2 "Sync inverse"
>    (scoped to NON-`key-schedule.*` leaves); the SubWord leaf gets class-1
>    "Copy S-box to decrypt" (scoped to `key-schedule.*` leaves). This both
>    fixes a real **corruption hazard** (the old type-wide inverse broadcast
>    would overwrite the decrypt key schedule's forward S-box — invisible to the
>    KAT gate) AND preserves the FIPS §5.2 "forward S-box even when decrypting"
>    teaching moment the retired `aes.key-expansion@1` Copy carried.
> 3. **KeyScheduleExplorer = retire the AES branch.** Unreachable (no
>    `aes.key-expansion@1` frame ships) AND redundant (the RotWord/SubWord/Rcon/
>    XOR frames are now scrubbable in the trace). Serpent + DES branches kept
>    until K3/K4 decompose them.

## Context

The four key schedules — `aes.key-expansion@1/@2`, `speck.key-schedule@1`,
`serpent.key-expansion@1`, `des.key-schedule@1` — are the last **monolithic
hybrid-ported** steps. Each carries `meta`: `auxReadPorts` projects
`aux[keyAuxName] → masterKey`, `auxWritePorts` projects each `key${r}` output →
`aux[outputPrefix.${r}]`. The real schedule math (RotWord/SubWord/Rcon/word-XOR
for AES) runs **invisibly inside one executor** — never a trace frame. That is
the opposite of the project thesis ("the math IS the cipher; every sub-step is a
scrubbable frame"), which Phase 2's SHA-256 already delivers.

"meta retirement" = **key-schedule decomposition**: turn each schedule into a
composition of existing port-native primitives so the sub-steps become visible,
and (where it doesn't hurt legibility) drop the `meta` projection. Opens with an
**AES-first spike** (hardest: RotWord/SubWord/Rcon + AES-256 `Nk>6` mid-word
SubWord + a recurrence whose groups don't align with round keys), per the memory
sequencing decision *"decompose AES alone end-to-end incl. a graph smoke, and
LOOK before committing all four."*

## Two axes — producer-only (B-minimal) first; consumer rewire (A) is gated

The fan-out is a matched meta pair: producer (schedule writes `roundKey.N` to
aux) ⟷ consumer (each AddRoundKey `xor-with-aux@1` reads `aux["roundKey.N"]`).

- **B-minimal (the spike):** decompose the schedule's *internal* math into
  primitive frames; end in a small **meta-bearing aux-publish tail** that writes
  `roundKey.N` exactly as today. **Consumers and `aes-round-builder-native.ts`
  are untouched.** Full pedagogical win, ~95% of key-schedule meta retired
  (only the tail keeps `meta`), ~zero topology risk.
- **A (gated, optional follow-on):** schedule emits each round key on an
  explicit output port; consumers rewire via explicit `portInputs`; aux fan-out
  + rest of `meta` gone — full retirement. **All the topology risk lives here**
  (N labelled wires across the canvas). **The A-vs-B call is the spike's
  OUTPUT** — decided at the K1-gate *with rendered visuals*, not up front.

## Design: unroll-over-groups (NOT FES) — advisor-reversed 2026-06-01

AES's key schedule has a **per-group constant** (Rcon[g]), so it is structurally
a sibling of SHA-256's **unrolled rounds** (each a `StepGroup` with its own
`byte-slice offset` constant), NOT its FES message schedule (uniform body, no
per-iteration constant). A shared FES body cannot carry a per-iteration
constant. So: **unroll the recurrence into one `StepGroup` per Nk-word group**,
chained port-to-port (group g seeds from group g-1's published output) — the
same idiom as SHA-256 rounds + the AES round body.

**Recurrence (FIPS-197 §5.2), per generated group g (words `g·Nk … g·Nk+Nk-1`):**
- head `split-bytes@1` (widths `[4]×Nk`) the previous group's Nk words → `pw[0..Nk-1]`
- `nw[0]`: RotWord(`pw[Nk-1]`)=`permute@1[1,2,3,0]` → SubWord=`byte-substitute@1`
  → XOR Rcon = `constant-load@1 [rc,0,0,0]` + `xor@1` (= `temp`); then
  `nw[0] = xor@1(pw[0], temp)`
- `nw[j]` (j=1..Nk-1): `xor@1(pw[j], nw[j-1])`; for **Nk=8, j==4**: insert
  `byte-substitute@1(nw[3])` before the XOR (FIPS-197 §5.2 mid-word SubWord)
- group `bodyOutput` = `concat@1(nw[0..Nk-1])`; group g+1's `seedInput` reads it

**Seed:** group 0 = the master key. `aux-load-bytes@1(auxName:"key", Nk·4)` →
group 1 seeds from it. (The master key already lives in `aux["key"]`.)

**Repack (groups don't align with round keys for Nk=6/8):**
`concat@1(seed, group1.out, …, groupLast.out)` → one word-stream of **exactly**
`totalWords·4` bytes (build the last group with fewer word-leaves so we emit
exactly `totalWords = 4·(rounds+1)`), then `byte-slice@1(offset 16·r, len 16)`
per round key `r = 0..rounds`.

**Aux-publish tail (the only surviving meta):** a new meta-bearing step
`aes.publish-round-keys@1` — identity executor taking `key0..keyN` on input
ports (wired from the repack byte-slices), `meta.auxWritePorts` mapping
`key${r} → roundKey.${r}`. Reuses the existing meta aux-write path (lower risk
than a new pure-port aux-writer; a general `aux-store-bytes@1` is deferred).

**Rcon:** computed at build time via `xtime` in TS for exactly the needed count
(one `constant-load@1` per group). No runtime Rcon table.

**Per-size structure** (`Nk = key.byteLength/4`, `totalWords = 4·(rounds+1)`):
- AES-128: Nk=4, 44 words → seed + 10 full groups (group=round key; trivial repack)
- AES-192: Nk=6, 52 words → seed + 7 full + 1 partial(4); non-trivial repack
- AES-256: Nk=8, 60 words → seed + 6 full + 1 partial(4); + the j==4 SubWord; non-trivial repack

## Slices

### K1a — static AES key-schedule decomposition (crypto-first)

- New `src/ciphers/aes-key-schedule-builder-native.ts`:
  `buildAesKeyScheduleNative(rounds, Nk)` → the `group "key-schedule"` above +
  per-leaf `narrationOverride`s; build-time `xtime` Rcon.
- New step `aes.publish-round-keys@1` (`src/steps/publish-round-keys.ts`) +
  register in `default-registry.ts` + ParamEditor block + narration handling.
- Rewire the 8 AES specs (`aes-128/192/256.ts` + `-decrypt` +
  `aes-ecb-builder.ts` + `aes-cbc-builder.ts`): replace the single
  `aes.key-expansion@1` leaf with `...buildAesKeyScheduleNative(rounds, Nk)`.
- New unit test: decomposed subgraph's published `roundKey.0..N` byte-equal the
  monolithic `keyExpansion` outputs for FIPS-197 §A.1/§A.2/§A.3 keys, all sizes.
- **Gate (crypto):** `aes-vectors`, `aes-192/256-vectors`, `aes-decrypt`,
  `aes-128-ecb-kat` byte-equal — UNCHANGED, the safety net.
- **Interim:** `bumpKeyExpansion` still throws "no key-expansion leaf" →
  duplicate-round tests RED here, **expected** (fixed in K1b).

### K1b — duplicate-round via builder rebuild + `@1/@2` collapse

- Rewrite `bumpKeyExpansion` (`spec-mutations.ts`) to locate the decomposed
  `key-schedule` group, compute `newRounds`/`Nk`, and splice
  `buildAesKeyScheduleNative(newRounds, Nk)` in its place.
- Collapse `aes.key-expansion@2` + `keyExpansionV2`/`xtime` runtime machinery
  (builder now handles arbitrary `rounds`); retire `key-expansion-v2.test.ts` or
  retarget to the builder.
- **Gate:** all `duplicate-round-*` green; new **end-to-end extended-KAT** test
  (duplicate a round, run, assert the extended-round ciphertext) pinning the
  producer↔consumer aux seam.

### K1c — blast radius + graph smoke + A-vs-B gate

- `cross-mode-mirror-registry.ts` "Copy S-box to decrypt" (keyed on
  `aes.key-expansion`) + `cross-mode-mirror-coverage.test.tsx` — re-home onto the
  decomposed SubWord `byte-substitute` leaf or retire (decide here).
- `ParamEditor.tsx` `KeyExpansionBlock` — orphaned; remove/repurpose.
- `KeyScheduleExplorer.tsx` + `key-schedule-sim/aes.ts` + sim-parity test —
  interception by stepType dissolves; **fate decided at the gate** (keep as
  high-level summary vs retire — the real computation is now in the trace).
- Frame-shape/dispatch tests retargeted: `frame-port-values`,
  `runtime-ported-dispatch*`.
- **Graph smoke** (throwaway Playwright per [[feedback_visual_smoke_vs_property_tests]]):
  render the decomposed AES key schedule; wire 1–2 round-key edges explicitly to
  preview option A; screenshot; then `AskUserQuestion` **A vs B** + explorer fate.

### K2 — Speck32/64 key-schedule decomposition (advisor-revised 2026-06-01)

> **Status:** advisor consulted 2026-06-01 — verdict "revise then ship." Three
> structural revisions applied below. **K2a SHIPPED 2026-06-01** (commits
> `c5b91ef` plan, `2f3d511` add-mod-16, `8f7434c` speck.publish-round-keys,
> `0c9f3a6` builder). Gate green (biome + tsc + 2227 vitest + vite build);
> KAT byte-equal across BE-paper / LE-NSA × encrypt / decrypt; decomposition
> parity test pins published `roundKey.0..21` byte-equal to the legacy
> monolith under both byte orders.
>
> **K2b SHIPPED 2026-06-01** — blast-radius cleanup landed as a thin
> hygiene slice (K2a's `feat` commit had already preemptively retargeted
> the aux-graph derivation tests; the remaining work was confirming the
> advisor-decided "keeps" with updated framing). Narration allowlist
> gained `speck.publish-round-keys@1` (parity with the AES analog), the
> stale `speck.key-schedule@1` allowlist comment was refreshed to
> acknowledge K2a's "no shipped spec uses this leaf" status (parallel to
> the AES @1/@2 comment), the `irreducible 6 entries` docstring rot was
> corrected, the narration-contract size pin bumped 8 → 9, and
> `SpeckKeyScheduleBlock`'s header was reframed as fallback-only (per
> the K2 advisor pass: keep for pre-K2 saved docs + palette-droppable
> legacy executor). Gate green (biome + tsc + 2227 vitest + vite build).
>
> **K2c-gate CLOSED 2026-06-01 (user-decided via AskUserQuestion, graph
> smoke in hand — 0 console/page errors across all 4 specs, KAT byte-equal
> ciphertexts a86842f2 / f24268a8, collapsed view shows a single `Key
> Schedule` chip with the 22-round aux fan-out tamed by
> `replicateHighFanoutSources`, expanded view stacks the iterations
> top-down with the (m-1)=3 lag arcs rendered as in-place `master-split`
> replicas not back-arrows). The user's verdict DIVERGES from K1's:
>
> 1. **Topology = A (explicit per-round-key ports).** Unlike K1 (where
>    the gate picked B-minimal — "A's wires would only relabel the same
>    fan-out for no legibility gain"), the K2 gate picked A: the schedule
>    will emit each round key on a labelled output port; each Speck round's
>    round-key consumer will rewire via `portInputs.roundKey`; aux fan-out
>    + the remaining `meta` (`auxWritePorts` on publish, `auxReadPorts` on
>    speck.round/speck.round-inverse) gone — FULL retirement. The K1 plan
>    explicitly sequenced A as an "optional follow-on" separate from the
>    spike; for Speck it now becomes **K2d** (below).
 > 2. **`SpeckKeyScheduleBlock` = retire now.** Initial K2c closure
>    (commit `347fbae`) retired the editor block only and kept the
>    legacy executor registered as a KAT oracle. An **advisor pass on
>    K2b+K2c flagged the partial-retire as diverging from the user's
>    literal Q2 option-text** (which said "Delete the block + retire
>    the speck.key-schedule@1 executor registration"). User re-confirmed
>    full retire; the **K2c follow-up commit** then:
>    - Deleted `src/steps/speck-key-schedule.ts` and the registration
>      block in `default-registry.ts`.
>    - Migrated `tests/speck-32-64-key-schedule-decomposition.test.ts`
>      from the monolith-executor oracle to an **inline Beaulieu §3
>      reference implementation** (decode master key per byteOrder →
>      run the ROR/ADD/⊕/ROL recurrence → encode round keys per
>      byteOrder). The decomposed schedule's published `roundKey.0..21`
>      still byte-equal across BE/LE; the oracle is now an independent
>      straight-line TS implementation of the same recurrence the
>      decomposed primitives express graphically.
>    - Rewired the runtime-dispatch (d) synthetic (`tests/runtime-ported-dispatch-speck.test.ts`)
>      to pre-seed `roundKey.0` in initialAux rather than instantiating
>      the retired step type.
>    - Dropped `speck.key-schedule@1` from the narration allowlist and
>      replaced the brittle size-pin (8→9 every K-slice churn) with a
>      `toEqual(new Set([...]))` set-equality assertion that pins the
>      whole allowlist shape — K3/K4 touch the data, not the arithmetic.
>    - Refreshed stale doc comments in `default-registry.ts`,
>      `narration/registry.ts`, `RoundKeyPanel.tsx`, and this plan.
>
> **K2c is now two commits.** The initial closure (`347fbae`) +
> the K2c follow-up. Both share the same `[Unreleased]` block in the
> CHANGELOG. Gate stays green across both.
>
> **K2d NOT STARTED.** A-topology rewrite for Speck — its own slice, its
> own advisor pass, its own KAT gate per [[feedback_iterative_slice_review]].

**Recurrence (Beaulieu et al. 2013 §3), per iteration `i = 0 … rounds-2`:**
`l_{i+m-1} = (k_i + ROR(l_i, alpha)) ⊕ i` ; `k_{i+1} = ROL(k_i, beta) ⊕ l_{i+m-1}`.
Speck32/64: `wordBits=16, m=4, rounds=22, alpha=7, beta=2`. 21 iterations writing
`roundKey.0..21`. The cipher's own ARX kernel runs in both round body and
schedule — the punchline this decomposition makes visible.

**New port-native primitives K2a ships:**
- **`add-mod-16@1`** — exact dual of `add-mod-32@1` (fixed 16-bit BE, N≥2
  operand ports, `inputCount` param). Posture: per-width fixed step types
  (mirror `add-mod-32@1`'s precedent — carry semantics differ per width).
- **`speck.publish-round-keys@1`** — parallel to `aes.publish-round-keys@1` but
  STRUCTURALLY DIFFERENT in two ways the advisor flagged: (a) emits **exactly
  `rounds`** round keys (not `rounds+1`), `for r in 0..rounds-1`; (b)
  per-round-key `byteLength` is `wordBits/8` (2 for Speck32/64), not AES's
  hardcoded 16. Cannot reuse the AES tail; the port contract's `byteLength`
  field would fail validation.

**Builder:** `buildSpeck32_64KeyScheduleNative(rounds, m, wordBits, alpha,
beta, byteOrder)` in `src/ciphers/speck-32-64-key-schedule-builder-native.ts`.
Structure (one outer `key-schedule` group, id-prefixed leaves):

- `key-schedule.load-key` — `aux-load-bytes@1(auxName:"key", byteLength: m*2)`.
- **`key-schedule.input-codec` — `permute@1` PRESENT IN BOTH MODES (different
  indices)** because the master-key memory layout differs from logical word
  order in BOTH conventions. Per `speck-word-codec.ts::decodeKey`:
  - **BE-paper** memory = `(l_{m-2}, …, l_0, k_0)`, BE-encoded per word →
    permute indices `[6,7,4,5,2,3,0,1]` for m=4 (reverse the four 2-byte
    words; no byte-swap within words).
  - **LE-NSA** memory = `(k_0, l_0, …, l_{m-2})`, LE-encoded per word →
    permute indices `[1,0,3,2,5,4,7,6]` for m=4 (byte-swap within each word;
    no word reorder).
  After the codec leaf, both modes produce the logical layout
  `[k_0(BE), l_0(BE), l_1(BE), l_2(BE)]`. `narrationOverride`: "Decode master
  key from {BE-paper | LE-NSA} memory layout to logical word order
  `[k_0, l_0, …, l_{m-2}]`, BE-encoded internally."
- `key-schedule.master-split` — `split-bytes@1(widths:[2]×m)` of the codec'd
  master key → `output0=k_0, output1=l_0, output2=l_1, output{m-1}=l_{m-2}`.
  Identical across modes (the codec handles the difference upstream).
- **Per iteration** `i = 0..rounds-2`, leaves `key-schedule.g{i}.{role}`:
  - `g{i}.l-source` — `portInputs.input` binds to: (for `i < m-1`)
    `master-split.output{i+1}`; (for `i ≥ m-1`) `g{i-(m-1)}.new-l.output`.
    (Advisor: parameterize by `m`; lag is `(m-1)` iterations, not the
    hardcoded 3.)
  - `g{i}.k-source` — `portInputs.input` binds to: (for `i = 0`)
    `master-split.output0`; (for `i > 0`) `g{i-1}.new-k.output`.
  - `g{i}.rot-l` — `rotate-bits-right@1(wordBits:16, bits:alpha)`.
  - `g{i}.sum` — `add-mod-16@1(inputCount:2)` of `k-source ⊞ rot-l`.
  - `g{i}.round-const` — `constant-load@1(bytes:[hi(i), lo(i)])` — BE
    encoding of the round counter `i`, since body bytes are always BE.
  - `g{i}.new-l` — `xor@1(inputCount:2)` of `sum ⊕ round-const`.
  - `g{i}.rol-k` — `rotate-bits-right@1(wordBits:16, bits: wordBits-beta)`.
    (ROL(x, β) = ROR(x, B-β).)
  - `g{i}.new-k` — `xor@1(inputCount:2)` of `rol-k ⊕ new-l`.

**Output codec — asymmetric across byteOrder (advisor pick):**
- **BE-paper:** body's `new-k` and `master-split.output0` are already BE per
  word, which matches BE-paper's published encoding. Direct wiring. Publish
  tail's `key0` ← `master-split.output0`; `key{i+1}` ← `g{i}.new-k.output`
  for `i = 0..rounds-2`. No intermediate concat/slice.
- **LE-NSA:** body's BE per-word bytes need a byte-swap to match LE-NSA's
  published encoding. Insert one codec sub-pipeline:
  `concat@1(master-split.output0, g{0}.new-k, …, g{rounds-2}.new-k)`
  (rounds × 2 = 44 bytes for Speck32/64) → `key-schedule.output-codec =
  permute@1 [bulk per-word byte-swap, indices [1,0,3,2,…,43,42]]` →
  `rounds × byte-slice@1` (each `[offset 2·r, length 2]`) → `publish.key${r}`.
  ONE codec leaf, clearly labelled. Mirrors K1's `word-stream → byte-slice →
  publish` pattern.

This is the advisor's load-bearing **substantive change**: byte-order
convention is a CODEC, not scattered plumbing. ONE leaf at input boundary,
ONE leaf at output boundary, LE-only. Body bytes are always BE-encoded. The
trace reads "LE-NSA = BE-paper computation with explicit codec at the
boundary," matching `speck-word-codec.ts`'s own design intent.

**Slices:**

- **K2a — decomposition + KAT gate.** Ship `add-mod-16@1` (+ doc + paramless
  ParamEditor block + register + test). Ship `speck.publish-round-keys@1`
  (parallel to the AES one but `byteLength` polymorphic + `rounds` not
  `rounds+1`). Ship the builder above. Rewire `buildSpeck32_64Spec` to call
  `...buildSpeck32_64KeyScheduleNative(...)` instead of emitting a monolithic
  `speck.key-schedule@1` leaf. **Decomposition unit test:** published
  `roundKey.0..21` byte-equal vs legacy `speck.key-schedule@1` for Beaulieu
  Table 4.1 key (`1918111009080100`) **under BOTH byte orders**. **Crypto
  gate:** `speck-32-64-vectors.test.ts` + `speck-32-64-decrypt.test.ts`
  byte-equal before/after, all four direction × byteOrder specs.

- **K2b — blast-radius cleanup.** ParamEditor's `SpeckKeyScheduleBlock`: keep
  as fallback (legacy executor stays registered for back-compat per K1
  pattern). `narration/registry.ts` allowlist entry: keep (legacy executor
  still palette-droppable). Aux-graph derivation tests keyed on
  `speck.key-schedule` leaf id → retarget to the `key-schedule` group
  (parallel to K1c's `key-expansion → key-schedule` rename).

- **K2c — graph smoke + A-vs-B gate.** Throwaway Playwright: render the
  decomposed schedule for ALL FOUR specs (BE/LE × enc/dec), screenshot,
  eyeball the topology. Advisor flagged the uncollapsed view as a risk —
  ~150 leaves × (m-1)=3-lag arcs reaching back may show crowding. Collapsed
  view should fan out clean from the `key-schedule` container.
  `AskUserQuestion` A-vs-B + ParamEditor block fate.

**Explicitly NOT in K2:**
- No `bumpSpeckRounds` analog. Builder's `rounds` param makes a future
  Speck-duplicate-round slice cheap; defer until user asks.
- No `rol/ror/wordMask` helper consolidation across `speck-key-schedule.ts` /
  `speck-round.ts`. Defer until Phase 4d's Speck rebuild settles whether the
  round becomes a builder.
- No `KeyScheduleExplorer` Speck branch retirement (never existed).
- No cross-mode mirror work (Speck has no S-box in schedule).

**Advisor-flagged uncertainty (worth surfacing at the K2-gate):** in LE-NSA
mode, the schedule body's intermediate frame values render in BE byte-order
(the param panel says LE-NSA, the frame view shows BE bytes). Less confusing
than "byte order changes mid-body" but not zero-confusion. The `input-codec`
and `output-codec` leaves' `narrationOverride` must explicitly say so.

### K2d — Speck A-topology rewrite (queued by the K2c gate, 2026-06-01)

> **Status: NOT STARTED.** The K2c gate picked A. Its own advisor pass +
> KAT gate per [[feedback_iterative_slice_review]] before shipping.

**What A means structurally:**

- **`speck.publish-round-keys@1` loses `meta.auxWritePorts`.** The
  publish tail's output ports `key0..key{rounds-1}` become the only
  consumer surface; nothing more lands in `aux["roundKey.N"]` from the
  decomposed schedule.
- **`speck.round@1` / `speck.round-inverse@1` lose `meta.auxReadPorts`
  and `params.roundKeyAux`.** Each round leaf reads its round-key word
  via `portInputs.roundKey` pointing at the publish tail's `keyN`
  output. The `roundKey` input port stays — only the projection path
  changes.
- **`buildSpeck32_64Spec` rewires.** Each round leaf gains
  `portInputs.roundKey = port("key-schedule.publish", "key{r}")` (or
  the reverse-order analog for the decrypt variant); the
  `params.roundKeyAux` line drops.

**Cross-container `portInputs` precedent.** The publish leaf has id
`key-schedule.publish` and lives inside the `key-schedule` group; round
leaves live OUTSIDE that group. `portInputs` wires by step id (a flat
ID space — container membership is rendering / collapse metadata, not
a scoping rule), so cross-container reads "just work" — same mechanism
the SHA-256 spec already uses for cross-group references.

**Back-compat trade-off (post-K2c-follow-up framing).** The K2c
follow-up fully retired the monolithic `speck.key-schedule@1`
step type, so a pre-K2 saved Speck doc carrying that LEAF no longer
loads. The K2a..K2d span is **a single un-released sub-phase under
one `[Unreleased]` CHANGELOG section — no tagged release of the K2a
state will ever exist**. That guarantee depends on K2d landing before
any release tag is cut; if K2d slips, the guarantee weakens and a
release manager will need to either (a) hold the tag, (b) restore the
legacy executor under a deprecation flag, or (c) accept that pre-K2
Speck docs are non-loadable in the next release. The K1c precedent
(AES @1/@2 kept registered) is broken here, by user-and-advisor pick.

**Open advisor questions for K2d:**

1. **Do `roundKeyAux` + `meta.auxReadPorts` survive as an optional
   fallback** (preserving any in-the-wild non-loadable scenarios as
   "loads but reads from aux") or fully retire? Cleaner posture argues
   for full retire — under A the round's `roundKey` input always comes
   from `portInputs`, so a fallback path would be dead code from day
   one.

2. **Decrypt-variant reverse-order port wiring.** Speck decrypt consumes
   `roundKey.21, .20, …, .0` in that order. Under aux this was free
   (the spec leaf names whichever aux entry it wants). Under A with
   explicit `portInputs`, the decrypt builder has to wire `round.0.roundKey
   ← publish.key21`, `round.1.roundKey ← publish.key20`, …, `round.21.roundKey
   ← publish.key0` — 22 cross-wires in reverse. This is **exactly** the
   topology risk the K1 plan flagged for A. The K2d graph smoke should
   confirm the decrypt graph reads cleanly under `replicateHighFanoutSources`,
   and not as a tangled cross-pattern.

3. **`RoundKeyPanel.tsx` retarget.** The panel's `isRelevantFrame`
   classifier reads `frame.auxRead` / `frame.auxWritten` on aux keys
   matching `prefix.N`. Under A the round bodies no longer write or
   read aux for the round keys (the `roundKey` port flows directly).
   The K2c follow-up updated the panel's doc comment but the actual
   classifier may quietly miss-classify Speck round frames if the
   round step's frame `auxRead` is empty under A. Grep before the K2d
   advisor pass: does the panel still light up correctly, or does it
   need a `portInputs`-aware fallback (e.g., also check whether any
   frame's port-input bytes match a known `prefix.N` value)? If the
   panel goes dark for Speck under A, the user picks: retarget the
   panel (worth doing), or accept (Speck never had a dedicated
   `KeyScheduleExplorer` arm anyway, so the round-key ribbon is the
   only schedule-aware UI surface — going dark for Speck is a regression).

4. **K2a parity test retarget.** The test currently asserts
   `aux["roundKey.0..21"]` byte-equality against the inline Beaulieu
   §3 reference (just landed in the K2c follow-up). Under A those aux
   entries don't exist; retarget to read the publish leaf's per-port
   output values out of the trace frame's `portOutputs` map. **Pre-draft
   decision** (advisor flagged it has a concrete answer): use the
   trace-frame `portOutputs` read; don't roll into the KAT byte-equal.
   The whole point of the parity test is to surface decomposition bugs
   the KAT can't catch (a one-bit-off in iteration `i` that the next
   iteration happens to cancel before round-1 consumes it).

5. **Vectors tests' "produces all 22 round keys in aux" assertions** —
   rewrite to assert "produces all 22 round keys on publish output
   ports" (same trace-frame read), or delete (KAT covers it).

6. **Graph rendering smoke.** Verify the 22 explicit port-flow wires
   from `key-schedule.publish` to the 22 round consumers fold via
   `replicateHighFanoutSources` the way the K2c B-defense argued (with
   the advisor verdict "would only relabel the same fan-out"), OR show
   a more legible topology the K2c gate user expected. Capture both
   encrypt + decrypt variants (the decrypt reverse-wiring of Q2 is
   where the risk concentrates). **Do not** re-cite the K2c B-defense
   in K2d's `AskUserQuestion` framing as if A had been observed and
   rejected — it hadn't been.

**Files affected (estimate):** 3 step files
(`speck-publish-round-keys.ts`, `speck-round.ts`, `speck-round-inverse.ts`),
1 builder (`speck-32-64-builder.ts`), 1 param-editor block
(`SpeckRoundBlock` — drop `roundKeyAux` row), 5-7 tests (vectors,
decrypt, decomposition parity retarget, round-key panel retarget,
runtime-ported-dispatch, maybe narration), 1 doc comment in
`RoundKeyPanel.tsx`. Bigger than K2a's blast radius; KAT gate is the
safety net.

### K3 — Serpent / K4 — DES (sequenced after K2)

Same unroll pattern for Serpent (per-round constants → unroll); DES has none
and is a different shape. Each its own KAT gate + advisor pass per
[[feedback-iterative-slice-review]].

## Critical files

- **New:** `src/ciphers/aes-key-schedule-builder-native.ts`,
  `src/steps/publish-round-keys.ts`.
- **Retire/collapse:** `src/steps/key-expansion.ts` (monolith + the @2/xtime
  variant), `tests/key-expansion-v2.test.ts`.
- **Rewire:** `src/ciphers/aes-128.ts`, `aes-192.ts`, `aes-256.ts`,
  `aes-128-decrypt.ts`, `aes-192-decrypt.ts`, `aes-256-decrypt.ts`,
  `aes-ecb-builder.ts`, `aes-cbc-builder.ts`.
- **Mutator:** `src/core/spec-mutations.ts` (`bumpKeyExpansion`).
- **Constants:** `src/ciphers/aes-constants.ts` (`AES_RCON` source for the
  build-time xtime helper; the runtime table is no longer wired into a spec).
- **Registry/UI:** `src/ciphers/default-registry.ts`,
  `src/ui/components/ParamEditor.tsx`, `cross-mode-mirror-registry.ts`,
  `KeyScheduleExplorer.tsx`, `src/ui/narration/*`.
- **Reference templates (reuse, don't re-derive):** `src/ciphers/sha-256.ts`
  (unrolled-rounds idiom + `byte-slice`/`concat`/`constant-load` usage),
  `src/ciphers/aes-round-builder-native.ts` (builder/narration idiom),
  `src/core/port-projection.ts` (`meta.auxWritePorts` for the publish tail).

## Verification

- `npm run check` green at each sub-slice.
- **Crypto gate:** FIPS-197 Appendix C KATs (all 3 sizes, enc+dec, ECB, CBC)
  byte-equal before/after (executors unchanged ⇒ they pin the round keys).
- **Duplicate-round:** `duplicate-round-*` green + the extended-KAT seam test.
- **Graph smoke:** throwaway Playwright; 0 console/page errors; screenshots for
  the A-vs-B judgment; delete the spec ([[feedback_playwright_dormant]]).

## Open questions

- **Resolved by the unroll design:** per-iteration Rcon (→ `constant-load@1` per
  group), over-generation (→ exact `totalWords`), duplicate-round (→ builder
  rebuild in `bumpKeyExpansion`; `@1/@2` collapse).
- **At K1-gate (with visuals):** A vs B topology; KeyScheduleExplorer fate.

## K1 closure notes (2026-06-01) — for K2–K4 + meta-retirement reviewers

- **Mirror hazard (the one the KAT gate can't catch).** Decomposition put
  `byte-substitute@1` in TWO mirror roles distinguished by leaf-id prefix:
  round-body SubBytes (class-2 inverse) and key-schedule SubWord (class-1
  identity — forward S-box even when decrypting). The type-wide
  `syncSboxInverseToCounterpart` broadcast would have overwritten the decrypt
  key-schedule SubWord leaves with the inverse table → corrupt decryption on a
  UI click. **Fix:** `updateAllStepsByType` gained an optional `idFilter`; the
  two sbox mirrors are role-scoped (`isRoundBodyLeafId` / `isKeyScheduleLeafId`
  in `cross-mode-mirror-registry.ts`); `ByteSubstituteBlock` renders the inverse
  row for round-body leaves and a re-homed Copy row for `key-schedule.*` leaves.
  Guard tests: `sync-sbox-inverse` (key-schedule untouched) + `sync-sbox-copy`
  (round-body untouched). **K2–K4 lesson: any future shared-type role split
  needs the same role-scoping + a corruption-guard test.**
- **KeyScheduleExplorer AES branch RETIRED** (component arm + `key-schedule-sim/aes.ts`
  + sim-registry entry + parity test + `isKeyExpansionStepType` membership). The
  real RotWord/SubWord/Rcon/word-XOR frames ARE the swimlane now. Serpent + DES
  branches kept until K3/K4 decompose them.
- **Graph blast-radius (the bulk of K1c).** In the **collapsed** default view
  the round-key fan-out originates from the `key-schedule` CONTAINER (publish
  remaps on collapse); `replicateHighFanoutSources` skips container sources, so
  the fan-out renders as a bundle, not replicas. In the **uncollapsed** pure
  graph, `key-schedule.publish` is the aux source (cross-scope → consumer-scope
  replicas, NO spine-replica) and `key-schedule.word-stream` is the port-flow
  source (same-scope → IS the spine-replica). Component graph tests retargeted
  `key-expansion` → `key-schedule` (container); pure-transform tests →
  `key-schedule.publish` / `key-schedule.word-stream`; palette drop-anchors →
  `initial.add-round-key`. **Serpent still uses real `key-expansion` — do NOT
  global-rename.**
- **`@1/@2` executors KEPT registered** (FIPS oracle for
  `aes-key-schedule-decomposition.test.ts` + backward-compat for pre-K1 saved
  docs + the synthetic `runtime-ported-dispatch-aes-core` (c) parity). Palette
  still lists them. Their deletion is a future release per `docs/versioning.md`.
  **Back-compat is "loads and runs", NOT "all features work":** an old doc
  carrying the monolithic `key-expansion` LEAF loads + encrypts/decrypts fine
  (executor present, writes `roundKey.N`, AddRoundKeys read it), but
  **duplicate-round won't work on it** — `bumpKeyExpansion` looks for the
  `key-schedule` GROUP and finds nothing on a pre-K1 doc. Acceptable (old docs
  are rare and re-selecting the cipher regenerates the decomposed spec), but
  narrower than "fully back-compatible."
- **url-share payload grew** ~4.4 KB → ~8.5 KB (AES-128) from ~114 schedule
  sub-step leaves each carrying a `narrationOverride`; still trivially URL-safe.
