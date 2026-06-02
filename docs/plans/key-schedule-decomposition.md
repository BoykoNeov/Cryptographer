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

### K2d — Speck topology: RESOLVED as B-minimal (2026-06-01, user decision)

> **Status: RESOLVED as B-minimal — no code changes required.** The K2c
> gate (recorded above, lines ~188–195) picked topology A; that direction
> is **reversed** here. `main` already ships B-minimal for AES (K1c) and
> Speck (K2a–K2c). See memory `project_group_scope_port_isolation`.

**Resolution summary:**

1. **A proved unbuildable** without new runtime machinery. A `group`'s
   children walk in an isolated `nodeOutputs` scope; `portInputs` resolve
   same-scope ONLY and throw across a group boundary (measured error:
   *"no recorded outputs in this scope … same-scope wiring only"*). The
   decomposed schedule lives inside the collapsed `key-schedule` group,
   so only the global `aux` map crosses the boundary. There is no way to
   wire a round leaf outside the group to a publish leaf inside the group
   via `portInputs` without a new group-output-export runtime feature.

2. **A's payoff narrowed to nothing on further inspection — three facts:**
   - **Collapsed-identical:** Collapsed, A and B render identically. The
     `key-schedule` container box draws the same fan of aux arrows to each
     consumer round; `collapseGraph` remaps aux and port edges the same
     way; the difference is only cosmetic edge-style/label in the expanded
     view.
   - **SHA-256 already ships B:** SHA-256 uses aux fan-out for its round
     constants K, initial hash H, and message-schedule W — all fanned off
     the global board across the iterate/message-schedule container
     boundary — with no complaint. B is the established cross-boundary
     fan-out pattern. (The earlier "SHA-256 cross-container precedent for
     A" was a misread — SHA-256's rounds are same-scope siblings, not
     grouped; that's why its `portInputs` cross-references work.)
   - **Derived = view-only:** Round keys are recomputed from the master
     key, so they are view-only by nature in either topology. A unlocks
     no inspect/edit that B does not.

3. **No code changes.** `main` already ships B-minimal end-to-end for
   both AES and Speck. K2d is closed without a code commit.

**Back-compat trade-off (still applies regardless of topology).** The K2c
follow-up fully retired the monolithic `speck.key-schedule@1` step type,
so a pre-K2 saved Speck doc carrying that LEAF no longer loads. The
K2a..K2d span is **a single un-released sub-phase under one `[Unreleased]`
CHANGELOG section — no tagged release of the K2a state will ever exist**.
That guarantee depends on K2d closing before any release tag is cut; if
K2d had slipped, a release manager would have needed to either (a) hold
the tag, (b) restore the legacy executor under a deprecation flag, or (c)
accept that pre-K2 Speck docs are non-loadable. K2d is now closed, so the
guarantee holds.

#### K2d-resolved: A vs B decision rule for K3/K4

**Policy (replaces the earlier "≥22 → A / ≤11 → B" threshold rule):**

> **B-minimal for all grouped schedules.** Topology A is only
> reconsidered if a group-output-export runtime feature ships.

**Rationale.** A is unbuildable for ANY grouped schedule under the current
runtime — all four schedules (AES/Speck/Serpent/DES) live inside a
`key-schedule` group, so the group-scope port isolation applies to all of
them. There is no per-cipher A-vs-B gate: K3 (Serpent) and K4 (DES)
proceed as B-minimal mechanically, without a smoke/re-gate. If a future
slice ships a group-output-export runtime feature, revisit A for the
cipher that benefits most from explicit per-round-key wiring visibility.

---

#### Deferred appendix — topology A (NOT being built)

> The A-topology design below is preserved for a possible future revisit,
> gated on a group-output-export runtime feature. Nothing below is being
> implemented. **The "cross-container portInputs precedent" claims in
> this section were found to be a misread** — SHA-256's cross-references
> work because its rounds are same-scope siblings, not grouped; they do
> NOT demonstrate cross-group resolution (which throws "same-scope wiring
> only" at runtime). That claim is annotated inline below.

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

**Cross-container `portInputs` precedent — MISREAD (preserved for history).**
The publish leaf has id `key-schedule.publish` and lives inside the
`key-schedule` group; round leaves live OUTSIDE that group. The original
claim was that `portInputs` wires by step id (a flat ID space) so
cross-container reads "just work" — citing SHA-256 as the precedent. This
was a misread: SHA-256's rounds are same-scope siblings (not grouped), so
their cross-references are within-scope and do not test group-boundary
crossing. Measured: a `portInputs` reference from a round leaf (outside
the group) to `key-schedule.publish` (inside the group) throws at runtime
with "no recorded outputs in this scope … same-scope wiring only." A
requires a new runtime feature to become buildable.

**Advisor verdicts (consulted 2026-06-01, pre-implementation; now moot):**

1. **Q1 — fallback path: full retire.** Drop `params.roundKeyAux` +
   `meta.auxReadPorts` on `speck.round@1` / `speck.round-inverse@1`.
   Dead-from-day-one fallback = maintenance liability + reader
   confusion ("which path is real?"). Single source of truth.

2. **Q2 — decrypt fan-out predictability: unknown until smoke.**
   `replicateHighFanoutSources` IS in scope for port-flow edges
   (verified at `GraphView.tsx` ~line 2885, eligibility key is
   `PORT_FLOW_AUX_KEY`-marked state edges). Encrypt should tame like
   K2c. Decrypt reverse-wiring (22 cross-wires `round.i ←
   publish.key{ROUNDS-i}`) is the open question — replication tames
   the source-side chip explosion but doesn't undo geometric reversal.
   **Don't pre-commit a mitigation; capture smoke first.**

3. **Q3 — `RoundKeyPanel` retarget: do it in the same commit.** The
   classifier currently pattern-matches `frame.auxRead`/`auxWritten`
   on `${prefix}.${N}` keys and is cipher-agnostic by design. Under A
   the Speck-side aux matches go cold; extend `isRelevantFrame` to
   ALSO match `frame.portInputs.has("roundKey")` (consumer side) or
   any `frame.portOutputs` `keyN` write (producer side). Avoids a real
   pedagogical regression (ribbon is Speck's only schedule-aware UI
   surface) and preserves the panel's cipher-agnostic invariant.

4. **Q4 — parity test retarget: agree, `portOutputs` read on the
   publish frame; do not fold into the cipher KAT.** KAT catches
   end-state divergence; parity test catches single-iteration
   cancellation bugs in ARX schedules. Different bug classes; merging
   loses the latter.

5. **Q5 — redundant aux-22 assertions: delete from vectors/decrypt
   tests.** Keep the single parity assertion at the decomposition-test
   layer. KAT covers cipher output; decomposition test covers schedule
   intermediates. Don't duplicate.

6. **Q6 — gate framing: clean B-fallback exit, not hedging.** K2c
   picked A without seeing A's graph. K2d is where the graph appears.
   The gate `AskUserQuestion` shows encrypt + decrypt smoke and asks
   "confirm A, or fall back to B-minimal like K1?" Don't editorialize;
   let the picture argue. (Moot — K2d resolved as B without a smoke gate.)

**Advisor-flagged risks (moot — A not being built):**

- **K2d_R1 (port-flow fan-out replication).** Encrypt likely tames
  like K2c. Decrypt unknown until smoke. Mitigation order if fishnet:
  (1) default-on offsets layout (shipped 2026-05-28, `?offsets=1`);
  (2) stub-placement heuristic that places replicas adjacent to
  consumers; (3) per-cipher special-case as last resort. **Do not**
  reverse port order on the decrypt-variant publish leaf — spec data
  should not differ between enc/dec on the same leaf type.

- **K2d_R2 (decrypt cross-pattern).** Tied to R1; same escalation.

- **K2d_R3 (K1=B vs K2=A codebase footgun for K3/K4).** Moot —
  resolved by the "B-minimal for all grouped schedules" rule above.

**Files that A would have affected (estimate, for future reference):**
3 step files (`speck-publish-round-keys.ts`, `speck-round.ts`,
`speck-round-inverse.ts`), 1 builder (`speck-32-64-builder.ts`), 1
param-editor block (`SpeckRoundBlock` — drop `roundKeyAux` row), 5–7
tests (vectors, decrypt, decomposition parity retarget, round-key panel
retarget, runtime-ported-dispatch, maybe narration), 1 doc comment in
`RoundKeyPanel.tsx`.

**Pre-verified facts (still accurate, useful if A is revisited):**

- `TraceFrame.portOutputs?: ReadonlyMap<string, Uint8Array>` exists
  (`src/core/types.ts:728-729`) — parity-test retarget is feasible.
- `replicateHighFanoutSources` covers port-flow edges (`GraphView.tsx`
  ~line 2885 via `PORT_FLOW_AUX_KEY`).
- Cross-container `portInputs` resolution by step id does NOT work across
  group boundaries (measured: throws "same-scope wiring only"). The cited
  SHA-256 precedent (`src/ciphers/sha-256.ts:1490` — `port("round.63",
  "out")`) is within-scope (rounds are ungrouped siblings) and does not
  apply here.
- `speckRoundKeyPortName(r)` already exported from
  `speck-publish-round-keys.ts` — reuse, don't duplicate `key${r}`.

### K3 — Serpent key-schedule decomposition (B-minimal)

> **Status: K3a + K3b SHIPPED 2026-06-02 — gate GREEN (biome + tsc + 2231
> vitest / 193 files + build for K3a; K3b re-gated below).** B-minimal, no A
> gate (per the K2d decision rule). The
> slice-open advisor pass picked **option (B): a dedicated `serpent.key-sbox@1`
> leaf** (lifts the oracle's bitsliced-S-box+IP internals verbatim → no mirror
> in the registry → no role-scoping, no corruption hazard, verified-by-
> construction) over option (A) reuse-via-identity. A throwaway probe CONFIRMED
> the identity `IP(bitslice_Sbox(w)) == nibble_Sbox(IP(w))` holds (400/400
> cases across S₀..S₇) — so **(A) is a viable future upgrade** if someone wants
> the extra per-nibble granularity AND ships the K1-style mirror role-scoping +
> guard test; (B) was chosen because the run was unreviewed and (A)'s mirror
> scoping is a silent, KAT-invisible corruption surface. Shipped:
> `serpent-key-sbox.ts` + `serpent-publish-round-keys.ts` (thin sibling — 33
> fixed keys, not AES's `rounds+1`) + `serpent-key-schedule-builder-native.ts`
> (unroll: load → pad → input-codec LE→BE → master-split → 132 ARX recurrence
> iterations (4-tap lags 8/5/3/1, φ + per-iteration index constants, ROL11 =
> `rotate-bits-right@1` bits 21) → 33 key-sbox groups → publish tail). Byte
> order: recurrence runs in BE (one `permute@1` input-codec swaps the LE master
> key); key-sbox decodes BE then runs `wordsToBytes4`(LE)+IP verbatim. **Gate:**
> `tests/serpent-32-key-schedule-decomposition.test.ts` pins published
> `roundKey.0..32` byte-equal to the monolith oracle for all 3 sizes; the
> shipped `serpent-vectors`/`roundtrip`/`key-schedule` KATs (now routing through
> the decomposition) stay byte-equal to published vectors. `serpent.key-
> expansion@1` KEPT registered (oracle + back-compat). **K3b SHIPPED
> 2026-06-02 — gate GREEN:** the dormant KeyScheduleExplorer Serpent branch
> was formally retired (the K1c-for-Serpent analog). Deleted
> `src/ui/key-schedule-sim/serpent.ts`, the Serpent variant + registry entry
> in `key-schedule-sim/registry.ts` (the `ScheduleSimulator` union is now a
> single DES member), the `SerpentExplorer`/`SerpentScheduleView`/`PadStageView`
> render branch in `KeyScheduleExplorer.tsx` (dispatch collapses to the lone
> `DesExplorer`), and the two Serpent-only tests
> (`serpent-key-schedule-sim-parity.test.ts` + `key-schedule-explorer.test.tsx`
> — the latter tested only the Serpent branch; DES dispatch through
> `<KeyScheduleExplorer>` stays covered by `des-key-schedule-explorer.test.tsx`).
> Premise verified directly (not just from the K3a commit message):
> `serpent-spec-builder.ts` routes the key schedule through
> `buildSerpentKeyScheduleNative`, so no shipped spec emits a
> `serpent.key-expansion@1` frame — the explorer branch was genuinely
> unreachable. The dead `.key-schedule-serpent*` CSS is LEFT in place to match
> the K1c choice (K1c left the parallel `.key-schedule-aes*` rules). Per the
> advisor, no heavy graph smoke — K3b changes no spec/trace/graph topology
> (viz-only linear-mode dead-code removal); the dormancy confirmation IS the
> relevant check. **K4 (DES schedule, different shape, no S-box mirror) is the
> remaining slice.**
> Behavioral note: malformed-key handling shifted from hard-reject to warn-and-
> run coercion (via `aux-load-bytes@1`), consistent with K1/K2. **Graph smoke
> (throwaway Playwright, deleted post-gate per [[feedback_playwright_dormant]]):
> all 6 Serpent specs (128/192/256 × enc/dec) render in graph view with 0
> console/page errors; the `key-schedule` group default-collapses (no
> ~469-chip wall — collapsed leaf count < 200) and expands without throwing.**

**Oracle (the ground truth to byte-match):** `src/steps/serpent-key-expansion.ts`
generates 33 round keys K_0..K_32 (16 bytes each) from a 128/192/256-bit master
key (Anderson/Biham/Knudsen 1998 §2):
1. Pad to 256 bits (`padded[keyByteLength]=0x01`; no-op for 32-byte keys).
2. Decode 8 LE 32-bit prekey words `w_{-8}..w_{-1}`.
3. Recurrence for `j=0..131`: `w_j = ROL(w_{j-8} ⊕ w_{j-5} ⊕ w_{j-3} ⊕ w_{j-1}
   ⊕ φ ⊕ j, 11)`, `φ=0x9e3779b9` (same golden-ratio constant Speck/TEA use).
4. Bitsliced S-box on each group of 4 prekeys; group `i` uses `S_{(35-i) mod 8}`
   (index walks DOWN with wraparound — the classic off-by-one trap).
5. Apply IP to each raw round key.

**Decomposition shape (unroll, like K1/K2):**

- **Seed + recurrence (clean, parallels K1/K2 ARX).** Pad via the
  `aux-load-bytes@1(byteLength: keyByteLength)` + a constant-load `0x01` tail
  when <32 bytes (or build the padded master at the codec boundary). Read 8 LE
  32-bit prekey words via `split-bytes@1`. Each generated prekey `w_j` is one
  unrolled iteration: `xor@1(inputCount: 6)` over `[w_{j-8}, w_{j-5}, w_{j-3},
  w_{j-1}, φ-const, j-const]` → `rotate-bits-right@1(wordBits: 32, bits: 21)`
  (ROL 11 = ROR 21). `φ` = one shared `constant-load@1`; the per-iteration index
  `j` = a build-time `constant-load@1` (exactly K1's per-group Rcon idiom). The
  four taps (lags 8/5/3/1) wire from prior iterations' outputs / the seed split —
  a four-tap generalization of Speck's single `(m-1)` lag.
- **S-box + IP per round key — THE load-bearing design call (verify, don't
  assume).** The oracle applies the *bitsliced* S-box across 4 words then IP.
  Decomposing the bitslice S-box as boolean gates (and/or/xor/not) would be
  ~15-20 gates × 33 groups ≈ 600 leaves. **Hypothesis to verify byte-equal
  against the oracle:** `IP(bitslice_Sbox(w)) == nibble_Sbox(IP(w))` — i.e. the
  same step pair the round body already ships (`serpent.bit-permutation@1` for
  IP, then `serpent.sub-bytes@1` with `S_{(35-i) mod 8}` per nibble). If it
  holds, K3 reuses the round-body steps for a tiny, legible decomposition and a
  real pedagogical payoff ("the schedule runs the SAME S-box the round body
  does"). If it does NOT hold, fall back to either a dedicated key-schedule
  S-box step or the gate decomposition (bigger; defer). **The byte-equal-to-
  oracle decomposition test settles this empirically — author it FIRST.**
- **Publish tail (B-minimal):** new `serpent.publish-round-keys@1` (parallel to
  `aes.`/`speck.publish-round-keys@1`) — 33 keys × 16 bytes, `meta.auxWritePorts`
  `key${i} → roundKey.${i}`. **Consumers (`serpent.add-round-key@1`) untouched.**
  Note the divergence from the AES/Speck tails: 33 fixed keys (no `rounds`
  param), `byteLength: 16` like AES (Speck's was 2) — reuse the AES publish block
  if the param shape matches, else a thin sibling.
- **Byte-order codec at the boundaries** (parallels K2): Serpent prekeys are LE
  32-bit words; the recurrence math is on those words. A boundary codec leaf
  (LE↔internal) may be needed so the `rotate-bits-right@1`/`xor@1` body operates
  uniformly — settle the exact reading against the oracle, like K2's input/output
  codecs.

**S-box mirror-corruption hazard — THE K3-specific trap (K1 lesson re-applies).**
If the key schedule reuses `serpent.sub-bytes@1`, the existing **class-2 "Sync
inverse S_i to decrypt" mirror** (registered on `serpent.sub-bytes@1`, per
`sboxIndex`) would broadcast the inverse table onto the key-schedule leaves on a
UI click → **corrupt the decrypt key schedule** (the schedule uses the FORWARD
S-box in BOTH directions, per the oracle: "same key schedule for encrypt and
decrypt"). Invisible to the KAT gate (KATs run specs as authored). **Fix
(mandatory, same as K1):** role-scope the mirror by leaf id (`isRoundBodyLeafId`
vs `isKeyScheduleLeafId`) so round-body SubBytes keeps class-2 inverse and the
key-schedule S-box leaves are NOT inverse-mirrored (forward-only); ship a
corruption-guard test (`sync-serpent-sbox-inverse` leaves the key schedule
untouched). **Alternative considered:** a dedicated `serpent.key-sbox@1` step
type sidesteps the mirror entirely (no role-scoping) but loses the
"same-S-box-as-the-round-body" pedagogy — the advisor pass decides reuse+scope
(K1 precedent, pedagogy) vs dedicated step (simpler).

**Blast radius:** rewire the 6 Serpent specs (`serpent-128/192/256{,-decrypt}.ts`
via `serpent-spec-builder.ts`) to call a new
`buildSerpentKeyScheduleNative(keyByteLength)` instead of the monolithic
`serpent.key-expansion@1` leaf. Retarget aux-graph derivation tests
(`serpent.key-expansion` leaf → `key-schedule` group). **KeyScheduleExplorer
Serpent branch** (`src/ui/key-schedule-sim/serpent.ts` + parity test) — fate
decided at the K3 gate (retire like K1's AES branch, since the frames are now in
the trace, OR keep as a high-level summary). **Keep the `serpent.key-expansion@1`
executor registered** as the KAT oracle + back-compat (K1 precedent; do NOT
global-rename `key-expansion`). The decomposition test byte-matches its 33
outputs.

**Gate (crypto):** `serpent-vectors`, `serpent-roundtrip`,
`serpent-key-schedule` byte-equal before/after, all three sizes × enc/dec; the
new decomposition test pins published `roundKey.0..32` byte-equal to the oracle
for all three key sizes. Graph smoke (throwaway Playwright) for legibility — but
**no A-vs-B gate** (B-minimal is the rule).

### K4 — DES key-schedule decomposition (B-minimal; sequenced after K3)

> **Status: K4a + K4b SHIPPED 2026-06-02 — gate GREEN.** B-minimal, no A gate
> (per the K2d decision rule).
> **K4b CLOSED (KeyScheduleExplorer DES-branch retirement) — gate GREEN (biome +
> tsc + 2228 vitest / 191 files + build).** Since DES was the *last* cipher with
> a registered simulator, K4b emptied the WHOLE subsystem: deleted
> `src/ui/components/KeyScheduleExplorer.tsx`, `src/ui/key-schedule-sim/des.ts`
> + `registry.ts` (the dir is gone), and the two explorer tests
> (`des-key-schedule-explorer.test.tsx` + `des-key-schedule-sim-parity.test.ts`).
> App.tsx's `isKeyExpansionStepType` intercept collapsed to a bare
> `<FrameStateView frame={frame()} />` (the fallback was already FrameStateView;
> no shipped spec emits the monolithic oracle frames, so no UX regression — the
> decomposed K1–K4 stages are real scrubbable frames the standard view renders).
> The shared `<ByteRow>` (`components/byte-row.tsx`) survives (its `key-schedule-`
> CSS class prefix is now just a naming holdover — kept, only the explorer-only
> CSS rules were removed). The four monolithic oracle executors
> (`aes.key-expansion@1/@2`, `serpent.key-expansion@1`, `des.key-schedule@1`)
> stay registered + on the narration allowlist (KAT oracle / back-compat); only
> the stale prose comments referencing the deleted explorer were rewritten.
>
> **The K4 load-bearing design call (advisor slice-open pass, 2026-06-02): the
> rotation representation.** DES's schedule is *pure bit-wiring* — no arithmetic,
> no S-box. The advisor picked a **dedicated `des.rotate-halves@1`** (verbatim
> lift of the monolith's `fipsBytesToBits`/`rotateBitsLeft`/`bitsToFipsBytes`
> loop body) over expressing the rotation as a build-generated `des.bit-permute@1`
> table. Rationale: a rotation IS pure bit-routing (so the "zero arithmetic"
> punchline survives either way), but the cycling C/D halves are *the* signature
> feature (the cumulative-28 cycle, C₁₆ = C₀), and `des.rotate-halves@1(shift: 2)`
> is self-describing where a 56-entry permute table buries "rotate" in narration;
> the verbatim lift is also byte-identical to the oracle by construction (the K3
> `serpent.key-sbox@1` principle). **Three new step types shipped:**
> `des.bit-permute@1` (PC-1/PC-2, generic `fipsPermute` lift, `{table, outBits}`),
> `des.rotate-halves@1` (`{shift, halfBits}`), `des.publish-round-keys@1` (thin
> sibling — 16 FIXED keys via `count`, 6 bytes each; NOT reuse Serpent's to avoid
> welding a `serpent.*` type into saved DES JSON). **No mirror hazard** (no
> schedule S-box — DES dodges K3's trap like Speck did). New
> `src/ciphers/des-key-schedule-builder-native.ts` (`buildDesKeyScheduleNative()`,
> no params): one default-collapsed `key-schedule` group: `load-key` → `pc1`
> (64→56) → 16× (`rotate-halves` → `pc2` 56→48) → publish. The 7-byte C‖D
> register threads round-to-round; no byte-order codec (DES is FIPS MSB-first
> throughout, unlike K2/K3). **Gate:**
> `tests/des-key-schedule-decomposition.test.ts` pins published `roundKey.0..15`
> byte-equal to the monolith oracle (FIPS App-B key + one more — no key-size
> variant, so no 3-size matrix); shipped `des-vectors`/`des-decrypt` KATs (now
> routing through the decomposition) stay byte-equal to published vectors.
> `des.key-schedule@1` KEPT registered (oracle + back-compat — never
> global-rename). Blast radius: both DES specs rewired; ParamEditor blocks
> (`des.bit-permute@1` reuses `DesPermutationBlock`; new `DesRotateHalvesBlock` +
> `DesPublishRoundKeysBlock`); publish tail on the narration allowlist; round-key
> fan-out graph/UI tests retargeted `key-schedule` → `key-schedule.publish`. The
> KeyScheduleExplorer DES branch is now dormant — its `des-key-schedule-explorer`
> test keeps it green by synthesizing the monolith frame (K3a pattern), pending
> K4b retirement. Malformed-key handling shifted from hard-reject to
> warn-and-run coercion (via `aux-load-bytes@1`), consistent with K1/K2/K3.
> **Graph smoke (throwaway Playwright, deleted post-gate per
> [[feedback_playwright_dormant]]): both DES specs (encrypt + decrypt) render
> with 0 console/page errors; the `key-schedule` group default-collapses to a
> single chip (no ~50-chip wall) and expands into the clean
> `load-key → pc1 → (rotate → pc2)×16 → publish` staircase; clicking a
> `rotate-halves` chip shows its read-only ParamEditor block (not raw JSON).
> The decrypt collapsed view (reversed round-key consumption) renders
> structurally identical to encrypt — the fan-out originates from the single
> collapsed container, so consumption order produces no fishnet (the K2d
> finding holds). Out-of-scope note: DES decrypt's default ciphertext is 16
> bytes, so single-block mode shows a "must be exactly 8 bytes" input-validation
> banner — pre-existing, unrelated to the key schedule (which runs first and
> rendered fine).** K4a is now fully closed; **K4b** (KeyScheduleExplorer
> DES-branch retirement — empties the whole subsystem) is the remaining slice.

DES's schedule is a **different shape** (no per-round arithmetic constant — PC-1
→ 16 rounds of left-rotations on the two 28-bit halves → PC-2 selects 48 bits per
round key). Decompose: PC-1 = `serpent.bit-permutation@1`-style `permute`/bit
step; per-round the C/D halves rotate (a bit-rotate on 28-bit halves) and PC-2
permutes → one `des.publish-round-keys@1` tail (16 keys × 6 bytes/48 bits),
B-minimal, `des.xor-with-K` consumers untouched. No S-box in the DES schedule, so
**no mirror hazard** (DES dodges K3's trap, like Speck did). Its own KAT gate
(FIPS 46-3) + advisor pass. Full design deferred to K4 slice-open.

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
