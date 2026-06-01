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

### K2–K4 — Speck / Serpent / DES (only after the K1-gate)

Same unroll pattern (Speck/Serpent also have per-round constants → unroll; DES
has none). Each its own KAT gate + advisor pass.

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
