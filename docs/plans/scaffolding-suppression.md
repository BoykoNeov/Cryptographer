# Scaffolding suppression — every leaf speaks only in byte arrays

> **Status: Phase A in progress — A0+A1+A2 SHIPPED 2026-05-28; A3 split
> into A3a+A3b with Q1–Q4 resolved (advisor pass + user co-design
> 2026-05-28); A3a next.** Drafted after the
> Slice 2.9b smoke (2026-05-28) surfaced a structural pedagogy gap, then
> shaped through a 7-decision walkthrough with the user (Position +
> Q1–Q5 + state-concept) and an advisor calendar-risk pushback that
> split the original "everything in one arc" into the hybrid below.
>
> Sits **before** Slice 2.9c–e (those depend on a stable spec shape,
> which this plan settles).

## The goal, stated plainly

**Every leaf executor consumes and emits only `Uint8Array`.** No leaf
reads or writes `state`; no leaf takes a `MatrixState` / `BitVecState`
/ `BigIntState`. A leaf is a pure bytes-in → bytes-out function on its
ports. Containers (`group`, `iterate`, `for-each-subgraph`,
`for-each-subgraph-with-history`, `feistel-round`) may still coordinate
iteration / history / branching, but their boundaries are bytes too.

State retirement is **a consequence, not the target.** When the last
legacy executor lands byte-native, `MatrixState` and friends have no
consumers and get deleted. We don't chase state removal directly — we
chase bytes-only leaves, and state falls out.

The user's verbatim framing (2026-05-28):

> *"The ultimate goal is that all leaves need to emit and consume only
> byte arrays to function properly… I am afraid that it will creep in
> again, as has already happened."*

The fear of **creep** is load-bearing: the plan includes an explicit
anti-creep guard (Slice A4) so the property can't silently regress.

## Context — what the smoke surfaced

Slice 2.9b's browser smoke (2026-05-28, `main` @ `3d26f22`) ran green,
but while scrubbing, the user landed on the **final `bytes-to-state`**
frame and asked a structurally-unanswerable question:

> *"If the previous `concat@1` step already assembled the digest
> (`ba78…`), what are these BEFORE values `50 d3 04 b8 …`?"*

Those BEFORE bytes are the end-of-round-63 working variables; the
digest had been living in `port-output` (a separate channel) the whole
time. `state` and `port-output` are independent channels in port-native
dataflow; only `bytes-to-state@1` moves data between them. The bridge
leaf is exactly where a student gets confused — and it only exists as
plumbing.

Memory anchors: [[project_slice_2_9_port_aware_provenance]] (smoke +
pivot), [[feedback_all_specs_port_native]] (the bytes-only baseline
this plan extends to leaf-internal shape handling).

## Resolved decisions

| ID | Question | Decision |
|---|---|---|
| Position | How literal is "leaves only bytes"? | **Position 3 — architectural collapse.** Leaf executors are byte-native; `MatrixState`/`BytesState` collapse to a layout tag, then go away. (Reached via hybrid sequencing so no cipher breaks mid-flight — see arc.) |
| Q1 | Where do FIPS constants live? | **`CipherSpec.cipherConstants`** (Option 1). Runtime materializes into aux at boundary. Sidebar legend with FIPS refs **AND** usage cross-refs (sidebar shows which leaves consume each constant; leaf inspector shows which constants a leaf reads). **Constants are editable** — ParamEditor-style UI + 200 ms debounce → re-run, same as step params today. Cross-mode mirror buttons (AES "Sync inverse S-box") follow the constant into its new home. |
| Q2 | FES / container seeding contract | **Explicit `seedInput` / `bodyOutput` `PortBinding` fields** on the container; container output via `outputPorts`. No state involvement. Uniform across `iterate` / `for-each-subgraph` / `for-each-subgraph-with-history`. |
| Q3 | Frame emission for bridges | **Retired — moot.** Under state retirement there are no bridges to emit frames for. |
| Q4 | Graph bridge visibility | **Hidden** — bridges are gone from the spec, so the graph derives from the cleaned spec and there's nothing to hide. |
| Q5 | Calendar / scope | **Hybrid.** SHA-256 cleanup + contract first; ciphers rebuilt one at a time on feature branches; `main` never holds a half-converted cipher; state retirement falls out in a final phase. (Advisor split this off from the "everything in one ~16-slice arc" the literal Q5 answer implied — see "Why hybrid" below.) |

### Why hybrid (advisor calendar-risk pushback)

The literal Q5 answer ("everything in this plan") + state retirement =
a ~16-slice multi-month arc with no clean `main` for the duration,
duplicating scope the universal-port-dataflow plan's Phases 3/4/4d/5
already track. The advisor flagged that the user's *motivation* was
the bridge confusion (Phase A) and the bytes-only pivot (the contract),
not a big-bang rewrite. The hybrid keeps the same end-state but ships
it as: contract + SHA-256 first → per-cipher feature-branch rebuilds →
state retirement as a consequence. Preserves
[[feedback_all_specs_port_native]]'s "`main` only holds 100%
port-native specs" guarantee throughout.

## The container port contract (Q2)

Three container checkpoints are state-mediated today; all three move to
ports. Using the existing `PortBinding` type (`types.ts:79`):

```ts
type PortBinding = { readonly node: string; readonly port: string };
```

New optional fields on each looping container:

```ts
readonly seedInput?: PortBinding;   // initial history / blocks source
readonly bodyOutput?: PortBinding;  // per-iteration result port
// outputPorts?: readonly string[]  // EXISTS — names the container's output(s)
```

**SHA-256 message schedule, after:**

```ts
{
  kind: "for-each-subgraph-with-history",
  id: "msg-schedule",
  iterationCount: 48,
  lookbackOffsets: [2, 7, 15, 16],
  historyEntryByteLength: 4,
  seedInput: { node: "length-append", port: "output" },  // was: bytes-to-state "seed-schedule"
  bodyOutput: { node: "wt-add", port: "output" },         // was: per-iter bytes-to-state exit
  outputPorts: ["full-history"],                          // was: state-to-aux "W-publish"
  children: buildScheduleBody(),
}
```

Runtime resolves `seedInput` at entry (slice into
`historyEntryByteLength` chunks → seed history), `bodyOutput` at each
iteration exit (append to history), and publishes the concatenated
history on `outputPorts[0]`. **`state` is never touched.** Same three
shape invariants validated today — just read from port-output maps
instead of `state.bytes`.

**Generalizes:** AES's `iterate` for ECB/CBC adopts the same fields
(`seedInput` replaces `generic.split-blocks@1`, `outputPorts` replaces
`generic.concat-blocks@1`) when AES is rebuilt (Slice B1).

### Graph effect

Two plumbing boxes (`seed-schedule`, `W-publish`) and one in-body
plumbing chip (body-exit `bytes-to-state`) vanish. The history-seed
synthetic edges (`inferHistorySeedEdges`) retarget their source from
the deleted `seed-schedule` leaf to whatever `seedInput` points at. The
FES output edge becomes an **ordinary port edge** (no synthetic
inference). The cross-iteration recurrence visibility gap (W_{t-N}
across iterations) is **unchanged** — still a separate follow-up in the
universal-port-dataflow plan family.

## Scaffolding inventory — SHA-256 spec, today (A0-CONFIRMED 2026-05-28)

Source: `src/ciphers/sha-256.ts`. Slice A0 (a throwaway probe that walked
every shipped spec + ran the "abc" KAT trace) replaced the original
hand-count with the measured figures below. The hand-count conflated
two different units in one column; A0 splits them.

**Two units, kept separate** (the original single "Count" column hid this):

- **Spec leaves to remove** = distinct `kind: "step"` nodes in the spec
  tree. This is the **A3 cleanup target** — what gets physically deleted
  from `sha-256.ts`.
- **Trace frames removed** = the runtime footprint on a single-block run.
  The FES message-schedule body runs 48×, so one spec leaf there
  (`schedule-out`) contributes 48 frames. This is the **density/UX claim**.

| Category | Leaves (spec) | Frames ("abc") | Fate |
|---|---|---|---|
| Boundary bridges — `state-to-bytes "plaintext-source"` + `bytes-to-state "final.out"` | 2 | 2 | Runtime-owned at cipher boundary; spec drops them (A3) |
| Container bridges — FES `seed-schedule` + FES body-exit `schedule-out` (×48 frames) + `W-publish` | 3 | 50 | Replaced by `seedInput`/`bodyOutput`/`outputPorts` (A2+A3) |
| Round-body bridges — round.t entry `state-in` ×64 + exit `state-out` ×64 + final-add entry `final.state-in` | 129 | 129 | Round groups gain port boundaries; runtime auto-bridges or absorbs (A3) |
| Constant loaders — `K-to-aux`, `H-to-aux`, `H-constant`, `init-working-vars` | 4 | 4 | Move to `cipherConstants` (A1) |
| **Total** | **138** | **185** | |

**Corrections A0 made to the locked draft:**

- **`final.out` was double-counted.** The original "Boundary bridges"
  row listed "final `bytes-to-state`" and the "Round-body bridges" row
  listed "final-add entry/**exit**" — both pointing at the same leaf
  (`final.out`). It is the cipher's terminal `bytes-to-state`, so A0
  assigns it to **boundary only**. That drops round-body from 130 → 129
  frames and the grand total from 186 → **185**.
- **Total frames is 2487, not "~2486".** Pinned by
  `tests/sha-256.test.ts:133` (frame-budget regression test). The probe
  asserts `frames.length === 2487` as a bucketing sanity check.
  Frame-drop = **185 / 2487 ≈ 7.4 %**.
- **The "~250–400 frame drop" estimate was too high.** The bridge
  frames removed are exactly **185**. The gap to 250–400 is the **321
  `aux-load-bytes@1` READ frames** (the per-iteration `fetch-p2/7/15/16`
  ×48 = 192, the per-round `fetch-K`/`fetch-W` ×64 = 128, and
  `final.fetch-H` ×1). Those are **not bridges** — they read W/K/H into
  the body and stay as legitimate port reads under the A1–A3 contract.
  Whether A3's round-group port boundary lets some of them collapse is
  open item #2 below; A0 does **not** count them as scaffolding.
- **`init-working-vars` is a `bytes-to-state` bridge, grouped under
  "constant loaders" for fate, not step type.** It semantically loads
  the H constant into state, so A1 retires it alongside the three true
  loaders (`K-to-aux`/`H-to-aux` are `generic.aux-load@1`, `H-constant`
  is `constant-load@1`). When A1 "deletes the 4 constant loaders," one
  of the four is a `bytes-to-state@1`, not a load step type.

**Full SHA-256 leaf inventory (A0 probe, 1829 spec leaves total):** the
138 scaffolding leaves are `bytes-to-state@1` ×68, `state-to-bytes@1`
×66, `generic.aux-load@1` ×2, `generic.state-to-aux-bytes@1` ×1,
`constant-load@1` ×1. The non-scaffolding remainder is genuine
computation: `rotate-bits-right@1` ×388, `and@1` ×320, `add-mod-32@1`
×265, `xor@1` ×258, `aux-load-bytes@1` ×133, `byte-slice@1` ×128,
`split-bytes@1` ×66, `concat@1` ×65, `not@1` ×64, `shift-bits-right@1`
×2, `pad-with-byte@1` ×1, `append-be64-length@1` ×1.

**Other shipped specs use ZERO of the 5 scaffold step types.** A0
walked all 22 AES/Speck/Serpent/DES specs (enc + dec): grand total 0
scaffold leaves. SHA-256 is the only port-native-primitive spec today
(the registry-`kind` discriminator does *not* distinguish them — every
step type is `kind: "ported"` since Slice 1.8 — so the step-type-set
predicate above is the meaningful one). A3's SHA-256 cleanup therefore
cannot touch another cipher.

**Headline win** is still qualitative, not the 7.4 %: the scrubber can
no longer land on a frame whose `state` value contradicts what the
student just watched (the smoke confusion in "Context" above).

## The arc — 10 slices, 3 phases

**Gate rule** ([[feedback_iterative_slice_review]]): advisor consult
before each phase boundary, and before each Phase B cipher.

### Phase A — Contract + SHA-256 cleanup + anti-creep (4 slices)

**A0 — Probe (pure measurement). ✅ DONE 2026-05-28.** A throwaway
vitest probe walked `sha-256.ts` (grouped all 1829 leaves by `stepType`
to *discover* rather than just verify the categorization), ran the
"abc" KAT trace and bucketed frames per scaffolding category, and
scanned the 22 other shipped specs. Findings folded into the inventory
section above: **138 scaffolding spec leaves / 185 trace frames** (was
"~186"), total **2487** frames (was "~2486"), the `final.out`
double-count resolved, the "~250–400" frame-drop corrected to 185 (the
321 `aux-load-bytes` reads are not bridges), and **0 scaffold leaves in
any non-SHA spec**. Probe deleted after capture; no committed code
change.

**A1 — `cipherConstants` + editor + panel. ✅ SHIPPED + SMOKED 2026-05-28.**
*(UX + leaf-delta resolved 2026-05-28 via advisor — see corrections
below. Shipped in two commits: mechanism + persistence first
(`6ec88e3`), then the editor panel + cross-refs (`3eaad35`). SHA-256 KAT
byte-equal; frame total 2487→2485; leaf count 1829→1827;
`ConstantsPanel.tsx` in main column for linear + graph; both cross-ref
directions wired + tested. **Browser smoke PASSED** (throwaway Playwright,
deleted): panel renders, K expands to 256 wrapping cells, editing
K[0]=00 changed the digest `ba7816…`→`6f5c08…` end-to-end through the
200 ms debounce, consumer link selects the leaf, back-ref visible, AES
inert with no layout artifact. Gate met.)*
- `CipherSpec.cipherConstants?: Record<string, Uint8Array>`
  (`core/types.ts`); runtime materializes each entry into `aux` (one
  loop before `walk()`).
- Editable in a new **main-column collapsible "cipher constants"
  section** (user pick — visible in every view incl. graph, rendered
  near `ParamEditor`). ParamEditor-style cells, byte-format honored,
  200 ms debounce → re-run via the existing spec-mutations path.
- Cross-refs render as **inline clickable links** (user pick): each
  constant lists its consuming leaves inline (K's ~64 `fetch-K` readers
  wrap, not truncate); the leaf inspector shows a clickable
  `reads: [K]` line that scrolls to the panel.
- **Document schema: additive, NO `schemaVersion` bump.** Add
  `cipherConstants?: Record<string, hex-string>` to the Zod schema
  (`CipherSpecSchema` — note Zod STRIPS undeclared keys, so it MUST be
  declared explicitly or it's dropped on round-trip); legacy specs
  without the field are unchanged. Hex matches the app's byte
  serialization convention; Save/Load/URL-share carry constants. (The
  current `CURRENT_SCHEMA_VERSION` is already 3 from Slice 2.10b's
  `algorithm` rename — NOT bumped by A1; A2's schema-version decision is
  spelled out in the A2 slice below.)
- **Cross-mode mirror re-homing is DEFERRED to B1, not A1.** SHA-256 has
  no mirror constants (the S-box class is AES, rebuilt in B1). Per
  [[feedback_all_specs_port_native]] `main` never holds half-converted
  state, so `cross-mode-mirror-registry.ts` +
  `tests/cross-mode-mirror-coverage.test.tsx` change *with* their first
  consumer (B1's AES S-box → `cipherConstants`), not here.
- **SHA-256 leaf delta is −2, NOT −4** (the inventory's "4 constant
  loaders" was a *fate* grouping, not a same-slice retirement set; one
  of the four — `init-working-vars` — is a load-bearing `bytes-to-state`
  state-seed, and `H` is dual-role: it seeds the working vars AND feeds
  the final add):
  - Drop `K-to-aux` + `H-to-aux` (`generic.aux-load@1` — true loaders;
    `cipherConstants["K"]`/`["H"]` now materialize K/H into aux).
  - **Replace** `H-constant` (`constant-load@1`) with `init.fetch-H`
    (`aux-load-bytes@1`, `auxName: "H"`) — seeds the working vars from
    the *same* materialized `aux["H"]` that `final.fetch-H` reads, so
    editing `cipherConstants["H"]` moves BOTH H consumers in lockstep.
    (Leaving `H-constant`'s hardcoded `params.bytes` in place would make
    round.0 start from a stale H while the final add used the edited one
    — a digest that changes for the wrong reason: the exact creep this
    plan exists to prevent.)
  - **Keep** `init-working-vars` (`bytes-to-state@1`), retargeted to read
    `init.fetch-H`. Until A3 rewires round-group port boundaries,
    `bytes-to-state` is the only thing that seeds round.0's state. It
    retires in A3.
  - **Frame total: 2487 → 2485.** Update the `tests/sha-256.test.ts:133`
    frame-budget pin in the same commit.
- **Gate:** "abc" KAT byte-equal (digest unchanged); editing a constant
  re-runs and changes the digest; cross-refs render both directions;
  no `generic.aux-load@1` / `constant-load@1` leaves remain in the
  SHA-256 spec; `validateShapes` clean.

**A2 — Container port contract. ✅ SHIPPED 2026-05-28.**
*(Pre-A2 advisor consult done; schema decision resolved (a); scope
narrowed per advisor — fields uniform on all three looping containers but
runtime resolution wired only for the A3 consumer (FES-with-history), with
loud throws on the deferred kinds. Full gate green: 2468 tests, biome +
tsc + build clean.)*
- `seedInput` / `bodyOutput` optional `PortBinding` fields added to
  `IterateGroup` / `ForEachSubgraphNode` / `ForEachSubgraphWithHistoryNode`
  (`core/types.ts`) — uniform shape, like `portInputs`/`outputPorts`. NOT
  on `group`/`feistel-round` (no body-loop there).
- **Runtime resolution wired for `for-each-subgraph-with-history` only**
  (the A3 consumer): `seedInput` resolved at the call site in `walk` (where
  the parent scope's `nodeOutputs` is live) and passed into the helper;
  `bodyOutput` resolved from the body scope via `walk` now **returning its
  `nodeOutputs` map** (the 6 statement-position callers ignore it; B1 adds
  iterate+FES consumers). Both paths are ADDITIVE — absent fields ⇒ the
  legacy state-mediated path runs unchanged (that's why A2 ships before A3
  without breaking SHA-256). The container still writes the concatenated
  history to `state` at exit, so `outputPorts` publication + downstream
  state-thread consumers keep working; the state-write is retired in Phase C.
- **Deferred kinds fail loudly** (advisor footgun fix): the runtime THROWS
  if `seedInput`/`bodyOutput` is set on `iterate` or `for-each-subgraph`
  ("deferred to Phase B1") rather than silently ignoring author wiring.
  B1 wires their resolution alongside the AES rebuild.
- **schemaVersion decision = (a) additive within 3.** Documented
  deliberately in `document.ts` (the bump would friendly-error
  *unchanged-cipher* docs to protect a near-nonexistent old-reader
  population; the reliance hazard only arrives in A3). `seedInput`/
  `bodyOutput` declared explicitly in `document-schema.ts`'s shared
  `loopingContainerSeedFields` (Zod default `z.object()` STRIPS undeclared
  keys — same gotcha A1's `cipherConstants` hit) → they survive Save/Load.
- `inferHistorySeedEdges` retargets the seed-edge anchor to `seedInput.node`
  when present, else spine predecessor (`graph.ts`). SHA-256 has no
  `seedInput` until A3, so its existing tests stay green.
- **spec-shapes pre-Run validation** reuses the `port-input-unresolvable`
  warning for `seedInput` (same-scope) + `bodyOutput` (direct body child),
  so unresolvable references surface in the graph editor before Run (no new
  warning kind / renderer branch).
- **Tests:** port-mode `seedInput`+`bodyOutput` KAT (matches state mode);
  same-scope throws for both; deferred-kind throws for iterate + FES;
  seed-edge retarget; spec-shapes binding resolution (missing-node /
  missing-port / clean). +10 tests. Existing state-path tests unchanged.

**A3 — SHA-256 spec cleanup. SPLIT into A3a + A3b (advisor pass +
user co-design, 2026-05-28).** Original single-slice A3 was too risky:
deleting leaves is cheap, but the 128 round-body bridges depend on a
genuinely-new `group` port contract, and bundling that with the
container/boundary cleanup means a red "abc" KAT can't be bisected to a
*mechanism* bug vs a *wiring* bug. Split so each tripwire (the KAT + the
frame-budget pin) isolates one change class.

**Resolved design (Q1–Q4 from the advisor brief + user picks):**

- **The unifying model (user, 2026-05-28).** A port endpoint is *either*
  another node's port *or* a named scratchpad cell. "Scratchpads outside
  the graph, accessed through standard ports": reads already work this
  way (`aux-load-bytes@1` = an input port whose address is a scratchpad
  cell); writes = "set the port's address to the scratchpad." Point-to-
  point data flows port-to-port (`portInputs` ⇄ `outputPorts`); broadcast
  values (K, W) live in `aux` and are read/written by addressing a port
  at the cell. This collapses the advisor's "three near-identical naming
  mechanisms" worry into one rule. **Decision rule for B-phase authors:**
  port-to-port for point-to-point single-consumer edges; a scratchpad
  (aux) cell for any value with many consumers (round constants, the
  expanded message schedule). Caveat: a *general leaf-level* port→aux
  write primitive is deferred — pure port-native leaves can't write aux
  today (only meta-carrying steps can, see `runtime.ts` aux-write block),
  so the scratchpad-write currently lives at the container boundary
  (`outputAux`, below). A leaf-level `aux-store-bytes@1` is a clean
  B-phase follow-up if a leaf ever needs it.

- **Q1 — round-to-round handoff.** The runtime ALREADY publishes a
  `group`'s exit bytes to the parent scope (`runtime.ts` `walk`'s `group`
  case → `publishContainerOutputs(node.id, …)`); the 64 rounds are
  top-scope siblings, so `round.{t+1}` can already see `round.t`'s
  output. The ONLY thing the `state-in`/`state-out` bridges do is cross
  the *body* scope wall. Fix (A3b): extend `group` with
  `seedInput`/`bodyOutput` (exactly mirroring A2's FES contract).
  `seedInput` resolves in the parent scope and the runtime injects the
  bytes into the body scope under a reserved source — keep it dead
  simple: `nodeOutputs.set(node.id, new Map([["in", seedBytes]]))` so the
  body's first leaf reads `port(groupId, "in")` with zero new resolver
  concepts. `bodyOutput` names which body leaf (`repack`) becomes the
  group's published exit. **Open A3b fork:** carry port-to-port between
  sibling rounds (deletes the 128 bridges) vs. through a `carry`
  scratchpad cell (uniform with the model but keeps ~128 load/store
  leaves). Both keep the carried a..h visible at `repack`/`split`.
  Resolve at A3b start.

- **Q1 visibility (USER, hard requirement).** The working variables
  carried between rounds MUST remain visible in the linear scrubber so a
  learner sees how they change. Satisfied because `repack` (round *t*
  output) and `split` (round *t+1* input) are real computational frames.
  A3b gate adds: *scrub a round boundary and confirm the carried a..h are
  visible AND consistent* (the deleted bridges were the opposite — they
  showed stale `state` contradicting the ports; that's the smoke bug).

- **Q2 — W reaches the 64 rounds.** `W-publish` (`state-to-aux-bytes`,
  reads `state`) is replaced by addressing the FES's output port at
  scratchpad `W`: a new optional `outputAux?: string` on the FES-with-
  history container. Runtime writes the concatenated history into
  `aux["W"]` at FES exit; rounds keep reading `aux["W"]` via
  `aux-load-bytes` unchanged. Same category as A1's K — an honest named
  broadcast table, not a hidden side channel.

- **Q3 — cipher entry/exit (USER framing).** Entry: the runtime exposes
  `initialState` bytes as a reserved top-scope source (`"$input"`, port
  `"out"`); `pad` + `length-append` wire to it; `plaintext-source`
  deleted. Exit: a new spec-level `outputFrom?: PortBinding` names the
  port whose bytes become `finalState` (`final.assemble`, port
  `"output"`); `final.out` deleted. Implementation note (advisor): the
  top scope's `nodeOutputs` is local to the top `walk` call — `runSpec`
  must read the returned map (walk already returns it) to resolve
  `outputFrom` before returning.

***A3a — boundary + container bridges (low-risk; mostly consumes A2).***
- `types.ts`: add `CipherSpec.outputFrom?: PortBinding`; add
  `outputAux?: string` to `ForEachSubgraphWithHistoryNode` (A3a consumer;
  deferral note on the other looping kinds, matching A2's posture).
- `runtime.ts`: seed top-scope `nodeOutputs` with `$input`; resolve
  `spec.outputFrom` → `finalState`; FES `outputAux` → `aux[name]` at exit.
- `document-schema.ts`: declare `outputFrom` + `outputAux` explicitly
  (Zod strips undeclared keys — same gotcha as `cipherConstants`);
  additive, NO `schemaVersion` bump (same posture as A1/A2).
- `graph.ts`: `$input` source node; W now reaches rounds via the FES's
  `outputAux` write (not the deleted `W-publish` leaf) — confirm the
  aux-edge derivation still draws W's 64 readers; `inferHistorySeedEdges`
  seed anchor already retargets to `seedInput.node` (A2).
- `sha-256.ts`: delete `plaintext-source` (pad/length-append read
  `port("$input","out")`); FES gains `seedInput {length-append,output}` +
  `bodyOutput {w-t,output}` + `outputAux: "W"`; delete `seed-schedule`,
  `schedule-out`, `W-publish`; add `spec.outputFrom {final.assemble,
  output}`; delete `final.out`. Keep `init.fetch-H` + `init-working-vars`
  (A3b territory). Remove the now-dead narration objects.
- **Frame delta: −52** (`plaintext-source` 1 + `seed-schedule` 1 +
  `schedule-out` 48 + `W-publish` 1 + `final.out` 1). 2485 → **2433**;
  update the `tests/sha-256.test.ts` frame-budget pin in the same commit.
  Leaf delta −5: 1827 → **1822**.
- **Gate:** "abc" KAT byte-equal (`ba7816bf…`); `validateShapes` clean;
  no `state-to-bytes`/`bytes-to-state`/`state-to-aux-bytes` leaf at the
  cipher boundary or schedule boundary; AES/Speck/Serpent/DES untouched;
  graph view still connects the schedule → W → rounds.

***A3b — round-body bridges (the new `group` port contract; KAT + graph
risk).***
- `types.ts`: add `seedInput`/`bodyOutput` to `StepGroup` (Q1).
- `runtime.ts`: `group` resolves `seedInput` in parent scope, injects as
  `port(groupId,"in")` in the body scope; `bodyOutput` selects the body
  node whose port becomes the group's published exit.
- `sha-256.ts`: delete the 64 `round.t.state-in` + 64 `round.t.state-out`
  + `final.state-in` + `init-working-vars` (~130 leaves); rounds gain
  `seedInput`/`bodyOutput`; resolve the carry fork (port-to-port vs
  `carry` scratchpad).
- `graph.ts`: **biggest risk** (advisor) — `inferStateEdges` / the spine
  assume the state thread we're deleting; the round chain could render as
  disconnected islands (inter-round edge is now a port edge between
  sibling *collapsed* groups, which port-edge inference may not draw).
  Trace explicitly.
- **Gate:** "abc" KAT byte-equal; **the Q1-visibility scrub** (carried
  a..h visible + consistent at a round boundary); graph shows a connected
  round chain (no islands); frame-budget pin updated; the open-item-#2
  question (do the 321 `aux-load-bytes` reads collapse?) answered here.

**A4 — Anti-creep contract test.**
- New test walks the step registry; **fails** if any registered leaf
  step type declares a non-bytes port shape (today: any
  `PortContract` input/output that isn't `bytes`). Allowlist of
  legacy lifted-matrix steps that haven't been rebuilt yet
  (AES/Serpent/DES executors) — the allowlist **shrinks** as Phase B
  ships, and a Phase B cipher's rebuild PR must remove its allowlist
  entry.
- **Gate:** test green with the legacy allowlist; a deliberately-broken
  fixture leaf (non-bytes port) makes it red.

### Phase B — Per-cipher byte-native rebuilds (4 slices, feature branches)

Each cipher rebuilt on its own feature branch; merged to `main` only
when fully byte-native + KAT byte-equal; `main` never holds a
half-converted cipher (per [[feedback_all_specs_port_native]]). Each
removes its A4-allowlist entry on merge.

- **B1 — AES** (deepest matrix coupling — the contract stress test).
  SubBytes/ShiftRows/MixColumns/AddRoundKey + key schedule byte-native;
  `iterate` adopts `seedInput`/`outputPorts` for ECB/CBC; S-box/Rcon
  move to `cipherConstants`. KAT: FIPS-197 Appendix C.
- **B2 — Speck** (easiest — already byte-flat `BytesState(4)`). Mostly
  conformance + contract adoption. KAT: both BE-paper + LE-NSA vectors.
- **B3 — Serpent.** Standard form (explicit IP/FP); S_i tables to
  `cipherConstants`. KAT: all three key sizes.
- **B4 — DES.** F-function / S-boxes / P-permutation / IP/FP
  byte-native; `FeistelRoundGroup` branching contract gains
  `seedInput`/`bodyOutput` analogue. This is the universal-port plan's
  Phase 4d DES rebuild — coordinate, don't duplicate. KAT: published
  DES vectors.

### Phase C — State retirement falls out (2 slices)

**C1 — Retire legacy state types.** With no executor consuming them,
delete `MatrixState` / `BitVecState` / `BigIntState` from `core/types.ts`
(layout-tag survives as an advisory port annotation for the inspector's
4×4 rendering). The A4 contract test escalates to **compiler-enforced**
— a non-bytes leaf port no longer type-checks. A4's allowlist is now
empty and the test is deletable (or kept as a guard).

**C2 — Frame / graph cleanup.** `TraceFrame.stateBefore`/`stateAfter`
retired or repurposed; `inferStateEdges` retired (no state → no state
spine; all edges are port edges). PortFlowView becomes the universal
inspector default; MatrixView/BytesView dispatch off the port layout
tag. Document `schemaVersion` bump if the frame shape change touches
persisted traces.

## What this plan defers

- **Slice 2.9c–e** (provenance hover) — enqueued behind this; wires up
  cleanly once the spec shape is stable.
- **Cross-iteration recurrence visibility** (W_{t-2/7/15/16} arrows
  across FES iterations) — derivation gap owned by the
  universal-port-dataflow plan family; unchanged by this plan.
- **Hierarchical frames** — interact with container port boundaries;
  re-open the inspector composition question when scoped.
- **inspector-overlays** (formula chips for T1/Σ1/Ch/Maj) — still future
  per the Slice 2.9 plan's deferral.

## Relationship to the universal-port-dataflow plan

This plan **front-loads** the contract that the universal-port plan's
Phases 3/4/4d assumed would emerge ad-hoc. After Phase A ships, those
phases inherit `cipherConstants` + container ports + the bytes-only-leaf
contract instead of re-deriving scaffolding each time. Phase B here
**is** that plan's per-cipher rebuild work, executed under the new
contract; Phase C **is** its Phase 5 legacy deprecation, reached as a
consequence. Update `docs/plans/universal-port-dataflow.md` Phase 3+
notes to point here for the contract.

## Cross-references

- Smoke + pivot: [[project_slice_2_9_port_aware_provenance]];
  `docs/plans/slice-2-9-port-aware-provenance.md`.
- Bytes-only baseline: [[feedback_all_specs_port_native]].
- Iterative review gate: [[feedback_iterative_slice_review]].
- Parent plan: `docs/plans/universal-port-dataflow.md` (Phase 2 host;
  Phase 3+ contract update needed).
- SHA-256 spec: `src/ciphers/sha-256.ts:1684–1772`.
- Container contract: `src/core/types.ts:477–520` (FES),
  `PortBinding` at `:79`; runtime FES walk at
  `src/core/runtime.ts:262`, seeding at `:1125`.
- Graph: `src/core/graph.ts` (`deriveAuxGraph`,
  `inferHistorySeedEdges`); `tests/graph-history-seed-edges.test.ts`.

## Not yet worked through (revisit at each phase gate)

1. **A1 sidebar UX details** — exact layout of the constants panel,
   how the forward/back cross-refs render (inline links? hover?).
   Resolve with a mockup at A1 start.
2. **A3 round-group port boundary** — RESOLVED 2026-05-28 (see the A3
   "Resolved design" Q1 above): extend `StepGroup` with
   `seedInput`/`bodyOutput` mirroring A2; the runtime injects the seed as
   `port(groupId,"in")` into the body scope. One sub-fork remains for A3b
   start: round carry port-to-port vs through a `carry` scratchpad cell.
3. **B4 / DES Feistel** — `FeistelRoundGroup`'s branching contract under
   ports is the least-explored container; coordinate with the
   universal-port plan's Phase 4d before B4.
4. **C2 frame-shape persistence** — whether retiring
   `stateBefore`/`stateAfter` forces a document `schemaVersion` bump for
   session-on exports. Measure at C2.
