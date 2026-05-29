# Scaffolding suppression — every leaf speaks only in byte arrays

> **Status: Phase A COMPLETE. Phase B IN PROGRESS — B1 (AES) started
> 2026-05-29 on branch `b1-aes-byte-native`: 3 byte-native primitives shipped
> (`45eff12`), byte-native AES-128 KAT-validated then reverted to keep the
> floor green; 259-test fixture fallout + padding/duplicate-round design items
> queued for next session (see "B1 progress + next-session continuation").**
> Phase A: A0+A1+A2+A3a+A3b SHIPPED + A3b follow-ups
> ⓐ–ⓕ DONE + A4 (anti-creep contract test) SHIPPED 2026-05-28. A3 split into A3a+A3b with Q1–Q4
> resolved (advisor pass + user co-design 2026-05-28); A3b's open carry
> fork resolved **port-to-port** (user pick 2026-05-28). Drafted after the
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

***A3a — boundary + container bridges (low-risk; mostly consumes A2). ✅
SHIPPED 2026-05-28.*** *(Full gate green: biome + tsc + 2468 vitest tests +
build. "abc" KAT byte-equal `ba7816bf…`; frame total 2485→2433; leaf count
1827→1822; `validateShapes` clean. New behaviors: runtime `$input` top-scope
source + `spec.outputFrom`→finalState + FES `outputAux`→`aux[name]`; graph
`$input` synthetic input pill (replaces `__cipher_input__` for port-native
specs, recognized by `isEndpointId` + `edge-value-lookup`) + FES-as-W-writer
stamping in `deriveEdges` (containers are excluded from replication, so W's
schedule→rounds connection is an aux edge from the `msg-schedule` container,
pinned by a new test). spec-shapes validator special-cases `$input`. Test
churn: frame/leaf pins updated; history-seed source `seed-schedule`→
`length-append`; two `W-publish`-specific `drop-aux-only-state-edges` cases
removed (no `state-to-aux-bytes@1` leaf left); preamble-lift + focus-dim +
replication-panel retargeted to surviving leaves.)*
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
risk). ✅ SHIPPED 2026-05-28.*** *(Full gate green: biome + tsc + 2473
vitest tests + build. "abc" KAT byte-equal `ba7816bf…`; frame total
2433→2303 (−130); leaf count 1822→1692 (−130). Carry fork resolved
**port-to-port** (user pick). `validateShapes` + `validateGraph` clean;
collapsed round chain fully connected — no islands.)*
- `types.ts`: added `seedInput`/`bodyOutput` to `StepGroup` (Q1), mirroring
  the A2 FES fields.
- `runtime.ts`: `group` case resolves `seedInput` in the parent scope and
  injects it into the body scope as `port(groupId,"in")` (via the existing
  `seedOutputs` walk arg); captures `walk`'s returned body `nodeOutputs`;
  when `bodyOutput` is set, publishes THAT port's bytes under `outputPorts`
  (default `"out"`) instead of the legacy `state`-derived publish. Absent
  fields ⇒ legacy path (AES round groups unchanged). Loud throws on
  unresolvable seedInput (parent scope) / bodyOutput (body direct-child).
- `sha-256.ts`: deleted the 64 `round.t.state-in` + 64 `round.t.state-out`
  + `final.state-in` + `init-working-vars` (130 leaves). Rounds gain
  `seedInput` (round 0 ← `init.fetch-H.output`; round t ← `round.{t-1}.out`)
  + `bodyOutput` (`repack.output`); `split` reads `port(round.t,"in")`;
  `final.split-wv` reads `port(round.63,"out")`. Removed the 4 dead
  narration objects; updated the file-header topology + counts.
- **Carry fork → port-to-port** (the plan's own decision rule: a
  single-consumer point-to-point edge goes port-to-port; only many-consumer
  broadcasts like K/W live in an aux scratchpad). Round t+1's input edge IS
  round t's output edge — max scaffolding suppression, honest pedagogy.
- `document-schema.ts`: spread `loopingContainerSeedFields` into
  `StepGroupSchema` (Zod strips undeclared keys); additive, no
  `schemaVersion` bump. Round-trip pinned by a new test.
- `spec-shapes.ts`: `walk` gained a `seedScopeOutputs` param; the group case
  validates `seedInput`/`bodyOutput` and seeds the body scope with
  `port(groupId,"in")` so the body's first leaf resolves pre-Run.
- `graph.ts`: **the advisor's biggest risk, resolved.** `inferStateEdges`
  already skips all (pure-port-native) SHA-256 leaves, so the deleted state
  thread carried no edges. `inferPortEdges` now resolves a leaf's
  `port(groupId,"in")` seed reference THROUGH the enclosing group's
  `seedInput` to the real producer — turning the self-referential
  `groupId → leaf` edge into the cross-round carry (`round.{t-1} → round.t`,
  `init.fetch-H → round.0.split`). Empirically verified: collapsed chain
  connected (all 64 inter-round edges + preamble seed + final exit), zero
  graph islands, `validateGraph` clean on both collapsed + uncollapsed.
- **Open-item #2 answered:** the 321 `aux-load-bytes` reads (K/W/H) do NOT
  collapse — they're legitimate many-consumer broadcast reads from aux,
  exactly the case the decision rule keeps as scratchpad cells. A3b only
  retired the point-to-point bridges.
- **Gate met:** "abc" KAT byte-equal; the Q1-visibility scrub pinned
  (`round.t.repack` output === `round.{t+1}.split` input at every boundary,
  both visible); connected round chain; frame/leaf pins updated.

***A3b follow-ups — ✅ DONE 2026-05-28.*** *(Advisor verdict: ship-it,
design + carry-fork-port-to-port confirmed right, no creep. One minor defect
+ four cheap test gaps + one comment; none blocking. All six closed in one
batch after the A3b ship; full `npm run check` green — biome + tsc + **2477
vitest tests** (+5) + build. SHA-256 NOT touched, so the 2303/1692
frame/leaf pins stayed stable. Pre-implementation advisor pass added one
real coverage gap: ⓔ became **two** tests — runtime-throws + a `validateShapes`
half — because the plan named `collectDirectChildOutputs` (the validator),
which my runtime test alone wouldn't exercise; a future "recurse into nested
groups" change to that helper would otherwise silently re-open the same
validator/runtime divergence as ⓐ.)*
- **✅ ⓐ [minor defect] self-referential `seedInput` slips the static
  validator.** Was: `spec-shapes.ts` records the container's own `out` (via
  `recordContainerOutputs()`) BEFORE `validateContainerBinding(...,
  "seedInput", ...)`, so `seedInput: port("<self>","out")` matched the
  freshly-recorded own output → NO pre-Run warning while the runtime threw at
  run. **Fix shipped:** a self-reference guard at the top of
  `validateContainerBinding` — `if (binding.node === containerId)` pushes a
  `port-input-unresolvable`/`missing-node` warning and returns. Chosen over
  the reorder option because it covers **both** the `group` and FES branches
  and **both** binding fields in one localized place and documents the
  invariant. Red-green confirmed (ⓒ was RED pre-fix).
- **✅ ⓑ [test] collapsed-graph carry parity.** Added to
  `graph-port-edge-derivation.test.ts`: builds the SHA-256 graph from a real
  "abc" trace, `collapseGraph(graph, round.0..63)`, asserts the carry
  survives — `init.fetch-H → round.0`, every `round.{t-1} → round.{t}` for
  t∈1..63 (no island), `round.63 → final.split-wv`. (Uncollapsed
  `round.{t}.split` remaps to `round.{t}`; the collapsed group source stays
  itself.) Pins the user's stated biggest A3b risk against a future
  collapse/layout refactor.
- **✅ ⓒ [test] for ⓐ.** `validateShapes` test: a group with `seedInput:
  port("<self>","out")` now emits the `port-input-unresolvable`/`seedInput`/
  `missing-node` warning. RED before the ⓐ guard, GREEN after — the
  regression that pins the defect.
- **✅ ⓓ [test] explicit `validateGraph` clean assertion.** `validateGraph`
  emits `[]` on SHA-256 (orphaned-read / unused-write / cycle) on **both**
  uncollapsed and collapsed graphs. **Confirmed empirically** — the
  collapsed assertion (the one GraphView actually validates) stays clean
  because rounds only READ K/W from aux and never write aux, so collapsing
  them can't orphan a consumed write into a false unused-write. The advisor's
  flagged failure mode did not materialize; no app bug surfaced.
- **✅ ⓔ [test] grandchild `bodyOutput` throws — runtime + validator.**
  Runtime half (`runtime-for-each-subgraph-with-history.test.ts`): a group
  whose `bodyOutput` names `g.inner.leaf` (a leaf inside a child group)
  throws "not a same-scope body output". Validator half
  (`spec-shapes.test.ts`): the same shape emits a `port-input-unresolvable`/
  `bodyOutput`/`missing-node` warning. The two pin the parallel "direct child
  only" implementations (`collectDirectChildOutputs` vs the runtime's body
  `nodeOutputs`) against a recurse-into-nested-groups regression.
- **✅ ⓕ [comment] single-hop seed resolver.** Comment added in `graph.ts`
  `inferPortEdges`: the `port(groupId,"in")` → `seedInput.node` resolution is
  deliberately single-hop (a seed-of-a-seed would need the chain walked), and
  the latent "resolves `port(groupId,"in")` for any leaf regardless of body
  membership → hand-malformed cross-scope read draws an unreachable edge" is
  noted as cosmetic-only (that spec can't run), not fixed.
- **→ B1 [cleanup] consolidate binding resolution.** runtime.ts group
  `seedInput` / group `bodyOutput` / FES `bodyOutput` / `outputFrom` are
  4 near-duplicate "resolve a `PortBinding` against a `nodeOutputs` map,
  throw if missing" blocks. When B1 lifts `iterate`/`for-each-subgraph`
  onto the contract (the 3rd real consumer), extract a
  `resolveBinding(map, binding, ctxLabel)` helper. Don't churn it before.

**A4 — Anti-creep contract test. ✅ SHIPPED 2026-05-28.**
- `tests/byte-native-ports-contract.test.ts` walks the step registry and
  **fails** if any registered `kind: "ported"` leaf declares a non-bytes
  port shape. **Terminology bridge:** the plan said "isn't `bytes`", but
  `PortLayout` has no `"bytes"` member — its byte-native layout is `"raw"`
  (absent ⇒ raw); `"bytes"` belongs to the *other* contract (`StateShape`).
  So non-bytes ≡ `layout` present and ≠ `"raw"`.
- **Allowlist seeded empirically** (throwaway probe vs `buildDefaultRegistry()`,
  not file greps — the grep missed two string-branch layouts). The 10 offenders
  are all `[legacy meta]` lifts; every port-native step is already raw-only:
  AES core (`add-round-key`, `byte-substitution`, `mix-columns`, `shift-rows`,
  `state-to-aux`, `xor-aux-into-state` — `matrix-cm-4x4`), AES mode boundary
  (`split-blocks`/`concat-blocks` — `matrix-cm-4x4-array`, `iv-load` — `matrix-cm-4x4`),
  and `aux-copy` (`preserve-input-variant` sentinel). Allowlist **shrinks** as
  Phase B ships; a rebuild PR must delete its entry.
- **Strengthened beyond the literal gate (advisor pick):** exact set-equality
  via two directional assertions — (1) offenders ∖ allowlist empty ("crept in"),
  (2) allowlist ∖ offenders empty ("rebuilt; drop the entry"). The subset-only
  gate couldn't enforce the prose requirement that each rebuild PR removes its
  entry. Escalates to compiler-enforced at C1.
- **Gate:** green with the allowlist; a deliberately-broken fixture leaf
  (`matrix-cm-4x4` port, not on allowlist) makes the checker red — plus a
  raw-only fixture confirms no over-reporting. Both directional asserts
  verified to bite via a temporary allowlist mutation.
- **Legacy-contract tripwire (advisor catch — extension beyond the literal
  A4 text).** The port-shape walk only sees `kind: "ported"` registrations;
  a bare `kind: "legacy"` step has no `PortContract`, so a matrix-creeping
  legacy executor would be **invisible** to the layout checks — the exact
  creep vector the plan exists to close. Adding the tripwire **disproved the
  "every step type is ported since Slice 1.8" assumption**: three legacy
  registrations remain (`compute-block-count`, `load-block`, `store-block` —
  the ECB/CBC multi-block mode primitives; `load-block`/`store-block` are
  genuinely matrix-interpreting, `bytes ↔ matrix4x4-bytes`). They get a
  second `LEGACY_CONTRACT_ALLOWLIST` with the same exact-equality two-
  directional discipline, removed in B1 when AES modes go byte-native.
- 9 tests total, suite 2477→**2486**.

### Phase B — Per-cipher byte-native rebuilds (4 slices, feature branches)

Each cipher rebuilt on its own feature branch; merged to `main` only
when fully byte-native + KAT byte-equal; `main` never holds a
half-converted cipher (per [[feedback_all_specs_port_native]]). Each
removes its A4-allowlist entry on merge.

- **B1 — AES** (deepest matrix coupling — the contract stress test).
  SubBytes/ShiftRows/MixColumns/AddRoundKey byte-native; `iterate` adopts
  `seedInput`/`outputPorts` for ECB/CBC. KAT: FIPS-197 Appendix C.
  **🔶 IN PROGRESS — branch `b1-aes-byte-native`. Slice B1.1 partially
  shipped (3 primitives committed `45eff12`). See the "B1 progress + next-
  session continuation" section below for the full state, the four resolved
  scope decisions, and the two cross-cutting work items discovered.**
  *Scope corrections vs the original bullet (resolved 2026-05-29):*
  key schedule stays the **monolithic** `aes.key-expansion@1` (already
  A4-clean — gate doesn't require touching it); the S-box/mix-matrix/permute
  indices stay **leaf params**, NOT `cipherConstants` (the A1 lockstep lesson —
  see below); `cipherConstants` migration + mirror re-homing defer to a later
  key-expansion-decomposition slice.
- **B2 — Speck** (easiest — already byte-flat `BytesState(4)`). Mostly
  conformance + contract adoption. KAT: both BE-paper + LE-NSA vectors.
- **B3 — Serpent.** Standard form (explicit IP/FP); S_i tables to
  `cipherConstants`. KAT: all three key sizes.
- **B4 — DES.** F-function / S-boxes / P-permutation / IP/FP
  byte-native; `FeistelRoundGroup` branching contract gains
  `seedInput`/`bodyOutput` analogue. This is the universal-port plan's
  Phase 4d DES rebuild — coordinate, don't duplicate. KAT: published
  DES vectors.

### B1 progress + next-session continuation (2026-05-29, session 1)

> Branch `b1-aes-byte-native`, base `684a112`. **End-of-session save** — the
> user approved the two design decisions below and asked to implement the rest
> next session. A future session should be able to resume entirely from this
> section + the memory file `project_scaffolding_suppression_plan.md`.

#### Session 2 (2026-05-29) — topology commits landed; mechanical sweep is next

Three of the planned five steps are DONE and committed (red-WIP `--no-verify`,
sanctioned). The suite is still broadly red (the ~50-file fixture sweep is the
remaining work — the advisor-designated session boundary). Findings that
**override the session-1 playbook** are flagged ⚠️.

- **Batch 1 `685b748` — byte-native AES-128 + topology-aware padding.**
  Re-applied the byte-native `aes-128.ts` (KAT re-confirmed `69c4e0d8…`, 52
  frames, ported-dispatch auto-on). Reworked `applyPaddingScheme` with a new
  **Branch 2** for byte-native AES: prepend pad reading `$input`, repoint
  `$input` consumers to the pad's output. ⚠️ **The lifted pad's output port is
  `"state"`, NOT `"output"`** (plan said "output" — wrong; lifted Phase-1 steps
  publish under `meta.stateOutputPort="state"`, see `port-projection.ts:713`).
  ⚠️ **Idempotency needs an EDGE restore**, not just leaf strip:
  `restoreInputSourceConsumers` repoints pad-output bindings back to `$input`
  before a strip removes the pad leaf (else dangling). `isByteNativeAesSpec`
  gates on the **AES family (id prefix)** — the hardcoded `AES_BLOCK_SIZE=16` is
  the real constraint, so Speck(4)/DES(8) must stay no-op (B3/B4 seam). Decrypt
  branch implemented symmetrically (forward-compat for B1.2, NOT exercised).
  `spec-mutations-padding.test.ts` rewritten + green.
- **Batch 2 `0405949` — cross-mode mirror: Option D descope (advisor-reviewed).**
  ⚠️ **Did NOT add byte-native mirror entries/buttons.** The sync mutators are
  same-type (`updateAllStepsByType` keys on ONE stepType); a B1 byte-native sync
  button would silently no-op against the matrix decrypt counterpart — a FALSE
  AFFORDANCE. `byte-substitute@1`'s natural home is B1.2 (once decrypt is also
  byte-native, both sides share the type and the existing mutator works with
  ZERO new code). The "class-2 can't ship without a mirror" rule is a
  merge-to-main gate; deferring within the branch is fine. Only change: the
  coverage test's `setupForEntry` now `setCipher("aes-192")` (still matrix) for
  the two legacy AES entries so they exercise the still-live matrix buttons.
  Registry UNTOUCHED. **→ B1.2 MUST add `{byte-substitute@1,sbox,inverse}` +
  `{gf-matrix-multiply@1,matrix,inverse}` entries + ParamEditor buttons.**
- **Batch 3 (duplicate-round) — EDITED + logic-validated, test-run PENDING a
  tooling outage.** Extended `renumberRoundGroup` (forward, presence-guarded so
  legacy matrix rounds untouched): bump `aux-load-bytes@1` auxName (byte-native
  carries roundKey.N on `fetch-rk`, not on the xor AddRoundKey); remap each
  child's `portInputs` + the group's `bodyOutput` by prefix; ⚠️ **RECOMPUTE
  `seedInput`** (`toN===1 ? initial.add-round-key/"output" : round.{toN-1}/"out"`)
  rather than rename-map remap — the predecessor shifts +1 for BOTH the clone
  and every renumbered sibling, which the rename map can't express (plan said
  "remap through rename map" — wrong for seedInput). ⚠️ **ALSO: `duplicateRoundGroup`
  must REMAP `spec.outputFrom` through the rename map** (`round.10`→`round.11` on a
  forward dup of the final round). Found via a parity probe: byte-native dup
  produced `d961a1…` vs matrix dup `bbcd9a…` despite IDENTICAL round structure
  (same keys/mix/seed-chain/internal-wiring, zero dangling) — the spec exit
  still pointed at the OLD final round (`round.10`, now a full mid-round),
  silently SKIPPING the real final round. After the fix both = `bbcd9a…`. Legacy
  matrix specs have no `outputFrom` (no-op); reverse keeps `inv-round.0` (not
  renamed). This is the difference between "the spec looks right" and "the cipher
  computes right" — structure dumps weren't enough; the byte-equal parity probe
  caught it. Validated: 11 rounds, auxNames bumped, full seedInput chain correct,
  **zero dangling bindings**, clean ported run, byte-native dup == matrix dup.
  Updated
  `duplicate-round-{mutator,store,save-load}.test.ts` + `graph-duplicate-button`
  for byte-native (auxName→`fetch-rk`, child-type list, rename count 5/round,
  encrypt run→bytes+ported; decrypt stays matrix). **DONE — committed `f055703`;
  46/46 duplicate-round tests green, `tsc` + `biome` clean.**

**Batch 3 was COMMITTED `f055703` (pushed).** The whole session (batches 1–3)
is on `origin/b1-aes-byte-native` at `f055703`.

**Remaining (mechanical sweep — next session's bulk; THIS IS WHERE TO RESUME):**

The suite is broadly red because the byte-native `aes128Spec` swap changed the
app's universal default fixture. **First action next session:** run the full
`npx vitest run` (or `npm run check`) and triage the failures by the three
buckets below. (Session-1 measured ~259 failures pre-rework; batches 1–3 fixed
the padding/mirror/duplicate-round subset, so the live number is lower — re-count.)

**Bucket A — mechanical (the bulk).** ~50 files reference `aes128Spec`/`aes-128`
(grep them). Any that BUILD A TRACE from it via `matrixFromBytes(...)` +
no `portedDispatchEnabled` now throw `aux-load-bytes@1 ... requires
portedDispatchEnabled: true`. Per-file transform (the exact pattern batches 1+3
already applied in `duplicate-round-*.test.ts` — copy it):
  - import `makeBytesState` from `@/core/state/bytes` + `requiresPortedDispatch`
    from `@/core/dispatch`;
  - `initialState: matrixFromBytes(ptBytes)` → `makeBytesState(ptBytes)`;
  - add `portedDispatchEnabled: requiresPortedDispatch(spec, registry)`;
  - `finalState.shape === "matrix4x4-bytes"` → `"bytes"`; read the 16 output
    bytes from `finalState.bytes` (still a `Uint8Array`);
  - intermediate per-step values: read `frame.portOutputs.get("output")` (or the
    relevant port) — NOT `frame.stateAfter` (byte-native leaves leave `state`
    untouched; the matrix `stateAfter` is gone).
  NOTE: the DECRYPT spec (`aes128DecryptSpec`) + AES-192/256 (both modes) +
  ECB/CBC are STILL MATRIX — leave their `matrixFromBytes` paths alone. Only the
  AES-128 single-block ENCRYPT path is byte-native. Many files exercise both.

**Bucket B — rewrite `aes-vectors.test.ts`.** It KATs the matrix encrypt and has
a "reorder steps by array swap" test that is MOOT under port wiring (order is
data-dependency, not array position). Rewrite the KAT for byte-native (bytes +
ported, `69c4e0d8…`); drop or convert the reorder test to a binding-rewire.

**Bucket C — legacy-CONCEPT tests using AES as a matrix fixture.** e.g.
`aux-graph-derivation.test.ts` asserts "40 state edges / spine crosses round
boundaries" — byte-native AES has NO state spine (port-to-port carry), so these
assertions are now false. Per-test decision: **retarget the state-spine machinery
tests to a STILL-LEGACY cipher (Speck/DES survive until B2–B4)** so they keep
exercising that code until Phase C — DON'T reflexively rewrite them as port-edge
assertions (the state-spine code outlives AES's use of it). Only rewrite if the
test is specifically about AES's graph, not about the spine machinery generally.

**Do NOT touch the A4 allowlist this session.** The matrix `generic.*` steps
(byte-substitution / mix-columns / shift-rows / add-round-key) are STILL LIVE on
decrypt + AES-192/256 + ECB/CBC → still A4 offenders → the allowlist stays exact.
It drains in B1.2 (decrypt) / B1.3 (192/256) / B1.4 (modes).

**After the sweep is green:** `npm run check` should pass → then a normal
(non-`--no-verify`) commit closes B1.2a–c's red window. Then continue to B1.2
(byte-native decrypt + the deferred cross-mode mirror entries, see batch 2),
B1.3 (192/256), B1.4 (modes: iterate `seedInput`/`outputPorts` + `resolveBinding`
extraction + A4 allowlist removals).

**Shipped this session (commit `45eff12`, full gate green, suite 2486→2520):**
- Three byte-native primitives + `aes-round-builder-native.ts` (unused so far)
  + 34 tests. `byte-substitute@1` (SubBytes), `permute@1` (ShiftRows,
  column-major indices via `shiftRowsIndices`), `gf-matrix-multiply@1`
  (MixColumns, reuses `gfMul`). All static `layout:"raw"` ports → A4-clean.
  AddRoundKey needs no new type (`aux-load-bytes@1` roundKey.N + `xor@1`).
- **Byte-native AES-128 VALIDATED then reverted to keep the floor green.** A
  throwaway probe ran the byte-native `aes-128.ts` (stateShape/plaintext →
  `"bytes"`, body = `buildAesEncryptBodyNative(10)`, `outputFrom =
  aesNativeOutputFrom(10)`): FIPS-197 §C.1 ciphertext **byte-equal**
  `69c4e0d8…`, frame count **52**, roundKey.10 correct, initial-ARK port
  output = PT⊕key. `aes-128.ts` is currently MATRIX again (reverted) so the
  primitives commit sits on a green suite. Re-applying the swap is a ~5-line
  edit using the committed native builder.

**Four resolved scope decisions (user, 2026-05-29):**
1. **Rendering:** flat bytes until Phase C2 (NO `PortFlowView` change in B1;
   AES renders as a flat 16-byte row — accepted temporary regression).
2. **MixColumns:** medium `gf-matrix-multiply@1` (GF math inside the executor).
3. **Key-expansion:** stays monolithic `aes.key-expansion@1` (A4-clean).
4. **Constants stay leaf params** (NOT `cipherConstants`) in B1 — key-expansion
   also consumes the forward S-box (SubWord); moving only the round S-box to a
   constant would diverge the two consumers (the A1 creep lesson). No worse
   than today (already two independent S-box params). Unify in the later
   key-expansion-decomposition slice.

**The big finding — converting `aes128Spec` (the app's universal default
fixture) breaks 259 tests.** Inherent cost, NOT a wrong approach (KAT byte-
equal; graph/UI infra already handles byte-native via SHA-256). Per
[[feedback_all_specs_port_native]] a red WIP window on this branch is
sanctioned — **stop optimizing for green-per-commit on `b1-aes-byte-native`.**
Triage (advisor 2026-05-29) — **resolve the (B) functional/design items FIRST;
they can change topology and would re-break a mechanical sweep:**

- **(A) Mechanical (do last):** `matrixFromBytes` initialState → `BytesState`;
  `finalState.shape === "matrix4x4-bytes"` → `"bytes"`; frame-count pins;
  read intermediate values via `frame.portOutputs.get("output")` not
  `stateAfter`. Rewrite `tests/aes-vectors.test.ts` this way (the reorder-by-
  array-swap test is moot under port wiring — drop or convert to a binding
  rewire).
- **(B) Functional / design — DECIDED, implement next session:**
  1. **Padding overlay → make topology-aware** (user pick). `applyPaddingScheme`
     (`src/core/spec-mutations.ts:1423`) branches on
     `stateShape === "matrix4x4-bytes"`; byte-native AES (`"bytes"`) falls into
     the no-op "non-AES" branch, AND the cipher head reads `$input` directly so
     a prepended pad is ignored. Fix: a byte-native branch that prepends `pad`
     (reads `$input`) + **repoints every `portInputs` binding pointing at
     `port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT)` to `port(padId,"output")`**; on
     decrypt append `unpad` reading the old `outputFrom` + set `outputFrom` to
     `port(unpadId,"output")`. Drop `load-block`/`store-block` for byte-native
     single-block. Fixes `app-padding-roundtrip.test.tsx`.
  2. **cross-mode-mirror coverage spans BOTH modes** → cannot split to B1.2.
     In the aes-128-byte-native conversion commit: ADD entries
     `{byte-substitute@1, sbox, inverse}` + `{gf-matrix-multiply@1, matrix,
     inverse}` to `cross-mode-mirror-registry.ts` + wire their ParamEditor
     buttons; KEEP the old `generic.byte-substitution@1`/`generic.mix-columns@1`
     entries (decrypt + ECB/CBC stay matrix until B1.2/B1.4). Fixes
     `cross-mode-mirror-coverage.test.tsx`.
  3. **duplicate-round → fix within B1** (user pick). `duplicateRoundGroup`
     (`src/core/spec-mutations.ts:1101`) renames ids via a rename map but does
     NOT rewire `seedInput`/`bodyOutput`/`portInputs`, so a cloned byte-native
     round points its bindings at stale ids. Extend it to remap those bindings
     through the rename map + the renumber shift. Fixes the `duplicate-round-*`
     test files.
- **(C) Legacy-concept tests using AES as a matrix fixture:** e.g.
  `tests/aux-graph-derivation.test.ts` asserts "40 state edges / spine crosses
  round boundaries" — byte-native AES has NO state spine (port-to-port carry).
  Per-test decision: retarget the state-spine machinery tests to a still-legacy
  cipher (Speck/DES survive until B2–B4) so they keep exercising that code
  until Phase C, **vs** rewrite as port-edge assertions. Don't reflexively
  rewrite — the state-spine code outlives AES's use of it.

**Recommended next-session order:** (1) re-apply byte-native `aes-128.ts`;
(2) padding-overlay topology-aware rework + tests; (3) cross-mode-mirror
entries+buttons (old+new); (4) duplicate-round binding rewire; (5) rewrite
`aes-vectors.test.ts` + sweep (A)/(C) by pattern until the suite is green with
byte-native AES-128 forward; (6) then B1.2 decrypt, B1.3 192/256, B1.4 modes
(iterate `seedInput`/`outputPorts` + `resolveBinding` helper extraction + all
A4 allowlist removals). Original full B1 plan: `~/.claude/plans/tidy-honking-
stearns.md`.

#### Session 4 (2026-05-29) — fixture SWEEP COMPLETE; suite GREEN; B1 core DONE

The sweep is finished. Started session at 89 failing / 21 files; ended at
**0 failures — full `npm run check` GREEN (2514 tests, 213 files, vite build
clean)**. The sanctioned red-WIP window is **closed** (batch 8 was a normal,
non-`--no-verify` commit). Three more batches on `origin/b1-aes-byte-native`:

- **`9beb153` batch 6 (Bucket B)** — `aes-vectors` rewritten byte-native (KAT
  `69c4e0d8…` + frame-stream pins preserved: 41→52 frames, 11 round keys,
  initial-ARK intermediate via `portOutputs.get("output")` = `193de3be…`; the
  array-swap reorder test dropped — array order no longer drives dataflow).
  `aes-decrypt` round-trip: forward half byte-native, decrypt half stays matrix.
- **`20030bd` batch 7 (functional, 10 files)** — toolbox #1–#3 + retargets:
  provenance-hover → AES-192 (MatrixView cell provenance; byte-native has no
  matrix stateAfter); graph-validation `runPorted` helper; key-schedule-explorer
  flag in shared helper; spec-mutations leaf-type `generic.byte-substitution@1`
  → `byte-substitute@1` + count 10; spec-mutations-structure 5-child rounds
  (+fetch-rk); spec-shapes matrix→bytes; run-history `{inputCount:2}`;
  built-from-palette 3 shape gates matrix4x4-bytes→bytes (Phase E/H byte-equality
  now actively fires — aux primitives run fine under ported dispatch).
- **`8080d03` batch 8 (Bucket C — state-spine machinery)** — aux-graph-derivation
  (structural adapt + 2 pure-spine deletes + collapse existence-rewrites +
  endpoint-pills→AES-192), replicate-fanout (fetch-rk replica ids + dup-victim
  #15 reduced to its killer assertion), port-projection-q-gate-9 (was a silently
  -failing SUITE — describe-body `runSpec` threw at collection; single-block→
  AES-192, aux-write stays byte-native with META `stateLayout`→`bytes`).

**Two reusable facts discovered this session (for B1.2/3/4 + future ciphers):**
(1) byte-native AES emits **dup state edges** — 51 spec-spine (`auxKey:"state"`)
+ 51 port-flow (`auxKey:"port-flow"`), EVEN with an empty trace (port edges
derive from spec bindings, not the trace). Count-based state-edge assertions
are dup-broken; existence-based survive. (2) the graph carries a **`$input`
source node** (`INPUT_SOURCE_ID`) → `g.nodes.length` = leaves + 1; it sits at
`rootIds[0]` and collides with synthetic endpoint pills (forced the
endpoint-pills retarget to matrix AES-192).

**The criterion that drove the whole sweep** (advisor-reviewed, reusable for
B1.2/3/4): assertions that COUNT/POSITION state edges → retarget to a
clean-spine matrix cipher / synthetic / existence-based; assertions about
structure / existence / leaf-membership / aux-edges → adapt on byte-native AES.
DELETE only uniquely-AES pure-spine tests covered by the Serpent spine test.

**aes-192 retargets re-break at B1.3** (enumerable — grep `aes192Spec` /
`aes-192` across `tests/`): graph-view-replication-force-on-ported,
provenance-hover-integration (6 MatrixView), aux-graph-derivation (endpoint
pills), port-projection-q-gate-9 (single-block), cross-mode-mirror (batch 3).
`frame-port-values` uses a SYNTHETIC `generic.byte-substitution@1` carrier
(survives all of Phase B; retires only with MatrixState at Phase C).

**Next: B1.2** (decrypt byte-native → enables the deferred byte-native mirror
registry entries `byte-substitute@1`/`gf-matrix-multiply@1` whose same-type
mutators now work) → **B1.3** (192/256 byte-native — drains the aes-192
retargets above + the A4 allowlist 192/256 entries) → **B1.4** (ECB/CBC modes:
iterate `seedInput`/`outputPorts`, `resolveBinding` extraction, remaining A4
allowlist removals). Consult advisor before each per [[feedback_iterative_slice_review]].

**FOLLOW-UP with a HARD DEADLINE at B1.4 (app-visible, papered over this sweep):**
the synthetic endpoint pill ("plaintext enters here" / "ciphertext exits here",
graph-narrative Slice 1) **collides with the byte-native `$input` source node**.
The probe found something sharper than a count change: in the byte-native graph
with pills, there is **no `CIPHER_INPUT_ID → initial.add-round-key` edge at all**
— `$input` already occupies `rootIds[0]` and the input-anchor role, so the
input pill's edge is absent. This session scoped it out by retargeting the
endpoint-pill tests to matrix AES-192. **At B1.4 every cipher is byte-native —
there is NO matrix carrier left to retarget to.** The concrete question to
answer then (or sooner, as a graph-view feature decision): *does the input pill
still render for a byte-native cipher, or does the `$input` source node
suppress/replace it — and is the `$input` node itself the honest "plaintext
enters here" affordance?* Likely resolves with Slice 2.9c-e / the universal
inspector work.

**Process fix for the B1.2/3/4 sweeps (cost a late surprise this session):**
a JSON-reporter triage that keys off `assertionResults` gives a **FALSE GREEN
for a suite that fails at COLLECTION time** (e.g. a describe-body `runSpec` that
throws — `port-projection-q-gate-9` did exactly this) because such a file has
ZERO assertionResults, so `filter(a => a.status !== "passed").length === 0`.
Only the full-suite `Failed Suites N` / `no tests` line catches it. Next sweep:
triage off `testResults[].status` (or grep `Failed Suites` / `no tests`), and
ALWAYS run the full `npx vitest run` (not just the per-file batches) before
declaring a sweep green.

#### Session 3 (2026-05-29) — mechanical sweep underway; 227 → 89 failures; 5 batches green-committed

The functional/topology items (batches 1–3 of session 2) were already done; this
session is the **fixture sweep**. Started at **227 failing / 45 files**, now at
**89 failing / 21 files**. Five commits on `origin/b1-aes-byte-native` (push at
session end): `6829e8a` ParamEditor blocks (app source), `fc1102f` batch-1 (9
graph fixtures), `7f8b5fe` batch-2 (drag/gutters/replicas geometry), `e581b4f`
batch-3 (cross-mode mirror → AES-192 + url-share threshold), `b7cbe7c` batch-4
(graph/panel fixtures). Each was `--no-verify` (sanctioned red-WIP window). The
suite is **still intentionally red** — finish the sweep, then a normal commit
closes the window.

**The reusable toolbox (every pattern below is already applied somewhere — copy it):**

1. **Mechanical (the bulk).** In a `runSpec(aes128Spec, …)` fixture:
   `matrixFromBytes(bytesFromHex(X))` → `makeBytesState(bytesFromHex(X))`, add
   `portedDispatchEnabled: true` (the fixture hardcodes the byte-native default —
   `true` is correct and self-documenting), and **drop the now-unused
   `import { matrixFromBytes }`** (biome fails otherwise; keep it only if the file
   still uses it for ECB/Serpent/DES/synthetic frames). ECB/192/256/decrypt stay
   matrix — leave their `matrixFromBytes` paths alone.
2. **Byte-native leaf-id remaps** (matrix → port-native): round-key consumer
   `round.N.add-round-key` → `round.N.fetch-rk` (the `aux-load-bytes@1` that reads
   `roundKey.N`); SubBytes `generic.byte-substitution@1` → `byte-substitute@1`;
   MixColumns `generic.mix-columns@1` → `gf-matrix-multiply@1`; ShiftRows
   `generic.shift-rows@1` → `permute@1`; cipher input `CIPHER_INPUT_ID`
   (`__cipher_input__`) → `INPUT_SOURCE_ID` (`$input`, import from `@/core/types`).
   **Counts:** whole byte-native AES-128 = **52 leaves** (key-expansion +
   init.fetch-rk + initial.add-round-key = 3, + 9 full rounds × 5, + final
   round.10 × 4); a round group has **5 children** (was 4 — `fetch-rk` added);
   collapsing one round drops 5 (52→47). round.10 is **still the final round**
   (byte-native AES-128 is still 10 rounds).
3. **Force replication OFF for geometry/count tests.** Byte-native (ported) specs
   auto-ON replication via GraphView's `effectiveReplicate`, which adds
   key-expansion replica chips (inflates leaf-rect counts, widens round boxes,
   replaces the single drag target with 11 replicas). Call
   `setReplicationEnabled(false)` after seeding (it sets the session-toggle so
   `effectiveReplicate` honours the explicit value). Re-enable per-test where a
   test specifically needs replicas (e.g. drop-gutters' "skips replica chips").
4. **Retarget to AES-192** — ONLY for cross-mode-mirror tests (Option D): AES-192
   stays matrix on both sides until B1.3, so `generic.byte-substitution@1` /
   `generic.mix-columns@1` + their Sync rows still exist. `setCipher("aes-192")`
   in `resetAll`. **Do NOT use aes-192 for state-spine tests** (it converts in
   B1.3 — pure can-kicking; advisor-confirmed).
5. **Retarget to Serpent** — for state-edge / clean-spine **machinery** tests.
   Byte-native AES has no clean spine: each internal connection yields BOTH a
   port-flow state edge (`auxKey:"port-flow"`, from `inferPortEdges`) AND a spine
   state edge (`auxKey:"state"`), so (from,to,kind) groups duplicate. Serpent is
   legacy/matrix — clean 1:1 `auxKey:"state"` spine, key-expansion fanout, no
   port-flow companions. (Used in `graph-bundle.test.ts`.)
6. **Synthetic graph fixture** — for **pure-layout** spine tests (call
   `layoutRoot` directly, not the component). `isSpineReplica` nodes are excluded
   from `isReplica` in `buildReplicaPlacement`, so a hand-built graph (source +
   root consumer + `kind:"state"` edge + `isSpineReplica:true` replica node) drives
   the no-lift/source's-old-slot branch. See `syntheticSpineReplicaGraph` in
   `graph-view-replica-gutter.test.ts`.
7. **Delete-with-Phase-C-comment** — sanctioned retreat ONLY for **uniquely-AES,
   component-level** state-spine tests that no cipher can retarget to (Serpent
   uses the lift branch, DES is Feistel) AND whose machinery is covered elsewhere.
   Used for two `graph-view.test.tsx` tests (spine-replica-on-spine-row +
   spine-edge-filter) — covered by the synthetic layout test + Serpent bundle
   tests. Leave a `// Phase C: re-pin when inferStateEdges retires` note.

**Key facts discovered this session:**
- Byte-native port-flow carry edges are `kind:"state"` + `auxKey === PORT_FLOW_AUX_KEY`,
  so they still render as `.graph-edge-state`. Byte-native AES-128 no-trace graph
  has **52 `.graph-edge-state`** edges (was 41 matrix).
- ParamEditor needed new `<Match>` blocks for `byte-substitute@1` /
  `gf-matrix-multiply@1` / `permute@1` — they reuse `SboxEditor`/`MatrixEditor` but
  **omit the cross-mode sync rows** (Option D false-affordance avoidance).
- url-share spec-only payload grew ~1.6 KB → ~4.4 KB (more leaves + per-leaf
  narrationOverride); threshold bumped 4096 → 8192.

**Remaining 21 files (with planned treatment) — RESUME HERE:**

*Ported-dispatch / predicate (expectation updates — byte-native AES IS ported now):*
- `requires-ported-dispatch.test.ts` — add byte-native aes-128 to the "requires
  dispatch" expectation (it now does).
- `runtime-ported-dispatch.test.ts`, `runtime-ported-dispatch-aes-core.test.ts`,
  `runtime-ported-dispatch-frame-parity.test.ts` — core dispatch tests; update
  expectations for byte-native AES (`frame.portOutputs` not `stateAfter`; 52
  frames; ported flag).
- `frame-port-values.test.ts` — read intermediate values via
  `frame.portOutputs.get("output")`, not `frame.stateAfter`.
- `graph-view-replication-force-on-ported.test.tsx` — byte-native aes-128 now
  triggers auto-ON (was the "AES default-off" control case). Use a still-matrix
  cipher (aes-192) for the "default OFF" assertion; keep SHA / byte-native AES for
  "auto-ON". (Memory `project_universal_port_dataflow_proposal.md` describes the
  4 cases.)

*Bucket B — AES vectors (pin the real FIPS-197 ciphertext `69c4e0d8…`, not just "runs"):*
- `aes-vectors.test.ts` — rewrite KAT byte-native (bytes + ported, `69c4e0d8…`);
  the "reorder steps by array swap" test is MOOT under port wiring — drop it or
  convert to a binding rewire.
- `aes-decrypt.test.ts` — **MIXED**: encrypt half byte-native (flag + bytes
  reads), decrypt half **still matrix** (`matrixFromBytes`, `finalState.shape
  === "matrix4x4-bytes"`). Don't blanket-convert. Round-trip pins plaintext.

*Bucket C — state-spine machinery:*
- `aux-graph-derivation.test.ts` — structural AES counts ("one node per leaf",
  node counts) AND state-spine ("40 state edges", "spine crosses round
  boundaries"). The spine-derivation tests test `inferStateEdges` **deriving from
  a spec** → can't be synthetic → **retarget those to Serpent** (round groups +
  spine, "spine crosses round boundaries" fits Serpent better than DES/Speck).
  The structural-count tests adapt to byte-native counts. Big file — split per-test.
- `replicate-fanout.test.ts` — fanout count adapts (key-expansion → 11 `fetch-rk`
  consumers); the "state edge from key-expansion to initial.add-round-key shares
  its replica" assertion is state-spine → synthetic-or-delete (same split as
  `graph-view-replica-gutter`).

*Mechanical / functional (per-file, mostly toolbox #1–#3):*
- `key-schedule-explorer.test.tsx` — `matrixFromBytes` used 10× incl. a
  `ReturnType<typeof matrixFromBytes>` type union; convert the aes calls, KEEP the
  import (Serpent/Speck + the type union still need it).
- `step-description-narration-override.test.tsx` — synthetic stateBefore/stateAfter
  frames KEEP `matrixFromBytes`; only the aes `runSpec` (line ~68) converts. May
  also need narration-id remaps (the round leaves changed type).
- `graph-validation.test.ts` — `matrixFromBytes` in a generic `runSpec(spec,…)`
  helper; convert the aes path + check validation expectations.
- `provenance-hover-integration.test.tsx` — matrix CELL provenance overlay; reads
  `frame.stateAfter as MatrixState`. Byte-native AES has no matrix stateAfter
  (accepted regression, scope decision #1). **Retarget the AES provenance test to
  Serpent** (still matrix) — the Serpent test in the file already shows the path.
- `port-projection-q-gate-9.test.ts` — reads `stateAfter`; byte-native. Inspect;
  likely retarget or read port outputs.
- `built-from-palette-roundtrip.test.tsx` — the default spec changed; check what
  it builds/asserts (palette-drop + save/load roundtrip).
- `run-history.test.ts` — likely a frame-count / spec-shape expectation.
- `spec-mutations.test.ts`, `spec-mutations-structure.test.ts` — mutations on the
  byte-native spec (counts/structure expectations).
- `spec-delete.test.tsx` — delete-step on byte-native spec.
- `spec-shapes.test.ts` — pre-Run validation expectations on byte-native spec.

**Process reminders:** re-run each file after editing (second-order failures hide
behind the dispatch error — counts, `stateAfter` reads, frame pins surface only
after the flag is added). Commit in logical batches with `--no-verify`. **Don't
touch the A4 allowlist** (matrix `generic.*` still live on decrypt/192/256/modes).
When the sweep is green → `npm run check` → a normal (non-`--no-verify`) commit
closes the red window → then B1.2 (decrypt + the deferred byte-native mirror
registry entries) / B1.3 (192/256) / B1.4 (modes).

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
