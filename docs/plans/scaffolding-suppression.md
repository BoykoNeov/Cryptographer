# Scaffolding suppression — every leaf speaks only in byte arrays

> **Status: PLAN LOCKED 2026-05-28. NOT STARTED.** Drafted after the
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

**A1 — `cipherConstants` + editor + sidebar.**
- `CipherSpec.cipherConstants?: Record<string, Uint8Array>`
  (`core/types.ts`); runtime materializes into aux before walking the
  tree.
- Editable in a new sidebar panel (ParamEditor-style cells, byte-format
  honored, 200 ms debounce → re-run via the existing spec-mutations
  path). Save/Load/URL-share carry constants.
- Sidebar shows **forward refs** (which leaves consume each constant);
  leaf inspector shows **back refs** (which constants a leaf reads).
- Cross-mode mirror buttons for S-box-class constants re-home here
  (`cross-mode-mirror-registry.ts` entries point at constant names, not
  step params). `tests/cross-mode-mirror-coverage.test.tsx` updated.
- SHA-256 drops `K-to-aux`, `H-to-aux`, `H-constant`,
  `init-working-vars` (4 leaves).
- **Gate:** "abc" KAT byte-equal; constants editable + re-run; cross-ref
  both directions; no constant-loader leaves in spec.

**A2 — Container port contract.**
- `seedInput` / `bodyOutput` optional `PortBinding` fields on `iterate`
  / `for-each-subgraph` / `for-each-subgraph-with-history`
  (`core/types.ts`); runtime resolves them in place of state I/O.
- `document-schema.ts` Zod extension; `schemaVersion` 2→3 (legacy specs
  leave fields undefined — additive migration).
- `inferHistorySeedEdges` retargets seed source to `seedInput`.
- **Gate:** FES contract test passes against both old (state) and new
  (port) seeding during the transition; toy fixture
  (`tests/runtime-for-each-subgraph-with-history.test.ts`) updated.

**A3 — SHA-256 spec cleanup.**
- Rewrite `sha-256.ts` to use `cipherConstants` (A1) + container ports
  (A2); delete all boundary / container / round-body bridges (~182
  leaves after A1's 4).
- Runtime owns cipher entry/exit bridging for the (still-existing-but-
  bytes-only) state at the boundary.
- **Gate:** "abc" KAT byte-equal; scrubber can't reproduce the smoke
  confusion (trace it explicitly per the smoke walkthrough); graph view
  shows the cleaned DAG; AES/Speck/Serpent/DES untouched.

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
2. **A3 round-group port boundary** — whether the 64 compression-round
   groups each declare port boundaries or the runtime auto-bridges at
   group entry/exit. Decide once A2's container contract is concrete.
3. **B4 / DES Feistel** — `FeistelRoundGroup`'s branching contract under
   ports is the least-explored container; coordinate with the
   universal-port plan's Phase 4d before B4.
4. **C2 frame-shape persistence** — whether retiring
   `stateBefore`/`stateAfter` forces a document `schemaVersion` bump for
   session-on exports. Measure at C2.
