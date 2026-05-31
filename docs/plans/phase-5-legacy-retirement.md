# Phase 5 — legacy retirement (dependency-ordered arc)

> **Status (2026-05-30): Slice 5.0 SHIPPED.** 5.1–5.3 sequenced below,
> not yet started. This is the universal-port-dataflow plan's **Phase 5**
> and the scaffolding-suppression plan's **Phase C**, unified here because
> the real arc is larger than either's 2-line sketch and feeds the
> Feistel-visualization rebuild that follows it. Source plans:
> `docs/plans/universal-port-dataflow.md` (Phase 5),
> `docs/plans/scaffolding-suppression.md` (Phase C).

## Why this exists

After Phase B (B1–B4 merged 2026-05-30) every shipped cipher/hash is
port-native and no shipped spec uses `feistel-round`. The written Phase 5
("delete `MatrixState`/`BitVecState`/`BigIntState`") reads as a quick pass,
but an audit showed the headline slice has an **unmet precondition** —
there are still live consumers. Phase 5 is dependency-ordered; the
state-type deletion is the *last* step, not the first.

## Verified facts that reorder the arc (2026-05-30 audit)

These de-risk `MatrixState` retirement substantially:

1. **The lifted AES key-expansion already emits plain bytes** to aux
   (`src/steps/key-expansion.ts:92–104`: 16-byte `Uint8Array` round keys;
   aux-only, passes `state` through). It is **not** a `MatrixState`
   producer → does **not** gate `MatrixState` deletion. The key-schedules
   gate `liftLegacyExecutor` removal + the BytesState passthrough (5.2/5.3).
2. **`MatrixState` is vestigial on the live path.** The inspector routes
   `isPortNativeFrame` frames to `PortFlowView`; `MatrixView` is only the
   fallback for legacy matrix-shaped frames, which post-B1 **only the
   deferred test fixtures** (`tests/fixtures/matrix-aes-192.ts`,
   `matrix-aes-ecb.ts`) still produce. Those fixtures' header says the old
   `generic.*` matrix primitives retire "at the same time" as the matrix
   machinery → they are **coupled to `MatrixState` retirement (5.1)**, not
   independently deletable.
3. **Persistence is additive.** `SessionSnapshot` (`src/core/document.ts`)
   stores selectors + input/key/IV bytes only — **no trace frames**. The
   trace is re-derived by re-running. Retiring state types / frame fields
   needs **no `schemaVersion` bump**. (5.0's `StateShapeSchema` enum
   narrowing is value-safe — no shipped spec ever produced
   `"bitvec"`/`"bigint"`.)

**Deliberate deviation from the written Phase 5:** the Feistel types
(`FeistelRoundGroup`/`BranchTrack`/`CombineKind`) + the `feistel.toy-add-k`
toy fixture **stay** through Phase 5. They are reserved for the next phase
(the port-native Feistel/swap visualization rebuild, an obligatory
user-required follow-up to B4). Advisor-confirmed.

## The arc

| Slice | What | Status |
|---|---|---|
| **5.0** | Underbrush: delete `BitVecState`/`BigIntState` + the dead `REPLICATION_THRESHOLD` alias + refresh stale `CLAUDE.md` stats. Zero crypto risk. | **DONE 2026-05-30** |
| **5.1** | Retire `MatrixState` (Phase C1-matrix): drain the test-only `generic.*` matrix primitives + the `sha2.*` monolithic steps, retarget/delete their MatrixView/projection tests, drive the 4×4 render off raw bytes, then delete the type. No crypto risk; broad UI surface. | **DONE 2026-05-30** |
| 5.2 | Convert the lifted key-schedules (`aes.key-expansion@1/@2`, `speck.key-schedule@1`, `serpent.key-expansion@1`, `des.key-schedule@1`) + the padding/aux primitives to true `PortedExecutor`s; drop their `legacy:` fields. **`liftLegacyExecutor` SURVIVES** as a bytes-only helper for `feistel.toy-add-k@1` (the reserved-through-Phase-5 toy — advisor verdict 2026-05-30: converting it would drop `legacy:` and flip the toy onto the PortFlowView capture path, doing the deferred Feistel-viz rebuild piecemeal). **Crypto KAT gates; own advisor pass** per `feedback_iterative_slice_review`. | **DONE 2026-05-31** |
| **5.3** | **Expanded into a dependency-ordered sub-arc (5.3a–e).** The one-liner ("retire `stateBefore`/`stateAfter` + `inferStateEdges` + `dropAuxOnlyStateEdges`; collapse `BytesState`; PortFlowView universal default") was **mis-ordered**: the field/edge removals depend on the reserved Feistel scaffolding AND the un-port-wired Speck/Serpent being gone first. End goal (Path C) unchanged. See sub-rows. | see 5.3a–e |
| **5.3a** | PortFlowView universal default + truth-up: formalize the `FrameStateView` default (BytesView = test-only-toy fallback), correct the stale S2(e) docstring, record this sub-arc + the BytesView-unreachable invariant test. No code-path change. | **DONE 2026-05-31** |
| 5.3b | Port-wire Speck + Serpent specs (declare explicit `portInputs` on round-body leaves) so `inferPortEdges` owns their spine + the S2(f) gate skips legacy inference for them. **Load-bearing spike FIRST:** declaring `portInputs` may flip the runtime from implicit state-thread to explicit port-resolution (runtime.ts:343-347) — diff the trace on ONE Speck round leaf to confirm KAT byte-equality before committing the approach; if not byte-equal, 5.3b becomes native Speck/Serpent decomposition. Arc size hinges on this. | **DONE 2026-05-31** |
| 5.3c | Migrate value/narration reads off `stateBefore`/`stateAfter` → frame ports: `edge-value-lookup` (endpoints + block-chips; isolate the toy-only rejoin), narration ×6, `StepStrip`, `RunExplorerModal`. | **DONE 2026-05-31** |
| 5.3d | **Port-native Feistel/swap visualization rebuild** (the obligatory user-required follow-up). New DES-port-native viz reading `portInputs`/`portOutputs`. **Independent of 5.3e** (the old components are toy-only). | **DONE 2026-05-31** |
| 5.3e | **Final removal.** Delete the old toy-only Feistel components (`RejoinFrameView`/`FeistelTrackContext`/`FeistelMiniDiagram`) + toy + feistel runtime walk + `FeistelRoundGroup`/`BranchTrack`/`CombineKind`; delete `stateBefore`/`stateAfter`, `inferStateEdges`, `dropAuxOnlyStateEdges`, `BytesView`, the legacy `port-projection` bridge; collapse `BytesState`/`State`/`StateShape`. Strictly after 5.3b + 5.3c. **Risk:** `inferStateEdges`'s empty-group-as-node case (graph.ts:1063-1071 — a cleared round in the editor) has no port-flow analogue → re-implement or accept as editor-only regression. | **Batches 1–3 DONE 2026-05-31** (`dd279be` + B2 + B3); Batch 4 sequenced |
| — | Feistel types + toy fixture: **no longer a separate "next phase"** — folded into 5.3d (rebuild) + 5.3e (delete). Order of 5.3d vs 5.3e is a judgment call (rebuild-as-reference first, or clean-slate then rebuild from git history), not a dependency. | folded into 5.3d/e |

## Slice 5.0 — what shipped

Deleted the two never-shipped State variants and dead bookkeeping. The
load-bearing distinction: the standalone **`bigint` in `AuxValue`**
(`types.ts`) is the block-count value (`compute-block-count`) and **stays**
— only the `BigIntState`/`BitVecState` *State variants*, the
`"bitvec"`/`"bigint"` *`StateShape`* enum members, and the
`switch (state.shape)` arms over them were removed.

- **`src/core/types.ts`** — `BitVecState`/`BigIntState` defs deleted; `State`
  union narrowed to `BytesState | MatrixState`; `StateShape` narrowed to
  `"bytes" | "matrix4x4-bytes"`; `LayoutTags` lost `bitLength` /
  `bigintEndian` / `bigintByteLength`.
- **`src/core/state/bitvec.ts`** — deleted (only export `cloneBitVec`,
  only consumer `clone.ts`); `clone.ts` lost the bitvec/bigint arms.
- **`src/core/port-projection.ts`** — removed the bitvec/bigint arms in
  `stateToBytes`/`bytesToState`, the `portBytesToState` relaxation, and the
  now-dead `readBitLength`/`readBigintEncoding` helpers.
- **`src/core/document-schema.ts`** — `StateShapeSchema` enum narrowed
  (value-safe, no schema bump).
- **`src/ui/components/GraphView.tsx`** — `formatStateOneline` bitvec/bigint
  arms removed (the plain `number | bigint` block-count branch kept);
  `StepPalette.tsx` `SHAPE_LABELS` + `StepStrip.tsx` comment trimmed.
- **`src/ui/stores/view-replication.ts`** — deleted the dead
  `REPLICATION_THRESHOLD` alias (no code consumer; only doc/CHANGELOG refs).
- **Tests** — removed the bitvec/bigint `switch` arms from the 6
  `runtime-ported-dispatch-*` `expectStatesEqual` helpers + `port-projection-q-gate-9`;
  deleted the two now-invalid `it` blocks in `port-projection-matrix-array-roundtrip`
  (+ trimmed the `BitVecState` import); dropped `"bitvec"`/`"bigint"` from the
  `state-shape-contracts` shape sets. `aux-primitives` +
  `runtime-ported-dispatch-serpent` untouched (plain-`bigint` AuxValue).
- **`CLAUDE.md`** — State-union description + test/build stats refreshed.

**Gate:** `npm run check` GREEN — biome clean, tsc passed, **2546 tests /
219 files** all passing, build OK. (Pre-commit hook is OFF in this env per
`feedback_precommit_hook_not_installed`; ran manually.)

## Slice 5.1 — what shipped (2026-05-30)

Retired `MatrixState` + the `matrix4x4-bytes` `StateShape`. `State` is now
`BytesState` only; `StateShape` is `"bytes"`.

- **Deleted 15 test-only step files** (registry imports + registrations
  removed): the 4 matrix AES round prims (`generic.byte-substitution@1` /
  `shift-rows@1` / `mix-columns@1` / `add-round-key@1`), the matrix multi-block
  boundary prims (`split-blocks@1` / `concat-blocks@1` / `compute-block-count@1`
  / `load-block@1` / `store-block@1`), the matrix chaining prims (`iv-load@1` /
  `xor-aux-into-state@1` / `state-to-aux@1` + `state-to-aux-bytes@1`), and the
  3 `sha2.*` monolithic helpers. **`compute-block-count`/`load`/`store-block`
  were the last `kind: "legacy"` registrations — no legacy-contract step
  remains.**
- **Render layer:** `MatrixView.tsx` deleted (it was only the legacy-matrix
  fallback; shipped port-native frames already route to `PortFlowView`).
  `TinyMatrix` props narrowed from `MatrixState` to raw `Uint8Array` (the live
  consumer is `RoundKeyPanel`, rendering round keys 4×4); `StepStrip` /
  `RunExplorerModal` gate the 4×4 thumbnail on a 16-byte state. `App.tsx`
  `FrameStateView` collapsed to `PortFlowView | BytesView` (`MixedShapeView` +
  the matrix branch deleted).
- **Core:** `port-projection.ts` lost the `matrix4x4-bytes` encode/decode arms
  (`bytesToState`/`stateToBytes`/`auxPortBytesToValue` `matrix-cm-4x4` +
  `matrix-cm-4x4-array`); `clone.ts` collapsed to `cloneBytes`; `matrix.ts`
  trimmed to `gfMul`/`xtime` (still used by the **shipped** port-native
  `gf-matrix-multiply@1`). The advisory `PortLayout "matrix-cm-4x4"` rendering
  tag SURVIVES — it's distinct from the deleted State variant.
- **Narration/provenance:** deleted `narration/aes.tsx` + `narration/boundary.tsx`
  + `provenance/aes.ts` (all keyed only to deleted step types); trimmed
  `narration/aux-primitives.tsx` to the 3 surviving byte-typed aux narrators;
  removed the 3 `sha2.*` entries from `NARRATION_NO_OP_ALLOWLIST` (8 entries now).
- **Tests:** deleted ~14 test files whose subject was a deleted step/view
  (chaining-primitives, load-store-block, state-to-aux-bytes, the 3 sha2-*,
  runtime-ported-dispatch-chaining, narration-aes/boundary, matrix-array-roundtrip,
  provenance-hover-integration, matrix-view, sha-256-decomposition-parity, the
  2 matrix-aes fixtures); retargeted the rest by the advisor's rule — **delete
  matrix `it`s, keep byte-native `it`s** (aux-graph-derivation, edge-value-lookup,
  q-gate-9, the drop/greying suites retargeted to `byte-substitute@1` /
  `feistel.toy-add-k@1` / synthetic byte specs).
- **Gate:** `npm run check` GREEN — **2348 tests / 205 files**, build 656.71 KB
  raw / 192.95 KB gzipped (down ~20 KB).

## Slice 5.2 — what shipped (2026-05-31)

Converted the lifted key-schedules + padding + aux primitives to true
`PortedExecutor`s (the **hybrid-ported** pattern: drop `legacy:`, **keep
`meta`**). The runtime still projects `aux[…] → masterKey`/state ports and
output ports → aux, so emitted frames stay byte-identical — the only new fact
is that `portInputs`/`portOutputs` now populate (runtime gate:
`registration.legacy === undefined`). Shipped in four batches:

- **Batch A** (`8beae14`, prior session) — `aes.key-expansion@1`/`@2`.
- **Batch B** (`f5e1f80`) — `speck.key-schedule@1`, `serpent.key-expansion@1`,
  `des.key-schedule@1`. Render delta: AES/Serpent/DES key-schedule frames stay
  intercepted by `KeyScheduleExplorer` (by stepType); **Speck reroutes to
  PortFlowView** (not in `isKeyExpansionStepType`). The Serpent sim-parity test
  was re-registered `kind:"ported"` flag-on; Speck/Serpent malformed-key
  rejection tests gained `portedDispatchEnabled:true` (flag-off now throws
  "requires portedDispatchEnabled" at the now-port-native schedule).
- **Batch C** (`d307656`) — the six padding step types
  (pkcs7/zero/iso7816-4 × pad/unpad). State-port pattern (`inputs.get("state")`
  → `outputs.set("state", …)`). **Load-bearing UX (advisor decision C1):**
  padding frames reroute BytesView → PortFlowView (input/output `state` port
  rows surface the length change), matching SHA-256's already-shipped
  `pad`/`length-append`. The App + PortFlowView dispatch comments were
  corrected — the port-capture gate is `legacy === undefined`, NOT
  `meta === undefined` (hybrid-ported frames capture ports). The padding
  dispatch test's flag-off parity was reduced to flag-on (B2/B3/B4 precedent);
  `app-padding-roundtrip.test.tsx` reads the PortFlowView port rows.
- **Batch D** (`9b4cd4c`) — the three aux primitives (`generic.aux-load@1` /
  `aux-xor@1` / `aux-copy@1`). Executors simplified (fixed port names, no
  `ctx.aux`); the **graceful missing-aux** semantics survive as a runtime
  behavior (absent port omitted + `frame.auxReadMissing` from `meta`).
  `aux-copy`'s output layout `preserve-input-variant → raw` (its only purpose
  was MatrixState round-tripping, gone since 5.1), and `generic.aux-copy@1`
  was removed from `NON_BYTES_ALLOWLIST` (now **empty** — no shipped ported
  leaf declares a non-bytes port).

**`liftLegacyExecutor` SURVIVES** with its sole caller now `feistel.toy-add-k@1`
(verified by grep). **Crypto gate:** `npm run check` GREEN at each batch —
2340 tests / 205 files (−8 from 5.1's 2348: vacuous flag-off parity + dead
executor-level assertions removed); AES-128/192/256 + ECB/CBC + Speck + Serpent
+ DES KATs all byte-equal. **Advisor pass DONE** this session (was deferred in
the prior handoff). **Unpad browser smoke DONE** (the advisor's hard gate — the
novel length-*decrease* with zero PortFlowView precedent): a throwaway
Playwright run drove PKCS#7 encrypt→decrypt, scrubbed to the `pkcs7-unpad`
frame, and screenshotted it — it renders as input `STATE (16 bytes)` over
output `STATE (5 bytes)`, the per-row byte-count labels + the visible 0x0b
padding run making the strip read as an obvious "11 bytes dropped." **C1
confirmed empirically; the PortFlowView length-delta affordance stays future
polish.** Optional remaining glances (not blocking — ordinary multi-port
PortFlowView shapes with SHA-256 precedent): a Speck key-schedule frame (22
round-key output rows) + an aux-primitive frame.

## Slice 5.3a — what shipped (2026-05-31)

First slice of the 5.3 sub-arc. **Formalized `PortFlowView` as the universal
inspector default** — no runtime code-path change, since it was already
de-facto true for every selectable cipher.

- **`App.tsx::FrameStateView`** — reframed the dispatch comment: `PortFlowView`
  is the intentional universal default. Every user-selectable cipher/hash is
  port-native (every leaf's registration has `legacy === undefined`, the
  `runtime.ts:767` port-capture gate), so every selectable frame lands there;
  `BytesView` is reachable ONLY by the lifted-legacy `feistel.toy-add-k@1`
  (test-only, injected via `__setSpecForTests`, never in the selector).
- **`tests/requires-ported-dispatch.test.ts`** — new describe block reusing the
  `shippedSpecs` enumeration: asserts every leaf of every shipped spec is
  port-native (`kind:"ported"`, `legacy === undefined`) → no selectable cipher
  reaches `BytesView`; plus a positive control that the toy IS lifted-legacy
  (so the invariant has teeth).
- **`graph.ts` (`inferPortEdges` docstring)** — truthed-up the stale S2(e)
  note: AES/DES are now port-wired (spine from `inferPortEdges`), but
  Speck/Serpent are NOT (monolithic hybrid-ported, no spec `portInputs`), so
  `inferStateEdges` remains the sole source of their spine — retiring it (5.3e)
  needs 5.3b first.

**Gate:** `npm run check` GREEN; browser-smoked AES round + Speck key-schedule
→ `PortFlowView`, and the graph spine for Speck/Serpent (`inferStateEdges`
retained) + SHA-256 (port-flow). No KAT or `schemaVersion` change.

## Slice 5.3b — what shipped (2026-05-31)

**Port-wired Speck + Serpent.** Every round-body leaf now declares an explicit
`portInputs.state`, so `inferPortEdges` owns their graph spine and the S2(f)
gate suppresses the legacy `inferStateEdges` consecutive-siblings inference for
them. With this, **no shipped spec's spine comes from `inferStateEdges`** —
its removal (5.3e) is unblocked. Shipped in two batches (Speck `70dd34d`, then
Serpent).

**The load-bearing spike resolved GREEN — byte-equality holds, no native
decomposition needed.** The risk: Speck/Serpent round leaves are *hybrid-ported*
(`meta` present, `legacy === undefined`), and declaring `portInputs.state` makes
the runtime resolve the carried block from `nodeOutputs` (Step A, runtime.ts:589)
and SKIP the `meta.stateInputPort` projection (Step B, runtime.ts:610). For
`stateLayout: "bytes"` that override is byte-identical to the projection it
replaces (the projection is the identity over the predecessor's recorded output
bytes), and the data still rides the shared threaded `state` (runtime.ts:145/806)
— so traces stay byte-equal. Confirmed empirically against the existing golden
frame-stream suites (Speck's per-frame `stateAfter` + 23-frame guard; Serpent's
per-spec SHA-256 checksum over `(stepId, hex(stateAfter), sorted(auxRead))` +
frame count, all 6 specs).

- **Speck** (`speck-32-64-builder.ts`): flat pipeline — `round.1 ← $input`,
  `round.N ← round.{N-1}.state`. Spine = 22 `port-flow` edges, `$input → round.1`
  the honest head (the `key-schedule → round.1` passthrough phantom is gone).
- **Serpent** (`serpent-round-builder.ts`): nested round groups, so each leaf
  gets `portInputs.state` AND each round group declares `seedInput`/`bodyOutput`
  — exactly mirroring byte-native AES. The advisor flagged that "group
  `seedInput`/`bodyOutput` over *meta-bearing* leaves" was proven by neither
  native-AES (no meta) nor flat-Speck (no groups); it proved byte-equal because
  the injected seed *is* the threaded state byte-for-byte (round.1's seed = IP's
  `stateAfter`; round.N's seed = round.{N-1}'s `bodyOutput`). Spine = 98
  `port-flow` edges, of which **32 are container-sourced** (`round.{n-1}`
  container → next round's first leaf via single-hop `seedInput` resolution,
  plus `round.32 → FP`) — structurally unlike Speck's flat leaf-to-leaf chain.
  The descending decrypt `seedInput = port("inv-round.{r+1}","out")` was the
  most error-prone line; wired encrypt-first (3 checksums green) then decrypt.
- **`roundKey` ports stay UNWIRED** for both — they keep flowing from
  `aux[roundKeyAux]` via the meta projection (Step C), preserving the
  key-schedule→round aux fan-out edges in `frame.auxRead`.
- **Tests:** `aux-graph-derivation` (Speck/Serpent node + spine assertions
  rewritten for the `$input` node + port-flow-owned spine, registry passed);
  `graph-bundle` (Serpent retargeted off "legacy clean state-spine" → port-flow
  singletons); new `(e)` suite in `runtime-ported-dispatch-speck` pinning auxRead
  preservation + the declared wiring on the shipped spec.

**Gate:** `npm run check` GREEN (2368 tests / 205 files; bundle 657 KB raw /
192.9 KB gzipped). Browser-smoked the Speck + Serpent graph view: the `$input`
"plaintext" pill materializes and connects to round.1 / `initial-permutation`,
key-schedule/key-expansion sit off-spine (aux-only). No KAT or `schemaVersion`
change. **NEXT: 5.3c** (migrate value/narration reads off `stateBefore`/
`stateAfter` → frame ports).

## Slice 5.3c — what shipped (2026-05-31)

Migrated every **non-toy** read of `stateBefore`/`stateAfter` onto the port
I/O, so 5.3e can delete the fields with only the isolated toy-rejoin branch
(deleted with the toy) still touching them. Shipped in three batches
(`29c1efa`/`e19252e` narrators+components, `e6a2f9b` edge-value-lookup,
`a1d2489` runtime+endpoints).

- **New `src/core/frame-state.ts`** — `frameStateInBytes` / `frameStateOutBytes`
  read the conventional `"state"` port first, falling back to the field until
  5.3e. Generalizes the private B4 copy DES shipped in `narration/des.tsx`.
  **NOT uniformly byte-identical — characterized by a corpus test
  (`trace-initial-state.test.ts`), advisor-driven:**
  - **Byte-identical** for (a) hybrid-ported leaves — the runtime reconstructs
    `stateAfter` FROM `portOutputs.get("state")`, so port == field (Speck,
    Serpent, padding, AES key-schedule); and (b) pure-port-native leaves with
    NO `"state"` port — the helper falls back to the field (SHA-256, native-AES
    `xor@1`/`byte-substitute@1` whose ports are `output`/`input`/`a`/…).
  - **Partial, incidental de-staling for DES.** Its F-leaves (IP/FP/expand-R/
    xor-with-K/s-boxes/p-permutation — 66 of 115 frames) are pure-port-native
    BUT name their output port `"state"`, and the runtime never reconstructs
    the threaded state from it → `stateAfter` is the STALE plaintext while the
    port carries the honest per-leaf value. The helper reads the honest port
    for those (the B4 de-staling `des.tsx` already relied on, now reaching the
    step strip + inspector). DES's generic steps in the same round —
    `split-bytes` (output0/1), chaining `xor` (output), `concat` (output),
    `key-schedule` (keyN) — have no `"state"` port, so they STILL show the
    stale field. So a DES round renders MIXED. Strictly better on the F-leaves,
    no worse on the rest; visually confirmed clean (DES re-smoke below).
- **Narration** (speck/serpent/padding migrated to the shared helper; des
  consolidated off its private copy; **coerce** migrated to read the
  `__coerce__` frame's new port I/O keyed by `params.portName`). Rejoin
  (`combine-kinds.tsx`) left isolated — toy-only, deleted in 5.3e.
- **`StepStrip` + `RunExplorerModal`** thumbnails/tiles read `frameStateOutBytes`.
- **`edge-value-lookup`** — block-chips + `lookupRegularState` spine
  (producer/consumer) + `lookupNodeValue` regular-leaf migrated; the
  `REJOIN_STEP_TYPE` branch ISOLATED (kept its direct `stateAfter` reads,
  toy-gated, deleted in 5.3e). `lookupPassthroughBytes` reads `params` only —
  already field-free.
- **`Trace.initialState: State`** (additive, runtime-only, NOT persisted → no
  `schemaVersion` bump). The endpoint INPUT pill / input-end edge resolve to it
  instead of `frames[0].stateBefore` — the only read the naive port-swap
  couldn't cover (SHA-256's first frame has no `"state"` input port; it's a
  constant-load). 17 `Trace`-literal constructors across 11 test files +
  GraphView's empty-trace fallback gained the now-required field.
- **The `__coerce__` frame** now carries `portInputs`/`portOutputs` (keyed by
  the coerced `portName`); it survives 5.3e (universal coercion mechanism, not
  toy scaffolding), so its narrator had to go field-free. Side effect: the
  frame now routes to `PortFlowView` via `isPortNativeFrame` — harmless
  (flag-on-only, never shipped).
- **`provenance/serpent.ts`** (the plan-enumeration gap — advisor item 4):
  2 bounds-guard `stateAfter` reads, registered but **unreachable** (Serpent
  renders via `PortFlowView`, which has no provenance overlay; the
  `BytesView`+provenance overlay is toy-only). Folded the 2-line port-first
  migration into 5.3c rather than spin a slice — deferring would leave the
  fields un-deletable. `App.tsx` (3 live reads) + `BytesView` +
  `FeistelTrackContext` + `RejoinFrameView` reads are all toy-only-reachable
  (BytesView is toy-only) → deleted with `BytesView` in 5.3e; no 5.3c action.
- **Deferred (one unified concern):** the cipher-agnostic surfaces (step strip,
  value inspector) only know the `"state"` port convention, so any leaf whose
  honest bytes live on a differently-named port shows the stale threaded field
  instead (→ null/"(no state)" once 5.3e removes the fallback): native-AES
  `xor`/`byte-substitute` (`output`/`input`), DES `split-bytes`/`xor`/`concat`
  (`output`/`output0/1`), SHA-256 primitives. This is byte-identical to the
  prior `stateAfter` read (not a 5.3c regression) and the same condition
  `narration/des.tsx` documents. The uniform fix — resolve each leaf's REAL
  output port by name — is the deferred **port-aware inspector** (same class as
  the block-chip port-value resolution, Slice 2.9c-e territory). 5.3c neither
  fixes nor worsens it; it incidentally de-stales the subset whose port is
  named `"state"` (the DES F-leaves).

**Gate:** `npm run check` GREEN each batch (2372 tests / 206 files; bundle 657
KB raw / 193 KB gz). New `tests/trace-initial-state.test.ts` pins
(1) `initialState`==input==`frames[0].stateBefore` + input-pill resolution for
SHA-256 (the load-bearing pure-port-native case) and AES-128 ECB, and (2) the
helper↔field relationship across the corpus: byte-identical on SHA-256 / AES /
Speck / Serpent, intentional-divergence on DES (helper reads the honest
`"state"` port, ≥1 frame genuinely diverges from the stale field). **Browser
smoke DONE** (throwaway specs, per `feedback_visual_smoke_vs_property_tests`):
(a) AES — input pill renders the plaintext via `trace.initialState`, step strip
+ value inspector render clean; (b) DES (the only diverging cipher — AES
structurally can't show it) — KAT correct, no page errors, and the step strip
renders the MIX cleanly (`key-schedule` shows stale `0123456789abcdef` next to
`initial-permutation` showing the honest de-staled `cc00ccfff0aaf0aa`),
variable-length port values fine.

**5.3e tracking — field-referencing code that 5.3e must delete/retarget:**
(i) the isolated `REJOIN_STEP_TYPE` branch in `edge-value-lookup` + the toy +
its Feistel UI; (ii) `trace-initial-state.test.ts`'s one
`initialState`==`frames[0].stateBefore` assertion (drop it; the
`initialState`==input assertion keeps correctness); (iii)
`runtime-ported-dispatch-coercion.test.ts` asserts `coerceFrame.stateBefore`/
`stateAfter` — retarget to the new `portInputs`/`portOutputs`; (iv) `App.tsx` +
`BytesView` + `FeistelTrackContext`/`RejoinFrameView` (deleted with BytesView);
(v) doc-comment references in `GraphView`/`provenance/*`/`step-id`/
`default-registry`/`bytes-to-state`/`pkcs7-pad`.

**NEXT: 5.3e** (final field/edge/BytesView/toy removal — unblocked by
5.3a+5.3b+5.3c; 5.3d is now done so the Feistel viz no longer depends on the toy
components 5.3e deletes).

## Slice 5.3d — what shipped (2026-05-31)

The obligatory port-native Feistel/swap visualization rebuild. When B4 made DES
port-native (each round a plain `group` of `split-bytes → …F… → xor → concat`),
the three `feistel-round`-keyed linear views went dark (they read `branchPath` /
the synthetic `:rejoin` frame). 5.3d rebuilds them **reading port I/O**, with
detection + structure **derived purely from the round group's wiring** (user
pick: no spec tag, zero schema change). The swap is read from the `recombine`
concat's argument order, so it stays correct across encrypt / decrypt / edits.

- **`src/core/feistel-shape.ts`** (NEW, pure) — `analyzeFeistelRound(group)`
  recognizes the split→F→xor→concat shape and returns the structural descriptor
  (split/fxor/recombine ids, F-stack, derived port names, `swap`, `roundKeyAux`);
  `findActiveFeistelRound(frame, spec)` walks `frame.path` for the round
  ancestor; `resolveFeistelRoundBytes(shape, frames, blockIndex)` reads
  L/R/F/L⊕F/new_L/new_R from the child frames' `portOutputs`/`portInputs`.
- **Three NEW components** (`src/ui/components/`), self-detecting, own CSS class
  names (`feistel-swap-diagram-*` / `feistel-round-bytes-*` / `feistel-recombine-*`,
  copied — NOT shared — from the old selectors so 5.3e can strip the old CSS):
  `FeistelSwapDiagram` (the abstract SVG; the swap CROSSING vs round-16 straight
  wires, click-leaf-to-scrub, active-leaf accent, K_i subscript),
  `FeistelRoundBytes` (round-level L/R/F/L⊕F/L'/R' byte rows), and
  `FeistelRecombineView` (additive panel on the `concat` frame labelling the swap).
- **Independent of 5.3e**: keyed off the new structural detection; the old
  `branchPath`/`REJOIN_STEP_TYPE` toy components + their App.tsx dispatch are
  untouched (5.3e deletes them). Mutually exclusive in practice (toy emits
  `branchPath`; port-native DES emits the split→concat shape).
- **Detection guard** — `findActiveFeistelRound` requires the active frame to be
  a leaf OF the detected round (every cipher names rounds `round.N`, so a
  transient spec/trace mismatch during a cipher switch could otherwise draw DES
  structure on an AES `round.N` frame; the composite browser look surfaced this).
- **Tests** (+26): `tests/feistel-shape.test.ts` (analyzer enc+dec swap pattern,
  null for AES/SHA/outer-`rounds`/broken-round/the mismatch guard,
  `resolveFeistelRoundBytes` KAT across all 16 DES rounds incl. the round-16
  `preFp` byte-order pin) + three jsdom component tests. **Browser-smoked**
  (throwaway Playwright): round-5 swap crossing + bytes, round-16 straight
  (no-swap), recombine inspector both modes, DES decrypt diagram, composite
  full-column look — byte values match FIPS 46-3. Gate GREEN (2402 tests / 210
  files). No schema change, no KAT change.
- **Out of scope**: graph view (B4's round-group render is user-confirmed good),
  scrubber track badges (N/A for port-native rounds).

## Slice 5.3e — in progress (Batches 1–3 shipped 2026-05-31)

The final removal, split into **4 batches** (the one-liner spanned the runtime,
types, graph, every UI surface, and the State-shape collapse — too broad for one
reviewable diff). Dependency order: Batch 1 (Feistel scaffolding + legacy bridge)
unblocks everything; Batch 2 (BytesView) needs the toy gone; Batch 3 (graph
state-edge inference) is independent of 2; Batch 4 (the irreversible
field/`State`-type collapse) lands last in its own commit.

**Batch 1 SHIPPED + pushed (`dd279be`)** — *retire Feistel branching scaffolding
+ legacy lift bridge*:

- **Runtime/types/core:** deleted `FeistelRoundGroup` / `BranchTrack` /
  `CombineKind` (`types.ts`) + `core/combine-kinds.ts`; `runFeistelRound`, the
  synthetic `:rejoin` frame, and the `branchPath` field + its threading
  (`runtime.ts`); the `:t…` / `:rejoin` / `:swap` stepId suffixes (`step-id.ts`
  regex narrowed to `/(?::b\d+|:r\d+)+$/`); the lifted-legacy projection bridge
  `liftLegacyExecutor` / `project` / `reconstruct` / `Projection` / `PortedFrame`
  (`port-projection.ts` / `types.ts`).
- **The toy** (`feistel.toy-add-k@1` — the last `legacy`-bearing step): fixture
  `feistel-toy.ts`, step file, registration, and narration entry all deleted;
  `NARRATION_NO_OP_ALLOWLIST` 8 → 7.
- **UI:** old toy-only linear components (`RejoinFrameView` /
  `FeistelTrackContext` / `FeistelMiniDiagram`) + App dispatch + StepList
  `FeistelRow` / `FeistelTrackRow`; all `feistel-round` graph handling
  (`kind:"feistel"` containers, `synthetic` rejoin/passthrough nodes,
  `processFeistelRound`, `feistelPassthroughId`, `rejoinSwapSourceXSign`, the
  per-track drop gutters + `into-track-start` + `prependChildToTrack` +
  `StepLocation.trackIdx`); the dead `.feistel-*` / `.rejoin-*` / track-badge CSS
  (≈440 lines).
- **Document schema:** the `feistel-round` Zod node was **unreleased** (DES went
  port-native before any cipher carried it into a saved doc — last tag v0.5.0,
  DES + `feistel-round` all under `[Unreleased]`), so it was **clean-deleted**:
  a `feistel-round` document now *rejects at parse* rather than silently skipping
  a node kind the runtime no longer walks.
- **Kept:** the 5.3d port-native Feistel/swap viz (`feistel-shape.ts` + the three
  self-detecting components, keyed off wiring — untouched); the `kind:"legacy"`
  registration variant + runtime legacy-dispatch path (registry still normalizes
  bare-executor registrations); `ProjectionMetadata` / `meta` (hybrid-ported
  key-schedules / padding / aux still project through it).
- **Coverage preserved:** coercion + coerce-badge tests retargeted onto a
  hybrid-ported (`meta`, no `legacy`) no-op so the live coercion mechanism keeps
  coverage; the container-output-port wiring test retargeted to a `not@1` leaf
  via group `seedInput` / `bodyOutput`. ~16 pure-Feistel/toy test files + the
  now-vacuous dual-flag frame-parity matrix removed.
- **Gate:** `npm run check` GREEN — biome clean, tsc 0 errors, **2265 tests /
  193 files** (from 2402 / 210), build **628.20 KB raw / 185.68 KB gz** (≈28 KB
  raw lighter). No KAT or `schemaVersion` change.

**Batch 2 SHIPPED + pushed (2026-05-31)** — *retire `BytesView`*:

- **Deleted** the `BytesView` component (`src/ui/components/BytesView.tsx`) + its
  test (`tests/bytes-view.test.tsx`). With the toy gone (Batch 1) it had no
  consumer — it had been the test-only-toy fallback ever since Slice 5.1 routed
  every shipped frame to `PortFlowView`.
- **`App.tsx::FrameStateView`** collapsed from the `isPortNativeFrame`
  `Show`/`BytesView`-fallback to an unconditional `<PortFlowView>`; dropped the
  `previousRunFrame` prop, the `before`/`after`/`prevAfter` accessors, and the
  `BytesView` + `isPortNativeFrame` imports. `isPortNativeFrame` survives
  (exported from `PortFlowView` — now an informational/contract predicate, no
  longer a render-dispatch gate).
- **CSS:** deleted the BytesView-exclusive rules (`.bytes-view`, `.bytes-row*`,
  `.bytes-block-*`, and the `.bytes-cell.changed`/`.diff-vs-prev`/
  `.bytes-cell-missing` highlight modifiers). **Kept the bare `.bytes-cell`** —
  shared by `PortFlowView` (port rows) + `StepStrip` (thumbnails), both of which
  render plain cells with no highlight modifiers.
- **The inline "compare to previous run" checkbox** (linear frame header) was
  removed too: its only renderer was `BytesView`'s `previousAfter` row, so it had
  been a no-op for every shipped cipher since 5.1 — left visible it would toggle a
  signal nothing renders. Removed the `previousRunFrame` memo + `showPrev` +
  `canCompare` + the `.compare-toggle`/`.compare-count` CSS; `history` +
  `historyCount` STAY (they feed the live Run Explorer "compare runs (N)" button).
  Cross-run diffing still lives in the Run Explorer modal.
- **Two subsystems left DORMANT, not deleted** (advisor verdict — they're
  symmetric with each other and reusable; rolled into one follow-up flag):
  (1) the cell-level **provenance overlay** — `lookupProvenance` /
  `setProvenanceHover` lose their only caller (BytesView) and RoundKeyPanel's
  aux-cell hover reader now always reads null, but the `des.ts`/`serpent.ts`
  output-byte→input-byte maps are the exact consumer for the enqueued
  **port-aware inspector (Slice 2.9c–e)**; (2) the **`history.ts` prev-run toggle
  exports** (`useShowPreviousRun` / `setShowPreviousRun` /
  `findPreviousRunFrameByStepId`) — uncalled but reusable for a future port-level
  prev-run diff. Both are *invisible* dead code (no UI artifact), unlike the
  visible checkbox; leaving them dormant is lowest-regret, and deleting one store
  but not the other inside a "delete BytesView" commit is the inconsistency a
  reviewer flags.
- **Live-code comments** naming `BytesView` as part of the dispatch were
  truthed-up (`PortFlowView` docstring + `isPortNativeFrame` doc, the `runtime.ts`
  coerce-frame comment, `pkcs7-pad.ts`, `default-registry.ts`, `StepStrip.tsx`).
  Comments inside the dormant `provenance/` subsystem were left (they retire with
  that subsystem).
- **No fresh browser smoke** — the graph-view smoke done in Batch 1 (`f6dfd7b`)
  covered the structural deletion; B2 deletes only `BytesView` markup + its
  exclusive CSS, whose selectors target no surviving surface (advisor-confirmed:
  same category as a markup+CSS deletion, jsdom-invisible but provably safe).
- **Gate:** `npm run check` GREEN — biome clean, tsc 0 errors, **2257 tests / 192
  files** (−8 / −1 = the deleted BytesView test), build **623.46 KB raw / 183.90
  KB gz** (≈4.7 KB raw lighter). No KAT or `schemaVersion` change.

**Batch 3 SHIPPED (2026-05-31)** — *retire graph state-edge inference*:

- **`graph.ts`:** deleted `inferStateEdges` (the legacy consecutive-siblings
  state-thread inference + its local helpers `emitChain` / `processScope` /
  `firstSpineId` / `lastSpineId` / `hasSpineContent` / `collectIterates` /
  `collectSkips` / the S2(f) `skipStateEdgeTo` gate) and `dropAuxOnlyStateEdges`
  (the aux-only-root spine-edge suppressor) — 390 lines. `deriveAuxGraph` no
  longer calls either; the spine is composed **entirely** by `inferPortEdges`
  (`portFlowEdges`). `opts.registry` is now unread there but retained on the
  signature for caller compat (~110 callsites). `STATE_AUX_KEY` (endpoint pills)
  + `PORT_FLOW_AUX_KEY` survive; ~10 doc-comments naming the deleted functions
  truthed-up.
- **`GraphView.tsx`:** dropped the `dropAuxOnlyStateEdges` import + the
  `auxOnlyFilteredGraph` memo (collapsed → `replicatedGraph` consumes
  `expandedGraph()` directly) + the now-dead `auxOnlyRootSinkIds` memo.
  **`auxOnlyRootIds` SURVIVES** — it still drives the layout-lift of aux-only
  roots off the spine row in `layoutRoot`.
- **The discriminator that made deleting the filter safe (advisor's #1):**
  every shipped spec wires its first consumer to `$input` (`seedInput`/
  `portInputs.state` = `port($input,…)`) → `specReferencesInputSource` is true
  for all → the legacy `CIPHER_INPUT_ID` pill never injects → the only surviving
  `kind:"state"+auxKey:"state"` edge is the OUTPUT pill (last step → output,
  never an aux-only root). So `dropAuxOnlyStateEdges` was **already a pure no-op
  for every shipped spec**; deletion is unconditionally safe. Probe-confirmed:
  AES-128 spine = 40 edges, ALL port-flow, legacy=0; SHA-256 legacy=0
  (pf=3245); DES legacy=0.
- **Accepted regression:** the empty-group-as-node spine (a cleared round in the
  editor staying connected via its own id) died with `inferStateEdges` —
  `inferPortEdges` has no analogue. User-accepted per the 5.3e risk note.
- **Tests:** deleted `drop-aux-only-state-edges-asymmetric.test.ts` (whole file —
  its subject is the deleted function) + the `replicate-fanout` "dropAuxOnly
  composes with replication" describe block (196 lines) + the 2 empty-group +
  2 non-ported-backward-compat tests (`aux-graph-derivation` /
  `graph-port-edge-derivation`) + the `legacyTwoLeafSpec`/`removeStep` they used.
  **Six tests written against the pre-deletion DUPLICATE spine** (legacy +
  port-flow coexisted) were fixed: 3 whose premise was "AES key-expansion has a
  state-out" (the legacy identity passthrough — DELETED, invariant survives in
  synthetic-graph cases + SHA-256 split-wv S2(i)); 3 RETARGETED to port-flow
  reality — the SHA-256 history-seed replica count `5→4` (length-append's only
  out-edges are now the 4 aux history-seed arrows, no spine replica), and the
  two `collapseGraph` round.5 tests' cross-boundary endpoints from leaf-to-leaf
  (`round.4.add-round-key → round.5`) to **container-sourced** (`round.4 →
  round.5`), matching the port-flow round→round handoff. `graph-bundle`'s
  singleton-bundle invariant retargeted from key-expansion to SHA-256 split-wv
  (8 `[port-flow]` singletons).
- **Gate:** `npm run check` GREEN — biome clean, tsc 0 errors, **2242 tests /
  191 files** (−15 / −1 vs B2), build **621.89 KB raw / 183.46 KB gz** (≈1.6 KB
  lighter). No KAT or `schemaVersion` change. **Browser-smoked the gating
  visual** (advisor's hard gate — the one place deletion changed visible
  structure beyond removing a duplicate): SHA-256 graph view shows
  `$input → pad → length-append` (white port-flow spine) then a light-blue
  history-seed arrow `length-append → Message schedule W_0..W_63` — msg-schedule
  reads cleanly connected, NOT stranded (the legacy spine arrow was a redundant
  duplicate of the always-rendered history-seed arrow). AES proven by the probe.

**Batch 4 (sequenced, next session):**
- **Batch 4 — field + `State`-type collapse (irreversible, own commit).** Delete
  `stateBefore` / `stateAfter` from `TraceFrame` + the runtime construction
  (incl. `coerceFrame`); `frame-state.ts` returns null on the field fallback
  (AES / SHA-256 step strip shows "(no state)" — **user-accepted** at Batch-1
  planning); collapse `State` / `StateShape` / `BytesState` to the bytes floor
  (`State` survives as the runtime-internal thread type). Retarget
  `runtime-ported-dispatch-coercion` (stateBefore/After → ports) + drop
  `trace-initial-state`'s one `frames[0].stateBefore` assertion. KAT gate +
  browser smoke.

## Verification (for 5.1+)

`npm run check` (`tsc` is the load-bearing gate — narrowing a union
surfaces every unhandled `switch` arm). 5.2 additionally pins
AES/Speck/Serpent/DES + ECB/CBC KATs byte-equal before and after. 5.1/5.3
warrant a browser smoke (MatrixView removal + inspector default change are
visual) per `feedback_visual_smoke_vs_property_tests`.
