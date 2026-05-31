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
| 5.3c | Migrate value/narration reads off `stateBefore`/`stateAfter` → frame ports: `edge-value-lookup` (endpoints + block-chips; isolate the toy-only rejoin), narration ×6, `StepStrip`, `RunExplorerModal`. | Sequenced |
| 5.3d | **Port-native Feistel/swap visualization rebuild** (the obligatory user-required follow-up). New DES-port-native viz reading `portInputs`/`portOutputs`. **Independent of 5.3e** (the old components are toy-only). | Sequenced |
| 5.3e | **Final removal.** Delete the old toy-only Feistel components (`RejoinFrameView`/`FeistelTrackContext`/`FeistelMiniDiagram`) + toy + feistel runtime walk + `FeistelRoundGroup`/`BranchTrack`/`CombineKind`; delete `stateBefore`/`stateAfter`, `inferStateEdges`, `dropAuxOnlyStateEdges`, `BytesView`, the legacy `port-projection` bridge; collapse `BytesState`/`State`/`StateShape`. Strictly after 5.3b + 5.3c. **Risk:** `inferStateEdges`'s empty-group-as-node case (graph.ts:1063-1071 — a cleared round in the editor) has no port-flow analogue → re-implement or accept as editor-only regression. | Sequenced |
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

## Verification (for 5.1+)

`npm run check` (`tsc` is the load-bearing gate — narrowing a union
surfaces every unhandled `switch` arm). 5.2 additionally pins
AES/Speck/Serpent/DES + ECB/CBC KATs byte-equal before and after. 5.1/5.3
warrant a browser smoke (MatrixView removal + inspector default change are
visual) per `feedback_visual_smoke_vs_property_tests`.
