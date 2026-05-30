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
| 5.2 | Convert the lifted key-schedules (`aes.key-expansion@1/@2`, `speck.key-schedule@1`, `serpent.key-expansion@1`, `des.key-schedule@1`) + the padding/aux primitives to true `PortedExecutor`s; drop their `legacy:` fields. **`liftLegacyExecutor` SURVIVES** as a bytes-only helper for `feistel.toy-add-k@1` (the reserved-through-Phase-5 toy — advisor verdict 2026-05-30: converting it would drop `legacy:` and flip the toy onto the PortFlowView capture path, doing the deferred Feistel-viz rebuild piecemeal). **Crypto KAT gates; own advisor pass** per `feedback_iterative_slice_review`. | Sequenced |
| 5.3 | Phase C2: retire `TraceFrame.stateBefore`/`stateAfter` + `inferStateEdges` + `dropAuxOnlyStateEdges`; collapse the residual `BytesState`; `PortFlowView` becomes the universal inspector default. | Sequenced |
| — | Feistel types + toy fixture: reserved for the **next phase** (port-native Feistel/swap viz rebuild). | Deferred |

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

## Verification (for 5.1+)

`npm run check` (`tsc` is the load-bearing gate — narrowing a union
surfaces every unhandled `switch` arm). 5.2 additionally pins
AES/Speck/Serpent/DES + ECB/CBC KATs byte-equal before and after. 5.1/5.3
warrant a browser smoke (MatrixView removal + inspector default change are
visual) per `feedback_visual_smoke_vs_property_tests`.
