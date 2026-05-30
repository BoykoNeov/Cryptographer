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
| 5.1 | Retire `MatrixState` (Phase C1-matrix): drain the test-only `generic.*` matrix primitives + the `sha2.*` monolithic steps, retarget/delete their MatrixView/projection tests (`provenance-hover-integration`, `port-projection-q-gate-9`, `aux-graph-derivation`, the matrix-aes fixtures), drive the 4×4 render off an advisory layout tag, then delete the type. No crypto risk; broad UI surface. | Sequenced |
| 5.2 | Convert the 4 lifted key-schedules (`aes.key-expansion@1/@2`, `speck.key-schedule@1`, `serpent.key-expansion@1`, `des.key-schedule@1`) + the padding/aux/boundary/iv primitives to true `PortedExecutor`s; drop the `legacy:` fields + `liftLegacyExecutor`. **Crypto KAT gates; own advisor pass** per `feedback_iterative_slice_review`. | Sequenced |
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

## Verification (for 5.1+)

`npm run check` (`tsc` is the load-bearing gate — narrowing a union
surfaces every unhandled `switch` arm). 5.2 additionally pins
AES/Speck/Serpent/DES + ECB/CBC KATs byte-equal before and after. 5.1/5.3
warrant a browser smoke (MatrixView removal + inspector default change are
visual) per `feedback_visual_smoke_vs_property_tests`.
