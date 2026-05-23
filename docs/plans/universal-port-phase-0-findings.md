# Universal port-based dataflow — Phase 0 findings

> **Status: Phase 0 GREEN — proceed to Phase 1.** All nine gate items
> validated (caveats on item 9 documented below); the migration's load-
> bearing claim is empirically supported on real AES-128 + AES-128 ECB
> traces under runtime dual-dispatch. No surprises forced a re-plan.
>
> **Date:** 2026-05-23.
> **Plan:** [`docs/plans/universal-port-dataflow.md`](./universal-port-dataflow.md)
> **Memory:** `project_universal_port_dataflow_proposal.md`

## TL;DR

The premise *"every TraceFrame is one projection of unified per-port byte
arrays; the legacy state/aux split is lossless against (PortedFrame,
LayoutTags)"* holds byte-by-byte across the three target shapes (pure
state-only, aux-reading, iterate-body) AND survives a real runtime walk —
not just synthetic-fixture round-trips. Phase 1 (adapter for every shipped
step + dual-dispatch widened to all step types + `narrationOverride` field)
is on solid ground.

The two structural design decisions taken inside Phase 0 — **side-map
projection-metadata registry** (not a `StepDefinition` field) and
**`portedDispatchEnabled` flag on `RuntimeInput`** (not a module global) —
worked exactly as the advisor consult sketched. Neither needs revisiting
for Phase 1.

## Nine gate items, walked

| # | Gate item | Status | Evidence |
|---|---|---|---|
| 1 | Linear view shows byte-identical frames for all three step types | **GREEN** (by frame-equality, item 8) | Every layer above the runtime reads `TraceFrame`. Frame-by-frame byte equality (item 8) implies linear view parity without UI surface changes. |
| 2 | MatrixView highlights (diff-vs-prev, source/destination overlay) still work | **GREEN** (by frame-equality) | Same logic — MatrixView reads `frame.stateBefore` / `frame.stateAfter`. Byte-equal frames means byte-equal highlights. |
| 3 | Provenance overlay still lights up source cells on hover | **GREEN** (by frame-equality) | Provenance overlay reads `frame.params` + `frame.stateBefore`. Both preserved exactly. |
| 4 | Step narration still fires correctly (including round-key narration for `add-round-key`) | **GREEN** (by frame-equality) | Narration reads `frame.params` + `frame.auxRead`. The ported path builds `auxRead` from metadata bindings; for `META_ADD_ROUND_KEY` it produces `Map([[params.auxName, <bytes>]])` byte-identical to the legacy executor's `result.auxReads`. Confirmed by the frame-parity test's `expectAuxMapsEqual`. |
| 5 | Graph derivation produces byte-identical edges before/after | **GREEN** (by frame-equality) | `core/graph.ts::deriveAuxGraph` reads `frame.auxRead` + `frame.auxWritten` to build edges. Both are byte-identical between paths. |
| 6 | `:b{i}` stepId suffix and `blockIndex` stamp preserved on iterate body frame | **GREEN** (direct assertion) | `tests/runtime-ported-dispatch.test.ts` "preserves :b{i} stepId suffix + blockIndex on ported iterate-body frames" — samples a byte-substitution frame from each of 4 ECB iterations, asserts `stepId.endsWith(":b{i}")` AND `blockIndex === i`. |
| 7 | Mirror registry buttons still render for ported steps (e.g., SubBytes inverse-mirror) | **GREEN** (by frame-equality) | Mirror registry (`src/ui/components/cross-mode-mirror-registry.ts`) keys on `stepType` + `params`; both unchanged. The button surface lives in the spec layer, not the runtime, so dispatch path doesn't reach it. |
| 8 | Full test suite still passes | **GREEN** | `npm run check`: biome ci + tsc + **1618/1618** vitest tests + vite build all pass. (Suite grew by 6: the new `runtime-ported-dispatch.test.ts`.) Legacy callers default to `portedDispatchEnabled !== true` so existing call sites are byte-equivalent to pre-Phase-0. |
| 9 | **Q-gate-9** — `deepEqual(reconstruct(project(legacyFrame), tags), legacyFrame)` byte-by-byte for all three lifted frames | **GREEN** (with structuredClone barrier) | `tests/port-projection-q-gate-9.test.ts` — 4 assertions covering pure state-only, aux-reading, and both shapes inside the ECB iterate (`blockIndex: 0`, `:b0` suffix). Tags are routed through `structuredClone(tags)` before `reconstruct` (advisor item 2, 2026-05-23) so anti-trivial discipline is enforced at runtime in addition to the type level. |

## The `outBlocksAux` caveat

> **This subsection is load-bearing — do NOT collapse it into item 9.**

The plan's Phase 0 gate description for the iterate-body case promises:
*"validates `:b0` suffix, `blockIndex` stamping, AND `aux[outBlocksAux]`
population."* Q-gate-9 directly covers the first two at frame level. The
third **cannot** be checked at frame level, by construction:

`aux[outBlocksAux]` is written by the **runtime's iterate machinery** as a
side-effect at iteration exit (see `runtime.ts::walk` inside the
`node.kind === "iterate"` branch — `aux.set(node.outBlocksAux, outBlocks)`
after the per-iteration loop). It is NOT written by any leaf executor's
`result.auxWrites`; therefore it does NOT appear in any
`TraceFrame.auxWritten`. A frame-level round-trip cannot validate
something that doesn't live on a frame.

**How it's verified anyway:** at the cipher boundary. The AES-128 ECB
KAT test (`runtime-ported-dispatch.test.ts` → "produces the published
4-block ciphertext under portedDispatchEnabled: true") asserts that the
4-block ciphertext matches NIST SP 800-38A §F.1.1 exactly. The ECB spec
reads `aux[outBlocksAux]` (specifically `"output-blocks"`) inside the
post-iterate `concat-blocks` step to assemble the final BytesState
ciphertext. So if the iterate's `outBlocksAux` publication didn't
populate correctly under ported dispatch — e.g., if a per-iteration
final state failed to round-trip back to `State` — the final ciphertext
would be wrong. It isn't. The verification is **at the integration
boundary, not at the frame round-trip**.

**Phase-1 implication.** When the iterate primitive itself is rebuilt
(Phase 1's for-each-subgraph node + Phase 2's first use in SHA-2),
this side-effect channel needs an explicit port-level model — likely an
output port on the for-each-subgraph node carrying the concatenated
per-iteration outputs. The Phase 0 finding here is that **the legacy
iterate's aux side-effect is not captured by the port projection**, and
that's expected: Phase 0 only lifts LEAF executors. The iterate runtime
itself remains legacy until Phase 1.

## Naming refinement adopted in Phase 0

The plan's contract sketch initially named the new contract
`StepShapeContract`. That identifier was already taken at
`src/core/types.ts:319` for the existing single-thread state-shape
contract (input/output `StateShape`, consumed by the palette chip,
drop-anchor greying, and `validateShapes`). The new contract was
**renamed to `PortContract`** so both can coexist during the migration.
Plan doc + memory both updated; no code references the old name.

## Design decisions taken inside Phase 0

These were intentional spike-time choices, validated by their working
outcomes. Carry forward into Phase 1 unless something forces revisiting.

### Side-map projection-metadata registry

**Decision:** `PROJECTION_METADATA: ReadonlyMap<stepType, ProjectionMetadata>`
lives at module scope in `src/core/port-projection.ts`. It is NOT an
optional `projectionMetadata?` field on `StepDefinition`.

**Why this worked:** projection metadata is the lift function's INPUT,
not a permanent registration field. Phase 1's eventual `StepRegistration`
discriminated union will hold `{executor: PortedExecutor, shape:
PortContract}` as the OUTPUT of lifting. Putting `projectionMetadata?`
on the legacy `StepDefinition` would have put it on the wrong end of
the pipe and forced two migrations (Phase 0 adds optional field → Phase
1 restructures). A throw-away side-map is cheaper to discard and
honestly signals "this is a spike."

**Phase 1 plan:** the side-map is **deleted**, not extended. Phase 1
replaces it with the discriminated-union registry.

### `portedDispatchEnabled` on `RuntimeInput`, not module global

**Decision:** per-call flag (`runSpec(spec, registry, { initialState,
initialAux, portedDispatchEnabled: true })`), defaulting to `false`.

**Why this worked:** task-6 tests stand legacy and ported runs side-by-
side in the same `it` block trivially (`runSpec(..., { ... })` and
`runSpec(..., { ..., portedDispatchEnabled: true })`). A module-level
singleton would have required either test isolation hooks (slow) or
forking the runtime export (uglier). Every shipped caller (UI, cipher
specs, ~1612 existing tests) ignores the new field; behavior is
byte-identical without opt-in.

**Phase 1 plan:** the flag stays. It becomes the kill switch as more
step types lift — flip subsets on incrementally; eventually the flag
defaults true; eventually (Phase 5) the legacy branch is removed and
the flag becomes a no-op.

### Aux flows dually in Phase 0

**Observation worth pinning:** during ported dispatch, aux flows BOTH
through the lifted executor's `ctx.aux` (which the legacy
`add-round-key` executor still reads via `ctx.aux.get(params.auxName)`)
AND through the runtime-built `inputs.get("key")` (which the ported
contract requires). By construction both paths see the same bytes — the
runtime puts them in `inputs` by reading from the same aux map.

**Why this is fine in Phase 0:** the test of "trace shape" is what
Phase 0 promised to validate, not "execution shape." The ported
executor's behavior is identical to legacy; what's new is that the
TraceFrame's `auxRead` is built from port projections (not from the
legacy `result.auxReads` field).

**Phase 1 plan:** cut the `ctx.aux` channel. Lifted executors read aux
ONLY through their input ports. The runtime stops populating `ctx.aux`
for ported steps. This is when "execution shape" actually unifies.

## Anti-trivial discipline (defense in depth)

Q-gate-9's GREEN status is evidence only if the projection genuinely
re-derives State variants from raw bytes + tags, not if it secretly
preserves the original State object. Two layers defend this:

1. **Type-level.** `LayoutTags` (in `core/types.ts`) declares no field
   that could carry a `State` object. `reconstruct` literally cannot
   read the original State variant from the sidecar at compile time.
2. **Runtime structural clone barrier.** Every Q-gate-9 assertion routes
   `tags` through `structuredClone(tags)` before passing to
   `reconstruct`. If a future refactor weakens the type to smuggle a
   State (e.g., a generic `extra?: unknown` field), structuredClone
   either fails (non-cloneable property) or strips the smuggled
   branding — the assertion's `expectFrameByteEqual` would catch the
   resulting drift. Node ≥17 (vitest's runtime target) supports
   structuredClone on `ReadonlyMap<string, string>` natively.

The two layers are independent: a hostile refactor would have to defeat
both before Q-gate-9 silently turned trivial.

## Surface areas changed

| File | Phase-0 role |
|---|---|
| `src/core/types.ts` | Added `PortShape`, `PortContract`, `PortLayout`, `StepInputs`, `StepOutputs`, `PortedExecutor`, `LayoutTags`, `PortedFrame`. None wired into the existing runtime; provisional contract for the migration. |
| `src/core/port-projection.ts` | NEW. `project` + `reconstruct` pure helpers; `liftLegacyExecutor` + `PROJECTION_METADATA` side-map; exported `stateToPortBytes` / `portBytesToState` for the runtime's use. |
| `src/core/runtime.ts` | Dual-dispatch added to `walk` leaf-handling. Legacy path unchanged when `portedDispatchEnabled !== true`. |
| `tests/port-projection-q-gate-9.test.ts` | NEW. 4 assertions; hardened with `structuredClone`. |
| `tests/runtime-ported-dispatch.test.ts` | NEW. 6 assertions (side-map sanity + FIPS-197 KAT + ECB KAT + frame parity × 2 cipher specs + suffix preservation). |
| `docs/plans/universal-port-dataflow.md` | Plan doc updated inside Phase 0 with progress notes and design picks. |
| `docs/plans/universal-port-phase-0-findings.md` | THIS DOC. |

No production UI code touched. No shipped spec touched. No registry
entry touched (legacy `default-registry.ts` exports the same step
types). Phase 0's surface is contained to additions in `core/` +
tests + docs.

## Bitvec and bigint — deferred to Phase 1

The plan's Phase-0 scope was explicitly bound to `matrix4x4-bytes` and
(by extension) `bytes` State variants. The two target step types use
matrix4x4-bytes; iterate boundary primitives (`split-blocks`,
`concat-blocks`) use bytes. `BitVecState` and `BigIntState` are
**TODO-marked in code** at:

- `src/core/port-projection.ts::stateToBytes` (bitvec arm copies bits;
  bigint arm throws with a "deferred to Phase 1" message).
- `src/core/port-projection.ts::bytesToState` (symmetric).
- `src/core/types.ts::LayoutTags` (the `bitLength` / `bigintEndian` /
  `bigintByteLength` fields are sketched but not exercised).

**Phase 1 forcing function:** SHA-2's word-array state (32-bit BE words
× 8) doesn't fit matrix4x4-bytes naturally; the first port-native cipher
will pick the canonical encoding rule. Bigint waits until RSA / elliptic-
curve work.

## Phase-1 entry checklist

All gates green; Phase 1 starts on user demand.

- [x] Q-gate-9 GREEN with anti-trivial discipline enforced.
- [x] Runtime dual-dispatch GREEN on real AES-128 + AES-128 ECB.
- [x] Full check (`npm run check`) GREEN — biome + tsc + 1618 tests + build.
- [x] Findings doc written + plan doc updated.
- [x] DES Phase 6e (manual browser smoke) shipped under legacy contract —
      completed 2026-05-22 across manual walks #1–#4 (M1–M7 checklist
      confirmed in `docs/plans/des-feistel.md`).

## Recommendation

**Proceed to Phase 1.** The widening of the lift to every shipped step
type is mechanical now that the contract and the dual-dispatch boundary
are validated. The first material design decision Phase 1 needs is the
`narrationOverride` field on spec nodes — the plan already settled the
shape; the rest of Phase 1 is enumeration.
