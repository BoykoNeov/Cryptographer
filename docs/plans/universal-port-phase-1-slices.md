# Universal port-based dataflow — Phase 1 sub-slice plan

> **Status: APPROVED 2026-05-23.** Drafted after two advisor consults
> following the Phase 0 close. Phase 1 widens the universal-port contract
> from Phase 0's three target step types to **every shipped step**, cuts
> the dual `ctx.aux` channel, and adds the `narrationOverride?` field on
> `StepNode`. It does NOT introduce the for-each-subgraph node (that
> remains Phase 2, when SHA-2 forces port-native iteration).
>
> **Parent plan:** [`docs/plans/universal-port-dataflow.md`](./universal-port-dataflow.md)
> **Phase 0 findings:** [`docs/plans/universal-port-phase-0-findings.md`](./universal-port-phase-0-findings.md)
> **Memory:** `project_universal_port_dataflow_proposal.md`

## Goal of Phase 1

Every leaf executor in `src/ciphers/default-registry.ts` runs under the
ported contract via `liftLegacyExecutor`. New ciphers (SHA-2 in Phase 2)
can be authored port-native. The legacy execution path remains the
default until Phase 5 deprecates it — Phase 1 only widens the contract
without forcing any caller to opt in.

## Three resolved design decisions taken at consult time

These shape the sub-slices below.

### Decision A — `ctx.aux` channel is cut IN-SLICE-1, in the runtime

Phase 0 ran both paths in parallel: the live `aux` map flowed into the
lifted executor via `ctx.aux` AND projected into `inputs.get(portName)`.
The lifted executor still read via `ctx.aux.get(params.auxName)`. Slice 1.9
cuts the live-aux channel: the runtime builds a **synthetic `ctx.aux`**
populated only from `inputs` per the metadata's `auxReadPorts` bindings.
Legacy executor signatures untouched.

**Why in Slice 1 (not deferred):** validates that input-port-only
semantics actually works for every aux-reading step on the same gate as
the lift itself. Lift bugs surface as byte mismatches; channel-cut bugs
surface as "executor read aux that wasn't in inputs" exceptions —
different failure modes, easy to attribute.

**Why in the runtime (not the adapter):** the adapter stays pure
(`(inputs, params, ctx) → outputs`). The runtime is the only
side-effecting actor — it reads `meta.auxWritePorts(params)` and copies
output bytes into `aux.set(...)`. Same boundary that handles
`result.auxWrites` legacy-side today.

### Decision B — Key-expansion uses ONE OUTPUT PORT PER ROUND KEY

Picked by user 2026-05-23 (option a) over a single concatenated output
port (option b). Matches the plan's "one named edge per port" semantic
and the canvas's per-key edge visualization.

| Today (legacy) | Ported (Slice 1.4) |
|---|---|
| `result.auxWrites = Map([['roundKey.0', <16 B>], ['roundKey.1', <16 B>], …, ['roundKey.N', <16 B>]])` | `outputs = Map([['key0', <16 B>], ['key1', <16 B>], …, ['keyN', <16 B>]])` + `meta.auxWritePorts(params) → Map(['key0' → 'roundKey.0', …])` |

The number of output ports is dynamic via `params.rounds` —
`auxWritePorts(params)` is the function-shaped binding that knows how
to materialize the right port count per leaf. This is the same shape
already used by `META_ADD_ROUND_KEY.auxReadPorts(params)` for the
inverse direction.

**Applies to:** `aes.key-expansion@1`, `aes.key-expansion@2`,
`des.key-schedule@1`, `serpent.key-expansion@1`,
`speck.key-schedule@1`.

**Aux-only pattern (lifted from Slice 1.4 implementation 2026-05-23):**
all five key-schedule step types declare `shapeContract: { input:
"any", output: "preserveInput" }`. Slice 1.4 lifted AES key-expansion
as aux-only — `stateInputPort` and `stateOutputPort` OMITTED, the lift
adapter creates a sentinel state for the legacy executor and discards
its passthrough return, the runtime preserves the caller's actual
state across the call. Slices 1.6/1.7/1.8 follow the same pattern
uniformly (verified: all three downstream key-schedules already
declare `input: "any"`). This is the precedent for any future cipher
adding a key-schedule under the universal-port contract.

### Decision C — Metadata co-located with executor files, not central side-map

Phase 0's `PROJECTION_METADATA` is a throw-away side-map at module
scope in `src/core/port-projection.ts`. Slice 1 has ~40 entries; a
central side-map at that scale divorces metadata from the executor
it describes and bloats one file to 500+ lines. Slice 1.1 onward
co-locates each metadata block with its executor (e.g.,
`byteSubstitutionMeta` alongside `byteSubstitution` and
`byteSubstitutionDoc` in `src/steps/byte-substitution.ts`); the
registry consumes them via the `StepRegistration` discriminated union.

## Open spec decisions (flagged, NOT resolved in this plan)

These need user picks before the named slice starts; surface at the
right moment, do not pre-resolve here.

### Open #2 — `aux-copy` variant preservation — **CLOSED 2026-05-23 (Slice 1.5b shipped candidate (a))**

`generic.aux-copy@1` was lifted in Slice 1.2 with a STATIC
`PortContract.outputs["result"].layout: "raw"` — sized for the
Uint8Array case (the only flag-on path that exercised it at the time).
Slice 1.5's lift of `state-to-aux` makes the latent gap reachable: the
decrypt CBC body advances the chain via `aux-copy(next-chain → chain)`
where `aux[next-chain]` is a MatrixState. The lift adapter correctly
extracts MatrixState bytes, but the runtime's auxWrite decode at
`runtime.ts:317-330` consults the static `"raw"` layout and produces a
Uint8Array, dropping the variant. The next iteration's
`xor-aux-into-state` reads aux["chain"] as Uint8Array and the legacy
executor throws on shape validation.

Encrypt is unaffected — the encrypt body
(`cbcXorEncryptLeaf` → AES → `cbcSnapshotEncryptLeaf`) doesn't use
aux-copy. That's why Slice 1.5's encrypt KAT passes and decrypt is
deferred (test block `it.skip`d with rationale in
`tests/runtime-ported-dispatch-chaining.test.ts` (c)).

**Not "broken in production":** `portedDispatchEnabled` defaults `false`
and no shipped UI path enables it. Latent, test-fixture-reachable only.

**Candidate fixes** (pick ONE in a dedicated slice; surface to user at
slice start):

- (a) **`"preserve-input-variant"` layout sentinel** — runtime treats
  this as "consult the producer/source live aux variant" rather than
  decoding via static layout. Requires the runtime to know the source
  aux key at decode time; the `auxReadPorts(params)` and
  `auxWritePorts(params)` bindings together identify which input feeds
  which output for passthrough steps. Smallest surface change; reuses
  existing layout-tag mechanism.
- (b) **Variant sidecar in `PortedExecutor` return** — widen the
  ported executor return shape from `outputs: Map<string, Uint8Array>`
  to `{ outputs, variants?: Map<string, "auto" | StateShape> }` so the
  lift adapter can mark passthrough aux variants without losing them
  to layout decode. Larger contract change; more general.
- (c) **Split "variant-preserving aux passthrough" as a distinct
  semantic** — aux-passthrough steps (`aux-copy`, future
  `aux-passthrough`) declare a different metadata field
  (`auxPassthroughBindings`) that bypasses the bytes round-trip
  entirely. Clean separation; doubles the metadata surface for the
  one step type that needs it today.

**When to slice it:** unblocks AES-CBC decrypt under flag-on AND any
future spec that aux-copies a MatrixState/State variant. The plan's
Slice 1.5 gate is encrypt-only, so this can land as Slice 1.5b after
1.5 ships, OR as a prerequisite to Slice 1.6 (Speck) if Speck's specs
end up touching the path. Today (2026-05-23) no Speck spec uses
aux-copy, so deferring past Slice 1.6 is also viable.

Memory entry: `project_aux_copy_variant_gap.md`.

**Shipped 2026-05-23 (Slice 1.5b) — candidate (a) chosen** after a
second advisor consult that confirmed (a)'s smallest blast radius
given the empirical verification that no concrete plan adds a second
variant-preserving aux-passthrough step (`aux-tee@1` is the closest
plausible candidate and would reuse (a)'s mechanism trivially via a
struct-form sentinel naming the donor port).

**Mechanism delivered:**

- `auxPortBytesToValue(bytes, layout?, sourceVariantHint?)` gained a
  third branch: when `layout === "preserve-input-variant"`, it clones
  the source variant's shape with a fresh-bytes copy of the output
  bytes. Supports `Uint8Array` and the two State shapes (`bytes`,
  `matrix4x4-bytes`) — other variants throw to surface a future gap
  loudly rather than coercing silently.
- Runtime write-decode loop at `runtime.ts:316-360` lazily resolves
  the source variant hint per frame: when at least one output port
  declares the sentinel layout, it pulls `portedAuxRead.get(<first
  auxReadPorts binding's aux-key>)`. The hint comes from the
  pre-executor snapshot (defensive against self-modifying steps,
  though aux-copy doesn't do this).
- `aux-copy.ts` swapped output port layout from `"raw"` to
  `"preserve-input-variant"`. Single-source convention: the donor is
  the FIRST `auxReadPorts` binding. aux-copy has exactly one read
  port so this is unambiguous; a hypothetical multi-port-input
  variant-preserving step would need a struct sentinel form
  (`{ kind: "preserve-input-variant", source: "<portName>" }`)
  — defer until a real cipher needs it.

**Test coverage delivered:**

- Per-primitive pin (`runtime-ported-dispatch-chaining.test.ts` block
  `(c-pre)`): 3 it()s — MatrixState round-trip via aux-load → iv-load
  → aux-copy, frame parity on the same fixture, negative pin that
  Uint8Array source stays Uint8Array (no false-positive variant
  promotion).
- Block `(c)` UNSKIPPED — AES-128 CBC decrypt §F.2.2 KAT sanity +
  full frame-parity across the 1200+-frame multi-block run, exactly
  the gate Slice 1.5 deferred.

Gate: 1701/1701 tests green; `npm run check` clean.

### Open #1 — `generic.split-blocks@1` `State[]` aux encoding (blocks Slice 1.3)

`split-blocks` writes `aux[blocksAux]` as a `readonly State[]` (array
of MatrixState). Today's `port-projection.ts::auxValueToBytes` throws
on non-`Uint8Array` AuxValues. Two viable port shapes:

- (a) **One output port per block** (e.g., `block0`, `block1`, …)
  sized by the computed block count. Matches Decision B's
  "one named edge per port" semantic. The port count is dynamic
  per-spec — same shape as key-expansion's per-round-key ports.
- (b) **One output port carrying the concatenated bytes** (right back to
  a `BytesState`-equivalent flat array). Simpler metadata; loses
  per-block edge granularity; would require the consumer (iterate
  runtime) to re-split at consumption time.

Decide before Slice 1.3 begins. **Same character as Decision B for
1.4** — the user already picked port-per-something for key-expansion;
the per-block analog probably gets the same answer for the same
reason, but confirm before authoring.

Alternative escape hatch: **defer split-blocks lift to Phase 2** along
with the for-each-subgraph node. The iterate runtime today reads
`aux[blocksAux]` directly via the side-effect channel; if iterate
stays legacy (per invariant 2 above), keeping split-blocks legacy
inside Phase 1 is consistent. This would be the "minimum-port-design"
choice.

## Three correctness invariants Slice 1 must preserve

1. **`TraceFrame` shape unchanged.** Both paths produce frames with
   byte-equal `auxRead` / `auxWritten`. Graph derivation (`core/graph.ts`)
   reads exactly those fields and works unmodified. Adding port info to
   the frame itself is Slice 2 work (Phase 1's later sub-slice or Phase 2,
   TBD).
2. **Iterate + feistel-round runtime expansion stays legacy.** Body leaves
   run ported (per-leaf dispatch is unconditional on container kind).
   `iterate`'s `outBlocksAux` publication and the Feistel rejoin frame
   stay on the legacy side-effect path. **Frame-parity gate is full-stream
   byte equality with no filter** — rejoin frames are pure runtime
   synthesis from `Uint8Array` track outputs, byte-identical between
   paths for free.
3. **For-each-subgraph node is NOT added in Phase 1.** The parent plan's
   own permission: "Legacy iterate continues to work via adapter."
   Phase 2 (SHA-2) introduces the new node kind when it has a forcing
   use case.

## Sub-slice breakdown (13 batches)

Each sub-slice ships as ONE commit + push, with `npm run check` GREEN
before the commit lands. A failing gate stops the sequence — surface to
user, do not silently continue.

### Slice 1.0 — Dynamic-N aux-port round-trip (validates Decision B)

> **Slice scope revised 2026-05-23 after advisor reconciliation.** The
> original draft proposed a bitvec round-trip first, on the premise that
> `serpent.bit-permutation@1` consumed `BitVecState`. **Primary-source
> check showed the file rejects non-bytes state** (`serpent-bit-
> permutation.ts:28-32`); no shipped step uses `BitVecState`. Bitvec
> round-trip de-risks nothing for Slices 1.1–1.8 and was dropped. The
> existing TODOs in `port-projection.ts:299-314` keep bitvec/bigint
> deferred until a real cipher needs them; whenever bitvec arrives, it
> arrives with a real frame and gets its round-trip then.

**What this slice actually validates:** the projection round-trip when
the port count is **dynamic** (sized by `params.rounds`). Phase 0 only
had static single-binding metadata (`META_ADD_ROUND_KEY` binds exactly
one aux key per leaf). Decision B's port-per-roundkey shape needs the
projection to round-trip when `auxWritePorts(params)` returns N
bindings — that's unproven on a real frame, and 5 subsequent slices
(1.4 AES, 1.6 Speck, 1.7 Serpent, 1.8 DES) commit to it.

**Scope:**
- Real AES-128 run; pick the `aes.key-expansion@1` frame (the
  one-to-many writer producing 11 round keys).
- Author a one-off `META_AES_KEY_EXPANSION` with
  `auxWritePorts(params) → Map(['key0' → 'roundKey.0', …, 'key10' →
  'roundKey.10'])` sized by `params.rounds`.
- `project(frame, meta)` → `(PortedFrame, LayoutTags)`.
  - Expected `outputs.size === 11`.
  - Expected `tags.auxOutputBindings.size === 11` with byte-identical
    name preservation.
- `reconstruct(portedFrame, structuredClone(tags))` → recovered frame.
- `expectFrameByteEqual(recovered, original)` — particularly that
  `auxWritten` regenerates all 11 entries with their original
  `roundKey.0` … `roundKey.10` keys.

**Test file:** extend `tests/port-projection-q-gate-9.test.ts` (or new
`tests/port-projection-aux-write.test.ts` if scope grows).

**Gate:** new assertion green; full check green; no encoding spec
decisions surface (e.g., does the projection need to preserve key
order? `auxWritten` is a `Map` — Map iteration is insertion-ordered in
JS; round-trip must preserve insertion order). If they do, this
slice's gate fails and the plan re-opens.

**Side-effect:** the one-off `META_AES_KEY_EXPANSION` does NOT get
added to `PROJECTION_METADATA` — it's a test fixture only. Slice 1.4
authors the co-located metadata in `src/steps/key-expansion.ts`.

### Slice 1.1 — `StepRegistration` discriminated union

Replace `StepDefinition` consumption in `StepRegistry` with the plan's
discriminated union sketch:

```ts
type StepRegistration =
  | { kind: "ported"; executor: PortedExecutor; shape: PortContract; doc: StepDocumentation }
  | { kind: "legacy"; executor: StepExecutor; doc: StepDocumentation };
```

All existing entries register as `kind: "legacy"`. Runtime branches on
`kind`: legacy entries take the unchanged path; ported entries take the
ported path (which Slice 1.2+ populates).

**Gate:** 1618 existing tests pass; no runtime behavior change because
nothing registers as `ported` yet.

### Slice 1.2 — Aux-only primitives lifted — **GREEN 2026-05-23**

Step types: `generic.aux-load@1`, `generic.aux-copy@1`,
`generic.aux-xor@1`, `generic.iv-load@1`.

These have no state input/output port (state passes through unmodified
at the runtime layer). Validates the aux-only lift path with both state
ports undefined.

Each step file gains a `<name>Meta: ProjectionMetadata` export +
`<name>PortContract: PortContract` export. `default-registry.ts`
registers each as `kind: "ported"` with the colocated metadata.

**Gate (achieved):** 1629 tests green (1622 prior + 7 new in
`tests/runtime-ported-dispatch-aux-only.test.ts`). Frame-by-frame parity
holds across the synthetic 4-step spec, the AES-128 CBC NIST SP 800-38A
§F.2.1 KAT (1629-frame multi-block run), and the two pre-flagged hazard
pins (Map iteration order on `aux-xor`'s `auxReadMissing`; empty-auxName
sentinel on all three aux writers).

**Two contract decisions landed mid-slice — capture for downstream
slices:**

1. **`PortShape.byteLength` is OPTIONAL** (user pick 2026-05-23 over
   sentinel-0 and contract-optional alternatives). Absent → polymorphic
   port (length determined by wiring at edit time). Scales to SHA-2's
   variable-length input → fixed-length output without another contract
   bump. Slice 1.4+ authors of fixed-length port contracts should still
   declare `byteLength` when the cipher demands it (AES rounds = 16);
   only steps with genuinely dynamic length (aux-xor / aux-copy) leave
   it absent.

2. **`PortContract.layout` is LOAD-BEARING for aux decode**, not just
   editor advisory. The runtime reads
   `registration.shape.outputs.get(portName).layout` after a ported
   step executes and reconstructs the AuxValue's variant from that tag.
   Today's vocabulary: `"raw"` / undefined → `Uint8Array`;
   `"matrix-cm-4x4"` → `MatrixState`. iv-load's output port declares
   `"matrix-cm-4x4"` so downstream `xor-aux-into-state` finds a
   MatrixState (which it validates). Future ports producing other State
   shapes extend `auxPortBytesToValue` in `core/port-projection.ts`
   with their decode targets.

**One interim field added — disappears at end of Phase 1:**

The `kind: "ported"` variant carries a `legacy: StepExecutor` field
alongside the lifted `executor: PortedExecutor`. Both are required
through Slices 1.2–1.8 so the runtime's frame-parity gate can run each
ported step under both flag values. Phase 2 (SHA-2 port-native) ships
without `legacy`; the field becomes optional then disappears in Phase 5
when the legacy contract retires.

### Slice 1.3 — Padding primitives lifted — **scope narrowed mid-slice 2026-05-23**

> **Two-round scope discovery during slice prep.** The original draft
> listed 11 step types: 6 padding + load-block + store-block + split-
> blocks + concat-blocks + compute-block-count.
>
> **Round 1 deferral (advisor consult, before authoring):**
> `split-blocks` writes `aux[blocksAux]` as `MatrixState[]`;
> `concat-blocks` reads it; `compute-block-count` writes a `number`.
> All three feed/are-read-by the **legacy iterate runtime** (invariant 2
> of this plan — iterate stays legacy in Phase 1). Lifting them now
> requires throwaway bridge code (array-aux encode/decode and
> number-aux encode/decode) that Phase 2's for-each-subgraph node
> retires. Decision: defer to Slice 1.9 (alongside the `ctx.aux` channel
> cut) or Phase 2.
>
> **Round 2 deferral (advisor consult, after primary-source check):**
> `load-block` (bytes → matrix4x4-bytes) and `store-block`
> (matrix4x4-bytes → bytes) are SHAPE-TRANSFORMING — their state input
> shape ≠ state output shape. The current `ProjectionMetadata.stateLayout`
> is a SINGLE field used for both stateBefore reconstruction
> (`bytesToState`) AND stateAfter encoding (`stateToBytes`). The latter
> throws if `state.shape !== expected`, so a single-field meta cannot
> describe a shape-transforming step. The natural fix (state ports
> consult `PortContract.inputs/outputs[port].layout` instead of meta
> carrying a separate `stateLayout` — unifying the layout mechanism
> already used for aux ports) is its own slice's design question, not
> Slice 1.3's. Decision: defer load-block + store-block to a future
> slice that addresses the `ProjectionMetadata.stateLayout`
> single-field gap.

**Final Slice 1.3 scope: 6 step types.** All bytes → bytes
(`shapeContract: { input: "bytes", output: "preserveInput" }`),
no aux reads/writes — the cleanest possible lift batch:

- `generic.pkcs7-pad@1`, `generic.pkcs7-unpad@1`
- `generic.zero-pad@1`, `generic.zero-unpad@1`
- `generic.iso7816-4-pad@1`, `generic.iso7816-4-unpad@1`

Each gets a colocated `<name>Meta: ProjectionMetadata` +
`<name>PortContract: PortContract` export per Decision C. Meta declares
`stateLayout: "bytes"`, `stateInputPort: "state"`,
`stateOutputPort: "state"`; no aux read/write port functions. PortContract
declares one `state` input + one `state` output, layout `"raw"`,
`byteLength` ABSENT (padding output is variable-length — input.length +
padLen for pad steps; input.length − padLen for unpad steps).

**Deferred to a later slice (5 step types):**

- `generic.load-block@1`, `generic.store-block@1` — shape-transforming;
  blocked on `ProjectionMetadata.stateLayout` contract extension.
- `generic.split-blocks@1`, `generic.concat-blocks@1` — array-aux
  encode/decode; blocked on iterate runtime deferral until Slice 1.9 or
  Phase 2.
- `generic.compute-block-count@1` — number-aux encode/decode; same
  deferral as split/concat (legacy iterate consumes it).

**Gate:** frame-byte equivalence between `portedDispatchEnabled: true`
and `false` for each of the 6 lifted step types on a synthetic spec.
Existing AES-128 CBC frame-parity test from Slice 1.2 continues to
pass (the cipher's load-block/store-block/split/concat/count stay
legacy, so the cipher-level parity gate is unchanged).

### Slice 1.4 — AES lifted (port-per-roundkey) — **GREEN 2026-05-23**

Step types: `generic.shift-rows@1`, `generic.mix-columns@1`,
`generic.byte-substitution@1`, `generic.add-round-key@1`,
`aes.key-expansion@1`, `aes.key-expansion@2`.

`byte-substitution` and `add-round-key` already had throw-away metadata
in `PROJECTION_METADATA`; this slice moved them to co-located metadata
per Decision C. The side-map entries stay as dead code through Slice
1.4 because the runtime's contract-priority dispatch at
`runtime.ts:217-221` shadows them; Slice 1.9 deletes the side-map
outright (Decision A).

Key-expansion uses **port-per-roundkey** per Decision B —
`meta.auxWritePorts(params)` returns N+1 bindings sized by
`params.rounds`. Key-expansion is **aux-only** (no state ports
declared, matching its `shapeContract: { input: "any", output:
"preserveInput" }`); the lift adapter creates a sentinel state and the
runtime preserves the caller's state across the call — same pattern as
the Slice-1.2 aux-only primitives (`iv-load`, `aux-load`, etc.).

**Contract evolution landed mid-slice:** the user-picked design
question was whether `PortContract.outputs` should be widened to accept
a function form (Option A — chosen), use a templated-name "keyN" lie
(Option B — rejected), or get a `dynamicOutputs?` sibling field
(Option C — rejected). Option A widens both `inputs` and `outputs` to
`PortShapeMap = ReadonlyMap | ((params) => ReadonlyMap)` — mirroring
`ProjectionMetadata.auxWritePorts`'s already function-only shape and
keeping the two contract layers isomorphic. A new helper
`resolvePortMap(spec, params)` in `core/port-projection.ts` is the
single funnel; the runtime's layout lookup site (`runtime.ts:317`)
calls it once per ported frame. Existing 10 static contracts pass
unchanged through the union — no source-code edits required to those
contracts.

**Gate (achieved):** 1651 tests green (1629 prior + 8 new in
`tests/runtime-ported-dispatch-aes-core.test.ts` + ~14 picked up from
suite expansion). All three FIPS-197 KAT sanity floors green under
`portedDispatchEnabled: true` (AES-128 §C.1, AES-192 §A.2 + NIST AES
Core 192, AES-256 §A.3 + NIST AES Core 256). Frame-by-frame byte
parity green for all three specs across 49 / 51 / 57 frames
respectively. `aes.key-expansion@2` byte-parity green at canonical
AES-128 rounds. Map insertion order on the 11 AES-128 round keys
pinned (roundKey.0 … roundKey.10 in order). The pre-existing Phase-0
side-map pin at `tests/runtime-ported-dispatch.test.ts:124` continues
to pass — the side-map's KEYS are untouched; the runtime just never
consults them for the now-ported registrations.

### Slice 1.5 — Chaining primitives lifted — **GREEN 2026-05-23**

Step types: `generic.xor-aux-into-state@1`, `generic.state-to-aux@1`.

Both lifted as `kind: "ported"` per Decision C colocated metadata.
State ports declared (both have `matrix4x4-bytes` state in/out today —
AES-CBC is the only shipping use). `xor-aux-into-state` declares a
`auxReadPorts` binding for `operand` (the chain), emitted even when
`auxName === ""` so `auxReadMissing: [""]` materializes identically
under both paths. `state-to-aux` declares an `auxWritePorts` binding
for `snapshot` (layout `matrix-cm-4x4` so the runtime decodes to
MatrixState, matching legacy's `cloneState(state)` shape); returns an
empty Map when `auxName === ""` (matches iv-load's outAuxName pattern).

**`stateLayout: "matrix4x4-bytes"` on `state-to-aux` despite
`shapeContract.input === "any"`** — these two fields are decoupled
(`shapeContract` is editor-UX, `stateLayout` is runtime port encoding).
AES-CBC is the only shipping use; a future Speck-CBC composition with
`bytes`-shape state would register a sibling step type, or `stateLayout`
would widen to consult the PortContract input port's layout. Pinning is
safe because `portedDispatchEnabled` defaults `false`; the runtime
throws loudly if a flag-on user drags `state-to-aux` into a non-AES
spec. Same gradualism Slice 1.3 applied to `load-block`/`store-block`.

**Runtime input-side widening landed mid-slice:** the previous Slice-1.2
hard throw on non-Uint8Array aux at `runtime.ts:254` ("aux ... must be
Uint8Array") was an explicit deferral; Slice 1.5's `xor-aux-into-state`
lift is the first ported step type to actually read a MatrixState
through an input port. Widening: drop the throw, encode bytes via the
existing `auxValueToPortBytes` helper (promoted from file-private to
exported), and **alias the live AuxValue into `portedAuxRead`** (rather
than cloning) to match the legacy path's `auxRead.set(k, v)` symmetry.
Aliasing is the parity-preserving choice — practically `toEqual`
deep-equals either way, but symmetry across paths is the cleaner
mental model.

**Gate (achieved):** 1657 tests green (1651 prior + 6 active in
`tests/runtime-ported-dispatch-chaining.test.ts`; 2 deferred — see
Open #2). AES-128 CBC encrypt KAT (NIST SP 800-38A §F.2.1) passes under
`portedDispatchEnabled: true`; full frame-by-frame byte parity across
all 1300+ frames. Per-primitive synthetic specs pin unit semantics
(MatrixState aux round-trip; layout-driven decode reconstructs
MatrixState). Empty-auxName parity pinned for both primitives.

**Deferred — see Open #2:** AES-128 CBC decrypt (§F.2.2) under flag-on.
Decrypt body advances the chain via `aux-copy(next-chain → chain)` —
aux-copy was lifted in Slice 1.2 with static layout `"raw"`, dropping
the MatrixState variant on decode. Needs contract design (variant
preservation in aux-passthrough steps), not a mid-slice patch. Test
block `it.skip`d with rationale; unskipping is the gate for the
variant-preserving slice (1.5b or 1.6-prereq).

### Slice 1.6 — Speck lifted — **GREEN 2026-05-23**

Step types: `speck.key-schedule@1`, `speck.round@1`,
`speck.round-inverse@1`.

`bytes` state shape (4-byte Speck32/64 blocks; polymorphic `byteLength`
on state + aux-read ports to cover variant differences — Speck64/128
would carry 8-byte blocks under the same step code). Key-schedule is
the SECOND one-to-many writer in the universal-port migration (after
AES key-expansion in Slice 1.4): **22 output ports for Speck32/64**
(`key0` … `key21`) sized by `params.rounds` via the function-form
`PortContract.outputs` already validated in Slice 1.4. Unlike AES
key-expansion which writes `Nr+1` round keys (initial AddRoundKey + one
per round), Speck writes EXACTLY `rounds` keys — `k_0 … k_{rounds-1}`,
one per round consumed in spec leaf order. The Decision B
port-per-roundkey shape carries over verbatim; the user re-confirmed at
Speck's 22-port count before Slice 1.6 started.

**Three port-shape decisions landed mid-slice (all flow from Slice 1.2
/ 1.4 precedents, no new contract evolution):**

1. **`stateLayout: "bytes"`** on round + round-inverse — Speck blocks
   are flat `BytesState`s, reusing the existing `bytes`-shape encoding
   in `port-projection.ts::stateToBytes`. No new layout token needed.
2. **Polymorphic `byteLength`** (absent) on every state + aux port
   that varies with Speck variant — block size = `2 × wordBits / 8`,
   round-key size = `wordBits / 8`, master-key size = `m × wordBits / 8`.
   The Slice 1.2 user pick (polymorphic over sentinel-0) covers this
   without per-variant numbers baked into the contract. Mirrors AES
   key-expansion's `masterKey` polymorphism.
3. **Aux-only key-schedule** — `stateInputPort` and `stateOutputPort`
   OMITTED. Same pattern as Slice 1.4's AES key-expansion: the lift
   adapter creates a sentinel zero-length `bytes` state for the legacy
   executor's ceremonial `state` arg, the runtime preserves the
   caller's actual state across the call so the next leaf
   (`speck.round@1`) sees its incoming 4-byte block unchanged.

**Gate (achieved):** 1667 tests green (1657 prior + 10 new in
`tests/runtime-ported-dispatch-speck.test.ts`). Beaulieu et al. 2013
Table 4.1 KAT sanity floors green under `portedDispatchEnabled: true`
for all four cipher specs (BE-paper encrypt + LE-NSA encrypt + BE-paper
decrypt + LE-NSA decrypt). Frame-by-frame byte parity green across all
four 23-frame traces. Map insertion order on the 22 Speck32/64 round
keys pinned (`roundKey.0` … `roundKey.21` in order). Per-primitive
synthetic spec (key-schedule + one round) pins the lift in isolation.
Aux-copy variant gap (Open #2) stays deferred — no Speck spec uses
aux-copy, the `it.skip` from Slice 1.5 still tracks the latent debt.

### Slice 1.7 — Serpent lifted — **GREEN 2026-05-23**

Step types: `serpent.key-expansion@1`, `serpent.bit-permutation@1`,
`serpent.add-round-key@1`, `serpent.sub-bytes@1`,
`serpent.linear-transform@1`, `serpent.inv-linear-transform@1`.

> **Slice 1.0 dependency note (stale) resolved.** The plan's original
> "depends on Slice 1.0 (bitvec)" wording dates from before Slice 1.0
> dropped bitvec mid-flight after primary-source check showed
> `serpent.bit-permutation@1` rejects non-bytes state. Serpent uses
> `bytes` state throughout (16-byte fixed); no shipped step exercises
> `BitVecState`. No real dependency.

Key-expansion per Decision B — **third one-to-many writer** in the
universal-port migration (after AES key-expansion in Slice 1.4 and Speck
key-schedule in Slice 1.6). **33 output ports** (`key0` … `key32`),
**FIXED across all three Serpent key sizes** unlike AES (Nr+1, scales
with `params.rounds`) and Speck (`rounds` keys, also param-driven). The
Serpent executor has no `rounds` param — the loop is hard-coded
`for i in 0..32`. Function-form `PortContract.outputs` retained for
uniformity with the precedents and so the `outputPrefix` param threads
through `auxWritePorts(params)` cleanly.

**Two contract decisions landed (both flow from prior slices, NO new
contract evolution):**

1. **byteLength split between state ports and key-expansion's
   round-key output ports** (user pick 2026-05-23). State ports on the
   five state-bearing step types declare `byteLength: 16` (Serpent
   state is always 128 bits, no variant exists — matches AES Slice 1.4
   posture "honest fixed declaration when no variant"). Key-expansion's
   33 round-key output ports leave `byteLength` ABSENT (matches Slice
   1.6 Speck posture uniformly across the round-key port batch, even
   though Serpent has no variant). Master-key input port also absent
   because the master key varies across 16/24/32 bytes per `keyByteLength`.
2. **Aux-only key-expansion** — same lift pattern as Slice 1.4 AES
   key-expansion and Slice 1.6 Speck key-schedule. `stateInputPort` and
   `stateOutputPort` OMITTED; the lift adapter creates a sentinel
   zero-length `bytes` state for the legacy executor and the runtime
   preserves the caller's actual state across the call. All three of
   AES/Speck/Serpent's key-schedules now share this aux-only pattern
   verbatim.

The four pure no-aux Serpent steps (`bit-permutation`, `sub-bytes`,
`linear-transform`, `inv-linear-transform`) are the cleanest possible
lift batch — bytes↔bytes 16-byte fixed, no aux traffic. Strictly
simpler than Slice 1.3's padding primitives (which had variable output
lengths) thanks to Serpent's fixed-size state. `serpent.add-round-key@1`
is the direct analog of `generic.add-round-key@1` (AES, Slice 1.4) but
with `stateLayout: "bytes"` instead of `"matrix4x4-bytes"` — same
single-aux-read function-form binding.

**Gate (achieved):** 1681 tests green (1667 prior + 14 new in
`tests/runtime-ported-dispatch-serpent.test.ts`). All three Serpent
KAT sanity floors green under `portedDispatchEnabled: true` (Serpent-128
+ Serpent-192 + Serpent-256, encrypt + decrypt). Frame-by-frame byte
parity green across all six cipher specs (3 key sizes × {encrypt,
decrypt}). Map insertion order on the 33 Serpent round keys pinned
(`roundKey.0` … `roundKey.32` in order). Per-primitive synthetic spec
(key-expansion + one add-round-key) pins the lift in isolation. Full
check green: biome + tsc + 1681/1681 active vitest tests + vite build.

**aux-copy variant gap (Open #2) stays deferred** — no shipped Serpent
spec uses chaining primitives (single-block only across all three
variants). The `it.skip` from Slice 1.5 (chaining test (c) — AES-128
CBC decrypt §F.2.2 under flag-on) remains tracking the latent debt.
DES (Slice 1.8) is the next checkpoint for the variant-preserving pick;
DES specs also don't use aux-copy in their canonical shape, so deferral
remains viable through 1.8 as well.

### Slice 1.8 — DES lifted — **GREEN 2026-05-23**

Step types: `des.key-schedule@1`, `des.initial-permutation@1`,
`des.final-permutation@1`, `des.expand-R@1`, `des.xor-with-K@1`,
`des.s-boxes@1`, `des.p-permutation@1`.

Plus `feistel.toy-add-k@1` (test fixture, lifted alongside).

`bytes` state shape throughout. **DES is the FOURTH cipher family
ported** (after AES Slice 1.4, Speck Slice 1.6, Serpent Slice 1.7).
Body leaves of `feistel-round` containers run ported via the same
`walk()` recursion that handles iterate-body leaves; the rejoin frame
stays as runtime synthesis (byte-identical between paths for free per
invariant 2).

Key-schedule per Decision B — **fourth one-to-many writer** in the
universal-port migration. **16 output ports** (`key0` … `key15`),
fixed across DES (no key-size variant — the 64-bit master key always
reduces to 56 effective bits via PC-1). Function-form contract for
uniformity with the AES/Speck/Serpent precedents.

**Three contract decisions landed (all flow from prior slices, NO new
contract evolution):**

1. **byteLength split between state ports and key-schedule's round-key
   output ports** (user pick 2026-05-23). State ports on six state-
   bearing step types (IP/FP/E/S/P/xor-with-K) declare honest fixed
   byteLength — matches the Slice 1.7 Serpent posture "honest fixed
   declaration when no variant" (DES has none). Key-schedule's 16
   round-key output ports leave `byteLength` ABSENT — matches Slice
   1.6 Speck + Slice 1.7 Serpent posture uniformly across the round-
   key port batch.
2. **Master-key input port byteLength: 8** — declared HONESTLY because
   DES is the first fixed-key-size cipher to land. Differs from AES
   Slice 1.4 (16/24/32 variant — absent) and Serpent Slice 1.7
   (16/24/32 variant — absent). Extends the "honest fixed when no
   variant" precedent from state ports to the master-key input port.
3. **Aux-only key-schedule** — `stateInputPort` and `stateOutputPort`
   OMITTED. Same pattern as Slice 1.4 AES key-expansion + Slice 1.6
   Speck key-schedule + Slice 1.7 Serpent key-expansion. All four
   key-schedules now share this lift pattern verbatim.

**The first slice with asymmetric state-port byteLength** —
`des.expand-R@1` declares input 4 / output 6, `des.s-boxes@1`
declares input 6 / output 4. Both share `stateLayout: "bytes"`; the
`bytes`-shape codec in `port-projection.ts` (`stateToBytes`, line
~286) copies bytes without a length check, so the asymmetric
declaration works without any runtime contract changes. The
executors' own length assertions remain the runtime gate on wiring
errors.

**Body leaves inside `feistel-round` run ported via the standard
`walk()` recursion** — `runFeistelRound` walks each track's children
through `walk()` (runtime.ts:493), reaching the same leaf-dispatch
site (runtime.ts:182) that handles `kind === "ported"` for iterate-
body leaves. No new runtime code; no special-case for Feistel body
dispatch. The rejoin frame is synthesized by `runFeistelRound` from
`Uint8Array` track outputs (runtime.ts:~514) — byte-identical between
dispatch paths for free.

**Gate (achieved):** 1696 tests green (1681 prior + 15 new in
`tests/runtime-ported-dispatch-des.test.ts`). All three DES KAT
fixture vectors (FIPS 46-3 Appendix B + all-zeros + all-ones,
`node:crypto` cross-checked) green under `portedDispatchEnabled: true`
for both encrypt and decrypt. Frame-by-frame byte parity green across
all 6 specs (3 vectors × {encrypt, decrypt}). Map insertion order on
the 16 DES round keys pinned (`roundKey.0` … `roundKey.15`).
Per-primitive synthetic spec (key-schedule + one xor-with-K) pins
the lift in isolation. **The `feistel.toy-add-k@1` lift coverage
(FEISTEL_TOY_SPEC under both dispatch paths) pins the load-bearing
invariant 2 claim** — body leaves inside `feistel-round` run ported,
rejoin frame stays byte-identical — without any DES-side noise.

**aux-copy variant gap (Open #2) stays deferred** — no DES spec uses
aux-copy (`des-decrypt.ts` grep confirms no `aux-copy` / `state-to-
aux` / `xor-aux-into-state`). The `it.skip` from Slice 1.5 (chaining
test (c) — AES-128 CBC decrypt §F.2.2 under flag-on) remains tracking
the latent debt. Pick is now scheduled before Slice 1.9 begins
(which deletes the `PROJECTION_METADATA` side-map outright).

### Slice 1.9 — `ctx.aux` channel cut + side-map deleted — **GREEN 2026-05-24**

Per Decision A. Two changes, one commit:

1. **Synthetic `ctx.aux` for lifted executors.** The runtime's ported-
   dispatch path now passes `aux: portedAuxRead` (a Map keyed by
   aux-key, populated only from `meta.auxReadPorts(params)` bindings)
   to the ported executor's `ctx`, instead of the live `aux` map.
   Aliasing `portedAuxRead` (rather than re-decoding from `inputs`
   port bytes) preserves AuxValue variants (MatrixState chain stays
   MatrixState), keeps the legacy executor inside the lift looking up
   by its real aux-key (`ctx.aux.get(params.auxName)`), and surfaces
   the load-bearing failure mode loudly: a legacy executor that reads
   an undeclared aux key gets `undefined` and falls off its own shape
   check. The live aux map (`aux`) now reaches NEITHER the lifted
   nor the ported executor; only the runtime's own write-decode path
   continues to mutate it.
2. **`PROJECTION_METADATA` side-map DELETED** from
   `core/port-projection.ts`. The two Phase-0 entries
   (`generic.byte-substitution@1`, `generic.add-round-key@1`) lifted
   to `kind: "ported"` registrations with colocated metadata in
   Slice 1.4; the side-map's runtime fallback branch had been dead
   code through Slices 1.4–1.8 and is removed here. Runtime's meta
   lookup collapses from a 3-way conditional to
   `portedDispatch && registration.kind === "ported"`; the
   `liftLegacyExecutor` import + the lift-on-the-fly fallback in the
   dispatch site both go away (`registration.executor` is already
   the pre-lifted closure built at registration time).

**Gate (achieved):** 1700 tests green (1701 prior − 1 deleted
side-map-keys-pin assertion in `tests/runtime-ported-dispatch.test.ts`,
which had pinned the now-deleted `PROJECTION_METADATA.keys()` to the
Phase-0 pair). All per-cipher ported-dispatch tests
(`runtime-ported-dispatch-{aes-core,chaining,speck,serpent,des}.test.ts`)
still pass — every cipher family's frame-by-frame parity assertion now
runs under the cut `ctx.aux` channel and matches the legacy path byte-
for-byte. `npm run check` clean (biome + tsc + vitest 1700/1700 +
vite build, ~75s).

**No `meta.auxReadPorts` widening was needed** — the channel cut
surfaced ZERO bugs. The Slice 1.4–1.8 lifts had already declared
`auxReadPorts` entries for every aux key their legacy executors read
(byte-byte parity gated them); the only thing they were doing "for
real" through the live `aux` channel was the same lookups the meta
declared. Decision A's predicted failure mode ("executor read aux
that wasn't projected") was preventatively closed by the per-cipher
parity gates of the upstream slices.

**Interim `legacy` field stays** — Slice 1.9 only cuts the runtime-
side `ctx.aux` channel; the off-flag legacy dispatch path still uses
`registration.legacy` to call the original executor with the LIVE
`aux` map. That's the explicit Phase-1-window contract per
`StepRegistration`'s `legacy` field docblock. Field becomes optional
when Phase 2 ships port-native executors that genuinely have no
legacy underlying; disappears when Phase 5 retires the legacy
contract.

### Slice 1.10 — `narrationOverride` field added to `StepLeaf` — **GREEN 2026-05-24**

```ts
type StepLeaf = {
  readonly kind: "step";
  readonly id: string;
  readonly type: string;
  readonly params: Json;
  readonly narrationOverride?: StepDocumentation;
};
```

**Landed on `StepLeaf`, not the union.** The slice prose said "`StepNode`"
but only `kind: "step"` leaves have a `type` for the docs to override;
group / iterate / feistel-round nodes have no equivalent registry doc
to shadow. The plan snippet's `kind: "step"` already pointed at the
leaf — the placement choice was confirmation, not a revision.

**Renderer landed in `<StepDescription>`, not `<StepNarration>`.** The
plan prose named `<StepNarration />` but the field's type is
`StepDocumentation`, which is the shape `<StepDescription>` consumes
(via `registry.getDoc`). `<StepNarration>` consumes `NarrationUnit[]`
— a different surface entirely. The plan name was a slip; the override
has to land in `<StepDescription>` to typecheck.

**Wiring depth:** option (a) — spec-store lookup. `<StepDescription>`
now imports `useSpec()` + `findStep` + `canonicalStepId`, looks up the
leaf via `findStep(spec(), canonicalStepId(frame.stepId))`, prefers
`leaf.narrationOverride` when present, and falls through to
`registry.getDoc(frame.stepType)` otherwise. Option (b) — threading
`narrationOverride` onto `TraceFrame` at runtime emit time — would be
cleaner for Phase 3 but widens this slice into runtime changes. Option
(c) — prop-pass — would change every caller. (a) is foundation-shaped:
no runtime changes, no API widening, Phase 3 can revise if per-port
narration emerges.

**No schema bump** — structural typing keeps existing saved documents
valid. The document schema (`document-schema.ts::StepLeafSchema`) does
NOT yet accept `narrationOverride` — Zod's default strip mode silently
drops it on load. That's fine for Slice 1.10 (no spec uses the field
yet); Phase 3 will widen the Zod schema when shipped specs start
carrying overrides.

**Foundation-only.** No shipped spec uses the field yet. Phase 3's AES
rebuild from medium primitives is where it earns its keep.

**Gate:** type compiles; existing tests pass; one new test file
`tests/step-description-narration-override.test.tsx` pins both the
fallback path (no override → registry doc) and the override path
(override present → override wins). 1702/1702 tests green.

### Slice 1.11 — Frame-parity test matrix — **GREEN 2026-05-24**

One file: `tests/runtime-ported-dispatch-frame-parity.test.ts`. Keyed
by cipher spec. Each `it`:

1. Build the spec with a known-answer plaintext + key.
2. Run twice: `runSpec(spec, registry, { …, portedDispatchEnabled: false })`
   and `runSpec(spec, registry, { …, portedDispatchEnabled: true })`.
3. **KAT sanity floor first:** assert `trace.finalState.bytes` matches
   the published ciphertext. A failure here is a louder signal than a
   1389-frame deep-equality miss.
4. **Then:** `expectFrameStreamsEqual(legacyTrace.frames, portedTrace.frames)`
   — full frame stream, **no filter**. Iterate / feistel-rejoin frames
   are byte-identical for free.

**Coverage settled mid-slice (advisor consult + user pick before
authoring):** the plan prose enumerated "AES-128/192/256, AES-128 ECB,
AES-128 CBC, Speck32/64 ×2 conventions, Serpent-128/192/256, DES"
which adds to **11 cipher specs** — the parenthetical "(8 cipher specs
total)" was a miscount. User chose to enumerate verbatim (11 specs)
AND to cover both encrypt + decrypt directions per spec (matches what
the per-cipher files already pin). Final shape: **22 rows** — one
`it()` per (spec, direction) pair, each row a self-contained `(KAT,
frames-byte-equal)` triple.

**Helper duplication intentional** — per advisor read of the existing
`runtime-ported-dispatch-*.test.ts` files, every file inlines the four
equality helpers (`expectStatesEqual`, `expectAuxMapsEqual`,
`expectFramesEqual`, `expectFrameStreamsEqual`) verbatim. Slice 1.11
mirrors that pattern; no `tests/helpers/frame-equality.ts` side-quest
(CLAUDE.md "no abstractions beyond what the task requires").

**Genuine new coverage:** AES-128 ECB encrypt + decrypt had no
dedicated dispatch-parity pin before this slice — the closest
existing pin (`runtime-ported-dispatch-aux-only.test.ts` block (b))
covers CBC, not ECB. Every other row is also pinned in a per-cipher
file; the matrix file's value is the single-file gate + the explicit
(spec, KAT, frames-byte-equal) triple per row, so a regression in any
cipher family surfaces here regardless of whether the family-specific
file caught it.

**KAT references:** FIPS-197 §C.1 (AES-128), §A.2 + NIST AES Core 192
(AES-192), §A.3 + NIST AES Core 256 (AES-256), NIST SP 800-38A §F.1
(ECB) + §F.2 (CBC), Beaulieu et al. 2013 Table 4.1 (Speck32/64
BE-paper + LE-NSA), pyserpent / Anderson-Biham-Knudsen reference
(Serpent 128/192/256), FIPS 46-3 Appendix B.1 (DES, cross-checked with
`node:crypto` des-ecb per the project's external-oracle convention).

**Gate (achieved):** 1724 tests green (1702 prior + 22 new). All 22
rows pass under `portedDispatchEnabled: true` with the KAT sanity
floor + full frame-stream byte equality. `npm run check` clean (biome
+ tsc + vitest 1724/1724 + vite build, ~75s). The bundle-size warning
at 540 KB carries forward from Phase 5; non-blocking, no Slice 1.11
contribution.

### Slice 1.12 — Coercion mechanism round-tripped — **GREEN 2026-05-24** (closes Phase 1)

Q2 of the parent plan: warn-and-run with right-pad / truncate-from-right.

**Surfacing mechanism settled mid-slice (user pick 2026-05-24 over
`coercionApplied` metadata field + the "both" combo):** synthetic
`__coerce__` trace frame per affected input port, emitted BEFORE the
consumer leaf. Same shape pattern as `__rejoin__` — runtime-synthesized
stepType, never registered with an executor, surfaces in the linear
scrubber via the existing frame iteration. Decision rationale:

1. Matches Q2 verbatim ("Coercion appears as a visible trace step
   (e.g., *'coerced 8 → 16 bytes by right-zero-padding'*)").
2. `__rejoin__` proves the synthetic-frame pattern fits this runtime
   cleanly.
3. Free scrubber visibility — every frame iterates; the metadata-field
   alternative would have required new inspector chip / scrubber badge
   plumbing in the same slice to meet Q2's "visible" bar.
4. Pedagogically richer than a hidden field — the byte morph reads as
   a discrete event in the scrubber sequence.

Frame-count divergence between legacy/ported paths on fixtures that
trigger coercion is the FEATURE under test; comparing them would defeat
the surface. Shipped-spec frame-parity (Slice 1.11's 22-row matrix)
remains green because no shipped spec triggers coercion.

**Mechanism delivered:**

- `COERCE_STEP_TYPE = "__coerce__"` constant + `CoercionMode` +
  `CoercionResult` types + `coerceToByteLength(source, targetLen)`
  helper in `src/core/port-projection.ts`. Three branches:
  `sourceLen === targetLen` → `mode: "exact"`, bytes returned
  reference-equal (runtime short-circuits the synthetic frame emit);
  `sourceLen < targetLen` → `mode: "right-pad"`, fresh `Uint8Array`
  with source at offset 0 and zeros trailing; `sourceLen > targetLen`
  → `mode: "truncate-right"`, fresh `source.slice(0, targetLen)`
  (keeps LEFTMOST targetLen bytes; "truncate from the right" names the
  discard side per Q2's prose).
- Runtime coercion loop at `runtime.ts` (between input build and
  executor call): walks `resolvePortMap(registration.shape.inputs,
  params)`, per-port checks if (a) bytes exist in the inputs map AND
  (b) port declares a fixed `byteLength` (polymorphic — `byteLength`
  absent — opts out per the Slice 1.2 user pick), coerces and replaces
  the entry, emits one synthetic `__coerce__` frame per affected port.
  Frame stamping respects `branchPath` / `blockIndex` via the existing
  `composeStepId`. Synthetic frame stepId: `<leafStepId>:coerce:<portName>`.
- Narrator at `src/ui/narration/coerce.tsx` registered under
  `"__coerce__"` in `src/ui/narration/index.ts`. Reads
  `params.{portName, mode, sourceLen, targetLen}` and explains the
  morph in Q2's prose style ("coerced 8 → 16 bytes by right-zero-
  padding for input port 'port-a'") with before/after byte rows under
  the chosen byte format.

**Test coverage delivered:** `tests/runtime-ported-dispatch-coercion.test.ts`,
5 surfaces:

- (a) right-pad — source 8 → port declares 16 → padded with 8 trailing
  zeros; synthetic frame params/state pinned.
- (b) truncate-from-right — source 8 → port declares 4 → keeps first 4
  bytes; discard half pinned unambiguously (Q2 names the discard side,
  not the keep side — easy to misread).
- (c) multiple ports on one leaf — two synthetic frames emit in
  declaration order of `meta.auxReadPorts`; frame indices monotonic;
  consumer leaf at index 2.
- (d) polymorphic port (byteLength absent) → no coercion, no synthetic
  frame regardless of source length.
- (e) exact length match → no synthetic frame; short-circuit pinned
  (critical for Slice 1.11's matrix gate).

**Gate (achieved):** 1729 tests green (1724 prior + 5 new). All 22
rows of the Slice 1.11 frame-parity matrix continue to pass — no
shipped spec triggers coercion. `npm run check` clean (biome + tsc +
vitest 1729/1729 + vite build, ~38s). The bundle-size warning at
~543 KB carries forward from Phase 5; non-blocking, no Slice 1.12
contribution.

**Honest caveats — surfaced before commit so future readers don't
mistake "Slice 1.12 GREEN" for "all of Q2 complete":**

1. **State-port coercion path is mechanically reachable but uncovered
   by fixture.** ~~The runtime loop iterates the contract's full input
   port map, which includes both state and aux input ports. The
   fixture is aux-only (`stateInputPort` undefined). A future fixture
   wiring a mismatched state port under a non-`bytes` layout
   (`matrix4x4-bytes`, etc.) would hit a gap: the lift adapter's
   `bytesToState` at `port-projection.ts:286-293` reconstructs without
   a length check, so a coerced payload of the wrong length for the
   target layout would produce a malformed state, throwing downstream
   when the legacy executor's own length assertion fires. Dormant
   because flag-on-only + no shipped spec + no fixture exercises it.
   Worth knowing when the first cipher actually wires mismatched
   state ports.~~
   **CLOSED 2026-05-24 (post-Phase-1 follow-up batch, per advisor's
   "preventive insurance" recommendation).** Added defensive throws in
   `bytesToState` (`matrix4x4-bytes` requires exactly 16 bytes;
   `bitvec` requires `ceil(bitLength/8)` bytes) AND in
   `auxPortBytesToValue` (`matrix-cm-4x4` and `preserve-input-variant`
   with `matrix4x4-bytes` source both require 16 bytes). All throws
   carry caveat-1 attribution ("See Slice 1.12 caveat 1 in
   docs/plans/universal-port-phase-1-slices.md") so a future
   mismatched-fixture failure has clear traceability. `bytes` layout
   stays length-agnostic per the Slice 1.2 polymorphic-port posture.
   Pinned by `tests/port-projection-coerce-defensive-throws.test.ts`
   (15 surfaces — happy paths, off-by-one, short, long, and the
   intentional `bytes`-variant negative pins). Caveat 1 stays
   important for Phase 3 (AES rebuild is matrix-layout-heavy); the
   throws are insurance for the first author who wires mismatched
   state ports under matrix layout.

2. **Q2's editor half is NOT in this slice.** Parent plan Q2 reads:
   "Editor flags mismatches with a red glyph + inspector explanation.
   Coercion appears as a visible trace step." Slice 1.12 delivers the
   second clause; the first clause (red glyph in the graph view on
   mismatched wirings, inspector explanation) depends on the sink-only
   edge model (Q-edges, decided 2026-05-23 but not implemented) +
   editor wiring UI that aren't shipped yet. Deferred until the
   editor wiring data model lands. **Stays deferred per the 2026-05-24
   advisor consult** — re-opening it now would mean designing two
   data-model pieces in service of one warning glyph; reopen when the
   sink-only edge model + editor UI ship.

3. **UI surfacing is plumbed-met, not demonstrated-met.** ~~Narrator
   registered + default frame view will render bytes-shape
   stateBefore/stateAfter pairs correctly. NOT covered by this slice:
   in-browser smoke of a `__coerce__` frame in the linear scrubber +
   timeline. `TraceTimeline.tsx` has a `⇄` glyph for `__rejoin__`;
   `__coerce__` falls through to the default. For a foundation slice
   with no live trigger path (`portedDispatchEnabled` defaults `false`
   + no shipped spec uses coercion), browser smoke isn't required.
   Live demonstration awaits the first port-native cipher with a
   mismatched fixture.~~
   **CLOSED 2026-05-24 (post-Phase-1 follow-up batch).** Added a
   `⚠` glyph for `__coerce__` synthetic frames parallel to `⇄` for
   `__rejoin__`. `TraceTimeline.tsx` extended with a new `coerce` badge
   kind (color: `var(--changed)` — the existing amber/warning token);
   tooltip names the port and "coerce (port byteLength mismatch)" so a
   learner hovering the badge maps glyph → meaning without scrubbing.
   Pinned by `tests/coerce-timeline-badge.test.tsx` (4 surfaces —
   single mismatch right-pad, multi-port leaf, badge position pin, and
   the exact-match short-circuit negative pin). The narrator at
   `src/ui/narration/coerce.tsx` already renders the disclosure when
   the user scrubs onto the frame; the badge is the additional
   loud-on-purpose surfacing so the frame is discoverable, not just
   reachable.

## Phase 1 exit criteria — **MET 2026-05-24**

- ✅ All 13 sub-slices green individually (1.0, 1.1, 1.2, 1.3, 1.4, 1.5,
  1.5b, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12 — 14 counting 1.5b's mid-
  course candidate-pick split).
- ✅ `npm run check` green at HEAD (1729 / 1729 tests).
- ✅ `portedDispatchEnabled: true` produces byte-equivalent traces for
  all five shipped cipher families (AES, Speck, Serpent, DES;
  AES-CBC, ECB) — pinned by Slice 1.11's 22-row frame-parity matrix
  AND every per-cipher dispatch test file.
- ✅ `PROJECTION_METADATA` side-map deleted from `port-projection.ts`
  (Slice 1.9).
- ✅ `narrationOverride?` field present on `StepLeaf` (placement
  refined from `StepNode` to `StepLeaf` — only leaves carry a `type`
  for the docs to override; Slice 1.10). No shipped spec uses it yet.
- ✅ `ctx.aux` dual-channel cut; lifted executors read aux only
  through input ports' synthetic `ctx.aux` populated from declared
  `auxReadPorts` bindings (Slice 1.9).
- ✅ Coercion mechanism (Q2 runtime half) plumbed and visible via the
  synthetic `__coerce__` frame (Slice 1.12). Editor half deferred to
  whenever the sink-only edge model + editor wiring UI ship.
- ✅ Post-1.12 follow-up batch (2026-05-24) closed caveats 1 + 3 —
  defensive throws in `bytesToState` / `auxPortBytesToValue` for
  matrix/bitvec layouts + `⚠` glyph in `TraceTimeline` for
  `__coerce__` frames. 1748/1748 tests, `npm run check` clean.
- Default `portedDispatchEnabled` remains `false`. Flipping to `true`
  as the shipped default is a follow-on slice (post-1.12) that decides
  the cutover gate — likely "all KATs match under ported + Phase 2
  SHA-2 ships." Not Phase 1.

**Phase 1 closure.** Every shipped step type runs under the universal-
port contract via `liftLegacyExecutor`; the `ctx.aux` dual channel is
gone; the projection metadata side-map is gone; per-spec narration
override is foundation-laid; mismatched wirings produce visible
deterministic coercion. Phase 2 (SHA-2 native + for-each-subgraph
node) is now unblocked.

## Out of scope for Phase 1

- **For-each-subgraph node.** Phase 2 (SHA-2 forces it).
- **TraceFrame port-info merge** (`PortedFrame` collapsing into
  `TraceFrame`). Either Phase 1's late sub-slice (1.13+) or Phase 2,
  TBD. The graph edge-model simplification (`core/graph.ts` →
  port-to-port edges, `inferStateEdges` becomes legacy-only fallback)
  depends on this and is Phase 1 work but not in this sub-slice plan.
- **`bigint` layout.** Defers to RSA / elliptic-curve future cipher.

## Operational notes

- **Commit cadence:** one commit per sub-slice. Co-author trailer per
  project convention.
- **Push cadence:** after each commit lands locally + check green.
- **Failure handling:** if a sub-slice gate fails, surface to user; do
  not silently continue. The previous green sub-slice is the rollback
  point.
- **Iterative slice review:** per memory `feedback_iterative_slice_review.md`,
  re-consult advisor before Slice 2 of any sub-slice batch that
  surfaces a non-trivial design surface (e.g., if Slice 1.0 forces a
  bitvec encoding spec change; if Slice 1.3 forces a `split-blocks`
  port shape design; if Slice 1.9 surfaces unexpected aux-read
  patterns).
- **Bisect plan:** Slice 1.1 introduces the discriminated-union
  registry but registers everything as `legacy` — that's the "baseline
  green" commit. If a later slice's frame-parity test goes red, bisect
  from there forward.
