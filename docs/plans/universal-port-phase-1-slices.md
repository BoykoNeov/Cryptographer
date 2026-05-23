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

### Slice 1.4 — AES lifted (port-per-roundkey)

Step types: `generic.shift-rows@1`, `generic.mix-columns@1`,
`generic.byte-substitution@1`, `generic.add-round-key@1`,
`aes.key-expansion@1`, `aes.key-expansion@2`.

`byte-substitution` and `add-round-key` already have throw-away metadata
in `PROJECTION_METADATA`; this slice moves them to co-located metadata
per Decision C.

Key-expansion uses **port-per-roundkey** per Decision B —
`meta.auxWritePorts(params)` returns N bindings sized by `params.rounds`.

**Gate:** frame-byte equivalence + FIPS-197 Appendix C KATs (3 key
sizes) pass for the ported path.

### Slice 1.5 — Chaining primitives lifted

Step types: `generic.xor-aux-into-state@1`, `generic.state-to-aux@1`.

`state-to-aux` is a one-to-one aux writer — straightforward.

**Gate:** AES-128 CBC end-to-end (NIST SP 800-38A §F.2.1 KAT) passes
under `portedDispatchEnabled: true`.

### Slice 1.6 — Speck lifted

Step types: `speck.key-schedule@1`, `speck.round@1`,
`speck.round-inverse@1`.

`bytes` state shape (4-byte Speck32/64 blocks). Key-schedule is
one-to-many writer per Decision B.

**Gate:** Speck32/64 KATs pass under both BE-paper and LE-NSA byte
conventions.

### Slice 1.7 — Serpent lifted (depends on Slice 1.0)

Step types: `serpent.key-expansion@1`, `serpent.bit-permutation@1`,
`serpent.add-round-key@1`, `serpent.sub-bytes@1`,
`serpent.linear-transform@1`, `serpent.inv-linear-transform@1`.

Includes the bitvec layout proven in Slice 1.0. Key-expansion per
Decision B (Serpent has 33 round subkeys).

**Gate:** Serpent KATs (3 key sizes) pass under ported.

### Slice 1.8 — DES lifted

Step types: `des.key-schedule@1`, `des.initial-permutation@1`,
`des.final-permutation@1`, `des.expand-R@1`, `des.xor-with-K@1`,
`des.s-boxes@1`, `des.p-permutation@1`.

Plus `feistel.toy-add-k@1` (test fixture).

`bytes` state shape. DES key-schedule writes 16 round keys per
Decision B. Body leaves of `feistel-round` containers run ported; the
rejoin frame stays as runtime synthesis (byte-identical between paths
for free).

**Gate:** DES KAT (NIST SP 800-17) passes under ported.

### Slice 1.9 — `ctx.aux` channel cut + side-map deleted

Per Decision A. The runtime stops passing the live `aux` map to lifted
executors; instead, it builds a synthetic ctx.aux populated only from
the input-port projections per metadata. Legacy executor signatures
unchanged.

`PROJECTION_METADATA` side-map in `port-projection.ts` is **deleted**.
All metadata now lives in `StepRegistration` entries.

**Gate:** all five cipher KATs pass under ported. Any "executor read aux
that wasn't projected" exception surfaces a missing
`meta.auxReadPorts` entry — fix and re-run.

### Slice 1.10 — `narrationOverride` field added to `StepNode`

```ts
type StepNode = {
  readonly kind: "step";
  readonly id: string;
  readonly type: string;
  readonly params: Json;
  readonly narrationOverride?: StepDocumentation;
};
```

**No schema bump** — structural typing keeps existing saved documents
valid. Renderer-side: `<StepNarration />` falls back to registry
documentation when the field is absent (the default for every existing
spec).

**Foundation-only.** No shipped spec uses the field yet. Phase 3's AES
rebuild from medium primitives is where it earns its keep. If Phase 3
discovers the field needs more (e.g., per-port narration), the field
shape revises then.

**Gate:** type compiles; existing tests pass; one new test asserts the
renderer falls back to registry doc when `narrationOverride` is
undefined.

### Slice 1.11 — Frame-parity test matrix

One file: `tests/runtime-ported-dispatch-frame-parity.test.ts`. Keyed
by cipher spec. Each `it`:

1. Build the spec with a known-answer plaintext + key.
2. Run twice: `runSpec(spec, registry, { …, portedDispatchEnabled: false })`
   and `runSpec(spec, registry, { …, portedDispatchEnabled: true })`.
3. **KAT sanity floor first:** assert `trace.finalState.bytes` matches
   the published ciphertext. A failure here is a louder signal than a
   1389-frame deep-equality miss.
4. **Then:** `expectFramesByteEqual(legacyTrace.frames, portedTrace.frames)`
   — full frame stream, **no filter**. Iterate / feistel-rejoin frames
   are byte-identical for free.

Coverage: AES-128/192/256, AES-128 ECB, AES-128 CBC, Speck32/64 ×2
conventions, Serpent-128/192/256, DES (8 cipher specs total).

**Gate:** all 8 frame-parity assertions green.

### Slice 1.12 — Coercion mechanism round-tripped

Q2 of the parent plan: warn-and-run with right-pad / truncate-from-right.
Wire a deliberately mismatched test fixture (one port declares 16-byte
input, source produces 8 bytes; another declares 4-byte, source produces
8 bytes). Assert:

- Right-pad: source 8 bytes → input becomes 16 bytes (8 source + 8 zeros).
- Truncate-from-right: source 8 bytes → input becomes 4 bytes (first 4
  of source).
- A trace step surfaces the coercion (e.g., as a synthetic frame or as
  a `coercionApplied: { mode, sourceLen, targetLen }` field on the
  affected frame's metadata — exact mechanism TBD in slice prep).

**Gate:** coercion assertions green; no behavior change for any shipped
spec (mismatch is opt-in via the fixture).

## Phase 1 exit criteria

- All 13 sub-slices green individually.
- `npm run check` green at HEAD.
- `portedDispatchEnabled: true` produces byte-equivalent traces for all
  five shipped cipher families (AES, Speck, Serpent, DES; AES-CBC, ECB).
- `PROJECTION_METADATA` side-map deleted from `port-projection.ts`.
- `narrationOverride?` field present on `StepNode`; no spec uses it yet.
- `ctx.aux` dual-channel cut; lifted executors read aux only through
  input ports.
- Default `portedDispatchEnabled` remains `false`. Flipping to `true` as
  the shipped default is a follow-on slice (post-1.12) that decides
  the cutover gate — likely "all KATs match under ported + Phase 2 SHA-2
  ships." Not Phase 1.

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
