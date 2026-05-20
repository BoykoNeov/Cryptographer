# DES + branching primitive — first Feistel cipher

> **Status: Phases 1–5 shipped 2026-05-19 / 2026-05-20.** Commits
> `91f143d` (P1 oracle), `6a046d0` (P2 primitive + toy), `be0bb6a`
> (P3 step types), `7b584f3` (P4 selector wiring), `9d16c95` (P5-pre
> StepList walker), `43703e9` (P5c rejoin view), `ef1cd92` (P5e DES
> key schedule), `1542e79` (P5a track-context), `2c7508c` (P5b mini
> diagram), `dcf291f` (P5d round-key panel coverage), and the present
> commit (P5f scrubber badges). Phase 6 (graph-view branched layout +
> manual smoke) pending.
>
> **Phase 5 sub-commit order: 5-pre → 5c → 5e → 5a → 5b → 5d → 5f**
> (fix-broken-UX-first per advisor: 5c and 5e replaced previously
> meaningless FrameStateView renders; 5-pre fixed a sidebar crash on
> DES; the rest are additive on top of working baseline). Phase 5d
> shipped with no code change — verified the existing 16-byte fallback
> already renders DES's 6-byte K_i ribbons correctly. Bit-grouped
> unfold deferred per advisor's "don't over-build" guidance.
>
> Originally drafted 2026-05-19; architecture direction (DES first +
> true branching, per Path C) approved by user. Multi-phase: 6 phases,
> ~3000–5000 lines including tests. The branching primitive is a load-bearing
> architecture change (touches `core/types.ts`, `runtime.ts`, `graph.ts`)
> deliberately designed-once against DES's harder constraints so it carries
> the rest of the Feistel family (TEA/XTEA, 3DES, eventually Twofish) without
> a representation refactor.

The first Feistel cipher in the project. Until now every shipped cipher (AES,
Speck, Serpent) has had a linear executor contract `(state, params) → state`
that lets the runtime treat consecutive same-parent leaves as sharing state.
Feistel breaks that — L and R halves evolve independently inside a round
body — so this plan introduces a new spec primitive AND wires the first
cipher to use it.

## Context

### Why DES, not TEA

The simpler-cipher-first pattern (AES → Speck → Serpent) is a bad fit here.
TEA's F function is a single ARX expression with no internal sub-structure;
shipping TEA as the first Feistel would let us dodge the F-decomposition
question that DES (and every other "real" Feistel) forces. Specifically:

| Question | TEA stresses? | DES stresses? | Blowfish stresses? |
|---|---|---|---|
| L/R branching visible | ✅ | ✅ | ✅ |
| F-decomposition with real spine | ❌ | ✅ | ✅ |
| Key-dependent components | ❌ | ❌ | ✅ |
| Self-referential key schedule | ❌ | ❌ | ✅ |
| n-way Feistel | ❌ | ❌ | ❌ (Twofish) |

DES is the sweet spot: it forces L/R + F-decomposition (the questions we need
to answer for the family) without piling on key-dependent S-boxes and
self-referential key schedules (orthogonal Blowfish concerns that would
muddy the design). It also reuses the bit-permutation machinery already
written for Serpent IP/FP, and ships with clean published KATs
(FIPS 46-3 + NIST CAVS).

TEA / XTEA become cheap follow-up commits once the primitive is in.

### Why true branching, not tuple state or aux-mediated

Walk a DES round body under each candidate representation:

**Aux-mediated** (state passthrough, L/R held in aux): 4 of 5 F-leaves
have state-passthrough, the spine through F is flat. Pedagogically wrong
for the most iconic Feistel; replaces the spine-as-headline-narrative
with an aux thicket.

**Tuple state** (new `feistel-pair-64` state shape): L/R cleanly labeled
between rounds, but F's internals (E-expand, S-boxes, P-permute) still
have to live in aux because state is the L|R tuple. Same flat-spine
problem inside F.

**True branching** (new spec primitive): the round body forks into a
left track (carries L unchanged) and a right track (runs F on R). Inside
the right track, state IS the 32-bit value being processed; E-expand
changes its shape (32→48 bits), S-boxes change it again (48→32),
P-permute preserves it. **Spine threads continuously through F's
internals.** Rejoin combines tracks via `L ← L XOR F_out, swap`.

True branching is the only option that makes DES's textbook diagram
literal on the canvas: a fork, two parallel tracks, F-computation
visible on R, rejoin at the swap. That diagram is *why* DES is taught
the way it is — flattening it would forfeit the cipher's pedagogy.

### Scope

Single-block DES (no ECB/CBC) — both encrypt and decrypt directions.
Branching primitive in core, DES step types, UI integration, KAT against
FIPS 46-3 Appendix B test vectors.

Out of scope: 3DES (mechanical follow-up once DES ships), DES ECB/CBC
(after the modes story settles for variable-block ciphers), TEA/XTEA
(cheap follow-ups under the same primitive), Twofish/Blowfish (n-way
Feistel + key-dependent S-boxes — separate plans), codegen.

## Approach

### Process: iterative slice review

Each of the 6 phases below ships as its own commit. **Before starting
the next phase, re-consult `advisor()` with the current state of the
codebase + the next phase's design.** This plan is too long-horizon to
front-load every decision — each phase produces real lessons (a
collapsed-edge rendering surprise, a port-spread tuning need, a
narration shape that doesn't fit the registry) that should inform the
next phase's design before code lands.

This is a project-wide pattern for multi-phase architectural plans, not
DES-specific — see `[[feedback-iterative-slice-review]]`.

### Phase 1 — verification oracle — SHIPPED 2026-05-19 (`91f143d`)

Per `[[feedback-crypto-verification]]`: before pinning ANY KAT, get an
external oracle running. Two viable choices:

- `node-forge` (npm, MIT) — has DES in its symmetric-cipher module.
- `pycryptodome` (Python) — used for previous cipher verifications.

Pin the FIRST KAT against the oracle's output, not against
FIPS 46-3 cited text. The published KAT
(`PT=0123456789abcdef, K=133457799bbcdff1 → CT=85e813540f0ab405`) is
the target; the oracle verifies our intermediate decomposition (IP
output, per-round L/R, FP output) matches the canonical reference.

A short verifier script lives at `scripts/verify-des.mjs` (or similar)
and is not shipped with the app — its only purpose is to produce the
intermediate KATs the tests pin against.

### Phase 2 — branching primitive in core — SHIPPED 2026-05-19 (`6a046d0`)

The headline architecture change. Adds one new spec node kind, runtime
support for executing it, and graph-derivation handling. No DES-specific
code in this phase — validated against a TOY Feistel (a 2-step round
where F is "XOR with constant key") that exercises the primitive
end-to-end without DES's complexity.

#### Data model (`core/types.ts`)

New node kind `feistel-round` alongside `step`, `group`, and `iterate`:

```ts
export type BranchTrack = {
  /** Byte indices from the input state that seed this track. */
  readonly inputBytes: readonly number[];
  /** Step nodes operating on the track's own state. May be empty
   *  (the passthrough case — typically the L track). */
  readonly children: readonly StepNode[];
};

/**
 * Named combine ops. Each is a 4-arg function over the per-track input
 * AND output snapshots: `(tracks_in, tracks_out) → new_state_bytes`.
 * The 4-arg shape is critical — textbook Feistel's `new_L = R_in` reads
 * the ORIGINAL right-track input, not its post-F output, so a combine
 * that sees only `tracks_out` can't reconstruct it.
 *
 * Pre-defined kinds cover the shipped use cases. Each is documented
 * with its (L_in, L_out, R_in, R_out) → (new_L, new_R) formula:
 *
 *   - "feistel-standard":     (R_in, L_in XOR R_out)
 *     Classic Feistel with swap. DES rounds 1..15.
 *   - "feistel-no-swap":      (L_in XOR R_out, R_in)
 *     Classic Feistel WITHOUT the post-round swap. DES round 16
 *     (and every cipher's "last round" by Feistel convention).
 *   - "feistel-add-into-left":  (L_in + R_out, R_in)
 *     One half of TEA's cycle. Modular byte-add into L; R unchanged.
 *   - "feistel-add-into-right": (L_in, R_in + L_out)
 *     The other half of TEA's cycle. Modular byte-add into R; L unchanged.
 *
 * Adding new ops is a kind-tag bump (no schema break since `CombineKind`
 * is a string union over `string` at the JSON layer).
 */
export type CombineKind =
  | "feistel-standard"
  | "feistel-no-swap"
  | "feistel-add-into-left"
  | "feistel-add-into-right";

export type FeistelRoundGroup = {
  readonly kind: "feistel-round";
  readonly id: string;
  readonly label?: string;
  /** Tracks in order. 2-track for binary Feistel (the only shipped
   *  case); future n-track ciphers (Twofish, 4-way) extend by adding
   *  entries here without a schema migration. The runtime + combine
   *  ops today assume `tracks.length === 2`; n-track unlocks when a
   *  future cipher adds the corresponding combine kinds. */
  readonly tracks: readonly BranchTrack[];
  readonly combineKind: CombineKind;
};

export type StepNode = StepLeaf | StepGroup | IterateGroup | FeistelRoundGroup;
```

Tracks declare which input bytes they consume via `inputBytes` rather
than auto-splitting at the midpoint. This keeps the primitive
representation-agnostic — a 4-way Feistel (Twofish) just declares four
tracks with non-overlapping byte ranges and registers a new
`feistel-4way-*` combine kind.

**Why 4-arg combine, not 2-arg-with-swap-flag**: a 2-arg combine over
post-track-output state can't reconstruct `new_L = old_R` (textbook
Feistel) because the R track's children replaced old-R with F(old-R).
The 4-arg model holds both input and output snapshots so the combine
can reference either. This also generalizes cleanly to Lai-Massey
(reads `L_in`, `R_in`, AND a parallel-computed F-value) without a
data-model bump.

#### Layer 0 — synthetic nodes, track naming, inspector row order

Three small but load-bearing data-model decisions for the primitive:

**Track naming**. `BranchTrack` gains an optional `name?: string` field
defaulting to the track's index in the parent's `tracks[]` array.
`TraceFrame.branchPath` is a `readonly string[]` of track names (not
indices) so the path remains readable across n-track futures
(`["upper-right"]` vs `["t2"]`). DES specs declare `name: "L"` and
`name: "R"` explicitly.

**Rejoin synthetic node**. The rejoin is rendered as a graph node
(click-target for the 4-arg combine inspector) but is NOT a spec
node. `GraphNode` gains an optional discriminator field
`synthetic?: "rejoin"` (analog to Slice 6's `blockChipOf`). The id is
deterministic: `{roundId}:rejoin`. Renderer + click-routing +
inspector all dispatch off `synthetic === "rejoin"`. The frame
emitted at rejoin uses the same `:rejoin` suffix on `stepId`
(matching the `:b{i}` / `:t{name}` convention).

**Split anchor**. NOT a synthetic node. The "split" is a virtual edge
endpoint — the state edge entering the round fans into N edges, one
to each track's first leaf. No new node id; no inspector entry.
Avoids node-count pollution and matches the iterate primitive's
treatment of "entry into the body" (no synthetic).

**Inspector row order on combine kinds**. `CombineKind` metadata
includes an `inspectorRowOrder: readonly ("L_in"|"L_out"|"R_in"|"R_out")[]`
ordering the 4 snapshots in the inspector to match the combine's
formula left-to-right. For `feistel-standard` (formula: `new_L = R_in,
new_R = L_in ⊕ R_out`), the order is `["R_in", "L_in", "R_out", "L_out"]`
— reading-order, not track-name-order. Pedagogical readability win.

**Frame-preservation test**. The `:t{name}` track suffix must thread
through `setTrace`'s stepId-matching the same way `:b{i}` does today
(per `[[feedback-frame-preservation]]`). A test in
`tests/frame-preservation-feistel.test.ts` pins this.

#### Runtime (`runtime.ts`)

`feistel-round` walks like `iterate` but two-tracks-in-parallel:

1. Slice input state by each track's `inputBytes` into a track-local
   `BytesState`.
2. Recursively walk each track's children with a track-tag in the
   per-frame metadata (`branchPath: ["left" | "right"]`, mirrors how
   `blockIndex` works).
3. Combine tracks per `combineOp` + `combineInto`. The rejoin emits
   ONE frame (kind = pseudo-leaf), stateBefore = pre-combine-snapshot,
   stateAfter = combined.
4. If `postSwap`, emit one more frame for the swap.
5. Resume parent-scope state thread from the rejoined value.

Per-iteration step ids gain a track suffix `:t{name}` when inside a
branch (analogous to `:b{i}` for iterates; uses the track's `name`
field — `"L"` / `"R"` for DES — not its index). Frame metadata grows
by one optional field:

```ts
type TraceFrame = {
  // ...
  readonly branchPath?: readonly string[]; // ordered list of track names
};
```

#### Graph derivation (`graph.ts`)

The `feistel-round` becomes a `ContainerNode` of a new kind
(`"feistel"` joins `"group"` / `"iterate"`). Two child-id lists
(`leftChildIds`, `rightChildIds`) instead of one. Rejoin + swap are
synthetic chip nodes the renderer can draw at the right edge.

State-spine inference rules grow one branch-aware case:

- Within a track: consecutive same-parent leaves share state (today's rule).
- Across tracks: NO state edge (tracks are independent).
- Into the round: the state edge entering the round fans into N virtual
  edges, one per track, each landing on the track's first leaf. No
  synthetic "split" node — the fan-out is realized at edge-rendering
  time only.
- Out of the round: state edge from the rejoin synthetic node →
  successor. Rejoin IS a node (clickable for the 4-arg inspector); see
  Layer 0 above.
- **Replica spine-successor tiebreaker**: when `replicateHighFanoutSources`
  picks a spine-replica for a source whose consumers span multiple
  tracks (e.g., `key-expansion` feeding both pre-F XOR in L AND F's
  XOR-K in R for some future cipher), prefer the track with NON-EMPTY
  children. Avoids 16 spine-replicas stacking above an empty L-track
  in DES. One-line rule added next to the existing first-state-consumer
  heuristic.

These rules are added in `inferStateEdges` + `replicateHighFanoutSources`,
NOT as Feistel-specific hooks — the design intent is that future branched
primitives (parallel hashing, AEAD's two-output shape) reuse the same
machinery.

**Collapsed-`feistel-round` edge fanning**: when a round container
collapses to a single chip, edges TOUCHING the round (aux from
key-schedule into per-track leaves, state spine through the round)
need to retarget at the collapsed chip — analogous to Slice 6's
`expandCollapsedIterates` and the spine-through-iterate fix (commit
`9029ab4`). A new pure transform `collapseFeistelRoundEdges` in
`core/graph.ts` runs alongside the existing collapse pipeline,
fanning per-leaf edges to the round chip while preserving auxKey
identity for inspector dispatch.

#### Test: toy Feistel

Before any DES code lands, a 4-byte-block "toy Feistel" exercises the
primitive end-to-end. **F must be asymmetric** (NOT self-inverse) so
the combine model is genuinely tested — `F(R, K) = R XOR K` would
round-trip even with a buggy combine (since `x XOR x = 0`):

```ts
// 2-round toy: F(R, K) = (R + K) mod 256 per byte. State = 4 bytes (2-byte halves).
{
  kind: "feistel-round",
  id: "round.1",
  tracks: [
    { inputBytes: [0, 1], children: [] },                                 // L track (passthrough)
    { inputBytes: [2, 3], children: [                                     // R track (F-computation)
      { kind: "step", id: "round.1.add-K", type: "feistel.toy-add-k@1", params: {} }
    ]},
  ],
  combineKind: "feistel-standard",
}
```

KAT pinned against a manual hand-computation: encrypt under a chosen
key, get a specific 4-byte ciphertext, decrypt round-trips. The
asymmetric F means a swapped combine produces a DIFFERENT ciphertext,
caught by the KAT assertion. Tests also pin the trace structure
(frame count, branchPath stamps, rejoin synthetic frame).

### Phase 3 — DES step types — SHIPPED 2026-05-19

DES needs 7 new step types (the optional `des.toggle-parity-bits@1` was
skipped — explicit decision, not an oversight). **Correction to the
original draft**: bit-permutation helpers do NOT reuse
`src/steps/serpent-bit-ops.ts`'s `applyBitPermutation`. Serpent's helper
is hardcoded to 16-byte input AND uses LSB-first numbering; DES uses
MSB-first AND varies its buffer length across 4/6/8 bytes. The fix is
option (b) from the advisor's pre-Phase-3 review: a new
`src/steps/des-bit-ops.ts` mirrors the Phase-1 oracle's `bitOf` /
`permute` / bit-array helpers verbatim (MSB-first, size-agnostic),
keeping Serpent's hot path untouched and the bit-numbering convention
literal at the call site.

| Step type | What it does | Input shape | Output shape |
|---|---|---|---|
| `des.initial-permutation@1` | IP, 64 bits → 64 bits | `bytes` (8) | `bytes` (8) |
| `des.final-permutation@1` | FP = IP⁻¹ | `bytes` (8) | `bytes` (8) |
| `des.expand-R@1` | E, 32 → 48 bits | `bytes` (4) | `bytes` (6) |
| `des.xor-with-K@1` | XOR with `aux[K_i]` | `bytes` (6) | `bytes` (6) |
| `des.s-boxes@1` | 8 parallel 6→4 S-boxes | `bytes` (6) | `bytes` (4) |
| `des.p-permutation@1` | P, 32 bits → 32 bits | `bytes` (4) | `bytes` (4) |

**Note on `StepShapeContract` and byte-length**: today's
`StepShapeContract` declares `input: "bytes"` without specifying the
expected byte count. E-expand's `bytes(4) → bytes(6)` and S-boxes's
`bytes(6) → bytes(4)` are correct at runtime (each executor throws on
wrong-length input) but `validateShapes` won't catch a misordered DES
spec at edit-time. This plan **accepts runtime-only validation for
byte-length** as a deliberate trade-off: extending the contract to
carry length would touch every shipped step type's doc block (~30
entries), and the pre-Run error surface already catches mis-wires
when the user clicks Run. A future polish slice could extend the
contract; not blocking for DES.
| `des.key-schedule@1` | PC-1 + 16 shifts + PC-2, writes `roundKey.0..15` | n/a (aux-only) | passthrough |
| `des.toggle-parity-bits@1` | Optional pedagogy: strip 8 parity bits | `bytes` (8) | `bytes` (8) |

Each step ships with executor + doc + `shapeContract` + ParamEditor
block (per `src/steps/CLAUDE.md`) + narration registry entry + provenance
registry entry. The 8 S-boxes are constants from FIPS 46-3 Appendix A,
stored in `src/ciphers/des-constants.ts`.

The cipher spec wires the round body inside the `feistel-round`. Rounds
1..15 use `combineKind: "feistel-standard"`; round 16 uses
`combineKind: "feistel-no-swap"` (the textbook "no swap on final round"
exception, made visible in the spec tree rather than hidden in the
runtime):

```ts
// Round 1 (template for rounds 1..15):
{
  kind: "feistel-round",
  id: "round.1",
  tracks: [
    { inputBytes: [0,1,2,3], children: [] },             // L track (passthrough)
    { inputBytes: [4,5,6,7], children: [                  // R track (F-computation)
      { kind: "step", id: "round.1.expand-R",  type: "des.expand-R@1", params: {} },
      { kind: "step", id: "round.1.xor-K",     type: "des.xor-with-K@1", params: { roundKeyAux: "roundKey.0" } },
      { kind: "step", id: "round.1.s-boxes",   type: "des.s-boxes@1", params: { sboxes: DES_SBOXES } },
      { kind: "step", id: "round.1.p-permute", type: "des.p-permutation@1", params: { table: DES_P } },
    ]},
  ],
  combineKind: "feistel-standard",
}

// Round 16 (identical body, different combineKind):
{
  kind: "feistel-round",
  id: "round.16",
  tracks: [ /* ... same shape ... */ ],
  combineKind: "feistel-no-swap",
}
```

16 rounds wrapped in a `group` ("rounds") between IP and FP at the top
level. The final round's distinct `combineKind` is **visible in the
spec tree** — the user can click round 16 and see why DES decryption
works (the no-swap last round makes the cipher its own inverse under
key-reversal). Decrypt-spec consumes round keys in reverse order
(round 16's key first); the math otherwise is symmetric, no separate
`s-boxes-inverse` etc.

### Phase 4 — UI wiring + per-step Param/Narration/Provenance

Mechanical wiring following the Speck precedent
(`docs/plans/speck.md` §"UI / store integration"):

1. **`stores/cipher.ts`** — `Cipher` union grows to include `"des"`.
   `DEFAULT_KEY_BYTES_BY_CIPHER["des"] = 0x133457799bbcdff1` (FIPS
   Appendix B test vector). `DEFAULT_PT_BYTES_BY_CIPHER["des"] =
   0x0123456789abcdef`. Label: "DES".
2. **`stores/spec.ts`** — `defaults["des"] = { "single-block": { encrypt, decrypt } }`.
3. **`stores/cipher-mode.ts`** — `SUPPORTED_CIPHER_MODES_BY_CIPHER["des"] = ["single-block"]`.
4. **Padding selector** — disabled when `cipher() === "des"`, same
   pattern as Speck. The AES `load-block`/`store-block` overlay is
   16-byte-only, so the existing `isAesCipher` guard already catches
   DES correctly.
5. **App.tsx initial-state seeding** — `spec.inputs.plaintext.shape ===
   "bytes"` already lights up for DES (no AES overlay path).
6. **ParamEditor** — one new `Match` arm per step type. The 8-S-box
   block is the heaviest: collapsed `<details>` wrapping 8 sub-tables
   (each 64 entries arranged 4 × 16). Pattern copies Serpent's
   8-S-box block.
7. **Provenance + narration** — register one entry per DES step type
   plus one per `CombineKind` (rejoin synthetic frames are not leaves
   — see Layer 0). The 8 S-boxes get per-S-box narration units; the
   bit permutations reuse Serpent's bit-level narration pattern
   (`[[feedback-bit-level-narration-pattern]]`): one structural
   overview + N per-output-byte drill disclosures. The rejoin
   narrator includes a one-sentence callout for the cross-row
   provenance optic ("the swap is why this highlight crosses rows")
   so users don't misread the cross-track overlay as a bug.

### Phase 5 — Linear-mode UI components

Six new linear-panel components, each landing as its own commit so
the iterative-slice-review process gets clean checkpoints. All six
are independently testable against a DES trace fixture; the manual
smoke pass at the end of Phase 6 exercises them together.

#### 5a — `FeistelTrackContext.tsx` (track-context panel)

Renders only when `frame.branchPath` is set. Three sections:
**Round entry** (8 bytes split into L | R), **Right now** (current
track's evolving state highlighted; other track shown in muted style),
**Round output** (post-rejoin L' | R'). Round entry/exit are read
from the round's enclosing frames; current state is read from
`frame.stateAfter`. Bytes color-coded per track (subtle accent),
provenance overlay carries over from existing cell-overlay machinery.
~150 lines. Tests pin: panel renders only inside a branchPath,
round-entry computed correctly across all 16 DES rounds, color
coding stable when scrubbing across tracks.

#### 5b — `FeistelMiniDiagram.tsx` (mini textbook diagram)

A compact SVG (~180×220px) rendering the Feistel round's *abstract
algorithm* — split, F-stack, XOR, swap — with the current frame's
position highlighted. Live cross-reference: clicking any node in the
F-stack scrubs the trace to that leaf; the K_i label highlights in
sync with the round-key panel's ribbon.

The pedagogical headline: graph view shows spec topology; this
diagram shows the abstract Feistel structure. Side-by-side they
teach different lessons.

Cipher-agnostic — driven by the active `feistel-round`'s `tracks` +
`combineKind` rather than hardcoded DES geometry. TEA/XTEA/Twofish
get the same component without modification (combine kind label
changes, F-stack shape adapts to the track's children count).

~250 lines (SVG layout + click routing + state-driven highlight).
Tests pin: SVG renders for any `feistel-round` spec, click on a
diagram node updates the scrubber, K_i highlight syncs with the
round-key panel.

#### 5c — `RejoinFrameView.tsx` (4-arg combine display)

Replaces `<FrameStateView />` when the scrubber lands on a rejoin
synthetic frame. Shows the combine kind name + formula at the top,
4 snapshot rows in **formula order** (per `CombineKind.inspectorRowOrder`
— see Layer 0), result at the bottom. Cross-cell provenance:
hovering a byte in `new_R` lights up its source bytes in `L_in`
AND `R_out` (the XOR pair).

`L_out` shows even when the combine doesn't consume it (e.g.,
`feistel-standard`) — pedagogy: "the L track ran its body; the
output is available but this combine doesn't use it."

~120 lines. Tests pin: row order matches `inspectorRowOrder`,
provenance overlay highlights correct source cells per combine
kind, "unused" L_out rendered in muted style.

#### 5d — `RoundKeyPanel` DES 48-bit extension

Today's panel reads `prefix.N` aux entries and renders Uint8Array
ribbons. DES round keys are 48 bits (6 bytes) — not byte-aligned
relative to AES's 128-bit blocks.

Hybrid display: default to 6 hex bytes per ribbon (matches existing
rhythm); per-ribbon expand-bits affordance unfolds the bit-level
structure showing the 48 bits in 8 groups of 6 (the S-box input
grouping). When unfolded, hovering an S-box output cell in the
current frame lights up its 6 input bits in the K_i ribbon.

~80 lines (extends `RoundKeyPanel.tsx`; new sub-component
`BitGroupedRibbon.tsx` for the unfold view). Tests pin: ribbon
default shows 6 hex bytes per round key, unfold renders 48 bits
in 6-bit groups, hover sync with S-box provenance.

#### 5e — `DesKeyScheduleSimulator` (key-schedule explorer)

Replaces `<FrameStateView />` for `des.key-schedule@1` frames. Per-
round table:

| Round | Cumulative shifts | C_i (28 bits) | D_i (28 bits) | K_i = PC-2(C_i ‖ D_i) (48 bits) |

Each row clickable → scrubs to that round's first body frame. Same
pattern as AES's `KeyScheduleExplorer` (RotWord→SubWord→Rcon→XOR
chain), adapted to DES's PC-1 → 16 shifts → PC-2 chain.

~200 lines (in `src/ui/key-schedule-sim/des.ts`; the explorer
component itself ~120 lines of those). Tests: per-round simulator
output equals the executor's `aux[roundKey.N]` values byte-for-byte
(parity test analogous to AES's), all 16 rounds enumerated.

#### 5f — Track membership badge in scrubber timeline

Subtle per-frame markers in the existing scrubber timeline indicating
track membership: tiny `L`/`R` chips above standard markers for
in-track frames, `⇄` for rejoin synthetic frames, plain marker for
root-scope frames (IP, FP, key-schedule). Lets users scan ahead/back
without reading frame headers.

~50 lines (extends the scrubber timeline component; CSS for the
chips). Tests pin: chip rendered iff `branchPath` is set, `⇄` chip
appears for rejoin frames, no chip for root-scope frames.

### Phase 6 — Graph view branched layout + smoke

Render-time work for the `feistel-round` container on the graph
canvas. Builds on the existing `iterate` rendering machinery —
branches are "iterate-like" in that they're a structural container
with internal spine — but renders two parallel tracks stacked
vertically instead of N sequential block chips.

#### Layout decisions (user-approved 2026-05-19)

- **Track orientation**: tracks stacked vertically inside the round
  container, each track flowing left-to-right. L on top, R on bottom.
  Container height ≈ 2× row height + padding; width = max(track widths).
  Rationale: matches canvas's global left-to-right flow; textbook
  diagram's top-to-bottom flow rotates 90° clockwise to top-vs-bottom
  rows. Same semantics, different coordinates.
- **Rejoin chip**: dedicated chip at the container's right edge,
  spanning the full height of both track rows. Both tracks end with
  arrows feeding into the chip; one arrow exits to the next spec
  node. Glyph indicates combine kind (`⇄` swap, `→` no-swap,
  `+L`/`+R` for add-into variants). The chip's label is the combine
  kind name; the formula renders only in the inspector (Layer 5
  detail). Port-spread machinery (`buildConsumerPortAssignment`'s
  `sideOf` callback from `[[project-crooked-round-arrow-q1]]`) handles
  the two-arrows-into-one-chip case via distinct `targetYOffset`
  values per source track.
- **Collapse**: single round-labeled chip ("Round 3"), matching how
  groups would collapse. Chevron toggles. The two-row-pill option
  (showing L/R summaries when collapsed) is deferred — would need
  per-cipher F-summary functions and adds a new collapsed-shape
  vocabulary. Revisit if Phase 6 smoke shows users want at-a-glance
  detail when collapsed.
- **Drop semantics**: per-track gutters (standard Slice 5 set:
  at-start, between-leaves, at-end) inside each track row. Container
  header stays click-to-collapse (NOT a drop target — there's no
  unambiguous default track for round-level drops). Inter-track gap
  is inert. Rejoin chip is inert as a drop target (consistent with
  synthetic endpoint pills per Slice 1). When a draggable hovers the
  container border or inter-track gap, show NO highlight — the
  absence of feedback communicates "drop into a track row, not into
  the round itself."

#### Smoke pass

Manual browser pass on:
- Forward DES with FIPS Appendix B vector — visual check L/R tracks,
  F-internals visible on R, rejoin and swap render correctly.
- Backward DES (decrypt) with same key — round keys consumed in
  reverse.
- Save → reset → Load with a `feistel-round` in the spec.
- URL share round-trip.
- Param edit on an S-box cell — trace re-runs, narration updates.
- Drop a new step into a `feistel-round` track via the palette
  (regression check: drop-anchor + drop-gutter logic handles the
  new container kind).
- Collapse round 3 — verify edges still render correctly
  (`collapseFeistelRoundEdges` from Phase 2 working end-to-end).
- Scrub through the trace — verify track context panel, mini
  diagram highlight sync, rejoin view, key-schedule explorer, and
  timeline badges all render and update together.

### Tests

- **`tests/des-vectors.test.ts`** — FIPS 46-3 Appendix B KAT
  (`PT=0123456789abcdef, K=133457799bbcdff1 → CT=85e813540f0ab405`),
  plus 2–3 NIST CAVS vectors. Frame count + structure assertions.
- **`tests/des-decrypt.test.ts`** — inverse KAT + round-trip on
  random 8-byte inputs.
- **`tests/feistel-primitive.test.ts`** — toy Feistel from Phase 2.
  Pins primitive semantics independent of DES.
- **`tests/feistel-graph.test.ts`** — graph-derivation assertions for
  the new container kind: state-spine rules, track-bounded edges,
  rejoin synthetic node placement.
- **`tests/des-roundtrip-document.test.ts`** — save→load on a spec
  containing `feistel-round` nodes. **Schema migration (revised at
  Phase 2 review, 2026-05-19)**: original plan bumped
  `CipherDocument.schemaVersion` 1 → 2 in Phase 2. Per advisor +
  user, the bump is **deferred to Phase 3** instead — Phase 2's
  `feistel-round` node kind exists only in the toy spec (not in the
  cipher selector), so AES docs saved during Phases 2–3 stay byte-
  identical to v0.5.0 and remain readable by v0.5.0 builds. Phase 2
  added `FeistelRoundGroupSchema` to the document-schema discriminated
  union without changing `CURRENT_SCHEMA_VERSION`; the toy spec round-
  trips through that path in `tests/document-roundtrip.test.ts`.
  Phase 3 will bump to schema 2 when DES enters the cipher selector
  and users can actually save a feistel-round-bearing doc.
- **`tests/state-shape-contracts.test.ts`** — extend the existing
  walker to descend into all of `feistel-round.tracks[*].children`.
  Coverage gate stays at 100%.
- **`tests/narration-registry-contract.test.ts`**, **`tests/provenance-registry-contract.test.ts`** — same extension; additionally register entries for each `CombineKind` (rejoin frames are not leaves but need narration + provenance).
- **`tests/frame-preservation-feistel.test.ts`** — pins that the
  `:t{name}` track suffix threads through `setTrace`'s stepId-matching
  the same way `:b{i}` does. Required by `[[feedback-frame-preservation]]`.
- **`tests/des-key-schedule-parity.test.ts`** — `DesKeyScheduleSimulator`
  output (per-round C_i / D_i / K_i) equals executor's
  `aux[roundKey.N]` byte-for-byte for all 16 rounds.
- **Linear-mode component tests** — one per Phase 5 component:
  `feistel-track-context.test.tsx`, `feistel-mini-diagram.test.tsx`,
  `rejoin-frame-view.test.tsx`, `round-key-panel-des.test.tsx`,
  `des-key-schedule-explorer.test.tsx`, `scrubber-timeline-badges.test.tsx`.
- **Branch-aware tests for existing graph features**: replication,
  arrow bundling, source-color coding, draggable replicas. Run as a
  regression check; expect 0–2 follow-up patches.

### Commit shape

Six commits, one per phase, plus six sub-commits inside Phase 5 (one
per linear-mode component). The iterative-slice-review process means
each commit gets an advisor pass against the current state of the
codebase BEFORE the next phase's work starts.

1. **Phase 1**: verification oracle script + initial KAT pinning (no
   shipped code). ~300 lines (oracle script + KAT capture).
2. **Phase 2**: branching primitive + toy Feistel + Layer 0 data
   model + frame-preservation test (no DES). ~1200–1500 lines.
3. **Phase 3**: DES step types + spec + KAT/roundtrip tests.
   ~1500 lines.
4. **Phase 4**: cipher selector wiring + ParamEditor blocks +
   narration/provenance for DES step types + combine-kind narrators.
   ~700 lines.
5. **Phase 5**: six sub-commits, one per linear-mode component
   (5a–5f). ~850 lines total.
6. **Phase 6**: graph view branched layout + comprehensive manual
   smoke. ~700 lines + smoke notes.

Each commit is independently shippable (passes `npm run check`). The
primitive in Phase 2 ships with the toy spec ONLY — registered in
`default-registry.ts` so the test reaches it, but not in the cipher
selector, so users can't drive it through the UI until Phase 4.

## Critical files

**New:**

- `src/steps/des-initial-permutation.ts` (+ `des-final-permutation.ts`)
- `src/steps/des-expand-r.ts`
- `src/steps/des-xor-with-k.ts`
- `src/steps/des-s-boxes.ts`
- `src/steps/des-p-permutation.ts`
- `src/steps/des-key-schedule.ts`
- `src/ciphers/des-constants.ts` (IP, FP, E, P, 8 S-boxes, PC-1, PC-2, shift schedule)
- `src/ciphers/des.ts` + `src/ciphers/des-decrypt.ts`
- `src/ui/components/FeistelTrackView.tsx` (graph view; in-container layout)
- `src/ui/components/FeistelTrackContext.tsx` (Phase 5a — linear panel)
- `src/ui/components/FeistelMiniDiagram.tsx` (Phase 5b — SVG abstract diagram)
- `src/ui/components/RejoinFrameView.tsx` (Phase 5c — 4-arg combine view)
- `src/ui/components/BitGroupedRibbon.tsx` (Phase 5d — DES bit-level ribbon)
- `src/ui/components/DesKeyScheduleExplorer.tsx` (Phase 5e)
- `src/ui/key-schedule-sim/des.ts` (Phase 5e — per-round simulator)
- `src/ui/narration/des.ts`
- `src/ui/narration/combine-kinds.ts` (rejoin narrators keyed by `CombineKind`)
- `src/ui/provenance/des.ts`
- `src/ui/provenance/combine-kinds.ts` (rejoin provenance keyed by `CombineKind`)
- `tests/des-vectors.test.ts`, `tests/des-decrypt.test.ts`,
  `tests/feistel-primitive.test.ts`, `tests/feistel-graph.test.ts`,
  `tests/des-roundtrip-document.test.ts`,
  `tests/frame-preservation-feistel.test.ts`,
  `tests/des-key-schedule-parity.test.ts`,
  `tests/feistel-track-context.test.tsx`,
  `tests/feistel-mini-diagram.test.tsx`,
  `tests/rejoin-frame-view.test.tsx`,
  `tests/round-key-panel-des.test.tsx`,
  `tests/des-key-schedule-explorer.test.tsx`,
  `tests/scrubber-timeline-badges.test.tsx`
- `scripts/verify-des.mjs` (oracle, not shipped)

**Modified (core architecture):**

- `src/core/types.ts` — `BranchTrack`, `FeistelRoundGroup`, `StepNode`
  union widened, `TraceFrame.branchPath`.
- `src/core/runtime.ts` — `feistel-round` walk.
- `src/core/graph.ts` — `ContainerNode.kind` widened to include
  `"feistel"`; `inferStateEdges` track-bounded rules; rejoin/split
  synthetic nodes.
- `src/core/document.ts` — schema-version bump, migration for older
  documents (no-op on existing schema 1 docs since they have no
  `feistel-round` nodes).
- `src/core/spec-mutations.ts` — recursive walks into track children.
- `src/core/spec-shapes.ts` — `validateShapes` walks branches; tracks
  declare their own shape contracts.

**Modified (UI wiring):**

- `src/ciphers/default-registry.ts` — register DES step types + toy
  Feistel.
- `src/ui/stores/cipher.ts` — `Cipher` union, label, defaults.
- `src/ui/stores/spec.ts` — `defaults["des"]`.
- `src/ui/stores/cipher-mode.ts` — `SUPPORTED_CIPHER_MODES_BY_CIPHER["des"]`.
- `src/ui/App.tsx` — minor: padding-disabled for DES (same `isAesCipher` guard).
- `src/ui/components/ParamEditor.tsx` — 7 new `Match` arms.
- `src/ui/components/GraphView.tsx` — `feistel-round` container layout
  (Phase 6 layout decisions: top/bottom tracks, dedicated right-edge
  rejoin chip, single-chip collapse, per-track gutters).
- `src/ui/components/LinearView.tsx` — branchPath-aware frame headers
  (path segment + track badge per Layer 6 of the UI architecture).
- `src/ui/components/RoundKeyPanel.tsx` — extended for DES 48-bit
  round keys (Phase 5d).
- `src/ui/components/Scrubber.tsx` (or wherever the timeline lives)
  — adds per-frame track membership chips (Phase 5f).
- `src/core/edge-value-lookup.ts` — new `CombineEdgeLookup` variant
  exposing all 4 snapshots in formula order (Layer 5 of UI arch).
- `src/ui/narration/registry.ts`, `src/ui/provenance/registry.ts` —
  walk into track children.
- `tests/state-shape-contracts.test.ts`,
  `tests/narration-registry-contract.test.ts`,
  `tests/provenance-registry-contract.test.ts` — track-aware walks.

## Out of scope

- **3DES**. Mechanical follow-up: same step types, three DES applications
  in sequence with different keys, two spec leaves wrapping the round
  group.
- **TEA / XTEA**. Cheap follow-up — same branching primitive, simpler F
  (one leaf, ARX expression).
- **DES ECB / CBC**. Multi-block modes for DES need block-size-aware
  `load-block`/`store-block` (currently 16-byte-only for AES). Separate
  plan once the modes story generalizes past AES.
- **Twofish**. 4-way Feistel — `BranchTrack` design already supports
  n-tracks but Twofish also needs key-dependent S-boxes (a separate
  architectural concern).
- **Blowfish**. Self-referential key schedule + key-dependent S-boxes,
  both orthogonal to the branching question.
- **Codegen target**. Architecture supports it eventually; not this plan.

## Pitfalls flagged for this work

- **Bit-numbering convention**: FIPS 46-3 uses 1-indexed bit numbering
  with bit 1 = MSB. JavaScript bitwise ops use 0-indexed LSB. The
  conversion is `bit_i (FIPS) = bit_(64 - i) (JS)` for a 64-bit value.
  Off-by-one here will pass the *first* IP test (output ≠ input) but
  fail the round-trip. Pin against the oracle EARLY.
- **DES key parity bits**: every 8th bit of the 64-bit key is a parity
  bit, ignored by the cipher. `des.key-schedule@1`'s PC-1 step drops
  them, so a user-typed key with arbitrary parity bits will produce the
  same trace as the parity-corrected version. Surface this in the
  step's narration so users don't see "I changed bit 7 of the key and
  nothing happened" as a bug.
- **Track state-shape changes**: E-expand turns 32 bits into 48; S-boxes
  collapse 48 back to 32. The state-shape walker MUST tolerate per-leaf
  shape changes within a track. The existing executor contract already
  allows this, but the new `validateShapes` walker needs to thread
  shape across track-internal leaves (NOT short-circuit at the track
  boundary).
- **Last-round combine kind**: forward DES swaps after every round
  EXCEPT the last (so L_16 || R_16 enters FP, not R_16 || L_16).
  Decrypt has the same exception. In this plan that's not a runtime
  special-case but a spec-visible distinction: rounds 1..15 use
  `combineKind: "feistel-standard"` and round 16 uses
  `combineKind: "feistel-no-swap"`. The "DES is symmetric under
  key-reversal" property is what makes a single executor work for both
  directions; it breaks if every round uses the same combine kind
  unconditionally.
- **Rejoin frame's `stepId`**: synthesized at runtime, NOT a user-
  authored leaf. It needs a deterministic id (`{roundId}:rejoin`)
  for trace stability across re-runs (`[[feedback-frame-preservation]]`).
  Same applies to the post-swap frame (`{roundId}:swap`).
- **Cross-mode mirror buttons**: DES has no class-1 or class-2
  cross-mode mirror surfaces. The 8 S-boxes have no "inverse" sibling
  that would benefit from a "Sync inverse S_i to decrypt" button — DES
  is symmetric under key-reversal, so encrypt and decrypt share the
  same S-boxes verbatim. `cross-mode-mirror-registry.ts` gets ZERO new
  entries. The `tests/cross-mode-mirror-coverage.test.tsx` walker
  doesn't need updating. Stated explicitly so a future session
  doesn't assume a missing surface.
- **`feistel-round` inside `iterate`**: ECB(DES) would nest a
  `feistel-round` inside an `iterate`. The branchPath + blockIndex
  combination on a frame stamps both — make sure the trace store
  scrubber preserves stepId correctly across re-runs with both
  suffixes. See `[[feedback-frame-preservation]]`.
- **Graph state-spine through `feistel-round`**: today's
  `inferStateEdges` has an iterate-boundary suppression rule
  (`[[feedback-state-spine-no-phantoms]]`). The new container kind
  needs an analogous boundary rule — state into the round flows to
  the split anchor, state out flows from the rejoin synthetic. Don't
  let DFS-consecutive-leaves leak across the branch.
- **Universal cipher-shape plan integration**: this plan's
  `BranchTrack` and `FeistelRoundGroup` are the lessons the
  `[[project-universal-cipher-shape-plan]]` was queued to absorb.
  After Phase 5 ships, revisit that plan's hybrid-type-alias-vs-union
  decision with the real data model in hand.
