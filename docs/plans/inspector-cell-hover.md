# Inspector cell-level hover — port-native provenance restore

> **Status: DRAFT (not yet built) — 2026-06-03.** Drafted after a session
> that re-surfaced the deleted cell-level provenance overlay, surveyed the
> port-native frame shape, ran two empirical de-risk checks, and consulted
> the advisor. Supersedes the never-created `docs/plans/inspector-overlays.md`
> placeholder for the **hover** half; the **identity-overlay** half stays
> deferred (see "## Non-goals").

## Context

### What this is

Restore the **cell-level provenance highlight** in the linear-view inspector:
hovering an **output** byte cell in `PortFlowView` lights up the **input**
cell(s) that feed it, on the same surface. This is the port-native rebuild of
the overlay introduced in `21d06cf` (2026-05-18) and deleted in `a1b64b2`
(2026-05-31, the Slice 2.9c-e "honest close").

### Why it was deleted, and why the rebuild won't rot the same way

The old overlay indexed `stateAfter.bytes` and coordinated across two surfaces
(`MatrixView` + `RoundKeyPanel`). Both the data field (`stateBefore`/
`stateAfter`, retired 5.3e B4) and the surfaces (`MatrixState`/MatrixView
retired 5.1) were deleted by the port-native migration, so the subsystem became
a corpse and was removed rather than ported.

The rebuild rests on a **structurally different** footing:

1. **Provenance is pure *index* math, not value lookup.** For every port-native
   primitive, "which input cell feeds output cell *i*" is fixed by the
   primitive's *structure* (its `params` + the port byte-*lengths*) — never by
   the byte *values*. So the whole feature is a pure function
   `(params, portInputs, portOutputs, outPort, outCellIndex) → ProvenanceCell[]`.
   It may read port lengths; it must **never** branch on byte values. That is
   the property that makes it un-rottable — it does not depend on any per-frame
   value snapshot.
2. **Everything that contributes is already an on-frame port row.** No
   cross-component coordination is needed.

### The reframe: this is an AES/DES restore, not a SHA-256 feature

The original Slice 2.9 was SHA-256-motivated — and SHA-256 is exactly where the
hover helps *least* (`xor` same-position is obvious; `add-mod-32` and the
rotates are only approximate). The primitives the hover genuinely illuminates
are the **AES round body** (`byte-substitute`, `permute`, `gf-matrix-multiply`,
`xor-with-aux`) and **DES permutations** (`permute`). The honest framing: the
port-native migration dropped the SubBytes/ShiftRows/MixColumns/AddRoundKey
highlight the user valued, and we are restoring it. SHA-256 `xor` is a bonus
where it applies. **Do not gate the slice on SHA-256 coverage.**

The hover is **not** redundant with the graph: the graph shows node/port-level
flow but **never** intra-step cell coupling (output byte 3 ← input byte 7). The
hover answers a question the graph cannot.

### Two facts verified before drafting (advisor's de-risk checks)

- **(a) AddRoundKey lands on one surface — CONFIRMED.** `runtime.ts:720`
  captures `framePortInputs = inputs` from the **post-projection** map, so
  `xor-with-aux@1`'s `frame.portInputs` carries both `input` (state) **and**
  `operand` (the round key projected from `aux[auxName]` via `meta.auxReadPorts`).
  The K_i XOR coupling is two input rows in the *same* `PortFlowView` — no
  `RoundKeyPanel` coordination like the old design.
- **(b) `permute@1` needs no table inversion — risk eliminated.** `permute` is
  authored as a pure *gather*: `output[i] = input[indices[i]]`. The provenance is
  the **forward read** of `indices` (output cell `i` ← input cell `indices[i]`).
  The advisor's "silent wrong-inversion" failure mode only existed for a
  scatter; this is the *simplest* exact mapping, not the riskiest.

## Design

### v1 scope — exact mappings only (user decision 2026-06-03)

The discriminating line is **exact vs. approximate**, not primitive count (the
mapping is tiny and pure; volume is not the constraint). Approximate mappings
that render *identically* to exact ones would silently break the "missing never
wrong" trust property and actively miseducate (e.g. "byte 3 ← byte 3" for a
bit-rotate-by-7, whose output bits come from two input bytes).

**v1 ships every EXACT mapping; the approximate primitives are allowlisted out**
(hover highlights nothing for them — the cleanest "missing never wrong" stance).
A distinct weaker treatment for approximate provenance (a dimmer, `≈`-marked
class) is a **fast-follow**, not v1.

| Primitive | `outPort[i]` ← | Exact? | v1 |
|---|---|---|---|
| `xor`, `and` | `operand0[i] … operand{N-1}[i]` (same column, N = `inputCount`) | exact | ✅ fn |
| `not` | `input[i]` | exact | ✅ fn |
| `xor-with-aux` (AddRoundKey) | `input[i]`, `operand[i]` (round key row) | exact | ✅ fn |
| `byte-substitute` (SubBytes / S-boxes) | `input[i]` (S-box swap, same pos) | exact | ✅ fn |
| `permute` (ShiftRows / P / IP-FP) | `input[indices[i]]` (forward gather) | exact | ✅ fn |
| `concat` | the input port + offset covering global index `i` | exact (uses lengths) | ✅ fn |
| `split-bytes` | `input[ (Σ widths before outPort) + j ]` | exact (uses `widths`) | ✅ fn |
| `byte-slice` | `input[offset + i]` | exact (uses `offset`) | ✅ fn |
| `gf-matrix-multiply` (MixColumns) | the 4 same-column input cells, each labeled with its GF(2⁸) coeff | exact + **richest** | ✅ fn |
| `add-mod-32` | all cells in the same 4-byte word (carry) | **approx** | ⛔ allowlist |
| `rotate-bits-right`, `shift-bits-right` | bit-level → byte-approx | **approx** | ⛔ allowlist |
| `constant-load` (outputs-only) | — (no inputs) | n/a | ⛔ allowlist |

`gf-matrix-multiply` is the headline: it's the one case where the `label` field
earns its place (the GF coefficients `×1 / ×2 / ×3` per contributor). Build the
`label` channel even though only MixColumns uses it in v1.

### The pure module

`src/core/port-provenance.ts`:

```ts
export type ProvenanceCell = {
  readonly portName: string;   // which INPUT port row
  readonly cellIndex: number;  // which byte cell in that row
  readonly label?: string;     // e.g. GF coeff "×2" (MixColumns only in v1)
};

export type ProvenanceCtx = {
  readonly params: Json;
  readonly portInputs: ReadonlyMap<string, Uint8Array>;   // lengths only — never values
  readonly portOutputs: ReadonlyMap<string, Uint8Array>;
  readonly outPort: string;
  readonly outCellIndex: number;
};

export type ProvenanceFn = (ctx: ProvenanceCtx) => readonly ProvenanceCell[];

// Registry keyed by the bare port-native step type ("xor@1", "permute@1", …).
export const lookupProvenance = (stepType: string): ProvenanceFn | undefined => …;
```

Lives in `src/core/` (not `src/ui/`) deliberately: it is pure index math,
node-testable with no jsdom, and cannot desync onto a render surface — the exact
rot vector from last time. The fn reads port **lengths** (for `concat`/`split`/
`slice`) but must not read port **values**; a node test pins that values don't
change the output.

**Per-step co-location vs central registry:** co-locating each fn in its step
file (next to the executor, like the doc blocks) keeps the index semantics from
drifting from the executor; a central registry makes coverage visible. Either is
acceptable — the hard requirement is that the fn and the executor cannot
silently desync. Lean: co-locate the fn export in each `src/steps/<prim>.ts`,
register it alongside `executor`/`doc` in `default-registry.ts`, and resolve via
the registry. (Decide at implementation time; not load-bearing.)

### Contract test — revive the CI coverage gate

Walk the port-native step types reached by shipped specs; assert each EITHER has
a provenance fn registered OR sits on an explicit `PROVENANCE_NO_OP_ALLOWLIST`
with a one-line rationale. This is what made the old coverage a real gate — a
future port-native primitive fails the test until a fn is wired or an explicit
"we considered this" lands on the allowlist. Standing allowlist entries:
`add-mod-32@1`, `rotate-bits-right@1`, `shift-bits-right@1` (approximate —
deferred to the distinct-treatment fast-follow), `constant-load@1` (no inputs).

### The hover wiring (`PortFlowView`)

- A stepId-gated hover signal carrying `{ stepId, outPort, outCellIndex,
  sources: ProvenanceCell[] }`, precomputed at hover-set time. **stepId-gating
  is mandatory** — a stale hover from a prior frame must not paint cells after a
  scrub (a gotcha carried forward from the deleted design).
- The signal keys on `(portName, cellIndex)`, **not a flat index** — `split-bytes`
  has multiple output rows; a flat index is ambiguous. Output cells become
  hover sources; input cells matching `sources` get a `.provenance-source`
  class (revive the class name; single-class composition, no `!important`).
- The `label` (GF coeff) renders as a small superscript/badge on the
  highlighted contributor cell.
- **Frame-local ⇒ iterate/`:b{i}`/multi-block "just works"** — provenance never
  crosses a frame boundary, so no per-block logic (unlike the graph).
- Honor the byte-format toggle (already cheap; cells are unreadable without it).

## Critical files

| File | Change |
|---|---|
| `src/core/port-provenance.ts` | **new** — pure mapping module + registry lookup + types |
| `src/steps/{xor,and,not,xor-with-aux,byte-substitute,permute,concat,split-bytes,byte-slice,gf-matrix-multiply}.ts` | add a `…Provenance: ProvenanceFn` export (co-located) |
| `src/ciphers/default-registry.ts` | register each provenance fn alongside `executor`/`doc` |
| `src/ui/components/PortFlowView.tsx` | hover signal + `.provenance-source` highlight + label badge |
| `src/ui/app.css` | `.provenance-source` (+ label badge) styles |
| `tests/port-provenance.test.ts` | **new** — per-primitive node tests + value-independence property |
| `tests/port-provenance-coverage.test.ts` | **new** — contract gate (fn-or-allowlist) |
| `tests/port-flow-view.test.tsx` | extend — hover sets sources, stepId-gating, `(portName,cellIndex)` keying |

## Implementation slices

1. **Pure core + tests.** `port-provenance.ts` with the 10 exact fns, the
   registry, the allowlist, node tests (per-primitive known mappings + a
   "shuffling input *values* leaves the mapping unchanged" property), and the
   coverage contract test. No UI. Gate green here before touching the view.
2. **Hover wiring.** `PortFlowView` hover signal + `.provenance-source` +
   label badge + jsdom tests (sources set on hover, cleared on leave,
   stepId-gated, keyed by `(portName, cellIndex)`). MixColumns label renders.
3. **Browser smoke + close.** Scrub AES-128: SubBytes (same-pos), ShiftRows
   (gather), MixColumns (4 same-column + GF labels), AddRoundKey (input + K_i
   rows). DES P-permutation. SHA-256 `xor`. Confirm approximate primitives
   highlight **nothing** (no false exact-looking highlight). Update `README`
   "What's in the box" if the linear-view surface is described there; update
   `docs/help/graph-view.md` only if it mentions the inspector. Memory + commit.

## Test plan / gates

- **Node:** per-primitive mapping correctness against hand-computed expectations;
  the **value-independence property** (permuting input bytes does not change the
  returned cell indices) — this is the formal statement of "pure index math."
- **Coverage contract:** every shipped port-native step type has a fn or an
  allowlist entry.
- **jsdom:** hover sets/clears sources; stale-frame hover paints nothing after a
  scrub; `(portName, cellIndex)` disambiguates `split-bytes` rows.
- **Browser smoke** (per `feedback_visual_smoke_vs_property_tests` — property
  tests passed last time while the visual shape was catastrophically broken):
  the AES round-body + DES + SHA checklist above.
- `npm run check` green; no schema bump (pure additive UI + core module).

## Non-goals (deferred — unchanged from prior advisor verdict)

- **Identity-overlay surface** — formula chips (SHA-256 T1/Σ1/σ1/Ch/Maj),
  labeled working-var rows, AES matrix overlays. Bigger; the JSX-vs-structured-
  data choice should be informed by 2–3 actual ciphers' overlays (SHA/AES/DES
  want different shapes), and by hierarchical frames if those land. Revisit gate:
  cells + hover scrubbed across a few sessions. Probable file when it happens:
  `docs/plans/inspector-overlays.md`.
- **Operand row *labeling*** ("K₃ (round key)" on the `operand` port row) — a
  cheap, separate, **non-hover** win. Deliberately kept out so this stays a clean
  provenance slice. Fast-follow.
- **Distinct treatment for approximate provenance** (`add-mod-32`, rotate/shift
  with a dimmer `≈` class) — fast-follow after v1's exact-only highlight has been
  used.
