# Twofish canonical round layout (4-rail Feistel) — plan

> **STATUS: SHIPPED 2026-07-12** — with one deliberate deviation from the design
> below. The recognizer, 4-rail placement, g-box decorations, and the
> replication-exclusion (`twofishRoundNeverModes`, which the smoke surfaced — the
> round split's 6-way fanout would otherwise scatter it into per-consumer chips)
> all shipped. **The inter-round 4-way swap-X was BUILT then REMOVED:** Twofish
> rounds lay out HORIZONTALLY (top-level steps, no outer `rounds` group), so the
> `recombine → next split` swap spans ~2000px up-and-over — a long diagonal
> tangle with overlapping labels, not a readable X (the `§2` swap design assumed
> the DES/BF vertical stacking, where rounds nest in an outer group). Browser
> smoke confirmed the tangle; per the DES-round-16 precedent we keep the plain
> `recombine → split` carry edge and let the cell + `recombine` narration tell
> the swap story. Files: `src/core/twofish-shape.ts`, `src/core/twofish-layout.ts`
> (placement only — no `twofishSwapWires`), GraphView parallel plumbing. Tests:
> `tests/twofish-shape.test.ts`, `tests/twofish-layout.test.ts`,
> `tests/twofish-graph-layout.test.ts`. Full `npm run check` green. Twofish
> linear-view diagram deferred as planned.

## Context

The graph-view canonical two-column Feistel layout now covers **DES + Blowfish**
(shipped `2adef23`): a round group whose wiring is `split[2] → F → xor → concat`
lays out as the textbook two-column cell instead of a generic vertical stack,
with an inter-round swap "X". **Twofish** (shipped cipher, third Feistel) still
renders as a generic vertical stack, because its round is a *4-rail* structure
the 2-way `analyzeFeistelRound` cannot express (4-way split, two parallel
g-functions, a pseudo-Hadamard transform, two rotation-interleaved mixes, and a
4-input concat).

Goal: give Twofish rounds a readable **4-rail canonical layout** (the two g
functions as F-boxes, the PHT in the middle, the R2/R3 mix rails, and a 4-way
swap X), matching the pedagogical quality of the DES/BF cells. Per the user's
decisions: build it as a **separate `TwofishRoundShape` type + analyzer +
layout**, parallel to the 2-way path, so the DES/Blowfish code is untouched
(zero regression risk) rather than forcing a discriminated union.

Non-goal (v1): Twofish-specific **linear-view** abstract diagrams. The 2-way
linear components (`FeistelSwapDiagram` / `FeistelRoundBytes` /
`FeistelRecombineView`) key off `analyzeFeistelRound`, which returns null for
Twofish's 4-input concat — so they simply **won't render** for Twofish (no
misrepresentation). The linear view keeps its per-step `PortFlowView` +
Twofish's existing rich `narrationOverride`. A Twofish 4-rail linear diagram is
a possible follow-up, flagged below.

## Twofish round anatomy (from `src/ciphers/twofish-spec-builder.ts::buildRound`)

16-byte block, four 32-bit words. Leaf ids under `round.N`:

```
split-bytes[4,4,4,4] → output0..3 = R0, R1, R2, R3
g0.*   = g(R0):        g0.split → g0.s0..s3 → g0.concat → g0.mds → g0.perm   (8 leaves) → T0
rolR1  = ROL(R1,8)
g1.*   = g(rolR1):     g1.split → g1.s0..s3 → g1.concat → g1.mds → g1.perm   (8 leaves) → T1
loadK0, loadK1         (aux-load subkeys)
PHT:   f0 = T0+T1+K0 (add-mod-32, 3-in) ;  dbl2T1 = T1+T1 ;  f1 = T0+2·T1+K1 (3-in)
R2 mix (encrypt): r2x = R2 ⊕ F0 ; r2p = ROR(r2x,1)     (decrypt: r2r = ROL(R2,1) ; r2p = r2r ⊕ F0)
R3 mix (encrypt): r3r = ROL(R3,1) ; r3p = r3r ⊕ F1     (decrypt: r3x = R3 ⊕ F1 ; r3p = ROR(r3x,1))
recombine = concat(r2p, r3p, split.output0, split.output1)   → next state (R2', R3', R0, R1)
```

**Direction-agnostic** — encrypt/decrypt differ only in the two rotation leaves
(`r2x`/`r2r`, `r3r`/`r3x`) and their order; the recombine wiring
`concat(r2p, r3p, output0, output1)` is identical for both. So the recognizer
must key off **wiring**, not leaf ids, exactly like the 2-way analyzer.

The recombine is byte-honest: `input0→new word0 (R2')`, `input1→new word1 (R3')`,
`input2→new word2 = carried R0`, `input3→new word3 = carried R1`. Next round's
split re-divides in order, so the two **mixed** words (produced on the R2/R3
rails) land in the R0/R1 slots and the two **carried** words (raw R0/R1) land in
the R2/R3 slots — the 4-way swap.

## Design

### 1. `src/core/twofish-shape.ts` (NEW) — recognizer

```ts
type TwofishRoundShape = {
  roundId: string;
  splitId: string;                 // the 4-way split
  recombineId: string;
  recombineOutPort: string;
  g0Ids: readonly string[];        // R0's g stack (spec order)
  g1Ids: readonly string[];        // ROL(R1)'s g stack incl. rolR1
  phtIds: readonly string[];       // loadK0/K1, f0, dbl2T1, f1
  r2MixIds: readonly string[];     // r2x|r2r, r2p
  r3MixIds: readonly string[];     // r3r|r3x, r3p
  // recombine input→role, byte-honest:
  mixedPortA: string;              // recombine input0 (→ new word0)
  mixedPortB: string;              // recombine input1 (→ new word1)
  carriedSplitPorts: readonly [string, string]; // split output0, output1
};
```

`analyzeTwofishRound(group): TwofishRoundShape | null`

**Recognizer direction — anchor BACKWARD from the PHT, not forward from the
split.** A forward cone from `split.output0` is wrong: each split output has
**fanout 2** (it feeds a g-function AND a carried `recombine` input), so a
forward cone leaks into the recombine. Anchor on the PHT — the two
`add-mod-32@1` leaves with **inputCount 3** ({f0, f1}) are unique to this shape
— and walk outward:

- recombine = `bodyOutput` target; require `concat@1` with `inputCount: 4`.
- `input2`/`input3` must read **raw halves of a 4-way `split-bytes@1`** (widths
  length 4) → identifies `splitId` + `carriedSplitPorts`. **Also assert
  `input0`/`input1` are NOT raw split reads** (they're the mixed cones); return
  null otherwise (the 2-way analyzer's try-and-verify discipline — guards a
  degenerate/edited spec).
- Require exactly two `add-mod-32@1` inputCount-3 leaves → {f0, f1}; else null.
- g heads = f0's two non-aux-load operands (each bottoms out in a `permute@1`);
  `dbl2T1` = f1's operand that is a 2-input `add-mod-32@1`; loadK0/K1 = the
  aux-load operands.
- Backward-cone each g head, stopping at the split → `g0Ids`/`g1Ids`;
  distinguish by which split port each bottoms at (g0 → `output0` raw; g1 →
  `output1` through `rolR1`). **`rolR1` lives in `g1Ids` but is flagged for
  exclusion from the g decoration box** (see layout §2) — it's a rail atop the
  column, not part of g (g0 has no such rotation).
- `r2Mix`/`r3Mix` = backward cones of `recombine.input0`/`input1`, **bounded by
  {f0, f1, split}** so they don't swallow the PHT.
- Classify every leaf by **type/structure, never operand position**
  (`operand0/1/2`), so recognition survives the encrypt/decrypt rotation swap —
  the whole point of a wiring-derived recognizer.
- Return null for any group that doesn't match (DES/BF 2-way, AES, SHA) — a
  null-sweep test mirrors the 2-way one. (Twofish has **no outer `rounds`
  group** — rounds spread directly into `steps` — so one fewer false-match
  candidate than DES; keep DES's outer group in the null-sweep anyway.)

Reuse the same helpers as `feistel-shape.ts` (`asRecord`, `paramNumber`,
`portInputsOf`, `leafChildren`, single-port rail walking) — they are currently
module-private; export them (or re-declare the trivial ones locally) but do
**not** modify `analyzeFeistelRound` itself.

`findActiveTwofishRound(frame, spec)` — mirror of `findActiveFeistelRound`
(innermost group ancestor that `analyzeTwofishRound` accepts, guarded by a
leaf-membership check).

### 2. `src/core/twofish-layout.ts` (NEW) — 4-rail placement + swap

`twofishRoundPlacement(shape, childIds, opts) → { offsets, bodyW, bodyH }`,
pure, unit-testable (mirrors `feistelRoundPlacement`). Column layout:
- Row 0: `split` centered on top.
- **Left band:** two adjacent columns for `g0Ids` and `g1Ids` (each a g-box).
  `rolR1` sits **atop** the g1 column but **outside** the g decoration box —
  exactly like Blowfish's `xorP` rail sits atop and outside the F-box, so a
  learner doesn't read the 8-bit rotation as part of g (g0 has none).
- **Middle-low:** the PHT (`loadK0/K1`, `f0`, `dbl2T1`, `f1`) below the g-boxes.
- **Right band:** two columns for `r2MixIds` and `r3MixIds` (the R2/R3 rails
  receiving F0/F1).
- Bottom: `recombine` centered.
- Defensive far-right parking for any unclassified child (hand-edited round).

`twofishSwapWires(shape, recombineBox, splitBox, dx) → 4 wires` — the 4-way X.
Unlike DES/BF there is **no lineage `swap` flag**: `recombine.input_i` maps
straight to the next split's `output_i` (a pure index map); the "swap" is only
the semantic role rotation (R2'→new R0, R3'→new R1, R0→new R2, R1→new R3). The
two mixed words (recombine input0/1, produced on the right rails) draw to the
next split's **left** two slots; the two carried words (input2/3, the R0/R1
rails on the left) draw to the **right** two slots. Each wire LABELED
(R2'/R3'/R0/R1). The test is an **endpoint index-map assertion** (input_i origin
→ output_i position) — no `resolveTwofishRoundBytes` needed, so deferring the
linear diagrams doesn't weaken the graph swap's correctness.

### 3. `src/ui/components/GraphView.tsx` — parallel plumbing (no 2-way changes)

- `twofishRoundsById` memo alongside `feistelRoundsById` (~L3559), walking the
  spec with `analyzeTwofishRound`.
- Thread it into `layoutRoot`/`layoutNode` as a **parallel param** next to the
  existing `feistelRounds` (keeps the 2-way threading untouched; safest for zero
  regression). In `layoutNode`, add a `twofish` dispatch branch beside the
  `feistel` branch (~L1304) that calls `twofishRoundPlacement`.
- `twofishDecorations` memo (two g-boxes labeled "g", `rolR1` excluded from the
  g1 box, optional PHT bracket) + `twofishSwaps` memo (the 4-way X) +
  carry-suppression: extend the `feistelCarryKeys` idea so the straight
  `recombine → next split` carry edge is suppressed for Twofish rounds too,
  redrawn as the 4-way X. **Fire the X + carry-suppression only when BOTH
  endpoints are recognized Twofish rounds** — so the round-15 → output-whitening
  edge is left alone (mirrors the deferred DES `round.16 → final-permutation`
  artifact). New render `<For>` blocks parallel to the existing feistel ones.

### 4. Tests + smoke

- `tests/twofish-shape.test.ts`: `analyzeTwofishRound` recognizes an encrypt AND
  a decrypt round (partition contents correct); rejects DES/BF/AES/SHA groups +
  the outer `rounds` group; `findActiveTwofishRound` resolves a frame inside a
  round and rejects a spec/trace mismatch.
- `tests/twofish-layout.test.ts`: placement invariants (two g columns left, PHT
  middle, mix columns right, split top / recombine bottom); `twofishSwapWires`
  crosses the mixed pair to the left slots and carried pair to the right,
  byte-honest.
- Regression: the full 2-way feistel suite (DES + Blowfish) must stay green
  untouched; full `npm run check`.
- Browser smoke (throwaway Playwright, per repo convention — not committed):
  select Twofish, graph tab, screenshot a round; confirm 4 rails, 2 g-boxes,
  4-way X, and N decorations, then delete the spec.

## Critical files

- `src/core/twofish-shape.ts` (NEW) — `TwofishRoundShape`, `analyzeTwofishRound`,
  `findActiveTwofishRound`.
- `src/core/twofish-layout.ts` (NEW) — `twofishRoundPlacement`, `twofishSwapWires`.
- `src/ui/components/GraphView.tsx` — parallel `twofishRoundsById` /
  `twofishDecorations` / `twofishSwaps` memos, `layoutNode`/`layoutRoot` param
  threading + dispatch branch, render blocks + carry suppression.
- `src/core/feistel-shape.ts` / `feistel-layout.ts` — **read-only reference**
  (shared helpers may be lifted out, but the 2-way analyzer/layout logic is not
  changed).
- `tests/twofish-shape.test.ts`, `tests/twofish-layout.test.ts` (NEW).
- `CLAUDE.md` — extend the "Canonical Feistel rounds" note to mention the
  separate Twofish 4-rail path.

## Recognizer note (resolved)

Recognizing the g0/g1/PHT/mix partition purely from wiring is the one genuinely
new bit of complexity (the 2-way case had a single F cone). The direction is
settled: **anchor backward on the two `add-mod-32@1` inputCount-3 PHT leaves**
(unique to this shape) and cone outward, bounding the mix cones by {f0, f1,
split} — a forward cone from the split would leak through the split outputs'
fanout-2 into the recombine. Classify by leaf type/structure, not operand
position, so encrypt and decrypt (which differ only in two rotation leaves)
recognize identically.

## Verification

1. `npx vitest run tests/twofish-shape.test.ts tests/twofish-layout.test.ts` +
   the existing `tests/feistel-*.test.ts` (DES/BF unchanged).
2. `npm run check` (biome + tsc + full vitest + build) — the pre-commit gate.
3. `npm run dev`, select Twofish, graph tab; visually confirm one round reads as
   the 4-rail cell with the two g-boxes and the 4-way swap X (screenshot).
