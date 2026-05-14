# Duplicate round

Add a "duplicate this round" affordance to the graph view's container
headers. Clicking it inserts a clone of the selected round immediately
after its source, renumbers subsequent rounds and their AddRoundKey aux
references in lock-step, extends the key schedule to produce the new
round's key, and applies the mirrored operation to the decrypt
counterpart so round-trip stays valid.

Pedagogical goal: students can ask "what happens if AES had 11 rounds?"
and see the answer end-to-end — the round structure, the key schedule
extension, the resulting (non-standard) ciphertext, and the matching
decrypt that recovers their plaintext.

Per user's chosen design (2026-05-14 session, advisor-consulted):
**renumber + extend schedule + auto-mirror**.

## Status

**Blocked by `docs/plans/trace-coupling-bug-fix.md`.** The bug-fix plan
removes the no-trace-before-Run failure mode that would make duplicate-
round changes hard to test interactively. Land that first.

## Context

### Design decision: renumber, not preserve-id

Two design paths considered. User chose RENUMBER.

- **Preserve-id (rejected).** New group labeled "Round 2 (copy)"; reads
  `roundKey.2` verbatim. No other rounds mutate, no layout migration, no
  key-schedule story. Cheaper, but cosmetic label doesn't match the
  "AES with N+1 rounds" mental model.
- **Renumber (chosen).** New group becomes `round.3`; subsequent rounds
  shift `round.N` → `round.N+1`; AddRoundKey `auxName` params shift
  `roundKey.K` → `roundKey.K+1` in lock-step. The cipher really does
  have N+1 rounds, and round labels match.

### Key-schedule blocker

`aes.key-expansion@1` (`src/steps/key-expansion.ts:45`) asserts
`rounds === Nk + 6`. Adding a round would make subsequent AddRoundKey
read `roundKey.{rounds+1}`, which the current key-expansion refuses to
emit. Three sub-options were considered; user chose **extend the
schedule** (sub-option b) — bump the step type to `@2` with the
assertion relaxed.

### Decrypt mirror

User chose AUTO-MIRROR. Duplicating `round.N` in encrypt also duplicates
`inv-round.{rounds-N}` in decrypt and renumbers correspondingly, so
round-trip stays valid by construction. This is more work than
encrypt-only (Phase 2) but produces a coherent cipher pair.

### Feistel forward-look

CLAUDE.md flags Feistel-style branching as a near-future addition.
Today's linear-sibling-order data-flow model handles state-edge
rerouting automatically (splice into the array, state flows via order).
A branching cipher would break that invariant — note in the plan that
duplicate-round on a Feistel cipher needs revisiting when the branching
primitive lands. Don't design for it now; today's model is sufficient.

## Critical files

- `src/steps/key-expansion.ts` — the `@1` executor + doc. Add `@2`
  alongside (don't replace — saved specs with `@1` must keep working).
- `src/ciphers/default-registry.ts` — register `aes.key-expansion@2`.
- `src/core/spec-mutations.ts` — new `duplicateRoundGroup` pure helper
  alongside the existing structural mutators.
- `src/ui/stores/spec.ts` — new `duplicateRoundInSpec(roundId)` store
  action. This is where the encrypt-vs-decrypt mirroring happens (it
  has access to the active spec + the cipher/mode selectors).
- `src/ui/stores/layout.ts` — new `renameLayoutIds(layout, oldToNew)`
  helper. Walks `positions` + `collapsedGroups`, applies rename map.
- `src/ui/components/GraphView.tsx` — duplicate button in container
  header, mirror of existing delete `×` affordance.
- `src/ciphers/aes-128.ts` + decrypt counterpart — the encrypt and
  decrypt spec factories. The mirror logic in `duplicateRoundInSpec`
  needs to know how to map encrypt round id → decrypt round id; either
  read this from the spec ids directly (`round.N` ↔ `inv-round.{rounds-N}`)
  or expose a small helper from these files.

## Plan

### Phase 1 — `aes.key-expansion@2`

Relax the `rounds === Nk + 6` assertion. Compute Rcon on-the-fly via
the FIPS-197 recurrence (`Rcon[i] = Rcon[i-1] << 1` over GF(2^8)) so
the table doesn't need to come in via params. Keep `@1` registered
verbatim.

```ts
// src/steps/key-expansion.ts — new export aliasing structure
export const keyExpansionV2: StepExecutor = (state, params, ctx) => {
  const p = readParams(params);  // same param shape, just no rounds-Nk assertion
  // ... walk i from Nk to totalWords-1, compute Rcon[i/Nk] inline ...
};
export const keyExpansionV2Doc: StepDocumentation = { ... };
```

Tests (in same commit per project convention):
- `tests/key-expansion-v2.test.ts` — known-answer parity with `@1` at
  canonical round counts (10/12/14), AND produces correct keys for
  non-canonical counts (e.g., rounds=11 with a 16-byte key).

### Phase 2 — `duplicateRoundGroup` pure mutator

`src/core/spec-mutations.ts`:

```ts
export type DuplicateResult = {
  readonly spec: CipherSpec;
  readonly renames: ReadonlyMap<string, string>;  // oldId -> newId, for layout migration
};

export const duplicateRoundGroup = (
  spec: CipherSpec,
  sourceId: string,
): DuplicateResult => {
  // 1. Locate source group via findStepAndParent. Throw if not found.
  // 2. Clone the group; suffix-rename children (round.2.sub-bytes -> round.3.sub-bytes
  //    in the cloned copy, before renumber).
  // 3. Splice the clone into parent.children immediately after source.
  // 4. Walk subsequent siblings:
  //      round.N -> round.N+1 (group id)
  //      round.N.* -> round.N+1.* (child leaf ids)
  //      AddRoundKey params.auxName: "roundKey.K" -> "roundKey.K+1"
  // 5. Find the key-expansion leaf at the top level; bump params.rounds += 1.
  // 6. Build rename map (oldId -> newId) for every renamed id; return.
};
```

Tests:
- `tests/spec-mutations.test.ts` extensions:
  - Duplicating `round.2` in canonical AES-128 produces 11 rounds
    `round.1..round.11`; `round.3` reads `roundKey.3`, ..., `round.11`
    reads `roundKey.11`.
  - Key-expansion's `rounds` param is bumped to 11.
  - Rename map is exhaustive (every renamed leaf + group id present).
  - Reference equality preserved on untouched branches (consistent with
    other mutators).

### Phase 3 — Layout-pin migration

`src/ui/stores/layout.ts`:

```ts
export const renameLayoutIds = (
  layout: LayoutSpec,
  renames: ReadonlyMap<string, string>,
): LayoutSpec => {
  // Pure: walk positions + collapsedGroups, rewrite keys per the rename map.
  // Untouched ids pass through unchanged.
};
```

Tests:
- `tests/layout-rename.test.ts` — rename map applied; pins for
  un-renamed ids survive; collapsed-group set updated.

### Phase 4 — Store action with auto-mirror

`src/ui/stores/spec.ts`:

```ts
export const duplicateRoundInSpec = (sourceRoundId: string): void => {
  // 1. Apply duplicateRoundGroup to active spec; capture rename map.
  // 2. Migrate layout via renameLayoutIds.
  // 3. Mirror onto the inverse spec:
  //      - Determine current mode (encrypt vs decrypt) and the counterpart.
  //      - Map sourceRoundId to its inverse: round.N <-> inv-round.{rounds - N}.
  //      - Apply duplicateRoundGroup to the counterpart with the mapped id.
  //      - Migrate the counterpart's layout pins.
  // 4. Setting the spec triggers the existing auto-rerun.
};
```

**Open question for implementation time:** today's store likely holds
the active spec; the inverse counterpart may need to be loaded from the
spec factories (`aes-128.ts` + `aes-128-decrypt.ts`) and persisted
separately. Investigate at the start of phase 4 — may need a small
"cipher-pair" abstraction or a `mirrorOp(spec, op)` helper that
re-runs the mutator on the counterpart with the mapped id.

### Phase 5 — UI trigger

`src/ui/components/GraphView.tsx`:

Add a "duplicate" button in the container header band, only for
groups whose id matches `round.N` or `inv-round.N` (a small regex
check). Mirror the existing delete `×` affordance's position +
styling.

### Phase 6 — End-to-end tests

- `tests/aes-duplicate-round.test.ts`:
  - Duplicate `round.2` in AES-128 encrypt spec. Run trace. Assert
    completion + 11 rounds executed + non-standard ciphertext is a
    valid 16-byte block.
  - Duplicate same in decrypt spec (or via the auto-mirror once
    phase 4 wires it). Run decrypt-of-encrypt. Assert plaintext
    recovers.
- `tests/duplicate-round-save-load.test.ts`:
  - Save a spec with duplicated round; reset; load; assert structure
    + layout pins survive.

## Out of scope

- **Speck / Serpent duplicate-round.** Different group structures and
  key schedules; revisit after AES variant is stable.
- **Feistel-aware rerouting.** Today's linear model suffices. When
  Feistel branching primitives land, revisit `deriveAuxGraph` AND this
  plan together.
- **Duplicating non-round groups** (key-expansion, iterate body, etc.).
  The button only appears on `round.N` / `inv-round.N` headers; "duplicate
  any group" can come later.

## Estimate

~150 lines of production code + 4 test files + the `@2` step type.
~1-2 days for an experienced hand on this codebase.
