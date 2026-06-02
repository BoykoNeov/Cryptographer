# Universal-port Phase 4f — Compose-and-save

> **Status: SHIPPED 2026-06-02.** All five slices (A–E) on `main`. The last open
> milestone of the universal-port plan's Phase 4 (`docs/plans/universal-port-dataflow.md`,
> Q-C decision **(b)**). Unblocked by the port-wiring editor (Phase 4d-bis,
> SHIPPED 2026-06-02). Memory: `project_compose_and_save_plan`.

## Context

Q-C(b): let the user **wire N primitives, name them, and save the composition
as a reusable element that appears in the palette**. A user looking at, say, an
AES round group clicks `[save as element]`, names it "AES Round", and it shows
up in a new **"my elements"** palette section. Dropping it inlines a fresh,
fully editable copy of that round into the spec — advancing the README's
"cipher = JSON, not code" claim: now the reusable *building block* is JSON too.

## Locked design (advisor + 2 user picks)

- **Composite = a stored `StepGroup` template, pure JSON** (Approach A). NOT a
  registered step type with a synthesized executor (Approach B) — B hides
  internals and fights the "internals stay scrubbable" pedagogy.
- **v1 selection model = "save an existing group"** (user pick). A shipped
  round group already carries a validated `seedInput`/`bodyOutput`/aux boundary.
  Arbitrary multi-node selection is a deferred follow-up.
- **Drop = copy / inline the subtree** (user pick). Fresh-id clone of the
  group's children inlined into the spec; internals visible + scrubbable;
  saved/shared docs stay self-contained.

## Key findings (why it's cheap + no schema bump)

1. **A plain `group` already has the exact composite boundary.** `StepGroup`
   carries `seedInput` (single port input → `port(groupId,"in")`), `bodyOutput`
   (published exit), `outputPorts` (default `["out"]`). That is one port-in /
   one port-out.
2. **Group-scope isolation defines the boundary for free.** A group's children
   reference only each other + the seed; only the aggregate output escapes. So a
   captured group is inherently single-port-in / single-port-out — **plus any
   number of aux reads** (aux is the cross-scope channel, e.g. a round's
   `xor-with-aux@1` reading `aux["roundKey.N"]`). Multi-*port*-input composites
   need the deferred group-export runtime feature (topology A) — **non-goal**.
3. **No schema bump.** Drop *inlines* the group, so any saved/shared
   `CipherDocument` is self-contained (never references the composite). The
   library is a localStorage-only global store; `core/types.ts` +
   `core/document.ts` are untouched. Matches the 4d-bis precedent.
4. **`duplicateRoundGroup` is NOT directly reusable** — its clone/rebase is
   hard-coded to AES `round.N` naming + key-schedule renumber. We reuse its
   *pattern* (`remapPortInputs`) inside a new prefix-agnostic
   `cloneGroupWithFreshIds`.

## What shipped (slices → commits)

- **Slice A — headless core** (`a90adc4`): `cloneGroupWithFreshIds(group,
  newGroupBaseId, existingIds) → { group, renames }` (collision-free id regen +
  internal-binding rebase; v1 step+group only) and `captureCompositeFromGroup`
  (context-free template: clears `seedInput`, sets `defaultCollapsed`, label =
  name; guards non-group / empty / looping-container) in `spec-mutations.ts`.
  `insertCompositeIntoSpec(template, anchor)` + `pickSeedBinding` +
  `primaryOutputPort` in `stores/spec.ts` — drop **auto-binds `seedInput` to the
  insertion-point predecessor** (the 4d-bis editor only rewires *leaf* ports, so
  a container seed left unbound would have no in-app fix).
- **Slice B — composites store** (`a75656c`): `src/ui/stores/composites.ts`, a
  global localStorage library (`cryptographer.composites`) mirroring
  `layout.ts`; `CompositeDefinition = { id, name, group, createdAt }`; CRUD +
  boundary-guarded `saveComposite`.
- **Slice C — palette "my elements"** (`5aadb53`): `StepPalette.tsx` renders the
  saved composites in a dedicated section (hidden when empty); a distinct
  `COMPOSITE_DRAG_MIME` (no `text/plain`, so a composite id can't be mistaken
  for a step type); inline rename (native prompt — v1) + delete.
- **Slice D — GraphView drop + save chip** (`85eec1f`): `[save as element]`
  hover-reveal `★` chip on every `group` header (slot 1; duplicate/reset slots
  shift right); drop handler branches on the composite MIME (extracted shared
  `resolveDropAnchor`); `isPaletteDrag` accepts the composite MIME.
- **Slice E — parity + smoke + docs**: `tests/composite-parity.test.ts` — the
  oracle: splice a captured+cloned round back into AES-128 and assert the
  FIPS-197 §C.1 ciphertext + per-leaf byte-identity. `e2e/composite-save-drop-smoke.spec.ts`
  — real Chromium: save chip → palette → **reload persistence** → **real HTML5
  drag** → inlined group, zero console errors. Docs (this file, help, README,
  CHANGELOG, memory).

## Non-goals (deferred)

- **Arbitrary-subgraph selection** (lasso + boundary inference) — v1 saves an
  existing group only.
- **Multi-port-INPUT composites** — needs the group-export runtime feature
  (topology A), unbuildable today.
- **Reference / linked definitions** (one edit updates all instances) — rejected
  for v1 (registered definition + runtime expansion + schema bump + hidden
  internals).
- **Parameterization** — params baked into the template for v1.
- **Exporting/sharing the composites library** — localStorage-only for v1.
- **A styled name dialog** — v1 uses native `window.prompt` for save + rename.

## Known limitation (on-brand, no special handling)

A dropped composite that reads aux (e.g. `aux["roundKey.5"]`) only computes
correctly if that aux cell exists in the new context. When absent, the existing
**coerce / aux-missing** machinery surfaces it in the trace — exactly the
"tinker and watch it break" pedagogy.

## Verification

`npm run check` green per slice (the `.githooks/pre-commit` gate is manual in
this env). The parity gate (`composite-parity.test.ts`) is the correctness
anchor; the Playwright smoke (`npm run smoke`, NOT in `npm run check`) pins the
browser-only persistence + drag.
