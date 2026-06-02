# Port-wiring editor (universal-port Phase 4d-bis)

> **Status: SHIPPED 2026-06-02.** All slices A–G landed on `main`. This is the
> in-app affordance to rewire a leaf's input ports (the prerequisite the
> universal-port plan names for 4f compose-and-save). Memory pointer:
> `project_universal_port_dataflow_proposal.md`.
>
> Slice → commit:
> - **A–D** (headless core: `setPortBinding`, `legalSourcesForInput`,
>   `classifyBinding`, `bindPortInSpec`) — `b064159`
> - **F** (dropdown editor + `setPortBinding` `{}`→absent normalization) — `029c197`
> - **E** (canvas click-to-arm gesture + Playwright smoke) — `38ac293`
> - **G** (document round-trip test + this doc + help) — see the docs commit

## Context

Port wiring used to be **source-file-only**: every shipped cipher spec declared
its `portInputs` (`Record<inputPortName, PortBinding>`, `PortBinding =
{ node, port }`) in TypeScript builders; the in-app graph editor let the user
drag containers for *layout*, drop palette steps to *insert*, and edit
*params* — but there was no way to change **which upstream output port an input
port reads from.** That gap blocked Phase 4f (compose-and-save): a user can't
compose primitives into a new named element without an affordance to wire them
together.

This slice (4d-bis) delivers the in-app port-wiring editor: select an input port
on a leaf, pick a **scope-legal** upstream source, and the binding is written to
the spec via a ref-equality-preserving mutation that round-trips through the
existing Save/Share/Load machinery (**no schema bump** — `portInputs` is already
part of `StepLeaf`/`document-schema`). **Scope was 4d-bis only;** 4f gets its
own plan.

**User decisions:** scope = 4d-bis only; primary gesture = **click-to-arm**
(click an input port to arm, click a legal source to bind), with a
**per-input-port dropdown** as the keyboard/a11y fallback. Drag-port-to-port was
deferred.

## Design spine: enumerate the legal-source set, don't validate the gesture

The discriminating call. Once "for input port P on leaf L, the legal source set
is {…}" is correct, the gesture is just a picker over that set, the warning
glyph is just "scope-legal but shape-mismatched," and the worst failure becomes
**unrepresentable by construction.**

**Two failure classes, kept separate** (conflating them ships specs that crash
on Run instead of coercing):

1. **Scope violation** → hard runtime throw (`resolveBinding` in `runtime.ts`).
   **Prevented by construction:** the editor only ever offers scope-legal
   targets, so a cross-scope binding can never be created. NOT a glyph — it
   simply isn't a dropdown entry / isn't a canvas bind handle.
2. **byteLength mismatch** among scope-legal targets → **soft warn-and-run
   coercion** (the runtime's existing port-coercion step), surfaced as an amber
   ring/handle on the canvas + a `⚠ size mismatch (coerces)` dropdown label.
   This is the pedagogical path ("permissiveness IS the pedagogy").

**The scope model** (verified against `runtime.ts:151-179` and the parallel walk
in `spec-shapes.ts`): scope = **one walk-frame**. Siblings within a `walk` call
share `nodeOutputs`; nested scopes (group bodies, iterate / for-each iterations)
start **fresh**; `$input` is pre-seeded **only at the top scope**. So the legal
sources for an input port on leaf L are: preceding same-scope nodes' output
ports; plus the container seed `port(<id>,"in")` (+ `"chain"` for a chaining
iterate) when L heads a seeded body; plus `port($input,"out")` at the top scope.

The enumerator (`src/core/port-sources.ts`) mirrors that walk and is **STRICT on
`$input`** (top scope only) where the validator is lenient
(`spec-shapes.ts:229`). Two tests bound it: a SUPERSET test (every binding in 7
shipped specs is enumerated — agrees with the runtime on real data) and
synthetic STRICT-EXCLUSION tests (a nested leaf must NOT enumerate `$input` or a
cross-scope sibling).

## What shipped, by file

- `src/core/spec-mutations.ts` — `setPortBinding(spec, stepId, portName,
  binding|null)`, ref-equality-preserving; clearing an emptied map normalizes
  `portInputs` back to **absent** (byte-stable saves).
- `src/core/port-sources.ts` *(new)* — `legalSourcesForInput` (scope-bounded,
  compat-annotated) + `classifyBinding` (`"ok"`/`"coerce"` on byteLength;
  layout differences are advisory).
- `src/ui/stores/spec.ts` — `bindPortInSpec` store boundary (active slot only,
  reuses the debounced rerun, never auto-syncs across encrypt/decrypt).
- `src/ui/components/PortWiringEditor.tsx` *(new)* — per-input-port dropdowns;
  honest current value (explicit unresolvable option); index-keyed options.
- `src/ui/stores/wiring.ts` *(new)* — transient armed-port signal (not
  persisted, not a viewer preference).
- `src/ui/components/GraphView.tsx` — input-port handles, armed/legal-target
  rings, right-edge bind handle (amber on coerce), Esc + empty-canvas disarm.
- Tests: `spec-mutations` (9 cases), `port-sources` (22), `port-wiring-editor`
  (jsdom dropdown, 6), `graph-view-wiring` (jsdom gesture logic, 3),
  `port-wiring-roundtrip` (document round-trip, 3), `e2e/port-wiring-smoke`
  (real Chromium, 2). Help: `docs/help/graph-view.md` "Rewiring ports".

## Verification

- `npm run check` green (194 files, 2269 pass / 2 skip + build).
- `npm run smoke -- e2e/port-wiring-smoke.spec.ts` green in Chromium: handles
  visible + clickable, armed/target classes paint, cross-scope leaf offers NO
  handle (scope-bounding in the browser), wire completes with no console
  errors, Esc cancels. (Smoke is NOT in `npm run check`, per
  `feedback_playwright_dormant` — expanded reactively for this canvas gesture.)

## Out of scope (4f and beyond)

- Composing N primitives into a new **named palette element** + saving it
  (4f — its own plan, depends on this).
- Drag-port-to-port gesture (deferred; click-to-arm + dropdown shipped first).
- Output-side / container `seedInput`/`bodyOutput` rewiring in the editor.
- Cross-scope wiring / a group-output-export runtime feature (topology A —
  unbuildable today, `project_group_scope_port_isolation`).
- Cross-mode mirror buttons for rewires (a rewire isn't a class-1/2 relationship).
