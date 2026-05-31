# Slice 5.2 handoff — true PortedExecutors for the lifted key-schedules + padding + aux primitives

**STATUS: COMPLETE (2026-05-31).** All batches shipped + pushed —
Batch A `8beae14`, Batch B `f5e1f80`, Batch C `d307656`, Batch D `9b4cd4c`;
close-out done. The advisor pass that was pending below **was run this session**
(advisor available again) and steered Batch C to decision C1 (accept the
PortFlowView reroute for padding) + flagged the unpad length-decrease smoke. See
`docs/plans/phase-5-legacy-retirement.md` "Slice 5.2 — what shipped" for the
canonical record. This file is retained as the historical approach reference.
The advisor's hard gate — the **unpad** browser smoke (novel length-*decrease*)
— was driven + viewed this session (renders as input `STATE (16 bytes)` over
output `STATE (5 bytes)`; reads clearly; C1 confirmed). Only optional glances
remain (Speck key-schedule frame, aux-primitive frame) — ordinary multi-port
PortFlowView shapes.

Parent plan: `docs/plans/phase-5-legacy-retirement.md` (Slice 5.2 row).
Topic memory: `…/memory/project_phase5_legacy_retirement.md`.

---

## What Slice 5.2 is

Convert the **lifted** key-schedules + padding/aux primitives from
`liftLegacyExecutor`-wrapped legacy executors into **true `PortedExecutor`s**,
and drop their `legacy:` registry field. `liftLegacyExecutor` **SURVIVES** as a
bytes-only helper — after 5.2 its **sole** caller must be
`feistel.toy-add-k@1` (the reserved toy fixture for the future port-native
Feistel/swap viz rebuild).

"True PortedExecutor" here = the **hybrid-ported** pattern: drop `legacy`,
**KEEP `meta`**. The runtime still projects `aux[keyAuxName] → masterKey` (via
`meta.auxReadPorts`) and `key${i} → aux[outputPrefix.i]` (via
`meta.auxWritePorts`), so emitted frames stay **byte-identical** —
`auxRead`/`auxWritten`/`stateBefore`/`stateAfter` unchanged. The *only* new
fact is that `portInputs`/`portOutputs` now populate (runtime gate:
`if (registration.legacy === undefined) capture ports`, ~`runtime.ts:767`).
This is the same operation B2/B3/B4 already did to the round **bodies**; 5.2
extends it to the key-**schedules** + padding + aux.

This is NOT a rewire of every round body's aux read. Each target file already
has its `meta` + `PortContract` (`shape`) authored from Phase-1 lifting — we
only swap the executor signature and the registration.

---

## The exact transform (validated in Batch A — use AES as the template)

**In the step file** (`StepExecutor → PortedExecutor`):
- Signature: `export const X: StepExecutor = (state, params, ctx) => {…}`
  becomes `export const X: PortedExecutor = (inputs, params, _ctx) => {…}`.
- Read the master key from the port, not aux:
  `const key = inputs.get("masterKey");` (was `ctx.aux.get(p.keyAuxName)`).
  Keep a descriptive throw: `"X: 'masterKey' port must carry the master-key
  bytes (projected from aux[keyAuxName] via meta.auxReadPorts)"`.
- Return a `Map<string, Uint8Array>` of `key${i}` ports, not
  `{ state, auxReads, auxWrites }`:
  `outputs.set(\`key${i}\`, …)` (was `auxWrites.set(\`${p.outputPrefix}.${i}\`, …)`).
- Imports: drop `AuxValue` / `StepExecutor` / (`StepContext` where unused); add
  `PortedExecutor`. Keep `Json`, `PortContract`, `PortShape`,
  `ProjectionMetadata`, `StepDocumentation`.
- **Do not touch** the existing `…Meta`, `…PortContract`, `…AuxReadPorts`,
  `…AuxWritePorts`, `…OutputPorts`, doc block — they're already correct.
- Add a short header comment per project comment-density convention (educational
  project) noting it's port-native since Slice 5.2 and that `meta` is retained.

**In `src/ciphers/default-registry.ts`:** read the **`aes.key-expansion@1` and
`@2`** registrations (already converted, commit `8beae14`) as the literal
template. They now read `{ kind:"ported", executor: keyExpansion, shape:
keyExpansionPortContract, meta: keyExpansionMeta, doc: … }` — no `legacy:`, no
`liftLegacyExecutor(...)` wrap. Apply the identical shape to the speck/serpent/
des rows: drop `legacy` + the lift wrap, keep `meta`. (Confirm the exact
current text by reading the AES rows; the harness was flaky when I tried to
re-grep line numbers, so don't trust a remembered line number — read it.)

---

## Correctness gate (per plan: "Crypto KAT gates")

Capture nothing extra — the existing per-cipher dispatch tests already ARE the
KAT gate, and they run flag-on through `runSpec`, reading frames. After each
batch run **`npm run check`** (biome + tsc + vitest + build). The pre-commit
hook is **OFF** in this env (see memory `feedback_precommit_hook_not_installed`)
— you MUST run the gate manually before committing `src/**`/`tests/**`.

Commit multiline messages via a file: `git commit -F .git/MSG.txt` then
`rm .git/MSG.txt`. **Do NOT** use a PowerShell here-string through the Bash
tool — it parse-errors. Trailer: `Co-Authored-By: Claude Opus 4.8
<noreply@anthropic.com>`. Push after each batch (commit cadence).

---

## Batch A — DONE (commit `8beae14`, pushed)

`aes.key-expansion@1` + `@2` → true PortedExecutors. Files changed:
`src/steps/key-expansion.ts`, `src/ciphers/default-registry.ts`,
`tests/key-expansion-v2.test.ts`, `tests/aes-key-schedule-sim-parity.test.ts`,
`tests/runtime-ported-dispatch-aes-core.test.ts`, `tests/frame-port-values.test.ts`.
All green (130 affected tests incl. AES-128/192/256 + ECB/CBC KATs + duplicate-
round; tsc clean). Working tree clean at `8beae14`.

---

## Batch B — Speck / Serpent / DES key-schedules (NOT STARTED)

The three step files are structurally identical to AES's — each reads
`ctx.aux.get(keyAuxName)`, builds an `auxWrites` map, returns
`{ state, auxReads, auxWrites }`, and **already has** `…Meta` +
`…PortContract` + the aux-read/write port projections. Apply the transform
above to all three:

1. `src/steps/speck-key-schedule.ts` — `speckKeySchedule`. Outputs
   `key0..key{rounds-1}` (22 for Speck32/64), 2-byte each. Error string +
   header comment as above. (NOTE: my earlier in-session edits to THIS file
   were **cancelled** and did **not** land — the file is the original lifted
   version. Re-read before editing.)
2. `src/steps/serpent-key-expansion.ts` — `serpentKeyExpansion`. Outputs
   `key0..key32` (33 fixed), 16-byte each.
3. `src/steps/des-key-schedule.ts` — `desKeySchedule`. Outputs `key0..key15`
   (16 fixed), 6-byte each. This file imports `StepContext` — drop it (the
   ported sig uses `_ctx` untyped-as-needed, or keep `StepContext` only if you
   type `_ctx`). It also has `AuxValue` to drop.

Then the registry: drop `legacy` + lift on `speck.key-schedule@1`,
`serpent.key-expansion@1`, `des.key-schedule@1`; keep `meta`.

**Test impact (read these — all read in full this session):**
- `tests/runtime-ported-dispatch-speck.test.ts`,
  `…-serpent.test.ts`, `…-des.test.ts` — **no executor-direct calls**; they run
  `runSpec(..., portedDispatchEnabled:true)` and read `auxWritten`/`auxRead`/
  `finalAux`. Because `meta` is retained, the projected aux is byte-identical,
  so the **Serpent frame-digest pin** (`99:<sha256>` over
  `(stepId, stateAfter, sorted(auxRead))`) and the Speck **golden frame stream**
  should pass UNCHANGED. **Do not edit the assertions.** BUT each file's
  **docstring/comments** say "the key-schedule stays lifted (keeps its `legacy`
  fallback)" — those are now stale; update the prose (Speck header lines ~9-12,
  Serpent ~11-14, DES ~16-17 and the `(c)` block comments) to "port-native
  since Slice 5.2; runtime projects the round keys to aux via meta." This is a
  comment-only edit but ships in the same commit.
- `tests/serpent-key-schedule-sim-parity.test.ts` — **THIS ONE BREAKS.** It
  registers `serpentKeyExpansion` directly as legacy:
  `registry.register("test.serpent-key-expansion", { executor: serpentKeyExpansion, doc })`
  and runs flag-OFF (`runSerpentExecutor`, ~lines 40-86). Rewrite exactly like
  `aes-key-schedule-sim-parity.test.ts` was rewritten in Batch A: register
  `{ kind:"ported", executor: serpentKeyExpansion, shape:
  serpentKeyExpansionPortContract, meta: serpentKeyExpansionMeta, doc }` and add
  `portedDispatchEnabled: true` to the `runSpec` opts. The round keys still land
  in `trace.finalAux` via `meta.auxWritePorts`, so the rest of the assertions
  stand. Import the two new symbols from `@/steps/serpent-key-expansion`.
- **No Speck or DES sim-parity test calls the executor directly** (only Serpent
  does). KeyScheduleExplorer sims are separate (`src/ui/key-schedule-sim/`) and
  unaffected.

**UX ripple:** AES/Serpent/DES key-schedule frames stay intercepted by
`KeyScheduleExplorer` (keyed by `isKeyExpansionStepType`, which includes aes@1/@2,
serpent.key-expansion@1, des.key-schedule@1) → inspector unchanged. **Speck is
NOT in that registry** → once `speck.key-schedule@1` becomes port-native, its
frame reroutes `BytesView → PortFlowView` (predicate `isPortNativeFrame`,
`PortFlowView.tsx:53`). That's acceptable (it's the honest port view) but
**browser-smoke a Speck key-schedule frame** to confirm it renders sanely
(master key in on `masterKey`, 22 round keys out on `key0..key21`).

---

## Batch C — padding family (NOT STARTED)

`src/steps/pkcs7-pad.ts` + unpad + zero-pad + iso7816-4 (pad+unpad ≈ 6 step
types). These are **pure bytes→bytes state-port** steps (no aux) — confirm each
has a `state` input/output port in its `meta`/contract, then convert the
executor to read `inputs.get("state")` and return `outputs.set("state", …)`.
Read each file first; the exact port name + whether a length-change is involved
matters. Tests: the padding dispatch test + the 3 padding unit tests + any
`spec-mutations-padding.test.ts` touch points (grep showed it references
`*.key-schedule|key-expansion` only incidentally — verify).

**UX ripple (load-bearing):** padding frames currently render in `BytesView`
(its header comment literally lists pkcs7-pad/unpad). Going port-native reroutes
them to `PortFlowView`. `BytesView` has the nice **length-delta highlight**
(ghosted added/removed cells) + **block grouping** that `PortFlowView` lacks.
**Decide before committing** whether that regression is acceptable or whether
`PortFlowView` needs the length-delta affordance (or padding stays on a special
case). **This is the main open design question of the slice — the advisor pass
should weigh in here.** Browser-smoke a pad frame and an unpad frame.

---

## Batch D — aux primitives (NOT STARTED)

`src/steps/aux-load.ts`, `aux-xor.ts`, `aux-copy.ts` (`generic.aux-load@1` /
`aux-xor@1` / `aux-copy@1`). Convert to PortedExecutors. Read each first.

**aux-copy atomicity (critical):** `generic.aux-copy@1` uses the
`"preserve-input-variant"` layout sentinel (handled in
`port-projection.ts::auxPortBytesToValue`). When it goes port-native to a raw
bytes contract, you must **simultaneously** delete `"generic.aux-copy@1"` from
`NON_BYTES_ALLOWLIST` in `tests/byte-native-ports-contract.test.ts` — that test
asserts **exact set equality**, so a stale entry fails. (Per the summary,
aux-copy is the **only** remaining allowlist entry — verify by reading the test;
after removal the allowlist may be empty.) See memory
`project_aux_copy_variant_gap` for the variant-preservation precedent.

**Don't confuse** `generic.aux-load@1` (legacy, this batch) with the
port-native `aux-load-bytes@1` used by SHA-256 — `sha-256.ts` references the
latter, a different already-port-native step. Tests: aux-only dispatch test +
`tests/aux-primitives.test.ts` (the CBC-from-scratch suite).

---

## Close-out (NOT STARTED)

1. Confirm `liftLegacyExecutor`'s **sole** caller is `feistel.toy-add-k@1`
   (grep `src/` for `liftLegacyExecutor` — should be the definition at
   `port-projection.ts:~541` + the one feistel-toy registration).
2. Update `docs/plans/phase-5-legacy-retirement.md` (mark 5.2 done) + `CLAUDE.md`
   (the architecture prose still says key-schedules are lifted in places) +
   the topic memory file. Per `feedback_session_end`: docs/memory **before**
   commit so they ride in the same commit.
3. Final `npm run check`. Browser smoke: PortFlowView for a Speck key-schedule
   frame, a padding frame, an aux-primitive frame.
4. Update `tests/frame-port-values.test.ts` if needed — it already asserts AES
   key-expansion carries ports (Batch A) and toy-add-k stays undefined; if any
   other test asserted a 5.2 target "stays lifted," fix it.

---

## Required advisor pass (STILL PENDING)

The plan mandates an "own advisor pass" for Slice 5.2 (per
`feedback_iterative_slice_review`). It was **not done** — the advisor tool was
unavailable this session. Before committing Batch C especially, run `advisor()`
and surface its output inline (per global `feedback_advisor_visibility`). Topics
to put to it: (1) the hybrid-ported pattern correctness; (2) the
`BytesView → PortFlowView` ripple for padding — is losing the length-delta
highlight acceptable, or does PortFlowView need it first; (3) the Speck
key-schedule reroute (no KeyScheduleExplorer interception); (4) the aux-copy
`preserve-input-variant → raw` + allowlist-deletion atomicity; (5) batch
ordering / whether padding should ship behind a PortFlowView enhancement.

---

## Environment cheat-sheet

- Pre-commit hook **OFF** (`core.hooksPath → .git/hooks`, no pre-commit). Run
  `npm run check` manually. (`feedback_precommit_hook_not_installed`.)
- Multiline commit: `git commit -F file` (NOT a PowerShell here-string via Bash
  — it parse-errors).
- `npm run check` ≈ 40s. Full vitest ≈ 45s, 2348 tests.
- Docs-only commits may use `--no-verify` (sanctioned exception only when every
  changed path is `*.md`).
- Harness was dropping tool results intermittently this session; if a tool
  returns blank, just re-issue it.
