# Step types

Each file in this directory implements **one** generic step type used by one or more cipher specs. Step types are addressed by string keys (e.g. `generic.byte-substitution@1`) that get baked into saved `CipherSpec` JSON files **forever** — pick names carefully and version aggressively.

## Anatomy of a step file

Every step file exports two things:

```ts
// 1. The pure executor
export const myStep: StepExecutor = (state, params, ctx) => {
  // validate params, transform state, return { state, auxReads?, auxWrites? }
};

// 2. The documentation block (StepDocumentation in core/types.ts)
export const myStepDoc: StepDocumentation = {
  name: "...",        // "Mix Columns"
  summary: "...",     // one-liner; rendered in compact UI contexts
  detail: "...",      // multi-paragraph markdown for the description panel
  params: new Map([
    ["paramName", "what it is and the legal range"],
  ]),
  references: ["FIPS-197 §X.Y.Z", "..."],
  // State-shape contract. Required for every shipped step type — three
  // UX surfaces read it: palette chip, drop-anchor greying, and the
  // pre-Run `state-shape-mismatch` warning. See `core/types.ts`'s
  // `StepShapeContract`. Use `"any"` when the step only touches aux
  // (key schedules, aux primitives) and `"preserveInput"` when state
  // passes through unchanged (the common case).
  shapeContract: { input: "matrix4x4-bytes", output: "preserveInput" },
};
```

Both get registered in `src/ciphers/default-registry.ts`:

```ts
r.register("generic.my-step@1", { executor: myStep, doc: myStepDoc });
```

Then a `CipherSpec` references the step type by string and provides params:

```ts
{ kind: "step", id: "round.1.my-step", type: "generic.my-step@1", params: { /* ... */ } }
```

## Naming conventions

- **`generic.<name>@1`** — operations that aren't tied to a specific cipher. Used by AES SubBytes, but also reusable for other ciphers that do byte substitution. Keep these param-driven so different ciphers can plug in different tables.
- **`<cipher>.<name>@1`** — specific to one cipher (e.g. `aes.key-expansion@1`). The step's logic encodes cipher-specific math that can't be reduced to params.
- **`@1`** version suffix is mandatory. If you ever change the parameter shape or step semantics in a backwards-incompatible way, bump to `@2` and keep `@1` for old saved specs.

## Required: contracts

- **Pure**: `(state, params, ctx) → state`. No I/O, no `console.log`, no `Date.now()`. Same input → same output, always. The runtime depends on this for replay and trace consistency.
- **Param validation**: throw a descriptive `Error` when params are wrong shape or out of range. Don't silently coerce. The catch in `App.tsx` will display the message inline; users learn faster from explicit errors.
- **State immutability**: don't mutate `state.bytes` in place. Allocate a new `Uint8Array` for the output. The runtime clones around you, but mutating the input state breaks the trace's `before` snapshot.
- **Aux discipline**: declare every aux key you read in `auxReads` (for trace bookkeeping). Aux values written via `auxWrites` are merged into the live aux map by the runtime — don't write directly.
- **State-shape contract**: declare `shapeContract` in the doc block (input shape the executor accepts; output shape it produces, or `"preserveInput"` if state passes through). Drives the palette chip + drop-anchor greying + the pre-Run `state-shape-mismatch` warning. `tests/state-shape-contracts.test.ts` enforces 100% coverage on the default registry.

## Adding a new step type — checklist

1. **Pick the name.** `generic.<name>@1` if reusable, `<cipher>.<name>@1` if not. Lowercase, hyphenated, single noun phrase.
2. **Create `src/steps/<name>.ts`** with the executor + doc block per the anatomy above.
3. **Register both in `src/ciphers/default-registry.ts`.** *Required* — the pre-commit hook fails commits that add a new file under `src/steps/` without test changes; also, if a CipherSpec references an unregistered type, the runtime throws.
4. **Write a test in `tests/`.** Either a per-step test (preferred for non-trivial logic) or a cipher-level known-answer test that exercises this step end-to-end. The pre-commit gate enforces a test file is touched in the same commit.
5. **Update an existing `CipherSpec` or write a new one** to reference the type.
6. **Add a dedicated block in `src/ui/components/ParamEditor.tsx`.** Wire a `Match` for your step's type into the `Switch`, point it at a small block component, and skip the raw-JSON fallback. The fallback's `JSON.stringify(params, null, 2)` puts each array element on its own line, so anything with a non-trivial param shape (256-entry S-box, 11-entry Rcon, even a single `{ blockSize: 16 }`) ends up as a wall of single-value lines. Patterns to copy: read-only `.param-scalars` `<dl>` for structural strings/numbers (where editing would break the cipher); horizontal byte-cell row for small editable arrays (`rcon-row`); collapsed `<details>` wrapping a reusable editor for big arrays (S-box). Skip `ApplyAllRow` when copying the value across siblings would be actively harmful (e.g. AddRoundKey, where each step points at a distinct `roundKey.N`).
7. **Add a narration unit fn (or allowlist).** If your step's input shape is `matrix4x4-bytes` or `bytes`, register a `NarrationFn` in `src/ui/narration/<cipher-or-family>.ts` (and wire it in `src/ui/narration/index.ts`) that yields one `NarrationUnit` per conceptual sub-unit (per row, per column, per byte — match the visual rhythm of `KeyScheduleExplorer`'s `.key-schedule-aes-stage` rows). Each `Prose` must be a `Component<{fmt: ByteFormat}>` so format-toggle re-renders byte text without closing open disclosures. AVOID per-byte disclosure on large states (a step on a 200-byte state must pick a coarser unit or land on the allowlist). OR: add the step type to `NARRATION_NO_OP_ALLOWLIST` in `src/ui/narration/registry.ts` with a brief rationale (the irreducible-after-Phase-3 set is the 4 key-expansion step types — already covered by `KeyScheduleExplorer` — plus the 3 bit-level Serpent transforms where byte-level prose would be misleading). The contract test (`tests/narration-registry-contract.test.ts`) gates the commit; an unhandled cell-shape step type fails CI.
8. **Run `npm run check`.** Biome ci, typecheck, tests, build all pass.
9. **Walk through it in the browser** (`npm run dev`) — confirm the doc renders, your new param block renders in the right shape, the matrix view still makes sense, and the narration unit disclosures expand into prose that names the right specific bytes.

## Common pitfalls (specific to this directory)

- **Forgetting the doc block.** Code compiles, runtime works, UI shows "no docs registered for step type ...". Easy to miss — add the doc *first* if you can, before the executor.
- **Forgetting the ParamEditor block.** Code compiles, the cipher runs correctly, but selecting a step in the UI dumps `JSON.stringify(params, null, 2)` — three lines for one scalar, hundreds for an S-box. Three commits' worth of retroactive cleanup (key-expansion, add-round-key, the padding family) have already chased this — keep the cost in the same commit instead. The raw-JSON fallback stays in `ParamEditor.tsx` only to keep the UI from crashing on unregistered types during development; it is not the intended end state for any step that ships.
- **Sharing param objects across CipherSpec leaves.** Each leaf gets its own params. If two leaves accidentally share a `{ sbox: [...] }` reference, editing one will silently edit the other (or `updateAllStepsByType` will short-circuit on reference equality). Always emit fresh objects in spec-builder helpers (`[...AES_SBOX]`, `matrix.map(row => [...row])`).
- **Aux values that aren't `Uint8Array` when the step expects them.** Assertion: `if (!(rk instanceof Uint8Array) || rk.length !== 16) throw new Error(...)`. Better than a misleading XOR result.
- **Off-by-one errors in cyclic shifts.** AES `ShiftRows` shifts row `r` LEFT by `shifts[r]`. The inverse is shifting RIGHT by the same amounts, equivalent to LEFT by `(4 - shifts[r]) mod 4` = `[0, 3, 2, 1]`. Test both directions with a known vector.

## Compose your own block-cipher mode (Slice 10 recipe)

Three small step types — `generic.aux-load@1`, `generic.aux-xor@1`,
`generic.aux-copy@1` — exist so a user can construct chaining modes (CBC,
OFB, CFB) entirely inside the visual editor, without writing a custom
executor. Each is dataflow-only: state is passthrough, the work happens
over the `aux` map. Each is graceful on missing reads — wiring up a spec
one step at a time produces orange `!` warning dots on under-wired nodes
instead of throwing.

**CBC encryption (chaining math), 2 blocks:**

```text
aux-load IV            → aux[iv]      (the initialization vector literal)
aux-load P0            → aux[p0]      (or seed via a state↔aux bridge later)
aux-load P1            → aux[p1]
aux-copy iv → feedback                 (initialize the running chain)
aux-xor  p0 → feedback                 (feedback now = P0 ⊕ IV = C0)
<cipher core>                          (when a state↔aux bridge primitive lands)
aux-copy feedback → c0                 (snapshot before next iteration overwrites)
aux-xor  p1 → feedback                 (feedback now = P1 ⊕ C0 = C1)
aux-copy feedback → c1
```

**Why each primitive earns its place:**

- `aux-load` is the only way to introduce a literal (IV, counter,
  per-mode constant) without baking it into another step's params.
- `aux-xor` is in-place by design — it's the chain accumulator. Pairing
  it with `aux-copy` is what gives you a per-iteration snapshot.
- `aux-copy` doubles as a rename/router when one step's output needs to
  feed two different downstream consumers under different aux names.

**Decryption** is symmetric: each block's plaintext recovers as `P_i =
C_i ⊕ C_{i-1}` (with `C_{-1} = IV`). Wire each `C_i` through an
`aux-copy` to a working slot, then `aux-xor` the previous ciphertext (or
IV) into it.

The full executable example lives in `tests/aux-primitives.test.ts`'s
CBC-from-scratch suite.

**Out of scope for Slice 10:** today's primitives operate only over the
aux map. Threading the cipher state through the chain (so a real AES
core can sit between `aux-xor` and `aux-copy`) needs a state↔aux bridge
step type — a future primitive. For now, "single-round CBC" means
"the chaining math, exercised standalone."

## What does *not* belong here

- **Cipher specs** (the JSON tree of step nodes). Those go in `src/ciphers/<cipher>.ts`.
- **AES constants** (`AES_SBOX`, etc.). Those live in `src/ciphers/aes-constants.ts` because they're cipher data, not generic step logic.
- **UI editor components** for params. Those live in `src/ui/components/` and dispatch by step type.
- **Tests.** Those live in `tests/` (the test runner config doesn't pick up `.test.ts` files inside `src/steps/`).
