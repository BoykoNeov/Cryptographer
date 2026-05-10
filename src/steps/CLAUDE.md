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

## Adding a new step type — checklist

1. **Pick the name.** `generic.<name>@1` if reusable, `<cipher>.<name>@1` if not. Lowercase, hyphenated, single noun phrase.
2. **Create `src/steps/<name>.ts`** with the executor + doc block per the anatomy above.
3. **Register both in `src/ciphers/default-registry.ts`.** *Required* — the pre-commit hook fails commits that add a new file under `src/steps/` without test changes; also, if a CipherSpec references an unregistered type, the runtime throws.
4. **Write a test in `tests/`.** Either a per-step test (preferred for non-trivial logic) or a cipher-level known-answer test that exercises this step end-to-end. The pre-commit gate enforces a test file is touched in the same commit.
5. **Update an existing `CipherSpec` or write a new one** to reference the type.
6. **Run `npm run check`.** Biome ci, typecheck, tests, build all pass.
7. **Walk through it in the browser** (`npm run dev`) — confirm the doc renders, the param editor handles the param shape (or falls back gracefully), and the matrix view still makes sense.

## Common pitfalls (specific to this directory)

- **Forgetting the doc block.** Code compiles, runtime works, UI shows "no docs registered for step type ...". Easy to miss — add the doc *first* if you can, before the executor.
- **Sharing param objects across CipherSpec leaves.** Each leaf gets its own params. If two leaves accidentally share a `{ sbox: [...] }` reference, editing one will silently edit the other (or `updateAllStepsByType` will short-circuit on reference equality). Always emit fresh objects in spec-builder helpers (`[...AES_SBOX]`, `matrix.map(row => [...row])`).
- **Aux values that aren't `Uint8Array` when the step expects them.** Assertion: `if (!(rk instanceof Uint8Array) || rk.length !== 16) throw new Error(...)`. Better than a misleading XOR result.
- **Off-by-one errors in cyclic shifts.** AES `ShiftRows` shifts row `r` LEFT by `shifts[r]`. The inverse is shifting RIGHT by the same amounts, equivalent to LEFT by `(4 - shifts[r]) mod 4` = `[0, 3, 2, 1]`. Test both directions with a known vector.

## What does *not* belong here

- **Cipher specs** (the JSON tree of step nodes). Those go in `src/ciphers/<cipher>.ts`.
- **AES constants** (`AES_SBOX`, etc.). Those live in `src/ciphers/aes-constants.ts` because they're cipher data, not generic step logic.
- **UI editor components** for params. Those live in `src/ui/components/` and dispatch by step type.
- **Tests.** Those live in `tests/` (the test runner config doesn't pick up `.test.ts` files inside `src/steps/`).
