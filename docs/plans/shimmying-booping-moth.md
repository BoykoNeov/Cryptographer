# RSA — textbook public-key cipher with traced key generation

## Context

RSA is the long-planned next cipher (CLAUDE.md lists it under "mandatory planning";
`feedback_crypto_verification` already anticipates it). It is the project's first
**public-key / asymmetric** primitive, and a deliberately awkward fit: it is not a
block cipher, has no symmetric key, and its core is big-integer modular arithmetic
rather than byte permutation. The pedagogical payoff is large — students watch the
two halves of the "magic": **key generation** (`p, q, e → n, φ(n), d`) and
**square-and-multiply exponentiation** (`c = mᵉ mod n`, `m = cᵈ mod n`).

The architecture already sanctions every piece this needs:
- **`BytesState` only; bignum math lives *inside* executors via `BigInt`, exchanging
  `Uint8Array` at port boundaries** (`core/types.ts` line ~18 comment;
  `feedback_all_specs_port_native`). RSA never introduces a new State shape.
- **SHA-256 is the precedent for a non-block, keyless algorithm**: there is already an
  `Algorithm = Cipher | Hash` union, a `Category` signal, a `hashDefaults` table, and a
  discriminated `SpecsByMode`. RSA adds a third sibling.
- **`cipherConstants`** materializes named editable constants into `aux` before the
  walk (`runSpec`, `runtime.ts` line ~116). RSA's `p, q, e` ride here → the user edits
  them in the constants panel and watches the whole derivation re-run in ~200 ms.
- **Unrolled-rung specs + port-native fan-out from `aux`** is exactly SHA-256's shape
  (fetch a constant once, slice/consume it per rung).

### Decisions locked (this session)

| Fork | Choice | Consequence |
|---|---|---|
| Key-gen visibility | **Trace it** | `n`, `φ` decomposed into visible `mul`/`sub` frames; `d = e⁻¹ mod φ` via a `mod-inverse@1` step (oracle for v1, see Phase 4). |
| Exponent | **Live-editable** | Fixed `N = W·8` ladder rungs; each rung's conditional multiply reads bit `i` of the exponent at runtime, so editing `e` (or `p,q`→`d`) re-runs live. Identity frames on 0-bits are accepted as honest. |
| Number size | Textbook (`n ≈ 3233`-class) | Uniform working width `W` bytes for every integer; `W=2` default (16 rungs, `n < 65536`, covers classic examples). `W` is a builder constant — widen + rebuild for bigger numbers. |
| Padding / OAEP | **None** (textbook RSA) | Out of scope; `m` must satisfy `0 ≤ m < n`. |

## Architecture

### Input / parameter mapping
- **Message `m`** → the plaintext input (encrypt) / ciphertext `c` (decrypt). Big-endian
  integer, `W` bytes, `< n`.
- **`p, q, e`** → `spec.cipherConstants` (both encrypt and decrypt specs carry the same
  three; decrypt needs them to derive `d`). Editable in the constants panel.
- **`n, φ, d`** → *derived* inside the spec's "Key Generation" group, never stored.
- **Symmetric key field hidden** (`inputs.key.byteLength: 0`, exactly like SHA-256).

### New port-native primitives (`src/steps/`)
All `<bare-name>@1`, `{ kind: "ported", executor, shape, doc }`, pure, BigInt-internal,
big-endian, output fixed `W`-byte width. **Operands need NOT be equal length** (unlike
`add-mod-32`) — each port is read as a BE integer.

1. `mul@1` — `a · b` (full product, no modulus). Used for `n = p·q`, `φ = (p-1)(q-1)`.
   Throws if the product overflows `W` bytes (surfaces "primes too large / widen W").
2. `sub@1` — `a - b` (for `p-1`, `q-1`). Throws on negative.
3. `mod-mul@1` — ports `a`, `b`, `modulus` → `a·b mod n`. **Squaring = wire `a` and `b`
   to the same upstream** (no separate square primitive).
4. `cond-mod-mul@1 { bitIndex }` — ports `base`, `factor`, `exponent`, `modulus`. Reads
   bit `bitIndex` of `exponent`; outputs `base·factor mod n` if set, else `base`
   unchanged. This is the live-editable conditional multiply.
5. `mod-inverse@1` — ports `value`, `modulus` → `value⁻¹ mod modulus` via extended
   Euclid (internal). Throws a friendly error when `gcd(value, modulus) ≠ 1`
   (the coprimality precondition; surfaces in the App error banner). **v1 = single
   oracle frame** — but make it *informative*: per-instance narration surfaces
   `gcd(e, φ) = 1` and the Bézout coefficient so the one black box isn't opaque.
   Phase 4 decomposes the EEA loop.

A **6th, HYBRID** step type (`rsa.publish-key-params@1` via `meta.auxWritePorts`,
precedent `des.publish-round-keys@1`) is needed **only in Phase 2** to export the
computed `n`/`d` out of the collapsible Key-Generation group — `aux` is global so it
escapes the group scope. It is NOT one of the 5 pure leaves and is NOT needed for the
flat Phase 1 build.

Add big-endian arbitrary-width helpers in a new `src/core/big-int-codec.ts`
(`bytesToBigInt(bytes)`, `bigIntToBytes(value, width)` — throws on overflow), siblings of
the 32-bit `core/word-codec.ts`.

### Spec shape (`src/ciphers/rsa.ts` + a shared `buildRsaSpec(direction, W)` builder)

Both encrypt and decrypt share one builder; they differ only in which exponent the
ladder consumes (`e` vs the derived `d`) and the input label (message vs ciphertext).

**Phase 1 = FLAT, no groups.** Every key-gen leaf is a top-level sibling of the ladder
rungs, so the computed `n`/`φ`/`d` fan out **port-to-port** to each rung (a node's output
in the scope-local `nodeOutputs` map can be referenced by any number of later siblings).
No `aux` broadcast, no group-scope crossing, no hybrid steps — just the 5 pure primitives.
(SHA-256 needed `aux` only because its consumers were *cross-scope*; flat = same scope =
ports suffice. This is the advisor's scope-isolation fix: prove the math before fighting
group boundaries.)

```
cipherConstants = { p, q, e }            (W-byte BE integers; seeded into aux by runtime)

key-gen leaves (top-level):
  load-p/load-q/load-e = aux-load-bytes "p"/"q"/"e"   (existing hybrid; constants→ports)
  n    = mul(load-p, load-q)                          (computed — never a constant)
  p-1  = sub(load-p, const 1)
  q-1  = sub(load-q, const 1)
  phi  = mul(p-1, q-1)
  d    = mod-inverse(load-e, phi)                     (decrypt's ladder exponent)
  result₀ = constant-load 1

ladder (N = W·8 rungs, MSB→LSB), per rung i (bitIndex = N-1-i):
  square : mod-mul(base=result, b=result, modulus=n's port)     → result
  maybe  : cond-mod-mul(base=result, factor=$input,
             exponent=<e-port | d-port>, modulus=n's port){bitIndex}  → result

outputFrom = last rung's result port         → finalState
```

`modulus` on every rung wires to the `n` leaf's output port; `exponent` wires to the
`load-e` port (encrypt) or the `mod-inverse` `d` output (decrypt); `factor` is `$input`
(the message `m` / ciphertext `c`). Per-rung `narrationOverride` names "Square",
"Multiply by m (bit i = 1)", "bit i = 0 → carry forward", etc.

**Phase 2** wraps the key-gen leaves in a collapsible `"Key Generation"` group. That
re-introduces the group-scope wall, so the computed `n`/`d` must cross it via the export
mechanism chosen then (hybrid `rsa.publish-key-params@1` → `aux`, **or** group
`bodyOutput = concat(n,φ,d)` + a top-level `byte-slice`). Sanity-check at that point that
a `meta.auxWritePorts` step fires correctly *inside* a group (the key schedules are
evidence it does).

### UI integration (mirrors the SHA-256 / hash-category work)
- `src/ui/stores/cipher.ts` — add family `Asymmetric = "rsa"`, extend `Category` with
  `"asymmetric"`, add `isAsymmetric`, `rsa`/`category` signal handling in
  `useAlgorithm`, `ASYMMETRIC_OPTIONS`/`_LABELS`, and `DEFAULT_*_BY_ASYMMETRIC` tables
  (default `p=61, q=53, e=17`; default message `m=65`; empty key).
- `src/ui/stores/spec.ts` — `asymmetricDefaults` table + `buildCanonicalAsymmetric`,
  and a **third `SpecsByMode` kind** `{ kind: "asymmetric", encrypt, decrypt }`. The ~15
  functions that pattern-match `.kind` get an asymmetric arm; the cross-mode S-box/matrix
  mirrors **throw** for it (same guard as the existing `hash` arms — RSA has no mirror).
  `setAlgorithm` routes `"rsa"` to a new `setAsymmetric`.
- `src/ui/App.tsx` — category branch in the run handler; hide the key field; parse the
  message as a `W`-byte BE integer; validate `0 ≤ m < n` (compute `n = p·q` from the live
  `cipherConstants` for a friendly error); input cap.
- `src/ui/components/ParamEditor.tsx` — blocks for the 5 new step types (mostly read-only
  scalar params — `bitIndex`, width); ensure the **cipherConstants panel renders `p,q,e`
  as editable small integers** (reuse the existing SHA-256 constants editing path —
  `editCipherConstant` in `spec.ts`).
- `src/ui/narration/*` — a narration unit fn (or allowlist entry) for each new step type;
  `tests/narration-registry-contract.test.ts` gates the commit.
- `src/core/document-schema.ts` — add `"rsa"` / the asymmetric family to the algorithm
  enum tuple so saved-doc round-trips type-check (additive; **no `schemaVersion` bump** —
  `cipherConstants` already serialize hex-encoded).

## Phases (build the tightest constraint first)

**Phase 1 — math + KAT, FLAT spec, zero UI.** Add `big-int-codec.ts` + the 5 pure
primitives + register them. Build `rsa.ts` (encrypt+decrypt) **flat — no groups, no aux
broadcast**, so `n`/`φ`/`d` fan out port-to-port. Write `tests/rsa-vectors.test.ts`: KAT
against a **Python reference** (not web-cited) — `pow(65, 17, 3233) == 2790`; full
pipeline encrypt→decrypt round-trip comparing **BigInt values, not raw bytes** (leading-
zero width differs); assert the derived `n=3233`, `φ=3120`, `d=2753` intermediate frames.
This is the tightest constraint with nothing in the way; if the math is right, the rest
is plumbing.

**Phase 2 — grouping + narration polish.** Wrap key-gen in the collapsible
`"Key Generation"` group; add the **6th hybrid** `rsa.publish-key-params@1` step (or the
`bodyOutput=concat`+slice alternative) to export `n`/`d` across the new group wall —
re-running the Phase-1 KAT after the wrap proves the export is byte-identical. Per-rung +
key-gen `narrationOverride` (including the `mod-inverse` gcd/Bézout prose), collapse
defaults, constants provenance, frame-count sanity.

**Phase 3 — UI integration.** The cipher.ts / spec.ts / App.tsx / ParamEditor / narration /
document-schema wiring above. jsdom integration test: select RSA, Run, see ciphertext;
flip to decrypt, recover the message; edit `e`/`p` in the constants panel → live re-run.
Browser smoke pass (`npm run dev`) per `feedback_visual_smoke_vs_property_tests`.

**Phase 4 — stretch: decompose the modular inverse.** Replace the `mod-inverse@1` oracle
with a *traced* extended-Euclid loop (quotient/remainder/coefficient recurrence over a
fixed max-iteration `for-each-subgraph`, signed intermediates). Substantial — its own
slice; v1 ships with the oracle + rich narration. (Same coarse-then-decompose path
SHA-256 and the key schedules took.)

## Verification
- `npm run check` (biome + tsc + vitest + build) — the gate. **Pre-commit hook is OFF in
  this env** (`feedback_precommit_hook_not_installed`) → run it manually before committing.
- `tests/rsa-vectors.test.ts` against the Python oracle (`feedback_crypto_verification`).
- jsdom: RSA selectable, encrypt/decrypt round-trips, constant edits re-run live.
- Browser: confirm the ladder + key-gen render, the constants panel edits `p,q,e`, and
  narration disclosures name the right operation per rung.
- Commit per batch (`feedback_commit_cadence`); 4.8 co-author trailer; update
  `README.md` "What's in the box", `CHANGELOG.md`, `docs/key-files.md`, and a memory entry.

## Critical files
- **New:** `src/core/big-int-codec.ts`; `src/steps/{mul,sub,mod-mul,cond-mod-mul,mod-inverse}.ts`
  (Phase 1) + `src/steps/publish-key-params.ts` (Phase 2 hybrid); `src/ciphers/rsa.ts`;
  `tests/rsa-vectors.test.ts`.
- **Edit:** `src/ciphers/default-registry.ts` (register the steps); `src/ui/stores/cipher.ts`;
  `src/ui/stores/spec.ts`; `src/ui/App.tsx`; `src/ui/components/ParamEditor.tsx`;
  `src/ui/narration/index.ts` (+ a new/extended narration module);
  `src/core/document-schema.ts`.

## Risks / notes
- **Width bookkeeping** is the fiddly part: one uniform `W` for every integer; require
  `n < 2^(W·8)`. `mul@1`/`mod-mul@1` throw on overflow so a too-large prime fails loudly.
- **`φ` vs Carmichael `λ`**: both produce a round-tripping `d` (φ→2753, λ→413 for the
  classic example). v1 uses **φ** (the classic textbook presentation); the test pins
  whichever the spec computes against Python, so it can't silently drift.
- **`SpecsByMode` third kind** touches every `.kind` switch in `spec.ts` — mechanical but
  broad; the type system flags each unhandled site at `tsc` time.
