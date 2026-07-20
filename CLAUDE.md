# Cryptographer

Interactive cryptography explorer. The user enters plaintext + key, sees every intermediate state of every step of every round, and can experiment by editing the cipher's parameters (swap the S-box, reorder steps, change the MixColumns matrix) and watch the trace re-run within ~200ms. Built as a learning tool, not a production crypto library.

## Quick reference

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server at `http://localhost:5173`. Hot-reloads on file changes. |
| `npm test` | Vitest, single run. Currently ~3070 tests across 253 files, ~115s total (jsdom UI tests dominate). |
| `npm run typecheck` | `tsc --noEmit`, strict. |
| `npm run check` | The gate: `biome ci . && tsc --noEmit && vitest run && vite build`. ~130s warm on this machine; **a cold first run can exceed 3 minutes**, so give the pre-commit hook a generous timeout or background it — a killed hook aborts the commit and silently leaves everything staged. |
| `npm run build` | Production build into `dist/`. ~264 KB gzipped JS. |

The pre-commit hook in `.githooks/pre-commit` runs `npm run check`. GitHub Actions in `.github/workflows/ci.yml` runs the same on push. Don't bypass with `--no-verify` unless you have a specific reason; both gates exist for a reason.

## Architecture

The whole app is built around one idea: **a cipher is JSON, not code.**

```
CipherSpec (JSON tree)  ──►  Runtime  ──►  Trace (immutable frames)  ──►  UI (Solid)
                              ▲
                              │ looks up by stepType
                           Registry: stepType → { executor, doc }
```

A `CipherSpec` (`src/core/types.ts`) is a tree of `StepNode`s. Leaves are `{ kind: "step", id, type, params }`; groups are `{ kind: "group", id, label, children }`; iterate nodes are `{ kind: "iterate", id, label?, countFromAux, blocksFromAux, outBlocksAux, children }`. The `Runtime` (`src/core/runtime.ts`) walks the tree, looks each leaf's `type` up in the `StepRegistry` (`src/core/registry.ts`), and calls its executor with `(state, params, ctx)`. Each executor is pure — `(state, params) → state` — and the runtime is the only place that knows about tracing or iteration.

**Multi-block modes are cipher-agnostic: `N ciphers + M modes`, not `N × M`** (`docs/plans/foamy-prancing-wren.md`, Phases A+B+C shipped 2026-07-17 — plan CLOSED). A **mode of operation** (ECB, CBC, CTR, CFB) is a rule for repeating a block cipher over a long message, and that rule is identical for every cipher — so it is written ONCE against the `BlockCipherCore` contract (`src/ciphers/block-cipher-core.ts`): block/key width, a key schedule, and seed-parameterized forward + inverse bodies returning an explicit output binding. `modes/ecb.ts` + `modes/cbc.ts` + `modes/ctr.ts` + `modes/cfb.ts` consume that and know nothing else about the cipher; `aes-core.ts` / `blowfish-core.ts` are the only places the mode machine learns a cipher's specifics. Adding a mode gives it to every core; adding a core gives it every mode.

**Cores today: AES ×3 + Speck ×2 + Blowfish + Serpent ×3 + DES + Twofish — every block cipher in the app.** Blowfish (Phase C) is load-bearing beyond "one more cipher": it is the first core whose block is **not 16 bytes**, so it is the first to actually exercise the block-size-generic arithmetic — every earlier core was AES, and a stray hardcoded `16` would have passed the whole suite. Serpent (2026-07-18, Blowfish-templated follow-up) is an **AES-shaped** core — 16-byte block, flat round groups between IP and FP — so it adds breadth, not block-size confidence; its seed-threading was already 90% done (only the IP leaf hardcoded `$input`, an explicit `TODO`), and like AES it is a `serpentCore(keyByteLength)` **family** of three. Speck32/64 (2026-07-18, Serpent-templated follow-up) is the **first core whose block is smaller than 8 bytes** — its 4-byte block pushes the block-size-generic arithmetic below every "round" width (the iterate splits at 4, the CBC IV is 4 bytes wide, the pad fills to 4), where a stray `>= 8` floor that survived Blowfish would surface; its seed-threading was one binding (round 1's `state`), and it is a `speck32_64Core(byteOrder)` **family** of two (BE-paper / LE-NSA — the same word-level cipher under two serializations). DES (2026-07-20, Speck-templated follow-up) adds **breadth, not block-size confidence** — its 8-byte block is Blowfish's — but it is the **first core whose body nests a port-mode group inside the mode's iterate**: every earlier core's body is a flat list of siblings, while DES wraps its 16 rounds in an outer `rounds` group that re-seeds from IP *inside* the loop, one scope deeper than any core had placed one. Its seed-threading was one binding (the IP leaf, the Serpent story — B4 had already port-chained every round), and it is the first core with a genuinely **external** oracle: `node:crypto`'s `des-ede3` under a tripled key `K‖K‖K` degenerates EDE to single DES. **CTR (2026-07-20) is the third mode, and the one that tests every core at once.** It cost one file + one step type with ZERO changes to `BlockCipherCore` — the contract was designed against it (hence forward+inverse bodies exposed independently, and padding as a per-mode flag). It is the strictest core test available: ECB/CBC both feed the body the message block (CBC XORs the chain in first, but the bytes still come from the iterate's `in` port), while **CTR feeds the body the COUNTER from the iterate's `chain` port and the message block never enters the cipher at all** — so every core's forward body is re-seeded from a port no prior mode reached. The counter rides CBC's existing cross-iteration carry (nothing in the runtime changed; what a mode threads through the carry is the mode's business) and advances via a visible `increment-counter@1` frame — a new port-native step whose width is **derived from the wired input, not a param**, because a counter block is one *cipher* block wide; that one fact is what keeps the mode cipher-agnostic. CTR runs the FORWARD body in both directions (XOR is self-inverse), so encrypt and decrypt specs are structurally identical. **Honest partial blocks shipped 2026-07-20** (`docs/plans/encapsulated-skipping-bubble.md`): CTR accepts any message length ≥ 1, emits ciphertext exactly as long as the plaintext, and engages NO padding overlay at all — `L < B` (a whole message shorter than one cipher block) is representable for the first time. Two halves of one mechanism: the iterate's new optional `allowPartialFinalBlock` relaxes the block-multiple throw to `ceil` and hands the last iteration a **short `in` block** (the runtime's per-block `subarray` already clamped, so that fell out free), and a new `truncate-to-reference@1` leaf (`ctr-trim`) sits between the cipher body and the XOR trimming the **keystream** to that block's width. Trimming the keystream rather than the final output is the pedagogical choice — the zero-pad-and-trim alternative would show a padded plaintext block visibly entering the XOR, contradicting the claim the mode exists to teach. **The core is untouched and stays cipher-agnostic because the counter rides `chain`, not `in`**: `chain` is full width `B` on every iteration, so every core still encrypts a full counter block and emits full-width keystream; only `in` goes short. Disengaging padding took FIVE coordinated sites (runtime throw, `App.tsx`'s `needsAlignment`, `paddingLimits`' own CTR branch at `{min:1}` **both directions**, and — most missable — `buildCanonicalPair` passing `blockBytes: undefined` for CTR so `overlayApplies` declines; a surviving pad step would re-fill the last block and the partial path would silently never run). **Twofish (2026-07-20) is the LAST core, and it closes the `N + M` story: every block cipher runs every mode.** Its 16-byte block is AES's, so it adds no block-size confidence — what it adds is the mode machine over the app's most structurally unusual body (the 4-rail round, recognized by shape in `twofish-shape.ts`), now nested a scope deeper inside the iterate. Its seed-threading was **one binding** — the input-whitening head's `permute@1`, the Serpent/Speck story — because every round already took a port-chained seed and, critically, **every subkey already reached its round through aux** (`aux-load-bytes@1` on `twofish.K.*`) rather than a port edge into the key-setup group. That aux routing is the load-bearing precondition for schedule-outside/body-inside: a port edge would throw the moment the body was wrapped in an iterate, since port flow cannot cross a group scope. Verify it before templating this on any future cipher — it is the one thing that makes the work "one binding" instead of a rewiring job.

Registering a core has THREE consequences: the cipher gains ECB/CBC/CTR/CFB, `paddingLimits` starts deriving its bounds from the core, and **the padding overlay becomes reachable — including in single-block mode** (user decision, Phase C: padding follows core-presence; a separate gate could only have encoded "AES is special"). **The STREAM modes (CTR + CFB) are exempt from the third**: `buildCanonicalPair` passes no block width for them and no pad is ever spliced in. That exemption is asked at three sites (`overlayBlockBytes`, `paddingLimits`, the App's padding selector) and is funnelled through one predicate, `isStreamCipherMode` in `stores/cipher-mode.ts` — as is the parallel "does this mode use an IV?" question (`cipherModeUsesIv`: CBC's chain bootstrap, CTR's initial counter, CFB's initial register all share `aux["iv"]`), asked at aux seeding, session export, and the IV field. A mode wired into two of three sites fails silently, which is why these are predicates and not inline comparisons.

**CFB (2026-07-20) is the fourth mode, and the first to cost NO new step type** — every leaf it uses already existed, so it cleared zero coverage gates. It is CTR's keystream shape (forward body both directions, seeded from `chain`, no padding, `allowPartialFinalBlock` + a `cfb-trim`) over CBC's feedback rule (the register holds the previous CIPHERTEXT block). **Its one structural quirk is the load-bearing one: encrypt and decrypt differ in exactly one wire** — `chainFeedback` is `cfb-xor.output` on encrypt, the iterate's raw `in` on decrypt — so it is templated on `cbc.ts`, NOT `ctr.ts` (whose "both directions are the same spec" is the one property CFB does not share). **The trap: get BOTH wires wrong in a matched way and encrypt/decrypt stay perfect inverses**, so a round-trip test passes on a mode no real implementation can read. `tests/cfb-all-cores-kat.test.ts` therefore ranks round-trip last and leans on `node:crypto`'s `aes-*-cfb` (CFB128 — **never** `-cfb8`/`-cfb1`, different modes), an ECB-rebuilt keystream per core, and CFB's error-propagation shape (one corrupt ciphertext byte ⇒ one byte of its own block + all of the next, then clean recovery). The perturbation was run, not assumed: swapping the wires fails 64/132 assertions while round-trip stays green.

Each mode wraps the core's body in a port-mode `iterate` (`seedInput`/`blockByteLength`/`bodyOutput`/`chainInput`/`chainFeedback`). The runtime splits the seed into `blockByteLength` chunks, runs the body per block, suffixes every emitted frame's `stepId` with `:b{i}` so the flat trace stays uniquely keyed, stamps each frame with `blockIndex: i`, and carries CBC's chain value across iterations. The key schedule runs ONCE outside the loop and publishes to aux — aux is global and crosses the iterate's scope freely, which is exactly why schedule-outside/body-inside works.

**Every block cipher now has a `BlockCipherCore`, so every one runs every mode** — Twofish landed 2026-07-20 and closed the table. A core is still what a cipher *needs* to run a mode at all (it requires the body to accept its block from an arbitrary port rather than hardcoding `$input` — per-cipher seed-threading work), and `src/ui/stores/block-cipher-cores.ts` stays `Partial<Record<Cipher, …>>` because absence remains meaningful for the *next* cipher added. `src/ui/stores/block-cipher-cores.ts` is the `Cipher`-keyed registry (AES ×3 + Speck ×2 + Blowfish + Serpent ×3 + DES + Twofish) — deliberately at the **consumption** layer, because nothing in `src/ciphers/` imports from `src/ui/` and a mode builder that enumerated the cipher list is the machine this seam deletes. **(Historical: the original aux-mode matrix iterate + its `split-blocks`/`concat-blocks` boundary steps were retired in Phase 5 Slice 5.1 (2026-05-30) with the `MatrixState` shape; `docs/plans/multi-block-aes-modes.md` describes that superseded design.)**

**Spine is port-flow-only (Phase 5 Slice 5.3e, 2026-05-31).** The graph spine is composed **entirely** by `inferPortEdges` from each leaf's declared `portInputs` — the legacy `inferStateEdges` (consecutive-siblings `state`-thread inference) and `dropAuxOnlyStateEdges` were retired in Batch 3, and the per-frame `stateBefore`/`stateAfter` State fields they relied on were deleted in Batch 4. Iterate boundaries draw no spine arrow because every shipped iterate is aux-mediated: the runtime overwrites `state` from `aux[blocksFromAux]` at iteration entry and publishes per-iteration output into `aux[outBlocksAux]` at exit, so no port-flow edge crosses the boundary — the aux arrows are the honest depiction of the handoff. (Historical: pre-5.3e, drawing a white spine arrow there showed phantom data, e.g. `compute-block-count → ecb-blocks` rendering plaintext bytes the iterate ignored.)

Each step type registers an executor *and* a `StepDocumentation` block (`name`, `summary`, `detail` markdown, `params`, `references`). The UI looks up the same key for both. Adding a new cipher = registering its step types in `src/ciphers/default-registry.ts` plus authoring a `CipherSpec` JSON file. **No UI changes needed for new step types** unless their params can't be edited by the existing `ParamEditor` blocks.

State is `BytesState` only (`{ shape: "bytes", bytes: Uint8Array }`) — every shipped cipher/hash is port-native byte-flat. AES/Serpent carry a 16-byte block, Speck32/64 a 4-byte block, DES an 8-byte block; the two-word/bit-level/column-major interpretations live inside the executors and exchange `Uint8Array` at the port boundary. `MatrixState` (the `matrix4x4-bytes` shape) was retired in Phase 5 / Slice 5.1 (2026-05-30) along with the test-only matrix AES primitives; a node wanting a 4×4 reading of its 16 bytes carries the advisory `PortLayout` tag `"matrix-cm-4x4"` (a rendering hint, NOT a State variant) and renders via `TinyMatrix`. `BitVecState`/`BigIntState` were retired in Slice 5.0 (see memory `feedback_all_specs_port_native`).

The future "binary export" feature is what *forced* the spec-as-data choice: a code generator can consume JSON, not closures.

**Detailed file-by-file inventory: see `docs/key-files.md`.** For step-type-specific guidance (adding new ones), see `src/steps/CLAUDE.md`.

### Graph view + persistence

The 2D editor (the "graph" view tab, alongside `linear` / `json` in
`src/ui/stores/view-mode.ts`) is a second derivation layered on top of
the same trace the linear view consumes. Pure functions own each step:
`deriveAuxGraph(trace, spec) → CipherGraph` builds the DAG from the
recorded `auxRead`/`auxWritten`/`auxReadMissing` on each `TraceFrame`;
`collapseGraph` rewrites it for collapsed containers; `replicateHighFanoutSources`
splits source nodes whose fanout exceeds a threshold; `validateGraph(graph, trace)`
emits `GraphWarning[]` (orphaned-read / unused-write / cycle). The SVG
renderer in `src/ui/components/GraphView.tsx` consumes the post-pipeline
graph and overlays the layout sidecar (`src/ui/stores/layout.ts`,
per-spec.id, persisted to localStorage) for pinned positions + collapsed
sets.

**Canonical Feistel rounds (DES + Blowfish, 2026-06-02 / 2026-07-12).** A round
group whose wiring matches `split → F → xor → concat` (detected by
`analyzeFeistelRound` in `src/core/feistel-shape.ts`, cipher-agnostic, no tag)
lays out as the textbook two-column Feistel cell instead of the generic vertical
stack — via the pure helpers in `src/core/feistel-layout.ts` threaded into
`layoutNode`. The analyzer is **orientation-aware**: DES mixes F into the LEFT
half (`mixedHalf==="L"` → F boxed on the RIGHT, fxor left, carried value "R"),
Blowfish mirrors it (`mixedHalf==="R"` → F on the LEFT, fxor right, combined
value "R⊕F"). The carried half may be a **pass-through rail** rather than a raw
split output — DES's is raw (`railNodeIds: []`); Blowfish's `L ⊕ P[i]` key mix
(`railNodeIds: [xorP]`) sits on it before feeding F and passing down, and is
excluded from the F-box. Every value label (`feistelValueLabels`) is derived
from `mixedHalf` so no surface hardcodes "L⊕F". The inter-round **swap (the
"X")** is two crossing wires between consecutive rounds, suppressing the straight
`recombine → split` carry; `swap` and the wire origin/dest sides are derived
byte-honestly from the wiring (which split half `recombine.input0` descends
from + which column the fxor sits in), so the X stays correct across DES *and*
the mirrored BF form. The X is the rail-level picture (byte-level flow is
straight — the swap lives in the concat order) so each wire is LABELED. The same
shape feeds the linear-view abstract diagram (`FeistelSwapDiagram` /
`FeistelRoundBytes` / `FeistelRecombineView`), also orientation-aware. Leaves
stay real (draggable / click-scrub / wireable); only LAYOUT + decoration change.

**Canonical Twofish rounds (4-rail, 2026-07-12).** Twofish's round is NOT the
2-way Feistel form, so it gets a **separate** `TwofishRoundShape` +
`analyzeTwofishRound` (`src/core/twofish-shape.ts`) + `twofishRoundPlacement` /
`twofishSwapWires` (`src/core/twofish-layout.ts`), threaded through `layoutNode`
as a `twofishRounds` param PARALLEL to `feistelRounds` (the 2-way path is
byte-identically untouched — zero regression). Recognition anchors **backward
from the PHT** (the two 3-input `add-mod-32@1` leaves = {f0,f1}, unique to this
shape) and cones outward: `input2`/`input3` of the 4-input `concat` recombine
read raw halves of the 4-way split (the carried R0/R1); the g heads are f0's two
non-aux-load operands; each g cone is classified g0-vs-g1 by which split output
it roots at; `rolR1` is split out of g1's cone (it rides atop the g1 box, OUTSIDE
the g decoration — a learner must not read the 8-bit rotate as part of g). Layout
= two g columns left, PHT below, R2/R3 mix rails right, recombine centered
bottom. **No inter-round swap-X overlay** (unlike DES/BF): Twofish rounds lay out
HORIZONTALLY (top-level steps, no outer `rounds` group), so a `recombine → next
split` swap spans ~2000px up-and-over — a long diagonal tangle with labels piling
up mid-canvas, not a readable X. We keep the plain `recombine → split` carry edge
and let the 4-rail cell + the `recombine` narrationOverride ("Swap →
(R2′,R3′,R0,R1) … the swap is just the concat order") tell the swap story
(DES-round-16 precedent for non-adjacent rounds; a swap-X was built, browser-
smoked as a tangle, and removed). **Gotcha (smoke caught it, not unit tests):**
the round split's 6-way port fanout exceeds the replication threshold (3), so it
would scatter into per-consumer chips and break the cell — `twofishRoundNeverModes`
in `GraphView` marks every recognized-round member `"never"` for replication (the
key-schedule publish source, NOT a round member, still replicates its 40
subkeys).

**Twofish linear-view diagram (2026-07-17).** The 2-way linear trio keys off
`analyzeFeistelRound`, which returns null for Twofish's 4-input concat, so none
of it renders for Twofish. `<TwofishRoundDiagram />` is the 4-rail equivalent:
a compact SVG of ONE round (4 input words → g / ROL+g → PHT → the two mix rails
→ the swap → 4 output words), self-detecting via `findActiveTwofishRound` and
inert for every other cipher. Its presentation model is a separate pure module
(`src/core/twofish-diagram.ts` — `twofishDiagramModel`), which keeps the
graph-critical `twofish-shape.ts` untouched; every label (rail↔word, `⊕ F0` vs
`⊕ F1`, `ROL 8`) is derived from wiring, so encrypt and decrypt both draw
correctly. **This is where the swap-X lives.** The graph view had to drop it
(rounds sit ~2000px apart horizontally → a tangle); at single-round scale the
same four wires are ~50px, so the linear view is the swap's honest home. Two
routing rules, both found by LOOKING and invisible to the unit tests: a wire may
CROSS another wire, but must never pass through a labelled box (F1 routed
straight across speared rail 2's `ROR 1` chip, reading as "ROR 1 feeds ⊕ F1");
and the carried words branch around the g/PHT block (R0 left, R1 right) so
neither runs behind the PHT. Elements accent on "you are here" and click to
scrub; composite boxes (g, PHT) scrub to their first leaf — the diagram is
deliberately ABOVE per-leaf altitude, since the graph's canonical cell already
draws g's interior.

Also deferred: the long `round.16.recombine → final-permutation` edge (a
pre-existing root-layout artifact, not a Feistel issue).

**Authoring** is a two-channel surface. The palette
(`src/ui/components/StepPalette.tsx`) lists every non-padding registered
step type and emits HTML5 drags carrying the `STEP_TYPE_DRAG_MIME`
payload; `GraphView`'s drop handler walks `closest("[data-drop-anchor]")`
to map cursor → spec node, and routes to `insertStepIntoSpec(stepType,
anchor)` in the spec store. The same store boundary handles in-place
param edits via `editStepParams(stepId, params)` (driven by the
`ParamEditor` rendered below `<GraphView />` so the panel is reachable
from inside graph mode).

**Persistence** lives in `src/core/document.ts` (the `CipherDocument`
schema) and routes all I/O through `applyDocument` in `App.tsx`. Three
entry points produce the same envelope:
[save] downloads it as a `.cipher.json` blob; [share…] packs it into
`#doc=<base64url-deflate-raw>` via the browser-native `CompressionStream`
(`src/ui/stores/url-share.ts`); a paste of the URL into a fresh tab
boots through `applyDocument` again. Spec-only saves (the default,
without "include session") are byte-stable so URL-share hashes are
deterministic — `metadata.createdAt` and `metadata.appVersion` are
session-gated to keep that property. Layout pins survive Save/Share
when the user has dragged or collapsed at least one container.

**The end-to-end round-trip** — palette drop → param edit → layout pin
→ Save → reset → Load — is pinned by
`tests/built-from-palette-roundtrip.test.tsx`, the integration assertion
the 11-slice plan promises. The in-app `?` button on the graph toolbar
opens `docs/help/graph-view.md` (loaded via Vite `?raw`) inside a
`<dialog>` for users who want a quick reference.

## Conventions

**Commits:** push to GitHub after every batch of related changes. Don't accumulate. Each commit message: 1 short title + a "why this exists" paragraph + bullet list of the substantive parts. Co-author trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

**Comments:** *override the default "no comments" rule for this project.* Comment frequently — file headers explaining purpose, JSDoc on step executors, FIPS-197 references where the code implements a published algorithm, "why" rather than "what." User explicitly requested this. Educational project; the user reads the code to learn.

**Tests:** new step types and new ciphers ship with tests **in the same commit** as the implementation. Test names should explain the property being checked, not just "it works." Known-answer tests against published vectors (FIPS-197 Appendix C, etc.) are the gold standard for cryptographic correctness. The pre-commit hook enforces "if a new file lands in `src/steps/`, at least one `tests/` file must also be modified."

**Type safety:** `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax` are on. Use `import type` for type-only imports (biome enforces). Cast through `Record<string, Json>` when you need to spread JSON params.

**Param editing in the UI:** when the user edits a step's params, the spec store creates a new spec via the helpers in `src/core/spec-mutations.ts` (which preserve reference equality on untouched branches). A `createEffect(on(spec, ...))` then debounces 200ms before re-running the cipher and producing a new trace.

**Frame preservation across re-runs:** `src/ui/stores/trace.ts::setTrace` is the single boundary that swaps in a new trace. It captures the current `stepId` and tries to land the scrubber back on the same step in the new trace; if that stepId is gone, it clamps the previous numeric index. Universal — every cipher's traces flow through this same boundary.

**Byte format toggle:** `src/core/format.ts` defines `ByteFormat = "hex" | "decimal" | "ascii"`. The App-level toggle parses with the old format and re-renders with the new one so user data survives. S-box axis labels stay hex regardless — they're addresses, not values.

**UI testing:** Most tests run in vitest's `node` environment (fast, no DOM). UI component tests opt into jsdom with a `// @vitest-environment jsdom` directive at the top of the file, then use `@solidjs/testing-library`. The Solid plugin needs `resolve.conditions: ["development", "browser"]` and `server.deps.inline: [/solid-js/]` in `vite.config.ts` — without those, `createSignal` throws "Client-only API called on the server side." Module-scope signals in stores produce a harmless "computations created outside createRoot" warning during tests; ignore.

**Cross-mode mirror buttons:** Encrypt and decrypt specs are held simultaneously in the store but *never* auto-synced — the user edits either side independently and learns what breaks. Every step whose param has a known cross-mode relationship ships with a labelled, opt-in button below its editor. Two classes today: class-1 *identity-mirror* ("Copy S-box to decrypt" — AES key-expansion per FIPS-197 §5.2: key expansion uses the FORWARD S-box even when decrypting) and class-2 *inverse-mirror* ("Sync inverse S-box to decrypt" — AES SubBytes; "Sync inverse S_i to decrypt" — Serpent SubBytes, per-`sboxIndex`; "Sync inverse MixColumns to decrypt" — AES MixColumns per FIPS-197 §5.3.3, gated on GF(2^8) invertibility via `gfMatInverse4x4` in `src/core/state/gf-matrix.ts`). The label names the specific operation; the tooltip cites the spec section that justifies the relationship. `src/ui/components/cross-mode-mirror-registry.ts` is the canonical list of (stepType, paramKey, class) entries; `tests/cross-mode-mirror-coverage.test.tsx` walks it and fails if a registered entry has no rendered button — so a new cipher in class 1 or 2 cannot ship without its mirror affordance.

## Things to avoid

A list of footguns Claude has historically tripped on, grouped by topic (AES, padding overlay, multi-block/iterate, Speck, Serpent, Solid UI, Graph view, port-native primitives, PowerShell tooling) lives in **`docs/gotchas.md`** — consult the relevant section when working on that area. Highlights that bite *cross-cutting* code:

- **Solid components need `createMemo` for derived values** read multiple times in JSX, and **`For` callbacks aren't reactive scopes** — inline dynamic prop reads into the JSX, don't capture them in a `const`.
- **Solid signal setters return the value they set**, so a `: void` wrapper around a setter must use a block body, not an expression body, under `exactOptionalPropertyTypes`.
- **Don't redirect native command stderr in PowerShell with `2>&1`** — wraps stderr in `NativeCommandError` and falsely flips `$?`.
- **Adding a new (cipher, cipherMode) spec means updating THREE tables**: `BLOCK_CIPHER_CORES` in `stores/block-cipher-cores.ts` (the cipher needs a core to run a mode at all), `defaults` in `stores/spec.ts`, AND `SUPPORTED_CIPHER_MODES_BY_CIPHER` in `stores/cipher-mode.ts`. `tests/cipher-mode-fallback.test.ts` is the canary — it asserts the three agree. **Adding a new MODE touches only the last two** (plus `SUPPORTED_CIPHER_MODES`, `CIPHER_MODE_LABELS`, and — the one CFB found the hard way — **`CIPHER_MODES` in `core/document-schema.ts`**, the persisted-document mode list, which is guarded by its own compile-time exhaustiveness assert (`assertCipherModeCoverage`) and so surfaces as a cryptic `Type 'true' is not assignable to type 'never'` rather than a named error). A mode adds no core, so `BLOCK_CIPHER_CORES` is untouched. Watch the AES-128 row in `defaults`: it keeps hand-authored ECB/CBC constants that ~35 modules compare by REFERENCE, so a new mode must be spread in via a narrow per-mode helper (`ctrFromCore`), never a full `modesFromCore` that would regenerate them.
- **A new bare-name port-native step type must clear TWO coverage gates**, both set-equality pins that fail CI until a conscious decision lands: `tests/port-provenance-coverage.test.ts` (an exact provenance fn in `core/port-provenance.ts` OR an entry in `PROVENANCE_NO_OP_ALLOWLIST` — *and* the test's own literal copy of that allowlist), and `tests/narration-registry-contract.test.ts` (which port-native steps escape only because they omit `shapeContract` — so **a step can ship with zero narration and CI stays green**; if the step's teaching point is per-frame and value-dependent, a static `narrationOverride` cannot express it and you must register a real `NarrationFn`, then *scrub to the frame in the browser and read it*). Note the provenance gate's set-pin lives in **two** files — `tests/port-provenance-coverage.test.ts` and `tests/port-provenance.test.ts`'s own exact-mapping count — so run the full suite, not just the file CLAUDE.md names. Also add a `ParamEditor` blurb — for a no-params step that means both `NO_PARAMS_PORT_NATIVE_TYPES` and `portNativeNoParamsLabel`.
- **Port-native primitives use DIFFERENT param names than legacy steps**: `rotate-bits-right` / `shift-bits-right` use `bits` (not `shift`), no `byteLength`; `add-mod-32` / `xor` / `and` / `concat` use `inputCount`, no `byteLength`; `not` takes empty params; `split-bytes` uses `widths`. Copy-pasting a spec node from a legacy step fails with "params.X must be …" naming the param the executor WANTED — not the wrong one supplied. Full table in `docs/gotchas.md`.

For AES gotchas (column-major state, FIPS-197 appendix keys, AES-256 Nk>6 branch, SubBytes/ShiftRows commute), Speck byte-order conventions, Serpent standard-vs-bitslice form mixing, and the padding overlay's block-width contract: read `docs/gotchas.md`.

## Planning mode usage

**Mandatory** for: new ciphers (Speck, ChaCha20, RSA), big architecture changes (DAG instead of linear pipeline, codegen target, file encryption), new state shape support, anything touching `core/types.ts`.

**Skip** for: typo fixes, tiny tweaks, isolated UI polish, fixing a failing test, adding a known-answer test for an existing cipher.

When in plan mode, exit with `ExitPlanMode` only after the plan file has the **Context** section answered and **Critical files** listed. The plan should match the scope of the requested change — don't propose a 12-step refactor when the user asked for one editor.

## What we explicitly chose not to adopt (yet)

These are common Claude Code best-practice recommendations; we considered each and skipped for now:

- **Custom subagents** (code-reviewer, build-fixer, etc.) — gatekeeps context for solo dev.
- **Skills system + UserPromptSubmit hook** — disproportionate setup for our scope.
- **Three-file dev-docs system** (plan/context/tasks per task) — the existing plan + memory + commits cover it.
- **Auto-format hooks** on every edit — confirmed token waste; biome runs in pre-commit gate instead.
- **PM2** — single dev server, no service mesh.
- **Worktrees** — solo dev, one branch.
- **MCPs beyond the bundled ones** — no integration target needs them yet.
- **Branded type pattern** — domain has few string IDs.

If a future need argues for one of these, revisit then.

## Pointers

**In this repo:**
- `README.md` — public-facing GitHub entry point (project description, install, command table, links). Keep it in sync with shipped features when the user-visible surface changes — adding a new cipher, mode, or major UI feature should update the "What's in the box" table.
- `CHANGELOG.md` — release log (Keep-a-Changelog format). Convert the `[Unreleased]` section into a dated `[X.Y.Z]` heading on each release; bump `package.json`'s `version` and tag in the same commit. `docs/versioning.md` carries the release process.
- `docs/key-files.md` — detailed file-by-file inventory (core contracts, ciphers, UI stores, components, tests).
- `docs/gotchas.md` — the full "Things to avoid" list, topic-grouped.
- `docs/versioning.md` — versioning policy for the three independent surfaces: app semver, step-type `@N` suffix bumps, document `schemaVersion` migration path. Read before any change that touches a step-type contract, the document schema, or the release process.
- `src/steps/CLAUDE.md` — step-type-specific guidance.
- `src/version.ts` — `APP_VERSION` constant re-exported from `package.json`. Consumed by the UI footer and the session-on document export.
- `docs/help/graph-view.md` — user-facing reference for the graph view (edges, drag/drop, palette, warning glyphs, toolbar). Bundled into the app via Vite `?raw` and rendered inside the in-app help modal (`?` button in the graph toolbar). Keep this file the single source of truth — both GitHub readers and the in-app modal display the same prose.

**Plans:**
- Original architectural plan: `~/.claude/plans/i-want-to-build-tender-spark.md`
- Approved UX/feature plan (phases 1–4: frame preservation, run history + diff, byte format toggle, deferred 2D viz): `docs/plans/suggestions-1-4.md`
- Plaintext input + visible padding plan (PKCS#7 + zero-pad + ISO 7816-4 shipped May 2026): `docs/plans/pkcs7-padding.md`
- Speck32/64 plan (shipped May 2026 — second cipher family, ARX, both BE-paper + LE-NSA byte conventions): `docs/plans/speck.md`
- Multi-block AES with ECB/CBC/CTR plan (Phases 1+2 — AES-128 ECB+CBC — shipped May 2026; Phases 3+4 superseded by the universal cipher-shape plan): `docs/plans/multi-block-aes-modes.md`
- Serpent cipher plan (all three key sizes, standard form with explicit IP/FP, single-block — shipped May 2026): `~/.claude/plans/i-want-serpent-cipher-indexed-finch.md`
- 2D/DAG visual cipher editor + JSON document export plan (all 11 slices shipped May 2026): `~/.claude/plans/peppy-knitting-fairy.md`. Memory: `project_2d_editor_plan.md`. Option B (click-to-expand with `LayoutSpec.expandedLabels`) is an optional V2 follow-up; pick up only on explicit user ask.
- Trace-coupling editor bug fix plan (shipped 2026-05-14): `docs/plans/trace-coupling-bug-fix.md`. Root cause was the `hasRunOnce` gate blocking auto-rerun. Option 3b (static spec validator) deferred until Feistel branching data model settles.
- Duplicate-round plan (shipped 2026-05-14): `docs/plans/duplicate-round.md`. Renumber + extend schedule (`aes.key-expansion@2` with relaxed `Nk+6` assertion) + auto-mirror to decrypt. AES today; Speck/Serpent + Feistel-aware rerouting + non-round-group duplication are out of scope.
- Port-spreading at consumer head plan (shipped May 2026): `docs/plans/port-spreading-consumer-head.md`. Mechanisms 1+2 + visual-target bucketing + horizontal-regime extension all closed. Mechanism 3 (off-chip clamp at chip-vs-leaf width) deferred — not visible on smoke fixture.
- Linear-mode pedagogy plan (all 3 phases shipped 2026-05-18 + BytesView follow-up): `~/.claude/plans/immutable-doodling-quokka.md`. Memory: `project_linear_mode_pedagogy_plan.md`. Three additions: `<RoundKeyPanel />` (cipher-agnostic ribbon), `<KeyScheduleExplorer />` (per-cipher simulators in `src/ui/key-schedule-sim/`) — **the explorer + its whole `key-schedule-sim/` subsystem were RETIRED in K4b (2026-06-02)** once every key schedule decomposed into port-native frames (K1–K4) that the standard view renders directly — and a cell-level provenance overlay (parallel registry at `src/ui/provenance/`) — **the provenance overlay was RETIRED in the Slice 2.9c-e honest close (2026-05-31)**: it was built on the deleted `stateBefore`/`stateAfter`/MatrixView, so unusable for any port-native hover; the value inspector / step strip / RunExplorer became port-aware instead (`framePrimaryOutBytes`), and the cell-level hover was formally deferred. `src/ui/provenance/` + `tests/provenance-registry-contract.test.ts` are gone.
- DES + branching primitive plan (Phase 6 complete under legacy contract; **superseded by the B4 port-native rebuild 2026-05-30**): `docs/plans/des-feistel.md`. Memory: `project_des_feistel_plan.md`. Introduced `FeistelRoundGroup` + `tracks: BranchTrack[]` + named `combineKind` (schema bump 1→2). **DES no longer uses `feistel-round`** — universal-port Phase 4d / scaffolding-suppression B4 rebuilt it from native `split-bytes`/`xor`/`concat` (the Feistel swap is the concat argument order). `FeistelRoundGroup`/`BranchTrack`/`CombineKind` survive only for the toy fixture (`src/ciphers/feistel-toy.ts`) + the linear/graph Feistel components, all Phase-5-deprecation-pending. See `docs/plans/scaffolding-suppression.md` "## B4".
- **Universal port-based dataflow plan (2026-05-21 — APPROVED, ACTIVE)**: `docs/plans/universal-port-dataflow.md`. Memory: `project_universal_port_dataflow_proposal.md` (slice-by-slice progress). Every cipher element accepts 0..N Uint8Array inputs / produces 0..N Uint8Array outputs; with explicit mismatch rules, any element can wire to any other. **SUBSUMES** the universal cipher-shape plan and **OBVIATES** the Feistel branching primitive. Key locked design decisions: bytes + advisory layout tag; warn-and-run coercion as visible trace step; for-each-subgraph (no canvas cycles); one frame per (body × iteration) preserving flat trace + `:b{i}` semantics; medium canonical primitives + fine as planned exploration; KAT parity at cipher boundary + `frameMap` for compound decompositions; narration preserved via `narrationOverride: StepDocumentation` field on spec nodes (falls back to registry doc); mirrors stay opt-in. DES rebuild in Phase 4d will use native split/concat/xor; `FeistelRoundGroup` fades with deprecation. **Six phases**: Phase 0 trace-shape spike → Phase 1 adapter + every step lifted + `narrationOverride` field → Phase 2 SHA-2 native (first port-native cipher) → Phase 3 AES rebuild → Phase 4+ rebuilds + fine primitives + compose-and-save → Phase 5 legacy deprecation. **Phase 2 status — CLOSED 2026-06-01.** SHA-256 ships port-native end-to-end: decomposed into port-native primitives, exposed via the hash algorithm selector with default-collapsed groups, narrationOverride on every leaf, and **multi-block** (Slice 2.11 — the per-block body folds over a port-mode `iterate` whose carried chain is the running hash H; `chainInput` bootstraps, `chainFeedback` advances, `chainOutput` harvests the digest). KAT byte-equal vs FIPS 180-4 §A.1 + §A.2 + node:crypto across the full length range (`tests/sha-256-kat-matrix.test.ts`); the explorer caps input at 512 bytes (trace-legibility ceiling, not a SHA-256 limit). Slices 2.9c-e closed the inspector as the "honest close" (see memory). Slice 2.0–2.8 history in `docs/plans/universal-port-phase-2-slices.md`. **Phase 3 note (2026-05-31)**: the AES *round-body* rebuild shipped EARLY under scaffolding-suppression Phase B (Slices B1.1/B1.2, 2026-05-29 — `aes-round-builder-native.ts`: SubBytes/ShiftRows/MixColumns/AddRoundKey as `byte-substitute`/`permute`/`gf-matrix-multiply`/`xor-with-aux`). What remains of "Phase 3 / AES rebuild" is **key-schedule decomposition**, now shared across all four still-monolithic key schedules (AES/Speck/Serpent/DES — each a hybrid-ported step carrying `meta`'s `auxReadPorts`/`auxWritePorts` round-key fan-out). Sequenced AFTER Phase 2 closeout; gets its own plan + AES-first spike. Unresolved graph-topology call: explicit per-round-key port wiring vs the current aux fan-out. Padding's `meta` (state-half) is independent and out of scope.
- **Key-schedule decomposition ("meta retirement", 2026-06-01 — K1/AES + K2/Speck + K3/Serpent + K4a/DES ALL CLOSED B-minimal; K4b CLOSED 2026-06-02 — the dormant `KeyScheduleExplorer` + whole `src/ui/key-schedule-sim/` subsystem retired, DES being the last cipher)**: `docs/plans/key-schedule-decomposition.md`. Memory: `project_key_schedule_decomposition_plan.md`. Decomposes the four monolithic hybrid-ported key schedules into visible port-native primitive frames (the productive half of "meta retirement"). **K1 (AES)** shipped end-to-end: `src/ciphers/aes-key-schedule-builder-native.ts` (unroll-over-groups — per-group Rcon `constant-load@1`; RotWord=`permute@1`, SubWord=`byte-substitute@1`, word-XOR=`xor@1`; word-stream→`byte-slice@1` repack; a single meta-bearing `aes.publish-round-keys@1` tail writes `aux["roundKey.N"]` byte-identically = **B-minimal**, consumers/`aes-round-builder-native.ts` untouched). Duplicate-round rebuilds via the builder (`bumpKeyExpansion`), collapsing the `@1/@2` distinction (executors KEPT as FIPS oracle + back-compat). **K1-gate (user-decided, graph-smoke in hand): B-minimal topology; re-home the S-box mirror role-scoped by leaf id (round-body=inverse, key-schedule SubWord=Copy — fixes a real corruption hazard the KAT gate can't catch); retire the KeyScheduleExplorer AES branch.** Gate GREEN (2180 pass/2 skip/189 files). K2–K4 (Speck/Serpent/DES) each get their own KAT gate + advisor pass.
- **Port-wiring editor (universal-port Phase 4d-bis, 2026-06-02 — SHIPPED)**: `docs/plans/port-wiring-editor.md`. Memory: `project_port_wiring_editor_plan.md`. In-app rewiring of a leaf's input ports — the prerequisite for 4f compose-and-save (now UNBLOCKED). Design spine = the scope-bounded legal-source SET (`src/core/port-sources.ts::legalSourcesForInput`), which makes cross-scope (runtime-throwing) bindings unrepresentable by construction; byteLength mismatch is the only soft "coerce" case (`classifyBinding`). Two surfaces over `bindPortInSpec`: canvas click-to-arm (input-port handles → legal-source rings + bind handle, amber on coerce, Esc/empty-canvas to disarm) and the per-input-port dropdown (`PortWiringEditor`, keyboard/a11y-complete + the only path to a container-seed source). `setPortBinding` normalizes a cleared map to absent (byte-stable saves); no schema bump. Verified by jsdom (dropdown + gesture logic) + `e2e/port-wiring-smoke.spec.ts` (real Chromium — handles clickable, scope-bounding holds, Esc cancels).
- **Compose-and-save (universal-port Phase 4f, 2026-06-02 — SHIPPED, closes Phase 4)**: `docs/plans/compose-and-save.md`. Memory: `project_compose_and_save_plan.md`. Save an existing graph **group** (e.g. an AES round) as a reusable, named palette element ("my elements"); drop a fresh editable copy onto any spec. **Composite = a stored `StepGroup` template, pure JSON** (Approach A — NOT a registered step type w/ synthesized executor; keeps internals scrubbable). Group-scope isolation = the boundary for free: one port-in (`seedInput`) / one port-out (`bodyOutput`) + any number of aux reads (multi-port-INPUT composites need topology A's group-export feature → non-goal). **Drop COPIES/INLINES** via `cloneGroupWithFreshIds` (collision-free id regen + internal-binding rebase; v1 step+group only) → saved/shared docs are self-contained → **localStorage-only library (`stores/composites.ts`), NO schema bump** (`types.ts`+`document.ts` untouched). Drop **auto-binds `seedInput` to the insertion predecessor** (`pickSeedBinding`) because the 4d-bis editor only rewires LEAF ports — a container seed left unbound has no in-app fix. `[save as element]` ★ chip on group headers (capture clears seedInput + sets `defaultCollapsed` + label=name). Oracle = `tests/composite-parity.test.ts` (captured+cloned round spliced into AES-128 → FIPS-197 §C.1 CT + per-leaf byte-identity). Smoke = `e2e/composite-save-drop-smoke.spec.ts` (real drag + reload persistence; chip clicked via `dispatchEvent` — hover-gated+edge-occluded defeats Playwright pointer clicks). v1 deferred: arbitrary-subgraph selection, reference/linked semantics, parameterization, library export, styled name dialog (uses `window.prompt`).
- **RSA — textbook public-key cipher (ALL 4 phases SHIPPED, 2026-06-08)**: `docs/plans/shimmying-booping-moth.md`. Memory: `project_rsa_plan.md`. First `asymmetric` family: seven bigint port primitives (`mul`/`sub`/`mod-mul`/`cond-mod-mul`/`mod-inverse`/`eea-step`/`eea-extract` — `bigint` math executor-internal, `Uint8Array` at every port), traced key-gen group (default-collapsed) with per-direction `rsa.publish-key-params@1` aux export, an unrolled square-and-multiply ladder whose rungs read their exponent bit at run time (live-editable `p`, `q`, `e`), and a Phase-4 traced extended-Euclid loop replacing the `mod-inverse@1` single-frame oracle (K = ⌈1.4404·8W⌉+2 pinned by the Fibonacci worst-case gate in `tests/rsa-eea-decomposition.test.ts`).
- **Twofish — sixth cipher family, third Feistel (ALL 4 phases SHIPPED, 2026-07-12)**: `docs/plans/twofish.md`. Memory: `project_twofish_plan.md`. Port-native round body (`split → g(R0)/g(ROL(R1,8)) → PHT combine (2 subkeys) → 1-bit rotations → concat`, swap = concat order); g = 4 aux-fed byte→byte `twofish.sbox-lookup@1` → MDS over GF(2⁸)/0x169 via new `gf-matrix-multiply@2` (generalizes `@1` with `fieldModulus`, backed by `gfMulPoly`; `@1` untouched). Words travel ports BIG-ENDIAN (reuse generic add-mod-32/rotate); LE↔BE crossing localized to visible `permute@1` reversals at endpoints + inside g (the `[3,2,1,0]` after MDS). Partial-visibility key schedule (user decision): 20 VISIBLE PHT blocks (add/rotate) → `twofish.publish-subkeys@1` tail (allowlisted); the h-function machinery (RS S-vector over 0x14D + key-dep S-box construction + 40 h-evals) is one opaque `twofish.h-expand@1` — but carries a RICH value-prose narrator (`twofishHExpandNarration`, 4 disclosure rows w/ REAL per-key values from published aux + display-only svec/M ports). Key fixed 128b v1. **Verified 3 levels (S-boxes/40 subkeys/CT) vs Ferguson ref C lib AND published spec constants**; canonical all-zero `9f589f5c…c35a`. q0/q1/MDS/RS = module consts (`twofish-constants.ts`). **Canonical 4-rail graph layout SHIPPED 2026-07-12** (separate `twofish-shape.ts`/`twofish-layout.ts`; see the "Canonical Twofish rounds" architecture note above). **Linear-view abstract diagram SHIPPED 2026-07-17** (`TwofishRoundDiagram` + `core/twofish-diagram.ts`; carries the swap-X the graph view had to drop — see the "Twofish linear-view diagram" architecture note above). Deferred: 192/256 keys, multi-block, RS-as-visible-frame, full h decomposition.
- **Blowfish — fifth cipher family, second Feistel (ALL 4 phases SHIPPED, 2026-07-10)**: `docs/plans/blowfish.md`. Memory: `project_blowfish_plan.md`. Port-native round body (`split → xor-with-aux(P[i]) → F → xor → concat`, swap = concat order); F = `((S0[a]+S1[b])⊕S2[c])+S3[d]` via new aux-fed `blowfish.sbox-lookup@1` (S-boxes key-DERIVED → table from aux). The one deliberate monolith: `blowfish.key-schedule@1` runs the cipher on itself 521× (no legible decomposition) → publishes P+S to aux (B-minimal `meta.auxWritePorts`, doubles as KAT oracle); the `key⊕P` mix IS visible (18 `xor@1` frames). π P+S seed tables are MODULE constants (`blowfish-constants.ts`), never spec params (4KB incompressible). Key fixed 8B v1. KAT vs Eric-Young/pycryptodome. Deferred: variable key, multi-block, two-column Feistel layout (pre-F `L⊕P[i]` breaks `analyzeFeistelRound`), per-leaf narrationOverride (DES-round-body precedent).
- Universal cipher-shape plan (2026-05-16 — **SUBSUMED by universal-port-dataflow plan**, kept only for historical reference): `~/.claude/plans/silly-brewing-sutton.md`. Memory entry `project_universal_cipher_shape_plan.md`. Registry consolidation falls out for free under unified ports.
- SHA-256 density polish plan (2026-05-26 — **DONE/CLOSED 2026-05-28**): `docs/plans/sha-256-density-polish.md`. Memory: `project_sha_256_density_polish_plan.md`. All named slices shipped (S1 ParamEditor blocks, S2 graph layout/focus-dim fixes, S3 narration density). Deferred polish (Case C, route B curve-altitude) not pursued — residual crowding palliated by the orientation-driven offsets layout (default-ON 2026-05-28, `?offsets=0` disables).

**Future:**
- **Feistel: rebuilt port-native (B4, 2026-05-30)**: DES was the first (and only) Feistel cipher, originally built on the branching primitive (`FeistelRoundGroup` + `tracks: BranchTrack[]` + named `combineKind`, Phase 2 of `docs/plans/des-feistel.md`). **B4 (universal-port Phase 4d) rebuilt DES port-native** — it now uses a port-mode `group` per round wiring `split-bytes`/`des.expand-R`/`des.xor-with-K`/`des.s-boxes`/`des.p-permutation`/`xor`/`concat`, proving the universal-port thesis that **Feistel needs no special primitive** (the swap is the `concat` argument order). No shipped spec uses `feistel-round` anymore. The primitive + its runtime walk (`runFeistelRound`, `:rejoin` synthesis) + the OLD linear/graph Feistel components + the toy fixture survive **Phase-5-deprecation-pending**; the track-bounded state-edge inference rule still applies to them. **OBLIGATORY follow-up — DONE (Slice 5.3d, 2026-05-31):** the port-native-aware Feistel/swap visualization was rebuilt — `src/core/feistel-shape.ts` derives the round structure + swap purely from the round group's wiring (no spec tag), and three new self-detecting linear components (`FeistelSwapDiagram` / `FeistelRoundBytes` / `FeistelRecombineView`) read port I/O. The OLD `feistel-round`-keyed mini-diagram/track-context/rejoin-view stay toy-only (deleted in 5.3e). See `docs/plans/phase-5-legacy-retirement.md` "## Slice 5.3d".

**External:**
- User preferences (commit cadence, comment density, AES pitfalls, frame preservation, crypto-verification): `C:\Users\boiko\.claude\projects\M--claud-projects-Cryptographer\memory\`
- GitHub repo: https://github.com/BoykoNeov/Cryptographer
