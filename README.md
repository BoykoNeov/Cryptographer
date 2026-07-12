# Cryptographer

An interactive cryptography explorer. Type a plaintext + key, watch every intermediate state of every step of every round, then edit the cipher itself — swap the S-box, reorder steps, change the MixColumns matrix — and see the trace re-run in ~200ms.

Built as a learning tool, not a production crypto library.

> **Status:** v0.7.0 — multiple ciphers and modes shipped, 2D visual editor complete (all 11 slices), **full linear-mode pedagogy**: every step narrates what it does inline with byte values (per-frame value-prose), every round key renders side-by-side as a labelled ribbon with the consumed `K_i` outlined, the key schedule that used to collapse into one passthrough frame now surfaces its per-word internals (AES `RotWord → SubWord → Rcon → XOR` chain; Serpent prekey recurrence + bitsliced S-boxes + IP), and hovering an output byte cell in the linear inspector lights up the input cell(s) that feed it (same-position for SubBytes/AddRoundKey, a gather for ShiftRows, the four same-column cells with GF `×N` labels for MixColumns). Cross-mode mirror buttons across every step type with a known encrypt↔decrypt param relationship. Compose-your-own block-cipher modes from the palette. See [CHANGELOG.md](./CHANGELOG.md) for the release log and [docs/versioning.md](./docs/versioning.md) for the versioning policy.

## What's in the box

Shipped ciphers (all with both encrypt + decrypt paths and FIPS / NIST / paper-vector tests):

| Cipher | Variants | Block | Key | Mode of operation |
|---|---|---|---|---|
| **AES** | 128 / 192 / 256 | 16 B | 16 / 24 / 32 B | single-block, ECB + CBC (AES-128 only today) |
| **Speck32/64** | BE (paper) + LE (NSA reference) | 4 B | 8 B | single-block |
| **Serpent** | 128 / 192 / 256 | 16 B | 16 / 24 / 32 B | single-block |
| **DES** | — | 8 B | 8 B (56 effective) | single-block |
| **Blowfish** | — | 8 B | 8 B (v1) | single-block |
| **Twofish** | — | 16 B | 16 B (v1) | single-block |

Padding schemes (AES only): **PKCS#7**, **zero-pad**, **ISO 7816-4**, plus a no-pad option for exact-block input.

Shipped hash (select **Hash** in the `kind` dropdown):

| Hash | Output | Block | Notes |
|---|---|---|---|
| **SHA-256** | 32 B | 64 B | multi-block, KAT-equal vs FIPS 180-4 §A.1 + §A.2 + `node:crypto`; the first fully port-native primitive |

SHA-256 is built entirely from the universal port-native vocabulary (`rotate-bits-right`, `shift-bits-right`, `xor`, `add-mod-32`, `and`, `not`, `concat`, `split-bytes`, `byte-slice`, …) — no SHA-specific executors. Its 64 compression rounds and the message schedule decompose into individually-scrubbable frames, and multi-block messages fold over a port-mode `iterate` that carries the running hash as its chain. The explorer caps input at 512 bytes to keep the per-byte trace scrubbable (not a SHA-256 limit).

DES is the project's first Feistel cipher. Its round body is built port-native — a `group` of `split-bytes → E-expand → XOR with K_i → 8 S-boxes → P-permute → xor → concat` — with the Feistel swap expressed as the `concat` argument order (rounds 1..15 swap; round 16 doesn't, the textbook last-round exception that makes the cipher self-inverse under key-reversal). No special branching primitive — the universal-port thesis is that Feistel needs none.

Blowfish is the second Feistel cipher, and the one place the app keeps a step deliberately opaque. Its round body is fully port-native (`split-bytes → xor-with-aux(P[i]) → F → xor → concat`, the swap again being the `concat` order; F is `((S0[a]+S1[b]) ⊕ S2[c]) + S3[d]` shown as four aux-fed S-box lookups + two `add-mod-32` + one `xor`). But its key schedule runs the cipher **on itself 521 times** to derive the key-dependent P-array + four S-boxes — a hard data-dependency chain with no legible frame-by-frame decomposition. So the `key ⊕ P` mixing IS shown (18 real XOR frames — how a variable-length key enters), while the 521-encryption loop is one honest black-box step that publishes the derived P/S into aux. Decryption is the same network with the P-array consumed in reverse. Key fixed at 8 bytes in v1; verified against the Eric-Young / pycryptodome vector set.

Twofish is the third Feistel cipher — Blowfish's 1998 AES-finalist successor, and the richest cipher in the box. Its round body is port-native (`split → g(R0) / g(ROL(R1,8)) → pseudo-Hadamard combine with two subkeys → 1-bit rotations → concat`, the swap again the `concat` order), where **g** is four aux-fed byte→byte S-box lookups feeding an MDS matrix over a *second* GF(2⁸) field (`0x169`, not AES's) via a generalized `gf-matrix-multiply@2`. The key schedule follows Twofish's **partial-visibility split**: the pseudo-Hadamard subkey mixing is 20 visible blocks of `add` / `rotate` frames, while the h-function machinery (the Reed–Solomon S-vector over a *third* field `0x14D`, the key-dependent S-box construction, and the 40 h-evaluations) is one honest opaque `twofish.h-expand@1` step — but, unlike Blowfish's silent monolith, it carries a **rich value-prose narrator** that discloses its four hidden stages annotated with the real per-key numbers this run produced (per user request). Words travel the ports big-endian to reuse the generic ARX primitives; the little-endian crossing is localized to visible `permute` reversals. Key fixed at 128 bits in v1; **verified at three levels — S-boxes, all 40 subkeys, and endpoint ciphertext — against Niels Ferguson's reference implementation *and* the published spec's constants**, agreeing on the canonical all-zero vector `9f589f5c…c35a`.

Shipped public-key algorithm (select **Public-key** in the `kind` dropdown):

| Algorithm | Key material | Notes |
|---|---|---|
| **RSA (textbook)** | editable `p, q, e` constants | traced key generation + square-and-multiply encrypt/decrypt; KAT-verified against a Python `pow()` oracle |

RSA is the project's first **public-key** cipher — no symmetric key, big-integer modular arithmetic instead of byte permutation. Both halves of the "magic" are visible frames: **key generation** derives `n = p·q`, `φ(n) = (p-1)(q-1)`, and the private exponent `d = e⁻¹ mod φ` as a **traced extended-Euclid loop** (one frame per division step — the `(r, newR, t, newT)` tuple shifting toward `gcd` and the inverse, the Bézout coefficient shown reduced mod φ to keep every value a non-negative integer), and **exponentiation** is an unrolled square-and-multiply ladder (`c = mᵉ mod n` / `m = cᵈ mod n`) built from `mul` / `sub` / `mod-mul` / `cond-mod-mul` / `eea-step` / `eea-extract` primitives whose `bigint` math lives inside the executor and exchanges `Uint8Array` at every port. The exponent is live-editable — each ladder rung reads its bit at run time, so editing `e` (or `p, q` → `d`) re-runs the trace. Textbook sizes (default `p=61, q=53, e=17`, `n=3233`); the message `m` must satisfy `0 ≤ m < n`.

Interactive features:

- **Per-frame value-prose narration** — every step in every cipher emits a collapsible `<details>` block per conceptual sub-unit (SubBytes → 16 byte units, MixColumns → 4 GF(2^8) dot-product breakdowns, AddRoundKey → 16 XOR cells naming the consumed aux, padding → input/output lengths + pad value, aux primitives → operands + result with the algebraic identity). Disclosures stay open across the byte-format toggle and across the debounced re-run after a param edit.
- **Round-key side-by-side panel** — every round key of the active schedule renders as a labelled ribbon (AES → 11/13/15 4×4 grids; Serpent → 33 grids; Speck → 22 two-byte strips). The `K_i` whose canonical name appears in the current frame's `auxRead` map lights up, so chain XOR and Rcon column injection become visible at a glance.
- **Cell-level provenance hover** — in the linear inspector, hover an output byte cell and the input cell(s) that feed it light up: same-position for SubBytes and AddRoundKey (whose round-key `operand` row lights up alongside the state), a gather for ShiftRows, the four same-column contributors for MixColumns (each annotated with its GF(2⁸) coefficient `×N`). It's pure index math over the port-native primitives — derived from each step's params + port lengths, never the byte values, so it can't go stale — and operations whose byte mapping is only approximate (SHA-256's modular adds and bit-rotates) intentionally highlight nothing rather than mislead.
- **Compose-your-own block-cipher mode** — drag `generic.aux-load`, `generic.aux-xor`, and `generic.aux-copy` primitives from the palette and wire up CBC, OFB, or CFB around any single-block cipher without writing a single line of executor code. Half-wired specs stay debuggable: missing aux references show up as orange `!` glyphs on the canvas instead of throwing a runtime exception. (See `src/steps/CLAUDE.md` for the canonical CBC recipe.)
- **2D graph view with drag-from-palette authoring** — pan / drag containers, collapse groups, see the aux-flow + state-flow edges that connect every step. Drag step types from the left palette to insert them into the spec; warning glyphs surface orphaned reads, unused writes, cycles, and state-shape mismatches **before** you click Run. High-fanout sources (Serpent's 33-key schedule, AES's 11 round keys) collapse to local replica chips with the parallel arrows bundled into one `×N` pill. Per-source edge colouring (Okabe-Ito 8-colour palette) makes overlapping dataflow readable at a glance. Replica chips and per-block iterate chips are draggable, with a per-node ↺ reset glyph and a toolbar `[reset layout]` button for the hard reset.
- **Rewire ports in place** — change which upstream output feeds a step's input without touching code: click a leaf's input-port handle to arm it, then click any scope-legal source's bind handle to wire it (or use the per-port dropdown below the graph). Only same-scope sources are offered, so a wire can never crash at run time; a size-mismatch wire is allowed but flagged amber (the bytes coerce as a visible trace step). Rewires save and share like any other edit.
- **Save a group as a reusable element ("compose-and-save")** — hover any group (e.g. an AES round) and click the `★` chip in its header to capture it into a **"my elements"** palette section; drag it back anywhere to drop a fresh, fully editable copy. A composite is pure JSON (a saved group template, not opaque code), so its internals stay visible and scrubbable — the "cipher = JSON" idea at the reusable-block grain. The library persists per browser; the dropped copy inlines into the spec, so saved/shared `.cipher.json` files stay self-contained.
- **Duplicate a round** — a `+` chip on any AES round container's header clones the round, renumbers subsequent rounds + their key indexes in lockstep, bumps the key schedule (Rcon table extended on the fly via `xtime`), and auto-mirrors onto the counterpart encrypt / decrypt spec so round-trip stays valid by construction. Answer "what would AES-128 with 11 rounds look like?" end-to-end.
- **Inline parameter editing on every step** — swap the S-box, change the MixColumns matrix, edit a single byte of a round key, and watch the trace re-run in ~200 ms. The current step in the graph view stays focused across edits.
- **Per-frame state view** (4×4 matrix or 1×N byte row) with before / after diff highlighting + FIPS-197 / paper references baked into each step's description panel.
- **Run history** (last 5) with a diff overlay showing how the current run differs from any prior one, plus a Run Explorer modal for side-by-side comparison.
- **Byte format toggle**: hex / decimal / ASCII, applied to every input + output cell. S-box axis labels stay hex (addresses, not values).
- **"Custom (was …)" indicator + one-click reset** — the moment your spec diverges from the canonical cipher default (any palette insert, param edit, or delete), the header label and the cipher dropdown advertise the divergence; a `reset` button snaps you back.
- **Save / Load** custom ciphers as `.cipher.json` documents (`schemaVersion: 3`, see [`src/core/document.ts`](./src/core/document.ts)). Layout pins (graph positions + collapsed groups) survive Save / Load. The "include session" toggle controls whether plaintext + key bytes are written.
- **Share via URL** — a `#doc=…` hash carries the whole document (deflate-raw + base64url, ~2 KB even for AES-256 + session) so a paste-able link reproduces a custom cipher in a fresh tab. Spec-only shares are byte-stable (deterministic across builds) and public-safe (no plaintext, no key bytes).

## Quickstart

```bash
git clone https://github.com/BoykoNeov/Cryptographer
cd Cryptographer
npm install
npm run dev
```

Open `http://localhost:5173`. Hot reload kicks in on every save.

## Development

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server with HMR. |
| `npm test` | Vitest, single run. ~2430 tests across 214 files, ~50s. |
| `npm run typecheck` | `tsc --noEmit`, strict mode. |
| `npm run check` | The full gate: `biome ci . && tsc --noEmit && vitest run && vite build`. ~60s. |
| `npm run smoke` | Playwright real-browser smoke specs (graph drag/collapse, port wiring, composite save/drop, inspector cell-hover, …). |
| `npm run build` | Production build into `dist/`. ~212 KB gzipped JS. |

The pre-commit hook in `.githooks/pre-commit` runs `npm run check`. GitHub Actions runs the same on push.

## Architecture (one paragraph)

The whole app is built around one idea: **a cipher is JSON, not code.** A `CipherSpec` (`src/core/types.ts`) is a tree of `StepNode`s. A `Runtime` (`src/core/runtime.ts`) walks the tree, looks each leaf's `type` up in the `StepRegistry`, and calls its pure executor `(state, params) → state`. Every executor registration includes a `StepDocumentation` block (name, summary, detail markdown, params, references) so the UI gets both behavior and docs from the same source. Adding a new cipher = registering its step types + authoring a JSON spec; **no UI changes needed** for new step types unless their params need a novel editor.

For the file-by-file map, read **[`docs/key-files.md`](./docs/key-files.md)**. For the cross-cutting footguns Claude has tripped on (AES pitfalls, Solid reactivity, PowerShell, padding overlay, multi-block iterate), see **[`docs/gotchas.md`](./docs/gotchas.md)**.

## Project layout

```
src/
  core/            cipher-agnostic engine: types, runtime, registry, spec mutations, document format, graph
  ciphers/         per-cipher specs + constants (AES, Speck, Serpent, DES)
  steps/           step-type executors + their StepDocumentation blocks
  ui/              Solid components, stores, app shell
tests/             ~214 files, ~2430 tests — vitest (node + jsdom mix)
e2e/               Playwright real-browser smoke tests
docs/              key-files.md, gotchas.md, versioning.md, plans/
.githooks/         pre-commit gate
```

## Versioning

Semver. App version lives in [`package.json`](./package.json) and is re-exported from [`src/version.ts`](./src/version.ts) so the UI footer and any saved-document `metadata.appVersion` field stay in sync. The release log lives in [`CHANGELOG.md`](./CHANGELOG.md). Step-type contracts carry an `@N` suffix (e.g. `aes.sub-bytes@1`) and the document file format has its own `schemaVersion` — see [`docs/versioning.md`](./docs/versioning.md) for when each gets bumped and how migrations work.

## License

[Boyko Non-Commercial License v1.0 (BNCL-1.0)](./LICENSE) — free to use, modify, and distribute for **non-commercial purposes**. Commercial use requires a separate written permission from the copyright holder. See [`NOTICE`](./NOTICE) for the short-form summary.

## For Claude Code contributors

`CLAUDE.md` at the repo root carries the assistant brief: architecture summary, conventions (commit cadence, comment density, type safety), planning-mode rules, and pointers into `docs/` and the user's auto-memory. Read it before non-trivial work.
