# Cryptographer

An interactive cryptography explorer. Type a plaintext + key, watch every intermediate state of every step of every round, then edit the cipher itself — swap the S-box, reorder steps, change the MixColumns matrix — and see the trace re-run in ~200ms.

Built as a learning tool, not a production crypto library.

> **Status:** v0.5.0 — multiple ciphers and modes shipped, 2D visual editor complete (all 11 slices), **full linear-mode pedagogy**: every step narrates what it does inline with byte values (per-frame value-prose), every round key renders side-by-side as a labelled ribbon with the consumed `K_i` outlined, the key schedule that used to collapse into one passthrough frame now surfaces its per-word internals (AES `RotWord → SubWord → Rcon → XOR` chain; Serpent prekey recurrence + bitsliced S-boxes + IP), and hovering an `after` cell in MatrixView lights up the contributing `before` cell(s) — plus the same-position cell of the consumed round key for AddRoundKey. Cross-mode mirror buttons across every step type with a known encrypt↔decrypt param relationship. Compose-your-own block-cipher modes from the palette. See [CHANGELOG.md](./CHANGELOG.md) for the release log and [docs/versioning.md](./docs/versioning.md) for the versioning policy.

## What's in the box

Shipped ciphers (all with both encrypt + decrypt paths and FIPS / NIST / paper-vector tests):

| Cipher | Variants | Block | Key | Mode of operation |
|---|---|---|---|---|
| **AES** | 128 / 192 / 256 | 16 B | 16 / 24 / 32 B | single-block, ECB + CBC (AES-128 only today) |
| **Speck32/64** | BE (paper) + LE (NSA reference) | 4 B | 8 B | single-block |
| **Serpent** | 128 / 192 / 256 | 16 B | 16 / 24 / 32 B | single-block |
| **DES** | — | 8 B | 8 B (56 effective) | single-block |

Padding schemes (AES only): **PKCS#7**, **zero-pad**, **ISO 7816-4**, plus a no-pad option for exact-block input.

DES is the project's first Feistel cipher — its round body uses the `feistel-round` branching primitive (an L track + R track that evolve independently, recombining via a named 4-arg combine kind). Rounds 1..15 use `feistel-standard` (textbook Feistel + swap); round 16 uses `feistel-no-swap` (the textbook last-round exception that makes the cipher self-inverse under key-reversal).

Interactive features:

- **Per-frame value-prose narration** — every step in every cipher emits a collapsible `<details>` block per conceptual sub-unit (SubBytes → 16 byte units, MixColumns → 4 GF(2^8) dot-product breakdowns, AddRoundKey → 16 XOR cells naming the consumed aux, padding → input/output lengths + pad value, aux primitives → operands + result with the algebraic identity). Disclosures stay open across the byte-format toggle and across the debounced re-run after a param edit.
- **Round-key side-by-side panel** — every round key of the active schedule renders as a labelled ribbon (AES → 11/13/15 4×4 grids; Serpent → 33 grids; Speck → 22 two-byte strips). The `K_i` whose canonical name appears in the current frame's `auxRead` map lights up, so chain XOR and Rcon column injection become visible at a glance.
- **Key-schedule explorer** — replaces the useless "matrix-on-both-sides" view on key-expansion frames with a per-word stage breakdown: AES emits one row per word with `RotWord → SubWord → Rcon → XOR` for chain-start words (and the AES-256 `Nk > 6` mid-Nk SubWord branch is visually distinguished); Serpent emits the pad → prekey recurrence (132 rows, collapsed by default) → bitsliced S-boxes → IP pipeline.
- **Cell-level provenance hover** — hover any `after` cell in MatrixView (or BytesView for Serpent) and the contributing `before` cell(s) light up in green; for AddRoundKey, the same-position cell of the consumed round key in the round-key panel lights up too. Coefficient labels (`× 0x02`, `× 0x03`) annotate MixColumns sources.
- **Compose-your-own block-cipher mode** — drag `generic.aux-load`, `generic.aux-xor`, and `generic.aux-copy` primitives from the palette and wire up CBC, OFB, or CFB around any single-block cipher without writing a single line of executor code. Half-wired specs stay debuggable: missing aux references show up as orange `!` glyphs on the canvas instead of throwing a runtime exception. (See `src/steps/CLAUDE.md` for the canonical CBC recipe.)
- **2D graph view with drag-from-palette authoring** — pan / drag containers, collapse groups, see the aux-flow + state-flow edges that connect every step. Drag step types from the left palette to insert them into the spec; warning glyphs surface orphaned reads, unused writes, cycles, and state-shape mismatches **before** you click Run. High-fanout sources (Serpent's 33-key schedule, AES's 11 round keys) collapse to local replica chips with the parallel arrows bundled into one `×N` pill. Per-source edge colouring (Okabe-Ito 8-colour palette) makes overlapping dataflow readable at a glance. Replica chips and per-block iterate chips are draggable, with a per-node ↺ reset glyph and a toolbar `[reset layout]` button for the hard reset.
- **Duplicate a round** — a `+` chip on any AES round container's header clones the round, renumbers subsequent rounds + their key indexes in lockstep, bumps the key schedule (Rcon table extended on the fly via `xtime`), and auto-mirrors onto the counterpart encrypt / decrypt spec so round-trip stays valid by construction. Answer "what would AES-128 with 11 rounds look like?" end-to-end.
- **Inline parameter editing on every step** — swap the S-box, change the MixColumns matrix, edit a single byte of a round key, and watch the trace re-run in ~200 ms. The current step in the graph view stays focused across edits.
- **Per-frame state view** (4×4 matrix or 1×N byte row) with before / after diff highlighting + FIPS-197 / paper references baked into each step's description panel.
- **Run history** (last 5) with a diff overlay showing how the current run differs from any prior one, plus a Run Explorer modal for side-by-side comparison.
- **Byte format toggle**: hex / decimal / ASCII, applied to every input + output cell. S-box axis labels stay hex (addresses, not values).
- **"Custom (was …)" indicator + one-click reset** — the moment your spec diverges from the canonical cipher default (any palette insert, param edit, or delete), the header label and the cipher dropdown advertise the divergence; a `reset` button snaps you back.
- **Save / Load** custom ciphers as `.cipher.json` documents (`schemaVersion: 1`, see [`src/core/document.ts`](./src/core/document.ts)). Layout pins (graph positions + collapsed groups) survive Save / Load. The "include session" toggle controls whether plaintext + key bytes are written.
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
| `npm test` | Vitest, single run. ~1389 tests across 122 files, ~30s. |
| `npm run typecheck` | `tsc --noEmit`, strict mode. |
| `npm run check` | The full gate: `biome ci . && tsc --noEmit && vitest run && vite build`. ~25s. |
| `npm run smoke` | Playwright real-browser smoke tests (currently the Slice 6 graph drag/collapse spec). |
| `npm run build` | Production build into `dist/`. ~132 KB gzipped JS. |

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
tests/             ~122 files, ~1389 tests — vitest (node + jsdom mix)
e2e/               Playwright real-browser smoke tests
docs/              key-files.md, gotchas.md, versioning.md, plans/
.githooks/         pre-commit gate
```

## Versioning

Semver. App version lives in [`package.json`](./package.json) and is re-exported from [`src/version.ts`](./src/version.ts) so the UI footer and any saved-document `metadata.appVersion` field stay in sync. The release log lives in [`CHANGELOG.md`](./CHANGELOG.md). Step-type contracts carry an `@N` suffix (e.g. `aes.sub-bytes@1`) and the document file format has its own `schemaVersion` — see [`docs/versioning.md`](./docs/versioning.md) for when each gets bumped and how migrations work.

## License

MIT — see [`LICENSE`](./LICENSE).

## For Claude Code contributors

`CLAUDE.md` at the repo root carries the assistant brief: architecture summary, conventions (commit cadence, comment density, type safety), planning-mode rules, and pointers into `docs/` and the user's auto-memory. Read it before non-trivial work.
