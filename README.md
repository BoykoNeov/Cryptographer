# Cryptographer

An interactive cryptography explorer. Type a plaintext + key, watch every intermediate state of every step of every round, then edit the cipher itself — swap the S-box, reorder steps, change the MixColumns matrix — and see the trace re-run in ~200ms.

Built as a learning tool, not a production crypto library.

> **Status:** v0.2.0 — multiple ciphers and modes shipped, 2D visual editor in progress. See [CHANGELOG.md](./CHANGELOG.md) for the release log and [docs/versioning.md](./docs/versioning.md) for the versioning policy.

## What's in the box

Shipped ciphers (all with both encrypt + decrypt paths and FIPS / NIST / paper-vector tests):

| Cipher | Variants | Block | Key | Mode of operation |
|---|---|---|---|---|
| **AES** | 128 / 192 / 256 | 16 B | 16 / 24 / 32 B | single-block, ECB (AES-128 only today) |
| **Speck32/64** | BE (paper) + LE (NSA reference) | 4 B | 8 B | single-block |
| **Serpent** | 128 / 192 / 256 | 16 B | 16 / 24 / 32 B | single-block |

Padding schemes (AES only): **PKCS#7**, **zero-pad**, **ISO 7816-4**, plus a no-pad option for exact-block input.

Interactive features:

- Per-frame **state view** (4×4 matrix or 1×N byte row) with before/after diff highlighting.
- **Step description** with FIPS-197 / paper references and inline parameter editing — swap the S-box and watch the trace update.
- **Run history** (last 5) with a diff overlay showing how the current run differs from any prior one.
- **Byte format toggle**: hex / decimal / ASCII, applied to every input + output cell.
- **2D graph view** (work-in-progress): pan/drag containers, collapse groups, see the aux-flow + state-flow edges that connect every step. Slices 1–6 of 11 are shipped.
- **Save / Load** custom ciphers as `.cipher.json` documents (`schemaVersion: 1`, see [`src/core/document.ts`](./src/core/document.ts)).

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
| `npm test` | Vitest, single run. ~528 tests across 42 files, ~4s. |
| `npm run typecheck` | `tsc --noEmit`, strict mode. |
| `npm run check` | The full gate: `biome ci . && tsc --noEmit && vitest run && vite build`. ~7s. |
| `npm run smoke` | Playwright real-browser smoke tests (currently the Slice 6 graph drag/collapse spec). |
| `npm run build` | Production build into `dist/`. ~72 KB gzipped JS. |

The pre-commit hook in `.githooks/pre-commit` runs `npm run check`. GitHub Actions runs the same on push.

## Architecture (one paragraph)

The whole app is built around one idea: **a cipher is JSON, not code.** A `CipherSpec` (`src/core/types.ts`) is a tree of `StepNode`s. A `Runtime` (`src/core/runtime.ts`) walks the tree, looks each leaf's `type` up in the `StepRegistry`, and calls its pure executor `(state, params) → state`. Every executor registration includes a `StepDocumentation` block (name, summary, detail markdown, params, references) so the UI gets both behavior and docs from the same source. Adding a new cipher = registering its step types + authoring a JSON spec; **no UI changes needed** for new step types unless their params need a novel editor.

For the file-by-file map, read **[`docs/key-files.md`](./docs/key-files.md)**. For the cross-cutting footguns Claude has tripped on (AES pitfalls, Solid reactivity, PowerShell, padding overlay, multi-block iterate), see **[`docs/gotchas.md`](./docs/gotchas.md)**.

## Project layout

```
src/
  core/            cipher-agnostic engine: types, runtime, registry, spec mutations, document format, graph
  ciphers/         per-cipher specs + constants (AES, Speck, Serpent)
  steps/           step-type executors + their StepDocumentation blocks
  ui/              Solid components, stores, app shell
tests/             ~42 files, ~528 tests — vitest (node + jsdom mix)
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
