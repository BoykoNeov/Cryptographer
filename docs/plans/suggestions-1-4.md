# UX/feature suggestions plan — Phases 1–4

**Date:** 2026-05-11
**Status:** Approved; execution deferred to a future session.
**Source:** Conversation between the user and Claude on 2026-05-11.

## Context

Four UX/feature suggestions to make the Cryptographer more useful as a learning tool:

1. **Preserve current frame on edit/run.** Right now editing any param (or clicking Run) resets the trace scrubber to frame 0. Annoying when you're trying to see *how an edit changes the byte you're staring at*. The user asked that this become the permanent principle, for all current and future ciphers.
2. **Multi-run history + diff visualization.** A separate window (and main-screen integration) showing the last 5 runs' frames side by side, with per-cell diff highlights and a legend describing what changed between runs (input plaintext, key, spec params).
3. **Byte format toggle.** Switch every byte display and input between hex (current), decimal (0–255), and ASCII (with `\xNN` escapes for non-printable bytes).
4. **2D / DAG-style cipher visualization.** A future direction where steps lay out in 2D, with arrows showing aux-buffer flow between non-adjacent steps and a palette of standard operations (XOR, padding, etc.). **Deferred** — to be designed jointly with the future binary-export feature, since both restructure how a cipher is expressed.

The intended outcome of phases 1–3: same data, much richer exploration. Phase 4 is left as a documented future direction with open questions surfaced for later.

---

## Phase 1 — Preserve current frame across re-runs

### Current behavior

`src/ui/stores/trace.ts` defines `setTrace(trace)` which unconditionally `setFrameIndex(0)`:

```ts
export const setTrace = (trace: Trace) => {
  currentTrace = trace;
  setFrameIndex(0);   // <- the reset
  setVersion((v) => v + 1);
};
```

`setTrace` is called from `App.tsx::run()` (the Run button) and indirectly via the `createEffect(on(spec, …))` that debounces param edits 200ms before re-running. So every re-run, manual or auto, snaps back to frame 0.

### Change

In `setTrace(trace)`, before swapping the trace, capture the currently-viewed frame's `stepId`. After the swap, find the same `stepId` in `trace.frames` and set `frameIndex` to that position. Fallback chain when the lookup fails (step removed, renamed, or first run): clamp the previous numeric index into the new trace's frame range. First-run case (no previous trace) keeps index 0.

```ts
// pseudocode for the new setTrace
const oldStepId = currentTrace?.frames[frameIndex()]?.stepId;
const oldIdx = frameIndex();
currentTrace = trace;
let nextIdx = 0;
if (oldStepId) {
  const found = trace.frames.findIndex((f) => f.stepId === oldStepId);
  nextIdx = found >= 0 ? found : Math.min(oldIdx, trace.frames.length - 1);
}
setFrameIndex(Math.max(0, nextIdx));
setVersion((v) => v + 1);
```

`stepId`-first preservation (not raw index) is intentional: if you're staring at `round.1.sub-bytes` and you edit the S-box, you stay on `round.1.sub-bytes` even if step ordering or insertion shifted other indices. Index-clamp is the safety net.

### Critical files

- `src/ui/stores/trace.ts` — modify `setTrace()`.
- `tests/trace-frame-preservation.test.ts` (new) — assert frame stays on same `stepId` after re-running with a different param; assert clamp-fallback when stepId disappears.

### Memory note

A matching feedback memory has been saved under `C:\Users\boiko\.claude\projects\M--claud-projects-Cryptographer\memory\` so this principle survives across conversations even if this plan file is moved or removed.

---

## Phase 2 — Run history + diff visualization

The user asked for the main-screen diff column **and** the modal explorer **together in one batch**. Split into four logical pieces; ship as one commit (or two if it gets large).

### 2a. History store

New file: `src/ui/stores/history.ts`. Ring buffer of up to 5 `RunSnapshot` entries:

```ts
export type RunSnapshot = {
  readonly id: number;                  // monotonic; 1, 2, 3…
  readonly capturedAt: number;          // Date.now()
  readonly inputHex: string;            // what the user had in the plaintext/ciphertext box
  readonly keyHex: string;
  readonly mode: "encrypt" | "decrypt";
  readonly specId: string;              // CipherSpec.id, e.g. "aes-128@1"
  readonly specParamsHash: string;      // cheap hash so we can detect param changes between snapshots
  readonly trace: Trace;
  readonly delta: RunDelta | null;      // computed against the immediately previous snapshot
  readonly hidden: boolean;             // user can toggle visibility in the explorer
};

export type RunDelta = {
  readonly inputChanged: ReadonlyArray<{ index: number; from: number; to: number }>;
  readonly keyChanged: ReadonlyArray<{ index: number; from: number; to: number }>;
  readonly paramsChanged: ReadonlyArray<{ stepId: string; paramName: string }>;
};
```

Hook the store into `setTrace()` (or into `run()` in `App.tsx`, which is where we have access to `inputHex`, `keyHex`, `mode`, and the live spec). Pushing a snapshot computes `delta` from the previous snapshot — input/key byte diffs and the list of step+param edits via `findStep` / structural comparison from `src/core/spec-mutations.ts`.

Eviction: when length hits 6, drop the oldest. Clear button in the explorer UI.

### 2b. Main-screen "previous run" overlay

Modify `src/ui/components/MatrixView.tsx`: today it renders two grids (before / after). Add an optional third grid: **previous run, same `stepId`**. Cells whose value differs from the *current* run's after-state get a distinct highlight (suggest: orange ring + value displayed in red). A toggle in the trace-view header above MatrixView switches this overlay on/off; defaults to on whenever history has 2+ runs.

Touch `src/ui/components/TinyMatrix.tsx` similarly so the StepStrip thumbnails also show the diff (optional, smaller; can ship as a follow-up if the main panel proves it's worth it).

### 2c. Run Explorer Modal

New component: `src/ui/components/RunExplorerModal.tsx`. Trigger: a button in `App.tsx` header next to Reset spec, label "Compare runs (N)" where N is `history.length`. Layout sketch:

```
┌─ Run Explorer ─────────────────────────────────────────────────────────────┐
│ [×]                                                                        │
│ Runs:                                                                      │
│  ┌─ Run #4 (current) ──────────────────────────┐ 👁                       │
│  │ pt: 10000000…0001  key: 00000000…0000       │ — "plaintext byte 0: 00→10"
│  └─────────────────────────────────────────────┘                          │
│  ┌─ Run #3 ────────────────────────────────────┐ 👁                       │
│  │ pt: 00000000…0001  key: 00000000…0000       │ — "plaintext byte 15: 00→01"
│  └─────────────────────────────────────────────┘                          │
│  ┌─ Run #2 ────────────────────────────────────┐ 👁 (hidden)              │
│  │ pt: 00000000…0000  key: 00000000…0000       │ — baseline               │
│  └─────────────────────────────────────────────┘                          │
│                                                                            │
│ Frame: [scrubber synced to main view ▼] — round.1.sub-bytes               │
│                                                                            │
│ ┌─ Run #4 ─┐   ┌─ Run #3 ─┐   ┌─ Run #2 ─┐                                │
│ │ ca 63 63 │   │ 63 63 63 │   │ 63 63 63 │                                │
│ │ 63 63 63 │   │ 63 63 63 │   │ 63 63 63 │                                │
│ │ 63 63 63 │   │ 63 63 63 │   │ 63 63 63 │                                │
│ │ 63 63 63 │   │ 63 63 63 7c│   │ 63 63 63 │                              │
│ └──────────┘   └──────────┘   └──────────┘                                │
│   (changed: 1)   (changed: 1 vs #2)   (baseline)                          │
│                                                                            │
│ [Legend] Each highlight color = source run that introduced the change      │
│ [Clear history]                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

Lookup by `stepId` rather than raw index — same principle as Phase 1, so the runs stay aligned even if the user reordered steps between runs. If a run lacks that `stepId`, show an "n/a" placeholder for that run+frame.

Color coding: each visible run gets a stable color (pick from a 5-tone palette). When a cell value differs from the previous visible run, ring it in that run's color. Legend at the bottom maps color → run id + the run's delta description. Two cells changing for two different reasons get two different rings (stacked).

### 2d. Identifying "what changed"

`RunDelta` already covers the three sources of change: plaintext bytes, key bytes, step params. The delta description string ("plaintext byte 15: 00→01", "round.1.sub-bytes.sbox[0x52]: 00→ff", etc.) is rendered next to each run tile in the legend.

### Critical files

- `src/ui/stores/history.ts` — **new.**
- `src/ui/components/RunExplorerModal.tsx` — **new.**
- `src/ui/components/MatrixView.tsx` — add `previousRunFrame` optional prop + rendering logic.
- `src/ui/components/TinyMatrix.tsx` — optionally extend with same overlay (smaller scope).
- `src/ui/App.tsx` — wire the modal trigger button, the "show previous run" toggle, and call `history.push(...)` in `run()`.
- `src/ui/stores/trace.ts` — possibly co-located with history if integration is tight, but keep them separate.
- `src/core/spec-mutations.ts` — already has `findStep`; may need a `compareSpecs(a, b)` helper. Add there.
- Tests in `tests/run-history.test.ts` — eviction, delta computation, ringbuffer behavior. UI components are harder to unit test (Vitest + Solid testing-library is doable; or smoke-test via the dev server manually).

### Open question (low-risk)

Snapshots store the full `Trace`, which holds every frame (each ~16 bytes for AES). 5 runs × ~50 frames × tiny matrices = trivial memory. No optimization needed.

---

## Phase 3 — Byte format toggle (hex / decimal / ASCII)

### 3a. Core formatters

Extend `src/core/state/bytes.ts` with format-aware helpers (or add a new `src/core/format.ts` if you prefer to keep `bytes.ts` minimal):

```ts
export type ByteFormat = "hex" | "decimal" | "ascii";

// single byte
export const formatByte = (b: number, fmt: ByteFormat): string => { … };
export const parseByte = (s: string, fmt: ByteFormat): number | null => { … };

// full sequence (for input fields and output strings)
export const formatBytes = (bytes: Uint8Array, fmt: ByteFormat): string => { … };
export const parseBytes = (input: string, fmt: ByteFormat, expectedLen: number): Uint8Array => { … };
```

Semantics:
- **hex** — current behavior. `formatByte(0x41, "hex") === "41"`. `parseBytes("000…000", "hex", 16)` → 16 bytes.
- **decimal** — `formatByte(65, "decimal") === "65"` (no padding by default; in a fixed grid pad to 3 chars on display). `parseBytes("0 0 0 65 …", "decimal", 16)` accepts space- or comma-separated tokens; rejects out-of-range.
- **ascii** — `formatByte(0x41, "ascii") === "A"`; `formatByte(0x00, "ascii") === "\\x00"` (4 characters, the user's chosen render). `parseBytes(...)` accepts a mix of literal printable chars and `\xNN` escapes. So `"AB\x00\x00…"` parses to `[0x41, 0x42, 0x00, 0x00, …]`.

Validation in `parseBytes` produces friendly errors: "expected 16 bytes (32 hex chars), got 12" / "expected 16 bytes (decimal tokens), got 14" / "expected 16 bytes (chars+escapes), got 10".

### 3b. Format store

New file: `src/ui/stores/format.ts`. Single signal:

```ts
const [byteFormat, setByteFormat] = createSignal<ByteFormat>("hex");
export const useByteFormat = () => byteFormat;
export { setByteFormat };
```

Persist in `localStorage` under key `cryptographer.byteFormat` so the user's choice survives reloads (read in `App.tsx` init, write in `setByteFormat`).

### 3c. Format toggle UI

A small segmented control rendered in `App.tsx` next to the input fields:

```
mode: [encrypt ▼]   bytes: [ hex | dec | ASCII ]
plaintext: 00000000000000000000000000000000   (32 hex chars)
key:       00000000000000000000000000000000
```

Same control could also live in the RunExplorerModal header.

### 3d. Threading the format through display sites

Every site identified in the byte-rendering inventory:

| Site | File | Change |
|---|---|---|
| Matrix cells (current frame) | `src/ui/components/MatrixView.tsx` (line ~51) | Replace `.toString(16).padStart(2,"0")` with `formatByte(cell[field], useByteFormat()())` |
| Tiny matrix cells (step strip) | `src/ui/components/TinyMatrix.tsx` (line ~35) | Same |
| Output string | `src/ui/App.tsx` (lines 113–118, 174–176) | Use `formatBytes(t.finalState.bytes, useByteFormat()())` and update the `outputLabel()` to include the format name |
| Plaintext input | `src/ui/App.tsx` (lines 146–150) | Label switches: "(hex)" / "(decimal)" / "(ASCII)". Parse uses `parseBytes(inputHex(), useByteFormat()(), 16)`. |
| Key input | `src/ui/App.tsx` (lines 152–158) | Same |
| Cell editor | `src/ui/components/HexCellInput.tsx` → **rename to `ByteCellInput.tsx`**, accept `format` prop (or read store) | Use `formatByte` / `parseByte`. Width: hex=2ch, decimal=3ch, ASCII=4ch (`\xFF`). |
| S-box cell editor (256 cells) | `src/ui/components/SboxEditor.tsx` (lines 61–73) | Inherits via `ByteCellInput` |
| MixColumns cell editor | `src/ui/components/MatrixEditor.tsx` (line ~32) | Inherits via `ByteCellInput` |
| S-box axis labels (0–F) | `src/ui/components/SboxEditor.tsx` (lines 40, 54, 84) | **KEEP HEX** — these are *addresses* (high/low nibble of the byte being looked up), not byte VALUES. Re-rendering them in decimal would imply a 16×16 grid indexed 0–255, which it isn't; in ASCII it'd be nonsense. Document this as a deliberate choice in a code comment. |
| ShiftsEditor | `src/ui/components/ShiftsEditor.tsx` | **No change** — shift counts are rotation amounts, not bytes. |

### 3e. Input validation edge cases

- ASCII mode: 16 chars on screen if all printable; if user types fewer than 16 chars, error like hex mode. Mixing escapes is fine: `"AB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"` is 14 logical bytes (`A`, `B`, 12 nulls), so the parse must count *bytes after escape expansion*, not raw chars.
- Decimal mode: separators are whitespace or commas. `"0,0,0,…,0"` and `"0 0 0 … 0"` both work. Rejects values >255 with a useful error.
- Switching mode in-place: the input field updates to the equivalent representation of the existing bytes (don't drop the user's data). So if they had `00000000…` in hex and switch to ASCII, the field becomes `\x00\x00\x00…`. Implementation: when format changes, parse the current input with the OLD format → bytes → re-render with the new format. Skip if the parse fails (leave the raw string alone but flag invalid).

### Critical files

- `src/core/state/bytes.ts` or new `src/core/format.ts` — formatters/parsers.
- `src/ui/stores/format.ts` — **new.**
- `src/ui/components/HexCellInput.tsx` → renamed to `ByteCellInput.tsx`.
- `src/ui/components/MatrixView.tsx`, `TinyMatrix.tsx`, `MatrixEditor.tsx`, `SboxEditor.tsx` — display sites.
- `src/ui/App.tsx` — input labels, parsers, the toggle UI.
- Tests: `tests/format.test.ts` covering round-trip (`parseBytes(formatBytes(x, fmt), fmt) === x` for all three formats), error cases, and the in-place format switch.

---

## Phase 4 — 2D / DAG cipher visualization (deferred)

**Status: design-only later, not in this plan.** Reasoning: this restructures how a cipher is expressed and is best designed jointly with the binary-export feature referenced in `CLAUDE.md` ("The future 'binary export' feature is what *forced* the spec-as-data choice"). Both features need to agree on:

- **Topology representation.** Today `CipherSpec.steps` is a linear `readonly StepNode[]`. A DAG needs explicit edges or implicit edges inferred from aux read/write names. Both are viable but they imply different mental models for the user editing a spec.
- **Layout storage.** If steps carry `{ x, y }` on `StepNode`, the spec couples data and presentation (and breaks the saved-JSON-forever contract in `types.ts`). Alternative: a sidecar `LayoutSpec` keyed by `stepId`.
- **Aux operations.** The user's "XOR / padding / etc. between buffers" idea — are these new step types in the registry (operating purely on aux), or edge decorations? Lean toward step types: it preserves the "everything is a step" invariant the runtime relies on, and keeps `runtime.ts` unchanged.
- **Codegen target.** What does the binary export emit (C? Python? WASM?), and does the DAG nature surface in that output (parallel evaluation hints?) or get flattened back to linear?
- **Step palette.** Discovery UI for the available aux operations — a list, a search, drag-and-drop?

Recommend revisiting when starting binary export. At that point: a dedicated plan-mode session with full design exploration.

---

## Implementation order

1. **Phase 1** (preserve frame) — single tight commit. Save the feedback memory.
2. **Phase 3** (format toggle) — single commit. Many files but each touch is small and independent of other phases.
3. **Phase 2** (run history + diff). Largest. Split if needed: 2a + 2b as one commit, 2c + 2d as the next. Coordinate with phase 1 (both use `setTrace` boundaries).
4. **Phase 4** — deferred. Document the open questions when the binary-export feature comes up.

This order ships the immediate UX wins first (frame preservation, format toggle), then layers the bigger run-history feature on top of them — and phase 2's run snapshots will naturally inherit the format toggle and frame-preservation behavior because of dependency order.

---

## Critical files (cumulative across phases 1–3)

**Modify:**
- `src/ui/stores/trace.ts` — Phase 1.
- `src/ui/components/MatrixView.tsx` — Phases 2b, 3.
- `src/ui/components/TinyMatrix.tsx` — Phases 2b, 3.
- `src/ui/components/MatrixEditor.tsx` — Phase 3.
- `src/ui/components/SboxEditor.tsx` — Phase 3.
- `src/ui/App.tsx` — Phases 2, 3.
- `src/core/state/bytes.ts` — Phase 3 (extend with formatters).

**Add:**
- `src/ui/stores/history.ts` — Phase 2.
- `src/ui/stores/format.ts` — Phase 3.
- `src/ui/components/RunExplorerModal.tsx` — Phase 2c.

**Rename:**
- `src/ui/components/HexCellInput.tsx` → `ByteCellInput.tsx` — Phase 3.

**Tests (new):**
- `tests/trace-frame-preservation.test.ts` — Phase 1.
- `tests/format.test.ts` — Phase 3 (round-trip, validation, in-place switch).
- `tests/run-history.test.ts` — Phase 2 (ring-buffer eviction, delta computation, lookup-by-stepId across reordered traces).

---

## Verification

For each phase, run the `npm run check` gate (biome + typecheck + vitest + vite build). Then manual smoke-test in the dev server (`npm run dev` → `http://localhost:5173`):

**Phase 1**
- Encrypt default vectors, scrub to frame 5 (round 1 SubBytes), edit any param, confirm scrubber stays on frame 5 (and the data updates).
- Edit input plaintext byte, confirm scrubber stays.
- Click Reset spec, confirm scrubber stays (or accept reset-to-0 if Reset is a "true reset"; this is a UX call).
- Delete a step from the spec (if reachable via UI; if not, manually edit `aes-128.ts`), reload, confirm fallback-to-clamped-index kicks in.

**Phase 3**
- Switch format to decimal — input field becomes `0 0 0 … 0` (16 tokens), matrices show 0–255, output shows space-separated decimals.
- Switch to ASCII — input becomes `\x00\x00…`, matrices show `\x00`, change input to `Hello, world!\x00\x00\x00`, confirm round-trip.
- Type an invalid value (decimal `256`, hex `ZZ`, ASCII less than 16 bytes) — error message names the format.
- Edit an S-box cell in decimal mode — confirm cell width adjusts and value parses.

**Phase 2**
- Run with plaintext `00…00`, then change to `00…01`, then to `10…01`. Confirm: 3 snapshots in history; legend shows the deltas; MatrixView's "previous run" column shows the prior cell values with rings on changed cells.
- Run 6 times to confirm oldest snapshot evicts.
- Open Run Explorer — confirm same-stepId alignment when scrubbing the modal's frame selector.
- Toggle a run hidden; confirm color coding shifts to next-visible run as baseline.
- Edit a step param (not just input) — confirm the delta description names the step+param.

---

## Pointers

- Frame index store: `src/ui/stores/trace.ts:10–26`
- Re-run trigger: `src/ui/App.tsx:92–102`
- Run button handler: `src/ui/App.tsx:64–87`
- Byte→hex helper: `src/core/state/bytes.ts:25–32`
- Spec mutation helpers: `src/core/spec-mutations.ts` (for delta computation in Phase 2)
- Original architectural plan: `~/.claude/plans/i-want-to-build-tender-spark.md`
- Original session plan file (mirror of this one): `~/.claude/plans/suggestions-1-after-changing-streamed-teacup.md`
