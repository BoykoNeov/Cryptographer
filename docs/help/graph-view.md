# Graph view

The graph view shows the active cipher as a directed graph of its step types,
side-by-side with the linear trace. It exists so you can *see* the dataflow
your spec describes and edit it in place: drop new step types, drag rounds
into a layout that fits your screen, collapse the parts you've already
internalized.

## Reading the picture

- **Boxes** are step nodes. A leaf step is a single primitive
  (e.g. `sub-bytes`, `mix-columns`); a container is a group or an iterate
  loop. Iterate containers carry a `×N` chip telling you how many times
  the body runs (one badge per plaintext block, one per round, etc.).
- **Solid horizontal arrows** are the *state spine*: the cipher state
  flowing left-to-right through consecutive same-parent leaves. Time
  flows rightward.
- **Dashed animated arrows** are *aux edges*: named values one step
  publishes (`auxWrites`) that another step reads (`auxReads`). The label
  on each edge is the aux key — `roundKey.0`, `feedback`, `iv`, etc.
- **`×N` badges** mark iterate containers (block-cipher modes). The body
  is one canonical copy; the runtime walks it once per block.
- **Orange `!` glyph** on a node means the validator found a wiring
  problem. Hover for the message: an orphaned read (the step asked for
  an aux key nothing produced), an unused write (this step's output is
  never consumed), or a cycle.

## Editing the graph

- **Drag from the palette.** The left sidebar lists every registered
  step type, grouped by namespace. Drag an entry onto the canvas. Drop
  on a leaf or container header to insert *after* that node in its
  parent. Drop on empty canvas to append at the root.
- **Drag containers** to rearrange. The pointer-down handle is the
  container's header band. Pinned positions persist per-spec in
  `localStorage`, and travel with `Save` and `Share` if you ticked
  "include session" or made any layout edits.
- **Collapse a container** with the chevron in its header. The body
  hides; aux edges that crossed into it now terminate at the chip.
  Click again to expand.
- **Click a leaf** to focus the linear trace's scrubber on the matching
  frame. The param panel below the graph shows that step's parameters
  for in-place editing.

## Toolbar

- **Density** rescales the box sizes and gaps. Compact fits long
  ciphers; spacious is easier on the eyes for one round at a time.
- **Replicate fan-out**, when on, splits any source whose aux output
  fans out to many consumers (typically a key schedule) into small
  per-consumer chips. Trades horizontal width for vertical height; the
  long fan-out lines collapse into local stubs.

## Composing your own block-cipher mode

The `generic.aux-load`, `generic.aux-xor`, and `generic.aux-copy`
primitives in the palette let you build chaining modes (CBC, OFB, CFB)
out of aux operations alone. See `src/steps/CLAUDE.md` for the full
recipe. Half-wired aux specs are tolerated — missing aux reads light up
the orange warning glyph without halting the run, so you can wire a
chain one step at a time.

## What survives a save

`Save` writes a JSON document. With "include session" off, only the
spec (and any layout pins or collapsed containers you set) lands in the
file — byte-stable, safe to share. With it on, the active mode, cipher,
input, key, byte format, and padding scheme are captured too. `Load`
restores everything; `Share…` packs the same document into a URL hash
so a single link reconstructs the view.
