# Graph view

The graph view shows the active cipher as a directed graph of its step types,
side-by-side with the linear trace. It exists so you can *see* the dataflow
your spec describes and edit it in place: drop new step types, drag rounds
into a layout that fits your screen, collapse the parts you've already
internalized.

## Reading the picture

- **Pill at each edge of the canvas** — `plaintext` on the left,
  `ciphertext` on the right — show where data enters and leaves the
  cipher. On a decrypt spec the labels swap (`ciphertext` on the left,
  `plaintext` on the right); the rest of the graph still flows
  left-to-right. The pills aren't editable: you can't drop a palette
  step on them, click them, or delete them. They're there so the
  cipher's I/O is self-evident at a glance.
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
  never consumed), a cycle, or a state-shape mismatch (the step expects
  a different state shape — e.g. bytes — than what arrives here).

## Editing the graph

- **Drag from the palette.** The left sidebar lists every registered
  step type, grouped by namespace, with a small chip showing the input
  state shape each step expects (`bytes`, `4×4 matrix`, or `any`). Drag
  an entry onto the canvas:
  - **Drop on a leaf** → insert *after* that leaf in its parent.
  - **Drop on a container's header band** (the labelled top strip of
    a group/iterate) → insert as the *first child* of that container's
    body. Use this when you want a new step at the start of a round.
  - **Drop in a container's body** → routes to one of the gutter
    strips that tile the body (see next bullet). The strips guarantee
    body drops never escape to the container's parent.
  - **Drop on empty canvas** → append at the root.
  While dragging a shape-constrained step, drop positions whose state
  shape doesn't match are dimmed — drop is still allowed, but you'll
  get an orange warning on the resulting node.
- **Drop gutters tile the container body.** While you drag, thin
  tinted strips cover the entire inside of each container body — one
  at the start (above the first step), one between every pair of
  sibling steps, and one at the end (below the last step). Drop on a
  gutter to insert at *that specific slot*. The gutter you hover
  lights up so you can see exactly where the new step will land
  before releasing. The body is fully tiled: a drop anywhere in the
  body whitespace is guaranteed to land at a body position, never
  escape upward to the container's parent.
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
- **Delete a node** three ways: hover any leaf or container and click
  the red `×` button at its top-left corner; or focus a node (click it)
  and press <kbd>Delete</kbd>; or open the param panel below the graph
  and use the "Delete this step" button. Deleting a container removes
  all its descendants too. No undo — drag the step back from the
  palette if you regret it.

## Toolbar

- **Density** rescales the box sizes and gaps. Compact fits long
  ciphers; spacious is easier on the eyes for one round at a time.
- **Replicate fan-out**, when on, splits any source whose aux output
  fans out to many consumers (typically a key schedule) into small
  per-consumer chips. Trades horizontal width for vertical height; the
  long fan-out lines collapse into local stubs.
- **Zoom** scales the rendered canvas from 50% to 200%. Use the
  toolbar's `−` / `+` buttons (or `reset` to return to 100%), or
  **just roll the mouse wheel while the cursor is over the canvas**
  (no modifier needed). <kbd>Shift</kbd> + wheel scrolls the canvas
  horizontally instead — useful on wide pipelines (AES-128 ECB,
  Serpent). Zoom is independent of density: density rescales the
  layout geometry (and re-flows the canvas); zoom rescales the
  rendered pixels (the layout is unchanged). Zoom is a viewer
  preference — it's saved per-spec in your browser, but doesn't
  travel with `Save` or `Share…`, so a link you share will render
  at the recipient's zoom, not yours.

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
