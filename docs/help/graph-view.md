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
  is one canonical copy; the runtime walks it once per block. The same
  `×N` notation also appears on **bundled aux arrows** — when two or
  more aux edges share endpoints (e.g. the 11 round keys from
  `key-expansion` to a collapsed iterate), they collapse into one
  thicker arrow tagged `×N`. Click the arrow to see the full list of
  aux keys it carries.
- **Colored dots where an arrow ends** mark exactly where each incoming
  value lands and are tinted to match that arrow — so when a box has
  several inputs (an `xor`'s two operands, a `mod-mul`'s `a`/`b`, a round
  key feeding `add-round-key`) you can tell at a glance which dot belongs
  to which arrow. They appear on leaves, on the two crossing rails of a
  Feistel round's swap (labeled `R` / `L⊕F`), on a fanned-out reference
  chip that has its own input, and on a collapsed container where a folded
  step's input arrives.
- **Orange `!` glyph** on a node means the validator found a wiring
  problem. Hover for the message: an orphaned read (the step asked for
  an aux key nothing produced), an unused write (this step's output is
  never consumed), a cycle, or a state-shape mismatch (the step expects
  a different state shape — e.g. bytes — than what arrives here).

## Editing the graph

- **Drag from the palette.** The left sidebar lists every registered
  step type, grouped by namespace, with a small chip showing the input
  state shape each step expects (`bytes`, `4×4 matrix`, or `any`). Below
  the built-in groups, a **"my elements"** section lists any composites
  you've saved (see "Saving a group as a reusable element" below) — drag
  one to drop a fresh, fully editable copy of that whole group. Drag
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
  Click the same chevron again to expand. **Collapsing an iterate**
  (the `ecb-blocks` loop in ECB, etc.) is a special case: the iterate
  box stays on screen with its `×N` badge and chevron, and its body
  fills with N parallel block-chips (`block 1`, `block 2`, …) showing
  the per-block fan-out at a glance. Aux arrows that fed the iterate
  still terminate on the iterate's box (one entry point regardless of
  N), not on a specific chip. The chips are capped at 6 — for N > 6
  the last is an ellipsis chip labelled `+M more blocks`. To bring the
  real body back, click the header chevron again.
- **Click a leaf** to focus the linear trace's scrubber on the matching
  frame. The param panel below the graph shows that step's parameters
  for in-place editing.
- **Delete a node** three ways: hover any leaf or container and click
  the red `×` button at its top-left corner; or focus a node (click it)
  and press <kbd>Delete</kbd>; or open the param panel below the graph
  and use the "Delete this step" button. Deleting a container removes
  all its descendants too. No undo — drag the step back from the
  palette if you regret it.
- **Save a group as a reusable element.** Hover any **group** (e.g. an
  AES round) and click the amber `★` chip in its header band (next to
  the `×`), then name it. The group is captured into the palette's
  **"my elements"** section as a *composite* — a saved copy of its whole
  contents (including the internal wiring). Drag it back from the palette
  anywhere to drop a **fresh, fully editable copy**; its input is
  auto-wired to whatever you drop it after. Composites are stored in your
  browser (`localStorage`) and persist across reloads; rename or delete
  them with the small `✎` / `×` controls on the palette entry. Two
  caveats: only *groups* can be saved (not single leaves or loop
  containers), and a saved round that reads a round key from `aux` only
  computes correctly where that key exists — drop it somewhere without
  the matching `roundKey.N` and you'll see the coercion/missing-aux
  warning, which is the point (watch it break).
- **Drag a replica chip or block chip** to nudge its position. Replicas
  (the small dashed chips that appear above their consumer when a
  high-fanout source is replicated) and block chips (the per-block
  chips inside a collapsed iterate) are now movable too. The pin is
  RELATIVE to the chip's natural anchor — drag the consumer afterwards
  and the chip rides along. To return a chip to algorithmic placement,
  hover it and click the small `↺` (blue) at its top-left corner.
  Containers and root-level leaves still pin absolutely; they're
  unchanged by this addition.

## Rewiring ports

Every leaf reads its inputs from named upstream **output ports**. You can
change which source feeds which input *in place* — the two-click "click-to-arm"
gesture on the canvas, or the dropdown panel below the graph.

- **On the canvas.** Each leaf has small **input-port handles** on its left
  edge (one per input port). Click one to **arm** it — the leaf gets a dashed
  accent outline. Every **scope-legal source** then lights up with a ring and
  grows a **bind handle** on its right edge; click one to complete the wire.
  Press <kbd>Esc</kbd> or click empty canvas to cancel. Click the same input
  handle again to disarm.
- **Size-mismatch (coerce) wiring.** If a source emits a different number of
  bytes than the input expects, its ring + bind handle turn **amber and
  dashed**. The wire is still allowed — the runtime coerces the bytes and shows
  it as a visible step in the trace — but the colour warns you it isn't a
  clean fit.
- **You can only wire within a scope.** A leaf offers only sources in its *own*
  scope: same-parent siblings that run *before* it, plus (inside a round/loop
  body) that body's incoming value, plus (at the top level) the cipher input.
  A leaf buried in one round can't read from another round, and nothing offers
  a forward or self reference — those would fail at run time, so they're never
  offered. This is why a round's *first* leaf shows no canvas bind targets: its
  only legal source is the round's incoming value, which has no on-canvas
  handle. Reach it via the dropdown.
- **The dropdown panel** below the graph (under the parameter editor) is the
  keyboard/accessibility-complete equivalent: when a leaf is selected it shows
  one dropdown per input port listing every legal source, a `— unwired —`
  choice, and — if the current binding has gone stale — an explicit
  `⚠ current (unresolvable)` entry so the control never lies about what's
  actually wired. It's also the **only** way to wire a leaf to its container's
  incoming value (the canvas draws no handle there).

Rewires save and share exactly like any other spec edit (no extra opt-in).

## Toolbar

- **Density** rescales the box sizes and gaps. Compact fits long
  ciphers; spacious is easier on the eyes for one round at a time.
- **Replicate fan-out**, when on, splits any source whose aux output
  fans out to many consumers (typically a key schedule) into small
  per-consumer chips. Trades horizontal width for vertical height; the
  long fan-out lines collapse into local stubs. The `>` number next to
  it is the **replication threshold** — a source replicates only when it
  fans out to *more than* this many consumers (default 3). A leaf or a
  collapsed group is *replaced* by its chips; a looping source that only
  feeds aux — SHA-256's **message schedule**, which publishes `W` to all
  64 rounds — instead **keeps its box** and grows a short `W` reference
  chip beside each round, so the loop stays visible while its fan-out
  declutters.
- **Color by source**, when on, paints each source's outgoing edges in
  a distinct color so you can track "all these arrows came from here" at
  a glance. The `≥` number next to it is the **coloring threshold** — a
  source gets a color when it fans out to *at least* this many consumers.
  **It defaults to 1 for every cipher and hash, so every source is
  colored on first open**; raise it to color only the larger fan-outs (or
  set it to 0, which is equivalent to 1 here — no source fans out to zero
  edges). (Endpoint pills — plaintext / ciphertext / message / digest —
  are never colored: they *are* the source.)
- **Style by source**, when on, gives each source's outgoing edges a
  distinct **dash pattern** — a second channel alongside color, so
  sources stay tellable-apart even when their colors repeat (which they
  do on dense specs like SHA-256, which has more sources than the color
  palette). It has its own `≥` **styling threshold**, independent of the
  coloring one; it *also* defaults to 1 for every spec, so every source
  is dashed on first open. Both channels are viewer preferences — turning
  one off, or changing a threshold, sticks per-spec in your browser but
  never travels with `Save` / `Share…`.
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
- **Collapse all** / **Expand all** fold or unfold every container
  (rounds, groups) on the canvas in one click, instead of clicking each
  header chevron. They compose with a spec's default-collapsed groups
  (SHA-256's 64 rounds): *collapse all* returns those to their folded
  default, *expand all* opens them. Each button is disabled when it
  would do nothing (everything already collapsed / already expanded),
  and both are undoable with <kbd>Ctrl</kbd>+<kbd>Z</kbd>.
- **Reset layout** clears every customization for the active spec
  in one click — drag-pinned positions (containers and root leaves),
  relative pins (replica chips and block chips), collapsed
  containers, and per-source replication overrides. A confirm
  prompt guards the action. The button is disabled when the spec
  has nothing to reset.

## Inspecting a value

Below the toolbar sits a collapsible **value inspector** panel. Open it
and click any element on the canvas to populate it:

- **An edge** shows the value flowing through it at the current
  scrubber position — the round key (`roundKey.3`), the per-block
  plaintext payload (`block 2`'s 16-byte matrix), the cross-iteration
  feedback IV, etc.
- **A leaf step** shows that step's primary value at the current
  scrubber position. Clicking a leaf also scrubs the trace to that
  step (the two behaviors are additive). Up to three expanders open
  below the value row:
  - **all port values** — every input and output port of the leaf, one
    labelled byte-row each (the operands going in, the result coming
    out, plus any aux inputs like a round key or S-box table). This is
    the honest "all incoming values" view — a fan-in step like `xor` or
    `concat` reads several operands, and they're all listed here.
    Hovering an output cell here still lights up the input cell(s) that
    feed it.
  - **where each byte comes from** — the always-on version of that hover:
    the whole input→output map at once, so you don't have to point at
    every byte. A uniform map collapses to one line (`xor`: "each output
    byte comes from the same-position input byte on operand0, operand1";
    a slice: "output[i] ← input[i + 8]"); a map where the wiring *is* the
    lesson enumerates one row per output byte — `permute` (ShiftRows'
    gather), `concat`/`split-bytes` (the offset boundaries), and
    MixColumns (each output byte's four same-column contributors with
    their GF(2⁸) `×2`/`×3` coefficients). Only appears for the steps with
    an exact byte-to-byte mapping; an approximate step (a bit-rotate, a
    big-integer add) shows nothing here rather than a misleading one.
  - **what this step does** — the operation's description. A step with a
    per-byte narrator shows the value-aware prose (what it did to *these*
    bytes, the same as the linear view); every other leaf falls back to
    the registry's "what this operation is" summary + detail, so every
    step carries *some* description.
- **A key-schedule group** (the collapsed "Key Schedule" / "Key
  Expansion" box, or one of its round-key chips) has no single output
  value — it fans out *all* the round keys at once. The row says so
  ("publishes 16 aux values: `roundKey.0` … `roundKey.15`") instead of a
  blank, and the **all port values** expander lists every published key
  in full.
- **An endpoint pill** ("plaintext" / "ciphertext") shows a descriptive
  label — pills aren't bound to a trace frame, so there's nothing
  numeric to display.
- **A block chip** (a `block 0` / `block 1` ... chip on a collapsed
  iterate) shows that block's outgoing payload — equivalent to
  `outBlocks[i]`.
- **A bundled edge** (a thicker arrow with a `×N` label) opens a
  scrollable list of the N aux keys the bundle carries (e.g. all 11
  round keys flowing from `key-expansion` into a collapsed iterate).
  Click any row to see that aux key's value in the panel below — the
  arrow on the canvas keeps its selection halo while you drill row to
  row.

The clicked element gets a soft halo on the canvas, and the panel keeps
showing its value while you scrub the trace — the "click and scrub"
flow is the killer demo: watch a round key stay constant while the
state value changes frame-to-frame, or click `block[1]` and step
through every iteration of the iterate body to see how that block's
matrix is being computed. Click the same element again to clear, or
click a different element to move the selection. Selection clears
automatically when you switch ciphers (otherwise it would point at an
id that doesn't exist in the new spec).

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
