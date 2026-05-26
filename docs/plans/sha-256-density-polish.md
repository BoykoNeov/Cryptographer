# SHA-256 density polish

Follow-up plan for the manual-smoke findings on 2026-05-26 that did not
fit the same-day Slice 2.8 close. Three Phase-2-density issues surfaced
*because* SHA-256 is the first reachable port-native cipher with 1829
leaves — they aren't caused by Slice 2.8's narration work, but they
make the SHA-256 experience worse than the AES/Speck/Serpent baseline.

## Context

Slice 2.8 (narrationOverride for every SHA-256 leaf) shipped today.
Manual smoke confirmed the narration prose is correct where checked
(`s_3`, `Ch`, `σ1`, `Σ1` rotation chains all matched FIPS 180-4 with
no errors). The smoke ALSO surfaced three classes of UX bugs that all
trace back to "SHA-256 is dense and port-native, the existing UI was
built around AES-scale legacy specs":

1. **Param panel raw-JSON fallback** for port-native primitives. Every
   `rotate-bits-right@1`, `xor@1`, `aux-load-bytes@1`, `byte-slice@1`,
   `add-mod-32@1` leaf — i.e. most of SHA-256 — renders the
   `ParamEditor.tsx:109` fallback that dumps params as raw JSON
   (`{"wordBits": 32, "bits": 17}`) with the prose "no editor for step
   type X (raw params view)". That's jarring and has no pedagogical
   value — the user already knows from the narration prose what the
   leaf does; the raw JSON below the description undermines the
   pedagogical surface.

2. **Graph layout obstructions on SHA-256's preamble row**. After the
   manual smoke + investigation probe (deleted; commit `47d12c7`'s test
   list captures the trial), several preamble-row leaves
   (`H-constant`, `init-working-vars`, `K-to-aux`, `H-to-aux`,
   `W-publish`) flow as siblings on a single horizontal row. Three
   distinct symptoms:
   - **Arrows behind chips:** `msg-schedule → W-publish` (state edge,
     confirmed via probe to exist), arrows from `W-publish` and
     `K-to-aux` to their consumers, all route behind H-row chips. User
     report: "message schedule ends with no arrows leading out from
     it". NOT a derivation bug — the edges exist; layout routes them
     under other chips.
   - **Long H-to-aux arrow:** the aux edge from `H-to-aux` to
     `final.fetch-H` (which lives 64+ rounds away) is rendered as a
     single long arrow passing behind every compression-round chip
     between them. Replication helps but doesn't eliminate the eyesore
     on the first source-end of the edge.
   - **Msg-schedule chip discoverability:** Even with the outgoing
     arrow drawn, the collapsed `msg-schedule` chip reads as a
     dead-end visually because the arrow is invisible.

3. **Narration prose density (deferred from this session's same-day
   uplift).** Today's commit uplifted 10 high-impact leaves to the
   `s_3` level (σ1/σ0/Σ1/Σ0/Maj combines, new_a/new_e, K_t and W_t
   fetch+slice, fetch-p2, K-to-aux, H-to-aux). The remaining "middle
   term" and "last term" rotation/AND leaves (~30 of them) still have
   minimal detail ("Middle term of `σ0(x) = ...` (FIPS 180-4
   §4.1.2)"). That's consistent with their role (you don't need full
   intuition on three near-identical rotation leaves) but a future
   pass could either:
   - **(a)** Add one-sentence "what bit positions this affects" per
     rotation leaf.
   - **(b)** Roll the three rotation leaves into one collapsed
     "compute three rotations" frame in linear mode so the eye lands
     on the combine leaf as the unit of explanation.

## Three sub-slices, can ship independently

### Slice S1 — port-native ParamEditor blocks

**Scope:** add `ParamEditor` blocks for the SHA-256-shaped port-native
primitives so the param panel renders prose + read-only display
(matching the existing `aes.sub-bytes` editor pattern, not the raw-JSON
fallback). Top of the list:

- `rotate-bits-right@1` / `shift-bits-right@1` — single editable
  `bits` integer, read-only `wordBits` (always 32 for SHA-256).
- `aux-load-bytes@1` — read-only `auxName` string + read-only
  `byteLength` int.
- `byte-slice@1` — editable `offset` + `length` integers.
- `add-mod-32@1` / `xor@1` / `and@1` — read-only `inputCount`.
- `not@1` — empty params, render an explanatory blurb instead.
- `state-to-aux-bytes@1` / `aux-load@1` — `auxName` (read-only after
  spec saved), `bytes` for `aux-load@1` (large readonly hex dump).
- `bytes-to-state@1` / `state-to-bytes@1` — empty params, explanatory
  blurb.
- `split-bytes@1` — editable `widths` int array (small grid editor).
- `constant-load@1` — `bytes` (large readonly hex dump).

**Pass/fail gate:** scrubbing every SHA-256 leaf in the linear mode
shows EITHER a meaningful editor (when params have user-tweakable
knobs) OR a read-only display with prose context (when params are
structural). The literal string "no editor for step type" should never
render on a registered step type.

**Cost estimate:** ~10 new ParamEditor blocks, each ~30 lines. Likely
one commit per editor or a single batch commit. No infrastructure work
— just filling the existing block-registration surface.

**Out of scope:** the SAME-day pedagogical concern over which params
should be USER-EDITABLE (e.g. should `bits: 17` on a σ1 rotation be
editable? Editing breaks FIPS conformance — but that's the point of
the "tinker with the cipher" thesis). Default to "render the editor,
let users break things; rely on KAT tests + visible trace to expose
the break." Locking specific params is a future concern.

### Slice S2 — graph preamble layout improvements

Three obstruction symptoms above; root cause is shared
("H-row siblings on the same horizontal row obstruct sibling-arrow
visibility"). Three candidate fixes, pick during planning:

- **(a) Force preamble verticalize.** Detect "aux-only setup row" by
  the `auxOnlyRootIds` heuristic already in GraphView and stack those
  leaves vertically along the canvas left side (like a "setup column")
  instead of horizontally. State-bearing spine continues horizontally
  to the right of the setup column.
- **(b) Replicate the preamble sources at consumer head.** Today's
  replication for `K-to-aux` / `W-publish` / `H-to-aux` already does
  this at high fanout — for the H-row, lower the threshold so a single
  long arrow (H-to-aux → final.fetch-H is the worst) is replicated
  even without crossing the fanout-6 threshold. Quick win but doesn't
  fix the spine-arrow-behind-H-row issue.
- **(c) Spine-arrow z-order lift.** Render the state spine edges
  ABOVE the chip rects (today they render below). This is the cheapest
  fix for the "msg-schedule has no arrow out" symptom — the arrow
  exists but is under the H-row chips; bringing it on top makes it
  visible without changing layout. Risk: also lifts spine arrows over
  other chips throughout the canvas. Per-edge z-order or
  per-edge-kind z-order may be needed.

**Discriminating question to answer in planning:** does (c) regress
the layout for non-port-native ciphers? If lifting spine arrows above
chips makes AES look worse, scope the lift to ported specs or to the
specific edges that pass behind chips.

**Pass/fail gate:** manual smoke on SHA-256: the
`msg-schedule → W-publish` state arrow is visible. The
`W-publish → first round` and `K-to-aux → first round` aux arrows
don't visually pass behind unrelated chips. The `H-to-aux →
final.fetch-H` arrow is either (a) replicated near the consumer or
(b) routed around the round bodies, not through them.

### Slice S3 — narration density second pass

Deferred from this session per the bucket-C scoping above. Two routes
(a) or (b) per the "Context" section. Defer until S1 + S2 ship — the
ParamEditor + layout fixes change what the user sees per scrub, which
may change which leaves "need more prose."

## Order

S1 first — it's pure additive editor work, no risk of regression to
the graph layout. S2 needs a planning round to pick (a) / (b) / (c) /
hybrid. S3 is the lowest priority and benefits from waiting on the
other two.

## What this plan does NOT cover

- The general "should ParamEditor allow editing structural params"
  question (per-cipher conformance lockdown). Worth raising
  separately if a user reports breaking SHA-256 by editing `bits:
  17` to `bits: 12` (which the existing trace-rerun discipline
  surfaces via a divergent digest — pedagogically arguably correct).
- Multi-block SHA-256. Today's spec is single-block (max 55-byte
  message); multi-block lands as its own slice. Not in scope here.
- Other future hashes (SHA-3, SHA-512, MACs, KDFs). Each gets its own
  density review when it ships.

## Memory pointers

- [[project_universal_port_dataflow_proposal]] — Phase 2 spine.
- [[feedback_port_native_param_names]] — gotcha table for the param
  names that S1's editors will surface.
- [[project_hash_future]] — endpoint-label seam closure (Slice S1 of
  THIS session, not of this plan; mentioned for cross-reference).
