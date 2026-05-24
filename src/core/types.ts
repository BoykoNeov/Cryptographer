/**
 * Load-bearing contracts. Saved CipherSpec JSON references these shapes
 * forever — changes here are breaking for any spec on disk.
 */

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

// ─── State ────────────────────────────────────────────────────────────────
// Discriminated union. Each variant carries the bytes plus enough shape
// metadata for the UI to pick the right view without a runtime cast.

export type StateShape = "bytes" | "matrix4x4-bytes" | "bitvec" | "bigint";

export type BytesState = {
  readonly shape: "bytes";
  readonly bytes: Uint8Array;
};

export type MatrixState = {
  readonly shape: "matrix4x4-bytes";
  /** Column-major, 16 bytes. AES convention: state[r + 4*c]. */
  readonly bytes: Uint8Array;
};

export type BitVecState = {
  readonly shape: "bitvec";
  readonly bits: Uint8Array; // packed; length in bits stored separately
  readonly bitLength: number;
};

export type BigIntState = {
  readonly shape: "bigint";
  readonly value: bigint;
};

export type State = BytesState | MatrixState | BitVecState | BigIntState;

// ─── Auxiliary lanes ──────────────────────────────────────────────────────
// Some steps need data alongside the main state — round keys, IVs, counters.
// They live in a typed `aux` map so executors stay pure of side channels.

export type AuxValue = State | Uint8Array | number | bigint | readonly State[];
export type Aux = ReadonlyMap<string, AuxValue>;

// ─── Spec ─────────────────────────────────────────────────────────────────

export type StepLeaf = {
  readonly kind: "step";
  readonly id: string; // unique within spec; UI references this
  readonly type: string; // registry key, e.g. "aes.sub-bytes@1"
  readonly params: Json;
  /**
   * Optional per-instance docs that shadow the registry's `StepDocumentation`
   * for this leaf only. Added in Slice 1.10 of `docs/plans/universal-port-phase-1-slices.md`
   * as a Phase 1 foundation for Phase 3's AES-rebuild-from-medium-primitives —
   * the rebuilt AES specs will lift each primitive's generic doc into
   * cipher-specific prose ("ShiftRows row 1 ← rotate left by 1 byte" rather
   * than the registry's generic "rotate row bytes by N").
   *
   * No schema bump — structural typing keeps existing saved documents
   * valid. No shipped spec uses the field yet; the `<StepDescription>`
   * renderer prefers it when present and otherwise falls back to
   * `registry.getDoc(stepType)`. Per-port narration (if Phase 3 needs it)
   * would extend this shape in place.
   */
  readonly narrationOverride?: StepDocumentation;
};

export type StepGroup = {
  readonly kind: "group";
  readonly id: string;
  readonly label: string; // "Round 1", "Key Expansion"
  readonly children: readonly StepNode[];
};

/**
 * Iteration primitive: the runtime expands this into per-iteration frames
 * inline at runSpec time. Used by multi-block cipher modes (ECB/CBC/CTR)
 * to run the AES round body once per plaintext block without unrolling
 * the JSON spec.
 *
 * Contract:
 *  - `aux[countFromAux]` must hold a `number` — the iteration count.
 *  - `aux[blocksFromAux]` must hold a `MatrixState[]` of length `count` —
 *    the per-iteration input. The runtime sets `state = blocks[i]` at the
 *    start of each iteration.
 *  - The runtime initializes `aux[outBlocksAux] = []` once before the loop
 *    and appends each iteration's final state to it.
 *  - Per-iteration step ids get a `:b{i}` suffix in the emitted frames so
 *    the flat trace stays uniquely keyed. Each frame is also stamped with
 *    `blockIndex: i` for renderers that want to display block context.
 *  - `aux["blockIndex"] = i` is exposed to step executors during iteration
 *    `i` (used by `xor-with-plaintext-block@1` in CTR mode to slice the
 *    right keystream-target block).
 */
export type IterateGroup = {
  readonly kind: "iterate";
  readonly id: string;
  readonly label?: string;
  readonly countFromAux: string;
  readonly blocksFromAux: string;
  readonly outBlocksAux: string;
  readonly children: readonly StepNode[];
};

/**
 * Branching primitive (Phase 2 of `docs/plans/des-feistel.md`). Introduces
 * the first non-linear control-flow shape into the spec tree: a round body
 * that forks into N parallel tracks, each operating on a slice of the input
 * state, and rejoins via a named combine op.
 *
 * Why a true branching primitive (not tuple state, not aux-mediated)? See
 * the plan's "Why true branching" section. Short form: only this shape
 * keeps the textbook Feistel diagram literal on the canvas — spine threads
 * continuously through F's internals on the R track, with L flowing
 * passively on a parallel track. Aux-mediated or tuple-state representations
 * would flatten F's internals into an aux thicket.
 *
 * The runtime contract:
 *   - At round entry, slice `state.bytes` by each track's `inputBytes`
 *     into a track-local `BytesState` (one per track).
 *   - Walk each track's children in turn, with `branchPath` stamped on
 *     every emitted frame so renderers (and `setTrace`'s stepId-matching)
 *     can keep tracks distinct.
 *   - Inside a track, frame stepIds gain a `:t{name}` suffix (innermost-
 *     first relative to any enclosing iterate, so a Feistel-inside-ECB
 *     frame ends up `node.id:t{name}:b{i}`).
 *   - After all tracks complete, emit ONE synthetic rejoin frame
 *     (`stepId = "{roundId}:rejoin"`, `stepType = "__rejoin__"`,
 *     `params = { combineKind }`). stateBefore = concat of all track outputs
 *     in declaration order; stateAfter = combined value per `combineKind`'s
 *     formula. The 4-arg inspector view (L_in, L_out, R_in, R_out) is
 *     reconstructed by `edge-value-lookup`, NOT carried as new fields on
 *     `TraceFrame`.
 *   - Resume parent-scope state from the combined value.
 *
 * Today's combine kinds and their (L_in, L_out, R_in, R_out) → (new_L, new_R)
 * formulas are documented inline on `CombineKind` below.
 */
export type BranchTrack = {
  /**
   * Optional human-readable track name. Defaults to the track's index in
   * the parent's `tracks[]` array. DES specs declare `name: "L"` and
   * `name: "R"` explicitly — the name appears in the `:t{name}` stepId
   * suffix and in `TraceFrame.branchPath` so future n-track ciphers
   * (Twofish 4-way Feistel) can use readable names rather than indices.
   */
  readonly name?: string;
  /** Byte indices from the input state that seed this track. */
  readonly inputBytes: readonly number[];
  /**
   * Step nodes operating on the track's own state. May be empty
   * (the passthrough case — typically the L track in textbook Feistel).
   * An empty track emits ZERO frames; the runtime still passes its
   * sliced input through to the combine as `L_out = L_in`.
   */
  readonly children: readonly StepNode[];
};

/**
 * Named combine ops. Each is a 4-arg function over the per-track input
 * AND output snapshots: `(tracks_in, tracks_out) → new_state_bytes`.
 * The 4-arg shape is critical — textbook Feistel's `new_L = R_in` reads
 * the ORIGINAL right-track input, not its post-F output, so a combine
 * that sees only `tracks_out` can't reconstruct it.
 *
 * Pre-defined kinds cover the shipped use cases. Each is documented
 * with its (L_in, L_out, R_in, R_out) → (new_L, new_R) formula:
 *
 *   - "feistel-standard":     new_L = R_in,      new_R = L_in XOR R_out
 *     Classic Feistel with swap. DES rounds 1..15.
 *   - "feistel-no-swap":      new_L = L_in XOR R_out, new_R = R_in
 *     Classic Feistel WITHOUT the post-round swap. DES round 16
 *     (and every cipher's "last round" by Feistel convention).
 *   - "feistel-add-into-left":  new_L = L_in + R_out (per byte mod 256),
 *                                new_R = R_in
 *     One half of TEA's cycle. Modular byte-add into L; R unchanged.
 *   - "feistel-add-into-right": new_L = L_in,
 *                                new_R = R_in + L_out (per byte mod 256)
 *     The other half of TEA's cycle. Modular byte-add into R; L unchanged.
 *
 * Adding new ops is a kind-tag bump (no schema break since `CombineKind`
 * is a string union over `string` at the JSON layer).
 */
export type CombineKind =
  | "feistel-standard"
  | "feistel-no-swap"
  | "feistel-add-into-left"
  | "feistel-add-into-right";

export type FeistelRoundGroup = {
  readonly kind: "feistel-round";
  readonly id: string;
  readonly label?: string;
  /**
   * Tracks in order. 2-track for binary Feistel (the only shipped case
   * today); future n-track ciphers (Twofish, 4-way) extend by adding
   * entries here without a schema migration. The runtime + combine ops
   * shipped today assume `tracks.length === 2`; n-track unlocks when a
   * future cipher adds the corresponding combine kinds.
   */
  readonly tracks: readonly BranchTrack[];
  readonly combineKind: CombineKind;
};

/**
 * For-each-subgraph: a port-native iteration primitive introduced in
 * Slice 2.0a of `docs/plans/universal-port-phase-2-slices.md`. Unlike
 * `IterateGroup` (which seeds each iteration's `state` from an aux array
 * of pre-split blocks AND publishes per-iteration outputs back through
 * aux), this primitive **threads state across iterations**: iteration
 * `i+1`'s body input is iteration `i`'s body output. The construct
 * exists to model SHA-256's 64-round compression loop (and similar
 * state-carrying round bodies) without aux mediation.
 *
 * Phase 2 contract surface (this slice — 2.0a — only):
 *
 * - **State-thread round-body pattern.** First child of the body reads
 *   the parent-scope `state` on iteration 0; each subsequent iteration
 *   re-enters with the previous iteration's body-final state. No clone-
 *   to-seed-from-aux, no per-iteration reset.
 * - **Iteration count source.** Literal `iterationCount: number` for the
 *   common case (SHA-256 compression: 64). `{ fromParam: string }` form
 *   anticipates per-cipher round-count variation. (Item-array source
 *   `{ fromInputPort: ... }` defers to Slice 2.0b; feedback/lookback
 *   defers to Slice 2.0c.)
 * - **Frame stepId suffix.** Each iteration appends `:r{i}` to body
 *   leaves' stepIds. Composed with the existing `:t{name}` (Feistel
 *   tracks) and `:b{i}` (iterate blocks) suffixes under a fixed type
 *   order — see `core/step-id.ts` and `core/runtime.ts::composeStepId`.
 *
 * Why a new kind rather than a flag on `IterateGroup`: the two have
 * opposite state-management contracts (clobber vs thread) and Phase 2
 * goal-state for `IterateGroup` is gradual deprecation as for-each-
 * subgraph subsumes both patterns (Slice 2.0b widens this kind to
 * handle item-array input + iteration-outputs port). Folding both
 * contracts into one kind would obscure the migration boundary.
 *
 * Slice 2.0b widens this shape with `inputArrayPort?` + `outputsPort?`.
 * Slice 2.0c widens it with feedback/lookback support (exact shape per
 * Open #N4 user pick — `aux.priorIterations` channel or sibling kind).
 * Until those slices land, the literal `iterationCount: number` /
 * `{ fromParam }` is the only iteration-source form.
 */
export type ForEachSubgraphNode = {
  readonly kind: "for-each-subgraph";
  readonly id: string;
  readonly label?: string;
  /** Literal count for the common case; param-form pulls from the first
   *  enclosing leaf's `params` at runtime (see `runtime.ts`). */
  readonly iterationCount: number | { readonly fromParam: string };
  readonly children: readonly StepNode[];
};

export type StepNode =
  | StepLeaf
  | StepGroup
  | IterateGroup
  | FeistelRoundGroup
  | ForEachSubgraphNode;

export type CipherSpec = {
  readonly id: string; // "aes-128@1"
  readonly name: string;
  readonly stateShape: StateShape;
  /** Inputs the runtime needs to seed the state and aux map. */
  readonly inputs: {
    readonly plaintext: { readonly shape: StateShape };
    readonly key: { readonly byteLength: number };
  };
  readonly steps: readonly StepNode[];
};

// ─── Trace ────────────────────────────────────────────────────────────────

export type TraceFrame = {
  /** Monotonic frame index across the whole trace. */
  readonly index: number;
  /** Path of group ids from root to this leaf, then the leaf's id. */
  readonly path: readonly string[];
  readonly stepId: string;
  readonly stepType: string;
  readonly params: Json;
  readonly stateBefore: State;
  readonly stateAfter: State;
  /** Aux entries that were read or written by this step. */
  readonly auxRead: ReadonlyMap<string, AuxValue>;
  readonly auxWritten: ReadonlyMap<string, AuxValue>;
  /**
   * Aux keys the step *requested* via `result.auxReads` but for which the
   * aux map held no value at read time. Populated by the runtime and used
   * by Slice 9's `validateGraph` to surface "orphaned-read" warnings.
   *
   * Why this needs to be on the frame, not derivable later: the runtime
   * filters out missing keys from `auxRead` (only successful reads land
   * there). Without recording the request list explicitly, the orphan
   * information is lost at the trace boundary.
   *
   * Omitted (rather than empty array) for frames whose step requested no
   * aux at all OR whose every request succeeded — keeps the common case
   * allocation-free and the discriminator unambiguous.
   *
   * Note on shipped strict steps (e.g. `add-round-key`): those THROW when
   * the named aux is missing, so they never emit a frame at all. This
   * field starts showing values once non-throwing graceful aux consumers
   * land in Slice 10 (`aux-xor`, `aux-copy`).
   */
  readonly auxReadMissing?: readonly string[];
  /**
   * 0-based index of the block this frame belongs to when emitted inside
   * an `iterate` node; undefined for frames outside any iterate.
   */
  readonly blockIndex?: number;
  /**
   * Ordered list of track names this frame lives inside, outer-first.
   * Set on every frame emitted inside a `feistel-round`'s tracks (including
   * the synthetic `:rejoin` frame, where `branchPath` resolves to the
   * enclosing round's `branchPath` — empty unless that round itself is
   * nested in another). Stripped from `path` for stepId-matching; preserved
   * as its own field so renderers (the FeistelTrackContext panel, the
   * scrubber timeline badges) can flag track membership without reparsing
   * step ids.
   *
   * Combine suffix order at frame-emit (innermost-first): `:t{name}` is
   * inside `:b{i}`, so a leaf inside a Feistel track inside an iterate
   * emits `node.id:t{name}:b{i}`. The runtime walker threads `branchPath`
   * + `blockIndex` through recursion and assembles the suffix string at
   * frame-construction time. Pin in `tests/frame-preservation-feistel`.
   */
  readonly branchPath?: readonly string[];
};

export type Trace = {
  readonly frames: readonly TraceFrame[];
  readonly finalState: State;
  readonly finalAux: Aux;
};

// ─── Executor contract ────────────────────────────────────────────────────

export type StepContext = {
  readonly stepId: string;
  readonly path: readonly string[];
  readonly aux: Aux;
};

export type StepResult = {
  readonly state: State;
  /** Aux changes; merged into the live aux map by the runtime. */
  readonly auxWrites?: ReadonlyMap<string, AuxValue>;
  /** Aux keys this executor consumed (for trace bookkeeping). */
  readonly auxReads?: readonly string[];
};

export type StepExecutor = (state: State, params: Json, ctx: StepContext) => StepResult;

// ─── Documentation ────────────────────────────────────────────────────────
// Human-readable explanation of a step type. Lives next to the executor in
// the registry so the UI can render a description for whatever step the
// user is currently inspecting — without needing to know about specific
// ciphers. New step types added by future ciphers describe themselves
// automatically via this same shape.
//
// `detail` is a tiny markdown subset: paragraphs, **bold**, `code`,
// # headings, and `- ` lists. See ui/components/Markdown.tsx for what
// renders. Keep snippets short and educational.

/**
 * Declared input/output state-shape contract for a step type. Consumed by:
 *   - the palette UI, which renders a "bytes" / "4×4 matrix" / "any" chip
 *     so users know what shape the step expects before they drag it;
 *   - the graph view's drop-anchor greying, which dims spec positions
 *     whose inferred state shape doesn't match the dragged step's input;
 *   - `validateShapes` in `core/spec-shapes.ts`, which emits a static
 *     `state-shape-mismatch` warning whenever a leaf's declared input
 *     disagrees with the shape arriving from upstream.
 *
 * Optional. Steps that omit the contract skip all three behaviors — the
 * palette shows no chip, drag never greys their target, validation skips
 * them. This keeps the field a soft addition: no existing executor breaks
 * by not declaring it (the runtime's existing throw is still the fallback).
 *
 * Why a discrete `"preserveInput"` output: most step types (every AES
 * round step, every padding step, the aux primitives) pass state through
 * untouched. Spelling that out as a literal keeps the static walker from
 * having to enumerate shapes for the trivial case.
 */
export type StepShapeContract = {
  /** What state shape this executor accepts. `"any"` for aux-only steps. */
  readonly input: StateShape | "any";
  /** What state shape this executor produces. `"preserveInput"` for
   *  passthroughs (the common case — AES rounds, padding, aux primitives). */
  readonly output: StateShape | "preserveInput";
};

export type StepDocumentation = {
  /** Human-readable name (e.g. "Byte Substitution"). */
  readonly name: string;
  /** One-liner shown next to the step in compact contexts. */
  readonly summary: string;
  /** Long-form markdown shown in the description panel. */
  readonly detail: string;
  /** Optional explanation for each parameter the step accepts. */
  readonly params?: ReadonlyMap<string, string>;
  /** Optional spec/standard references (e.g. "FIPS-197 §5.1.1"). */
  readonly references?: readonly string[];
  /** Optional state-shape contract. See `StepShapeContract` for usage. */
  readonly shapeContract?: StepShapeContract;
};

/**
 * Combined unit registered for each step type: the runtime executor plus
 * (optionally) human-readable docs. Existing call sites can still register
 * by passing just an executor — the registry coerces it to this shape.
 *
 * Kept as a top-level export because external test fixtures
 * (`tests/runtime-iterate.test.ts`) annotate their step constants with
 * this type before passing them to `registry.register`. The discriminated
 * union (`StepRegistration`, below) wraps this shape on the legacy side.
 */
export type StepDefinition = {
  readonly executor: StepExecutor;
  readonly doc?: StepDocumentation;
};

// ═══════════════════════════════════════════════════════════════════════════
// Universal port-based dataflow — Phase 0 spike (2026-05-23)
// ═══════════════════════════════════════════════════════════════════════════
//
// Per `docs/plans/universal-port-dataflow.md` Phase 0. The contract here is
// PROVISIONAL — it lives alongside the legacy contract while Q-gate-9
// (project→reconstruct→deepEqual round-trip) is validated. None of these
// types are wired into the runtime walker yet; that happens at Task 5 of
// Phase 0 once the round-trip passes.
//
// IMPORTANT NAMING NOTE: the plan's contract sketch uses the identifier
// `StepShapeContract` for the new port contract. That name is already
// taken at line 319 above for the single-thread state-shape contract
// (input: StateShape, output: StateShape) consumed by the palette chip,
// drop-anchor greying, and `validateShapes` in `core/spec-shapes.ts`.
// The new shape is renamed to `PortContract` to avoid the collision.

/**
 * Per-port shape descriptor. `byteLength` is OPTIONAL — when present, it's
 * what the editor checks for the warn-and-run coercion rule per Q2; when
 * ABSENT, the port is **polymorphic** (length determined by the wired
 * source at edit time). User pick 2026-05-23 (Slice 1.2): aux-xor /
 * aux-copy / iv-load and other dynamic-length aux primitives need
 * `byteLength` to be absent rather than a magic-numbered sentinel like 0.
 * Future SHA-2 (variable-length input → fixed-length output) reuses the
 * same shape without another contract bump.
 *
 * The `layout` tag is ADVISORY only — the runtime always passes raw
 * `Uint8Array`s; the tag exists so the inspector and editor can pick the
 * right view (matrix vs flat bytes vs word groups) without forking the
 * runtime contract.
 */
export type PortShape = {
  /**
   * Declared byte length of the port payload. Absent → polymorphic
   * (resolved at wiring time from the source).
   */
  readonly byteLength?: number;
  readonly layout?: PortLayout;
};

/**
 * The advisory layout vocabulary. Extensible — the type is open via the
 * `string` branch so future ciphers can introduce their own tags without
 * a core-types edit, but the four named entries are the round-trip
 * targets for State→ports projection.
 *
 * - "raw": flat byte sequence (the default for aux values, IVs, counters)
 * - "matrix-cm-4x4": 16 bytes interpreted as a 4×4 column-major matrix
 *                    (the AES State convention; `state[r + 4*c]`)
 * - "be-word": big-endian 32-bit (or 16-bit, per byteLength) word array
 * - "le-word": little-endian word array (e.g., Speck NSA convention)
 */
export type PortLayout = "raw" | "matrix-cm-4x4" | "be-word" | "le-word" | string;

/**
 * A per-port-name shape map, either as a static `ReadonlyMap` (the
 * common case for fixed-arity steps — `byte-substitution` has one state
 * port in, one state port out) or as a function from the leaf's
 * `params` (for dynamic-N steps — `aes.key-expansion@1`'s output port
 * count is `params.rounds + 1`, varying per leaf).
 *
 * The function form mirrors the shape `ProjectionMetadata.auxWritePorts`
 * already uses for dynamic aux bindings — keeping the two contract
 * layers isomorphic. User pick 2026-05-23 (Slice 1.4) over a templated-
 * name "keyN" lie and over a `dynamicOutputs?` sibling field.
 *
 * Callers MUST resolve via `resolvePortMap` (in `core/port-projection.ts`)
 * — never a raw `.get(...)` — because the function form needs `params`
 * to materialize. Resolving once per frame and caching the result is the
 * runtime's responsibility.
 */
export type PortShapeMap =
  | ReadonlyMap<string, PortShape>
  | ((params: Json) => ReadonlyMap<string, PortShape>);

/**
 * Declared input/output port contract for a ported step type.
 *
 * Map-of-port-name → shape, not array, because port names are part of
 * the step's UX (the inspector labels arrows by port name; the editor
 * lets the user re-wire by typing the source port at the consumer end
 * per Q-edges sink-only edges decision).
 *
 * Each side is a `PortShapeMap` — static for the common fixed-arity
 * case, function-form for dynamic-N steps (key-expansion: state +
 * `params.rounds + 1` round keys).
 *
 * Distinct from the existing `StepShapeContract` (line 319) which
 * describes the single-thread state shape. The two contracts coexist
 * during the migration: legacy step types declare `StepShapeContract`;
 * ported step types declare `PortContract`. Once the migration completes
 * (Phase 5), `StepShapeContract` deprecates.
 */
export type PortContract = {
  readonly inputs: PortShapeMap;
  readonly outputs: PortShapeMap;
};

/**
 * Per-port byte arrays flowing into / out of a ported step execution.
 * The runtime passes raw `Uint8Array`s; layout interpretation happens
 * via the corresponding `PortShape.layout` tag on the contract.
 */
export type StepInputs = ReadonlyMap<string, Uint8Array>;
export type StepOutputs = ReadonlyMap<string, Uint8Array>;

/**
 * Ported executor contract. Pure: `(inputs, params, ctx) → outputs`.
 * No State union, no aux read/write — every value crosses the boundary
 * as raw bytes through a named port.
 */
export type PortedExecutor = (inputs: StepInputs, params: Json, ctx: StepContext) => StepOutputs;

/**
 * Per-step-type metadata sufficient to LIFT a legacy `StepExecutor` into a
 * `PortedExecutor` (via `liftLegacyExecutor` in `core/port-projection.ts`)
 * AND for the runtime's ported-dispatch path to project legacy `State` /
 * `Aux` values into per-port byte arrays + reconstruct them back.
 *
 * Defined here in `core/types.ts` (rather than alongside the lift logic
 * in `port-projection.ts`) so the `StepRegistration` discriminated union
 * below can carry it as the `meta` field on the `kind: "ported"` variant
 * without forcing a circular import. The lift logic still lives in
 * `port-projection.ts`; this is just the contract.
 *
 * - `stateInputPort` / `stateOutputPort` are UNDEFINED for aux-only steps
 *   (e.g., `generic.aux-load@1`, `generic.aux-xor@1`, `generic.aux-copy@1`,
 *   `generic.iv-load@1`). The lift adapter then skips state encode/decode
 *   entirely and the runtime preserves the parent state's shape across
 *   the call (matches each executor's `shapeContract: { input: "any",
 *   output: "preserveInput" }`).
 * - `auxReadPorts` / `auxWritePorts` are FUNCTIONS of `params` (not static
 *   maps) because aux key names are spec-leaf-specific (e.g., one leaf
 *   binds `roundKey.0`, the next `roundKey.1`). The function returns an
 *   **empty Map** when no aux is in play — e.g., an `aux-load` whose
 *   `params.auxName` is `""` (fresh palette drop) must NOT emit a binding
 *   to the empty string, or frame-parity diverges from the legacy
 *   executor's `return { state }` no-op behavior.
 * - **Iteration order matters.** Legacy executors declare `auxReads` in a
 *   specific order; the ported path's `auxReadMissing` array iterates the
 *   metadata's `auxReadPorts(params)` Map. JS Maps preserve insertion
 *   order — author the metadata's binding order to match the legacy
 *   executor's `auxReads` literally, or frame-parity tests will fail on
 *   the `auxReadMissing` field.
 */
export type ProjectionMetadata = {
  /**
   * The State variant the legacy executor accepts/produces. Recorded in
   * `LayoutTags.stateLayout` so reconstruction can rebuild the right
   * variant from the port bytes. For aux-only steps where no state port
   * is declared, this value is unused — pick anything (convention:
   * `"bytes"`).
   */
  readonly stateLayout: StateShape;
  /** Name of the input port that carries `stateBefore`. Convention: "state". */
  readonly stateInputPort?: string;
  /** Name of the output port that carries `stateAfter`. Convention: "state". */
  readonly stateOutputPort?: string;
  /**
   * Function mapping the step's `params` to a `portName → auxKey` map for
   * aux INPUTS. Return an empty Map when no aux is read this call (e.g.,
   * unset params on a fresh palette drop). The function may also throw if
   * params are malformed — mirroring the legacy executor's validation.
   */
  readonly auxReadPorts?: (params: Json) => ReadonlyMap<string, string>;
  /** Symmetric to `auxReadPorts`, for aux OUTPUTS. */
  readonly auxWritePorts?: (params: Json) => ReadonlyMap<string, string>;
};

/**
 * The unit `StepRegistry` stores per step type, as a discriminated union
 * over the two execution contracts that coexist during Phase 1 of the
 * universal-port-dataflow migration (see
 * `docs/plans/universal-port-phase-1-slices.md` — Slice 1.1).
 *
 *   - `kind: "legacy"` — the existing `(state, params, ctx) → StepResult`
 *     executor contract. Every shipped step registers as this today.
 *   - `kind: "ported"` — the universal port-based contract:
 *     `(inputs, params, ctx) → outputs`, with `shape: PortContract`
 *     declaring the named port surface AND `meta: ProjectionMetadata`
 *     carrying the binding rules the runtime needs to project legacy
 *     `State` / `Aux` values into per-port byte arrays. Slice 1.2 lands
 *     the first real ported entries (the four aux-only primitives —
 *     `generic.aux-load@1`, `generic.aux-copy@1`, `generic.aux-xor@1`,
 *     `generic.iv-load@1`).
 *
 * Slice 1.1 was a NO-OP foundation slice: the union compiled, every
 * existing `register(...)` call site kept working unchanged via
 * normalization in `StepRegistry.register`, and dispatch behavior was
 * unchanged for every caller. Slice 1.2 introduces the `meta` field
 * AND the first real ported registrations.
 *
 * `doc` is REQUIRED on the ported variant (a ported step type is a
 * deliberately authored migration target — there's no excuse for it to
 * lack documentation). On the legacy variant `doc` stays optional to
 * match the pre-Slice-1.1 `StepDefinition` shape, so no existing call
 * site is forced to invent docs in this slice.
 */
export type StepRegistration =
  | {
      readonly kind: "legacy";
      readonly executor: StepExecutor;
      readonly doc?: StepDocumentation;
    }
  | {
      readonly kind: "ported";
      readonly executor: PortedExecutor;
      readonly shape: PortContract;
      readonly meta: ProjectionMetadata;
      readonly doc: StepDocumentation;
      /**
       * Legacy-shape executor preserved alongside the lifted ported
       * executor during the Phase 1 migration window. Required for every
       * Slice 1.2–1.8 ported entry because the runtime's frame-parity
       * gate runs each ported step under BOTH `portedDispatchEnabled:
       * true` (calls `executor`) and `portedDispatchEnabled: false`
       * (calls this `legacy`) — without it the legacy path can't reach
       * a step type that's been lifted.
       *
       * Phase 2 onward authors port-native executors directly; those
       * entries genuinely have no legacy underlying. When the migration
       * ends (Phase 5 retires the legacy contract), this field can
       * become optional and then disappear. For now: required, holds
       * the same function the step file's old `register` call passed
       * as `executor`, and the lifted `executor` is built from it via
       * `liftLegacyExecutor(legacy, meta)`.
       */
      readonly legacy: StepExecutor;
    };

/**
 * Sidecar metadata sufficient to reconstruct a legacy `TraceFrame` from
 * a `PortedFrame`. The Phase-0 load-bearing assertion (Q-gate-9) is that
 * `deepEqual(reconstruct(project(legacyFrame), tags), legacyFrame)` holds
 * byte-by-byte for every lifted step.
 *
 * The discipline: `LayoutTags` MUST carry only what's needed to interpret
 * raw bytes back into the legacy variants — it MUST NOT carry the
 * original `State` object verbatim under a different field. Doing so
 * would make the round-trip trivial and would not validate the
 * "flatten-to-Uint8Array" claim that the entire migration rests on.
 *
 * Phase-0 scope (per user pick 2026-05-23): only `matrix-cm-4x4` and
 * `bytes` (raw) layouts are exercised — the three target step types
 * (`generic.byte-substitution@1`, `generic.add-round-key@1`, one ECB
 * iteration body) all use `MatrixState`. The fields for `bitvec` and
 * `bigint` reconstruction are sketched here but not exercised; first
 * cipher to use them (likely SHA-2 in Phase 2 or RSA later) forces them
 * through the round-trip.
 *
 * TODO(Phase 1, bitvec): exercise round-trip with a synthetic `BitVecState`
 * frame so `bitLength` correctly survives. Needed before any cipher that
 * carries bit-aligned state (Serpent's bitslice form, if it ever ships).
 *
 * TODO(Phase 1, bigint): exercise round-trip with a synthetic `BigIntState`
 * frame; design the endianness convention. RSA and elliptic-curve work
 * will force the question. `bigintByteLength` is needed because a bigint
 * value alone doesn't preserve leading zero bytes.
 */
export type LayoutTags = {
  /**
   * The State variant the legacy frame's `stateBefore`/`stateAfter` carried.
   * Phase-0 fixture only exercises "matrix-cm-4x4"; "bytes" is reachable
   * by other shipped step types but not in the three targets.
   */
  readonly stateLayout: StateShape;
  /** For `bitvec` reconstruction. Undefined for other shapes. */
  readonly bitLength?: number;
  /** For `bigint` reconstruction. Undefined for other shapes. */
  readonly bigintEndian?: "be" | "le";
  /** For `bigint` reconstruction (preserves leading zero bytes). */
  readonly bigintByteLength?: number;
  /**
   * For each input port that was sourced from an aux entry in the legacy
   * frame, the original aux key name. The reconstruction reads
   * `portedFrame.inputs.get(portName)` and writes it back to `auxRead`
   * under this key. Output ports going to aux work analogously via
   * `auxOutputBindings` below.
   *
   * Why this lives in the sidecar (and not on the PortedFrame): port
   * names are *contract-level* identifiers, stable across runs of a
   * given step type. Aux keys are *spec-level* identifiers, varying per
   * leaf (`roundKey.0`, `roundKey.1`, …). Keeping the binding in the
   * sidecar reflects that asymmetry: the PortedFrame is fully described
   * by the contract; the sidecar carries the spec-specific projection
   * details.
   */
  readonly auxInputBindings?: ReadonlyMap<string, string>;
  /** For output ports that wrote to aux in the legacy frame. */
  readonly auxOutputBindings?: ReadonlyMap<string, string>;
};

/**
 * The port-projection of a legacy `TraceFrame`. Every legacy field
 * either survives unchanged (index, path, stepId, stepType, params,
 * blockIndex, branchPath, auxReadMissing) or projects through `inputs`/
 * `outputs` (stateBefore, stateAfter, auxRead, auxWritten).
 *
 * Reconstructing a legacy frame from a PortedFrame requires the
 * `LayoutTags` sidecar (see above). The Phase-0 spike validates that
 * `(PortedFrame, LayoutTags)` is lossless against `TraceFrame` for the
 * three lifted step types.
 */
export type PortedFrame = {
  readonly index: number;
  readonly path: readonly string[];
  readonly stepId: string;
  readonly stepType: string;
  readonly params: Json;
  readonly inputs: StepInputs;
  readonly outputs: StepOutputs;
  readonly auxReadMissing?: readonly string[];
  readonly blockIndex?: number;
  readonly branchPath?: readonly string[];
};
