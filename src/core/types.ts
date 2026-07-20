/**
 * Load-bearing contracts. Saved CipherSpec JSON references these shapes
 * forever — changes here are breaking for any spec on disk.
 */

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

// ─── State ────────────────────────────────────────────────────────────────
// Discriminated union. Each variant carries the bytes plus enough shape
// metadata for the UI to pick the right view without a runtime cast.

// Phase 5 Slice 5.1 (2026-05-30) retired the `matrix4x4-bytes` variant
// (`MatrixState`) along with the test-only matrix AES round primitives. The
// only surviving State shape is raw bytes — every shipped cipher/hash is
// port-native byte-flat (see `feedback_all_specs_port_native`). A node that
// wants a 4×4 reading of its 16 bytes carries the advisory `PortLayout` tag
// `"matrix-cm-4x4"` (a rendering hint, NOT a State variant) and renders via
// `TinyMatrix`. A future cipher needing a bit-aligned or bignum shape
// handles it INSIDE its executor and exchanges `Uint8Array` at the port
// boundary.
export type StateShape = "bytes";

export type BytesState = {
  readonly shape: "bytes";
  readonly bytes: Uint8Array;
};

export type State = BytesState;

// ─── Auxiliary lanes ──────────────────────────────────────────────────────
// Some steps need data alongside the main state — round keys, IVs, counters.
// They live in a typed `aux` map so executors stay pure of side channels.

export type AuxValue = State | Uint8Array | number | bigint | readonly State[];
export type Aux = ReadonlyMap<string, AuxValue>;

// ─── Spec ─────────────────────────────────────────────────────────────────

/**
 * Sink-side spec edge wiring (universal-port plan Phase 2 Slice 2.6a,
 * 2026-05-25). A `PortBinding` declares where ONE input port on a leaf
 * sources its bytes from: the upstream node's id plus the output port
 * name on that node.
 *
 * Carried on `StepLeaf.portInputs` as a `Record<inputPortName, PortBinding>`
 * — record-shaped (not Map) so it round-trips losslessly through the
 * `CipherDocument` JSON schema without a custom Zod transformer. The
 * runtime resolves the binding at leaf invocation by looking up the
 * upstream node's recorded outputs in a scope-local `nodeOutputs` map.
 *
 * **Resolution rules** (Q-edges-3 user pick 2026-05-25 — "unbound ports
 * fall back to implicit state thread"):
 *   - Pure port-native leaves (`StepRegistration.kind === "ported"`
 *     with `meta` absent): EVERY declared input port must be wired.
 *     A leaf with an unwired port throws at runtime entry; the
 *     spec-shapes validator emits a `port-input-unwired` warning
 *     pre-Run.
 *   - Lifted-legacy ported leaves (`kind: "ported"` WITH `meta`):
 *     unbound ports fall back to the meta-driven projection (state
 *     port projects parent state; aux ports project from aux map).
 *     The portInputs map can override the state projection by binding
 *     `meta.stateInputPort` explicitly, but 2.6a does not yet exercise
 *     this mode — flagged as a 2.6b+ feature.
 *
 * **Scope** (2.6a): only same-scope (sibling) wiring within one walk
 * frame. A leaf inside an iterate/for-each-subgraph body CANNOT wire
 * to a node outside that body. Cross-scope wiring is deferred to 2.6b
 * when SHA-256's constant chips need to feed compression-body leaves
 * across the for-each-subgraph boundary.
 */
export type PortBinding = {
  readonly node: string; // upstream node id (StepLeaf or container)
  readonly port: string; // output port name on that upstream node
};

/**
 * Reserved top-scope source exposing the cipher's `initialState` bytes
 * (scaffolding-suppression plan Phase A Slice A3a). The runtime seeds the
 * top-scope `nodeOutputs` map with one synthetic producer under this id,
 * carrying the initial state bytes on port `INPUT_SOURCE_PORT`. Specs wire
 * their first byte-consumers to it (`portInputs: { input: { node:
 * INPUT_SOURCE_ID, port: INPUT_SOURCE_PORT } }`) instead of routing through a
 * standalone `state-to-bytes@1` "plaintext-source" bridge leaf. The graph
 * derivation materializes a synthetic input pill for it.
 *
 * The leading `$` keeps the id outside the spec-id namespace (spec ids use
 * lowercase + dots + dashes only), so it can never collide with a real node.
 */
export const INPUT_SOURCE_ID = "$input";
export const INPUT_SOURCE_PORT = "out";

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
  /**
   * Sink-side port-edge wiring (universal-port plan Phase 2 Slice 2.6a).
   * Key = this leaf's INPUT port name (matches a port from the step
   * type's `PortContract.inputs`); value = `PortBinding` to an upstream
   * node's output port.
   *
   * Empty / absent map means "no edges declared." Pure port-native
   * leaves require every input port to be bound (throws at runtime
   * if any port is unwired). Lifted-legacy leaves fall back to the
   * `meta`-driven state/aux projection for unbound ports.
   *
   * See `PortBinding` doc for the full resolution semantics.
   */
  readonly portInputs?: Readonly<Record<string, PortBinding>>;
};

export type StepGroup = {
  readonly kind: "group";
  readonly id: string;
  readonly label: string; // "Round 1", "Key Expansion"
  readonly children: readonly StepNode[];
  /**
   * Author-declared default-collapse for this container in graph view
   * (universal-port plan Phase 2 Slice 2.6d follow-up, 2026-05-25).
   * `true` means: first render with no user layout entry shows this
   * container collapsed; the user can expand via the chevron, and that
   * expansion is recorded as an explicit override on `LayoutSpec.
   * expandedGroups` so the user's choice survives subsequent re-runs.
   *
   * Why on the container itself, not in a UI-store switch: the "this
   * container is too dense to render uncollapsed by default" judgment
   * is the cipher author's, not the renderer's. Travels with saved /
   * shared specs so a custom palette-built SHA-256-shaped spec ships
   * the affordance to recipients. Absent / `false` ⇒ standard behavior
   * (uncollapsed unless `LayoutSpec.collapsedGroups` records a user
   * collapse). First consumer: SHA-256's 64 compression round groups
   * (1792+ leaves uncollapsed → chip wall on first render).
   */
  readonly defaultCollapsed?: boolean;
  /**
   * Sink-side port-edge wiring on the container itself (Slice 2.6a — Q-edges-2
   * user pick "Leaves AND containers"). A container CONSUMES at its sink (the
   * implicit state-thread fallback handles the first child's state-input
   * today; explicit `portInputs` would let a future "two-input container"
   * shape declare its own inputs). For 2.6a no container kind reads
   * explicit portInputs at its boundary — the field is declared on every
   * container type so the schema + types are uniform, but the runtime
   * doesn't yet consume it on containers. Pure forward-compatibility.
   */
  readonly portInputs?: Readonly<Record<string, PortBinding>>;
  /**
   * Container's PUBLISHED output port names (Slice 2.6a — Q-edges-4 user
   * pick "Author-declared per node, defaulting to `out`"). Downstream
   * siblings can wire `{ node: "this-container-id", port: portName }` and
   * the runtime resolves to the container's exit-state bytes at exit.
   *
   * When absent, defaults to `["out"]` — the single canonical port that
   * carries the container's final-state bytes (encoded from `state` via
   * `stateToPortBytes(state, state.shape)` at container exit). Multi-
   * output container semantics (e.g., exposing both "out" = concat AND
   * "history" = per-iteration outputs separately) are deferred to a
   * future slice when a real consumer surfaces; for 2.6a all declared
   * ports get the SAME bytes (the exit state) — sufficient for SHA-256's
   * message-schedule-into-compression handoff in Slice 2.6b.
   */
  readonly outputPorts?: readonly string[];
  /**
   * **Group port contract — scaffolding-suppression plan Phase A Slice A3b.**
   * The looping containers got `seedInput`/`bodyOutput` in A2; a plain
   * `group` (a single body walk, no iteration) gets the same pair here so a
   * round body can cross its scope wall in bytes instead of through a
   * `state-to-bytes@1` entry bridge + `bytes-to-state@1` exit bridge.
   *
   *   - `seedInput` — a `PortBinding` to a **same-scope preceding sibling's**
   *     output port. When set, the runtime injects that port's bytes into the
   *     body scope as `port(groupId, "in")`, so the body's first leaf reads
   *     `{ node: <groupId>, port: "in" }` instead of a `state-to-bytes@1`
   *     bridge. (SHA-256 A3b: `round.0.seedInput = { node: "init.fetch-H",
   *     port: "output" }`; `round.t.seedInput = { node: "round.{t-1}",
   *     port: "out" }` — the previous round's published exit. This is the
   *     port-to-port round carry: round t+1's input edge IS round t's output.)
   *   - `bodyOutput` — a `PortBinding` to a **direct child of the body** whose
   *     output port becomes the group's published exit (under `outputPorts`,
   *     default `"out"`), instead of `state` at body exit. (SHA-256 A3b:
   *     `{ node: "round.{t}.repack", port: "output" }`, replacing the
   *     `state-out` bridge.)
   *
   * Both are OPTIONAL and ADDITIVE (no `schemaVersion` bump — same posture as
   * `cipherConstants`/`portInputs`/the FES `seedInput`/`bodyOutput`). When
   * absent, the legacy path runs unchanged: the body reads/writes `state` and
   * the group publishes its exit `state` bytes. The decision rule (plan A3b):
   * a single-consumer point-to-point carry goes port-to-port via this pair; a
   * many-consumer broadcast (K, W) lives in an `aux` scratchpad cell.
   */
  readonly seedInput?: PortBinding;
  readonly bodyOutput?: PortBinding;
};

/**
 * Iteration primitive: the runtime expands this into per-iteration frames
 * inline at runSpec time. Used by multi-block cipher modes (ECB/CBC/CTR)
 * to run the AES round body once per plaintext block without unrolling
 * the JSON spec.
 *
 * Two modes (mutually exclusive; discriminated by `seedInput` presence —
 * mirrors `ForEachSubgraphNode`'s state-thread-vs-item-array split):
 *
 * **Aux mode (legacy — matrix CBC/CTR until Phase B):** the per-iteration
 * input is pre-split into `aux[blocksFromAux]` and the runtime threads
 * `state`:
 *  - `aux[countFromAux]` must hold a `number` — the iteration count.
 *  - `aux[blocksFromAux]` must hold a `State[]` of length `count` — the
 *    per-iteration input. The runtime sets `state = blocks[i]` at the start
 *    of each iteration.
 *  - The runtime initializes `aux[outBlocksAux] = []` once before the loop
 *    and appends each iteration's final state to it.
 *
 * **Port mode (byte-native — scaffolding-suppression B1.4):** the iterate
 * is a pure port-graph container, like `group` (A3b):
 *  - `seedInput` resolves (in the parent scope) to the full input byte array;
 *    the runtime splits it into `blockByteLength`-sized chunks (count =
 *    `seedInput.length / blockByteLength`) and injects each chunk into the
 *    body scope as `port(iterateId, "in")` — so the body's head reads
 *    `{ node: iterateId, port: "in" }` instead of `aux[blocksFromAux]`.
 *  - `bodyOutput` names the body node + port whose bytes are the per-iteration
 *    result; the runtime concatenates them and publishes on `outputPorts`
 *    (default `["out"]`), retiring the `concat-blocks@1` boundary. `state` is
 *    never threaded; `countFromAux`/`blocksFromAux`/`outBlocksAux` are unused.
 *
 * Common to both modes:
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
  /** Aux mode only — the iteration count's aux key. Absent in port mode. */
  readonly countFromAux?: string;
  /** Aux mode only — the pre-split per-iteration input aux key. Absent in port mode. */
  readonly blocksFromAux?: string;
  /** Aux mode only — the aux key the per-iteration output is appended to. Absent in port mode. */
  readonly outBlocksAux?: string;
  readonly children: readonly StepNode[];
  /** Author-declared default-collapse (see `StepGroup` for shared semantics). */
  readonly defaultCollapsed?: boolean;
  /** Slice 2.6a container port-edge wiring (see `StepGroup` for shared semantics). */
  readonly portInputs?: Readonly<Record<string, PortBinding>>;
  readonly outputPorts?: readonly string[];
  /**
   * Container port contract (scaffolding-suppression A2 + B1.4). Setting
   * `seedInput` switches the iterate into **port mode** (above): the runtime
   * resolves it in the parent scope, splits the bytes into `blockByteLength`
   * chunks, and injects each as `port(iterateId, "in")`. `bodyOutput` names
   * the per-iteration result port. See `ForEachSubgraphWithHistoryNode` for
   * the shared resolution semantics.
   */
  readonly seedInput?: PortBinding;
  readonly bodyOutput?: PortBinding;
  /**
   * Port mode only — the byte width of each per-iteration block `seedInput`
   * is split into (16 for AES). Required when `seedInput` is set; the
   * iteration count auto-derives as `seedInput.length / blockByteLength`
   * (which must divide evenly). Unused in aux mode.
   */
  readonly blockByteLength?: number;
  /**
   * Cross-iteration feedback (scaffolding-suppression B1.4b — byte-native
   * CBC). Distinct from `seedInput` (which carries the *whole* multi-block
   * input, split per iteration): the chain port carries a *single-block*
   * value that updates each iteration — the previous ciphertext block in CBC.
   * Both required together (port mode), or both absent (plain ECB-style loop).
   *
   *  - `chainInput` — a `PortBinding` resolved in the **parent scope**
   *    (a preceding sibling, like `seedInput`). Its bytes are the chain value
   *    for iteration 0 — the IV in CBC. The runtime injects it as
   *    `port(iterateId, "chain")` into the body scope so the body's chaining
   *    XOR can wire to `{ node: iterateId, port: "chain" }`.
   *  - `chainFeedback` — a `PortBinding` resolved in the **body scope** at the
   *    END of each iteration; its bytes become the `chain` port injected into
   *    the NEXT iteration. CBC's encrypt/decrypt asymmetry lives entirely here:
   *    encrypt feeds the previous *output* (`round.N.out`), decrypt feeds the
   *    previous *input* (`port(iterateId, "in")`, the raw ciphertext block).
   *    Resolving the latter relies on the injected `chain`/`in` ports surviving
   *    in the body's returned `nodeOutputs` map (they do — see `walk`'s
   *    `nodeOutputs = new Map(seedOutputs)` seeding).
   *
   * The general "value carried from iteration i to i+1" shape (CTR counter,
   * OFB/CFB feedback) would reuse this; B1.4b builds it CBC-shaped and the
   * plan's deferred recurrence-visibility work owns the general graph edge.
   */
  readonly chainInput?: PortBinding;
  readonly chainFeedback?: PortBinding;
  /**
   * Port-mode only — harvest the FINAL chain value (after the last
   * iteration's `chainFeedback`) onto a named output port of the iterate
   * container. The honest dual of `chainInput`: `chainInput` *seeds* the
   * fold, `chainOutput` *reads it back out*. Required by no existing mode
   * (CBC's result is the concatenated per-block `bodyOutput`, not the
   * carried chain), but it is exactly what a *fold-to-a-single-value*
   * needs — e.g. SHA-256 multi-block, where the running hash H is the
   * chain and the digest is its final value after the last block.
   *
   * Only meaningful with chaining: setting `chainOutput` without
   * `chainInput`/`chainFeedback` throws (a fold with no carry has no final
   * chain to publish). The name is added to the node's output map *in
   * addition to* `outputPorts` (which still carry the concatenated
   * `bodyOutput`), so a single iterate can expose both the per-block
   * stream and the folded result on distinct ports.
   *
   * Additive optional field (no `schemaVersion` bump — same posture as
   * `seedInput`/`bodyOutput`/`chainInput`).
   */
  readonly chainOutput?: string;
  /**
   * Port mode only — allow the message to end mid-block (CTR's ragged tail).
   *
   * By default `seedInput.length` must be a whole multiple of
   * `blockByteLength`; a remainder throws, because ECB and CBC feed each block
   * *through* the cipher and a block cipher has no meaning for a partial
   * block. That is why those modes need padding at all.
   *
   * CTR does not. It encrypts the **counter** to manufacture a keystream and
   * XORs that keystream with the message, so the message never enters the
   * cipher and a 5-byte message wants exactly 5 keystream bytes. Setting this
   * flag makes the iteration count `ceil(len / blockByteLength)` and hands the
   * final iteration a **short** `in` block (the runtime's per-block
   * `subarray` already clamps at the end of the seed, so the short block falls
   * out for free). The body is then responsible for trimming its full-width
   * result down to that block's width — in CTR, a `truncate-to-reference@1`
   * leaf between the keystream and the XOR.
   *
   * Note the chain carry is unaffected and stays full width: CTR's counter
   * rides `chain` (bootstrapped one block wide from the IV, advanced by
   * `increment-counter@1`), not `in`. So the cipher core always encrypts a
   * full counter block and always emits full-width keystream — only `in` goes
   * short, and no `BlockCipherCore` needs to know this flag exists.
   *
   * Additive optional field (no `schemaVersion` bump — same posture as
   * `seedInput`/`bodyOutput`/`chainInput`). Absent ⇒ today's behaviour
   * byte-identically, which is what keeps ECB and CBC provably unaffected.
   */
  readonly allowPartialFinalBlock?: boolean;
};

/**
 * For-each-subgraph: a port-native iteration primitive introduced in
 * Slice 2.0a of `docs/plans/universal-port-phase-2-slices.md` and widened
 * in Slice 2.0b. Subsumes two iteration patterns under one spec node kind:
 *
 *  1. **State-thread round-body** (Slice 2.0a). First child of the body
 *     reads the parent-scope `state` on iteration 0; each subsequent
 *     iteration re-enters with the previous iteration's body-final state.
 *     No clone-from-aux, no per-iteration reset. SHA-256's 64-round
 *     compression loop is the first shipped consumer. Selected when
 *     `iterationCount` is set AND the four item-array fields are absent.
 *
 *  2. **Item-array per-block iteration** (Slice 2.0b). Parent-scope state
 *     (BytesState) is split into `blockByteLength`-sized chunks; each chunk
 *     becomes the body's seed `state` for one iteration (decoded via
 *     `portBytesToState(slice, blockLayout)`); each iteration's body-final
 *     `state` is encoded via `stateToPortBytes(state, blockLayout)` and
 *     accumulated; on node exit the accumulator concatenates back into the
 *     parent-scope `state` as a BytesState. Selected when the four
 *     item-array fields are set AND `iterationCount` is absent.
 *
 * Frame stepId suffix is shared across modes: each iteration appends
 * `:r{i}` to body leaves' stepIds. Composed with `:t{name}` (Feistel
 * tracks) and `:b{i}` (iterate blocks) under fixed type order `:t < :b <
 * :r` with outer-first walk order within a type — see `core/step-id.ts`
 * and `core/runtime.ts::composeStepId`.
 *
 * Why one node kind for both patterns: Phase 2 Q4 superset pick. The
 * legacy `IterateGroup` is targeted for gradual deprecation in Phase 4/5
 * as for-each-subgraph subsumes both its aux-seeded iteration AND
 * SHA-256's state-thread pattern. Folding two kinds into one keeps the
 * Phase-2 spec vocabulary small.
 *
 * Mode discriminator (validator-enforced in `core/spec-shapes.ts` and
 * the runtime's per-node throw):
 * - State-thread mode: `iterationCount` set, `inputArrayPort` /
 *   `outputsPort` / `blockByteLength` / `blockLayout` all absent.
 * - Item-array mode: all four item-array fields set, `iterationCount`
 *   absent.
 * Mixing the two (e.g., `iterationCount` + `inputArrayPort` both set)
 * is a spec authoring bug; the validator surfaces it pre-run.
 *
 * Slice 2.0c widens this shape with feedback/lookback support (exact
 * shape per Open #N4 user pick — `aux.priorIterations` channel or sibling
 * kind). Until that slice lands, the two modes above are the only ones.
 *
 * Note on "ports" today: the `inputArrayPort` and `outputsPort` fields are
 * semantic NAMES on the node's pseudo-input / pseudo-output. Slice 2.0b's
 * runtime reads the input array from parent-scope `state.bytes` and writes
 * the output back to parent-scope `state`; the names are anchors for the
 * future port-edge wiring story (Phase 4+ when container nodes gain
 * first-class PortContract). User pick 2026-05-24 (Open #N1 = (b)
 * concatenated single port) drives the byte-flat encoding.
 */
export type ForEachSubgraphNode = {
  readonly kind: "for-each-subgraph";
  readonly id: string;
  readonly label?: string;
  readonly children: readonly StepNode[];
  /**
   * State-thread mode (Slice 2.0a). Literal count for the common case;
   * `{ fromParam }` resolution is deferred to the first param-form
   * consumer. Set ONLY when item-array fields are absent.
   */
  readonly iterationCount?: number | { readonly fromParam: string };
  /**
   * Item-array mode (Slice 2.0b). Semantic name for the input data
   * anchor on the node. The runtime reads parent-scope `state.bytes` as
   * the input array. Future Phase 4+ port-edge wiring will resolve this
   * name to an explicit upstream source.
   */
  readonly inputArrayPort?: string;
  /**
   * Item-array mode (Slice 2.0b). Semantic name for the output data
   * anchor; the runtime writes the concatenated per-iteration outputs to
   * parent-scope `state` as a BytesState at node exit.
   */
  readonly outputsPort?: string;
  /**
   * Item-array mode (Slice 2.0b). Per-iteration byte slice length;
   * `iterationCount` auto-derives as `parent.state.bytes.length /
   * blockByteLength`. Must be a positive integer that evenly divides the
   * input array length.
   */
  readonly blockByteLength?: number;
  /**
   * Item-array mode (Slice 2.0b). State variant the body operates on
   * per iteration. `portBytesToState(slice, blockLayout)` seeds the
   * body's state at iteration entry; `stateToPortBytes(state,
   * blockLayout)` collects body's exit state. AES-CBC body uses
   * `"matrix4x4-bytes"`; the Slice-2.0b toy fixture uses `"bytes"`.
   */
  readonly blockLayout?: StateShape;
  /** Author-declared default-collapse (see `StepGroup` for shared semantics). */
  readonly defaultCollapsed?: boolean;
  /** Slice 2.6a container port-edge wiring (see `StepGroup` for shared semantics). */
  readonly portInputs?: Readonly<Record<string, PortBinding>>;
  readonly outputPorts?: readonly string[];
  /**
   * Container port contract (scaffolding-suppression A2). See
   * `ForEachSubgraphWithHistoryNode.seedInput`/`bodyOutput` for the full
   * semantics. **Runtime resolution is deferred to Phase B1**, same as
   * `IterateGroup` — the runtime THROWS if either field is set on a
   * `for-each-subgraph` node until B1 wires item-array/state-thread modes
   * to ports. Use `inputArrayPort`/`outputsPort`/`iterationCount` for now.
   */
  readonly seedInput?: PortBinding;
  readonly bodyOutput?: PortBinding;
};

/**
 * `ForEachSubgraphWithHistoryNode` — Slice 2.0c of the universal-port
 * dataflow plan. Per-iteration **lookback/feedback** primitive: each
 * iteration's body reads named priors from a runtime-maintained history
 * buffer. The forcing function is SHA-256's message schedule, where
 * `W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}`.
 *
 * **Why a sibling kind, not a third mode on `for-each-subgraph`** (Q2 user
 * pick 2026-05-24). The existing 2-mode discriminator in
 * `runtime.ts::runForEachSubgraph` (item-array vs state-thread) is already
 * a ~90-line block of partial-fields × both-modes-set invariants. A third
 * mode multiplies the matrix to 3-choose-2 = 3 pairwise invariants and
 * makes the validator harder to read. The discriminated-union approach
 * keeps each kind's invariant block local; the type system carries the
 * "these fields are inseparable" constraint without runtime ceremony.
 *
 * **Why declarative offsets, not full-history channel** (Q1 user pick).
 * Body declares `lookbackOffsets: [2, 7, 15, 16]`; runtime sizes a ring
 * buffer to `max(offsets)` and exposes only the requested priors via
 * `aux["prior-N"]`. Memory bounded, dependency explicit in spec. Mirrors
 * the declarative-input posture of `PortContract` elsewhere.
 *
 * **Per-outer reset semantics** (Q3 user pick). The history buffer
 * resets at each *invocation* of the node — when wrapped inside an outer
 * loop (iterate / for-each-subgraph / for-each-subgraph-with-history),
 * each outer iteration starts with fresh history. Reset is trivially
 * by construction: `history` is a local variable inside the runtime
 * walker. A future cipher needing cross-outer persistence would add
 * a `persistAcrossOuter?: boolean` flag — defer until a use case
 * surfaces.
 *
 * **Aux key namespace.** Runtime sets `aux["prior-{N}"]` per offset before
 * each iteration's body walks; **snapshot + restore semantics** preserve
 * any pre-existing aux key under the same name across the node's
 * lifetime (so the body of the surrounding scope can keep its own
 * `prior-*` keys if it had any, though that's an edge case). Nested
 * `for-each-subgraph-with-history` inside another's body is NOT
 * recommended — the inner overwrites the outer's `prior-*` keys for
 * the duration of the inner's run, which is fine if the outer's body
 * doesn't read them between calls, but the design hasn't been audited
 * for that pattern. Defer until a real consumer needs it.
 *
 * **Initial history sourcing.** Parent-scope `state.bytes` is sliced into
 * `historyEntryByteLength` chunks; chunk count = seed count. Must be at
 * least `max(lookbackOffsets)` seeds; otherwise iteration 0 can't read
 * its longest-lookback aux key. SHA-256's message schedule will seed
 * with W[0..15] (64 bytes at `historyEntryByteLength=4`); the toy
 * fixture seeds with 2 bytes at `historyEntryByteLength=1`.
 *
 * **Body-per-iteration starting state.** Zero `Uint8Array` of
 * `historyEntryByteLength`. Unlike state-thread mode where the body's
 * state thread carries information, here the iteration's output is built
 * **only** from lookback reads — the starting state is a blank slate the
 * body writes into. Body's exit state IS the new history entry; the
 * runtime appends it. Wrong shape / wrong length at body exit throws.
 *
 * **Node exit state.** Full history (seeds + all iteration outputs)
 * concatenated as a flat `BytesState` becomes the parent-scope state.
 * Length = `(seedCount + iterationCount) × historyEntryByteLength`.
 *
 * **Frame emission.** Body frames emit with `:r{t}` suffix (same as
 * `for-each-subgraph` state-thread mode). The type-order rule
 * (`:t < :b < :r`) governs composition when nested under iterate or
 * Feistel — see `core/step-id.ts`.
 */
export type ForEachSubgraphWithHistoryNode = {
  readonly kind: "for-each-subgraph-with-history";
  readonly id: string;
  readonly label?: string;
  /**
   * Per-invocation iteration count. Body runs N times, each iteration
   * appending one entry to history. Literal `number` is the common case;
   * `{ fromParam }` form is reserved for a future consumer (same
   * deferral as `ForEachSubgraphNode.iterationCount.fromParam`).
   */
  readonly iterationCount: number | { readonly fromParam: string };
  readonly children: readonly StepNode[];
  /**
   * Positive integer offsets relative to the current iteration's
   * absolute history index. Each `N` in this list exposes
   * `history[absIndex - N]` to the body via `aux["prior-{N}"]` where
   * `absIndex = seedCount + currentIteration`. Must be non-empty; every
   * offset must be ≥ 1 (offset 0 would read the not-yet-written current
   * entry); `max(offsets)` must not exceed `seedCount` (otherwise
   * iteration 0 can't satisfy the deepest lookback).
   *
   * SHA-256 message schedule: `[2, 7, 15, 16]`. Toy fixture: `[1, 2]`.
   */
  readonly lookbackOffsets: readonly number[];
  /**
   * Per-history-entry byte length. Each entry — initial seeds AND
   * body-produced outputs — is exactly this many bytes. SHA-256 = 4
   * (32-bit words); toy fixture = 1. Must be a positive integer.
   *
   * Drives THREE shape invariants validated at runtime entry / exit:
   *   1. Parent state.bytes.length must be a multiple of this value
   *      (so seeds slice cleanly).
   *   2. Body's exit state.bytes.length must equal this value (the new
   *      history entry has fixed width).
   *   3. The node's exit state is `(seedCount + iterationCount) ×
   *      historyEntryByteLength` bytes (concatenated full history).
   */
  readonly historyEntryByteLength: number;
  /** Author-declared default-collapse (see `StepGroup` for shared semantics). */
  readonly defaultCollapsed?: boolean;
  /** Slice 2.6a container port-edge wiring (see `StepGroup` for shared semantics). */
  readonly portInputs?: Readonly<Record<string, PortBinding>>;
  readonly outputPorts?: readonly string[];
  /**
   * **Container port contract — scaffolding-suppression plan Phase A Slice
   * A2.** The looping containers historically moved data across their
   * boundary through `state`: the spec author inserted a `bytes-to-state@1`
   * bridge before the container (to seed it from a sibling's bytes) and the
   * body's last leaf was another `bytes-to-state@1` so its exit `state`
   * became the per-iteration result. `seedInput` / `bodyOutput` retire those
   * bridge leaves by naming the byte sources directly:
   *
   *   - `seedInput` — a `PortBinding` to a **same-scope preceding sibling's**
   *     output port. When set, the runtime slices that port's bytes into
   *     `historyEntryByteLength` chunks to seed the initial history, instead
   *     of reading parent-scope `state.bytes`. (SHA-256 A3:
   *     `{ node: "length-append", port: "output" }`, replacing the
   *     `seed-schedule` bridge.)
   *   - `bodyOutput` — a `PortBinding` to a **direct child of the body**
   *     whose output port carries each iteration's result. When set, the
   *     runtime appends that port's bytes to history per iteration instead
   *     of reading the body's exit `state`. (SHA-256 A3: `{ node: "w-t",
   *     port: "output" }`, replacing the `schedule-out` bridge.)
   *
   * Both are OPTIONAL and ADDITIVE (no `schemaVersion` bump — same posture
   * as `cipherConstants`/`portInputs`; deliberate, see `document.ts`). When
   * absent, the legacy state-mediated path runs unchanged — that's why
   * A2 ships before the SHA-256 cleanup (A3) without breaking any spec.
   * The container still writes the concatenated history to `state` at exit,
   * so `outputPorts` publication and downstream state-thread consumers keep
   * working; the state-write is retired later, in Phase C.
   */
  readonly seedInput?: PortBinding;
  readonly bodyOutput?: PortBinding;
  /**
   * **Container-to-scratchpad output — scaffolding-suppression plan Phase A
   * Slice A3a.** When set, the runtime writes the container's exit value (the
   * full concatenated history) into `aux[outputAux]` at exit, so many
   * downstream consumers can read it by name via `aux-load-bytes@1`. This
   * retires the standalone `generic.state-to-aux-bytes@1` "publish" bridge
   * leaf that used to read the container's exit `state` and copy it into aux.
   *
   * It is the broadcast counterpart of `bodyOutput`: `bodyOutput` is a
   * point-to-point per-iteration result; `outputAux` is the whole-history
   * fan-out (SHA-256 A3a: `outputAux: "W"`, replacing the `W-publish` bridge —
   * the 64 compression rounds keep reading `aux["W"]` unchanged). Optional +
   * additive (no `schemaVersion` bump — same posture as `seedInput`/
   * `bodyOutput`). A future leaf-level `aux-store-bytes@1` primitive would
   * generalize this for non-container writers; deferred to a B-phase
   * follow-up (pure port-native leaves can't write aux today).
   */
  readonly outputAux?: string;
};

export type StepNode =
  | StepLeaf
  | StepGroup
  | IterateGroup
  | ForEachSubgraphNode
  | ForEachSubgraphWithHistoryNode;

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
  /**
   * Named published cryptographic constants (FIPS S-boxes, SHA round
   * constants K, SHA initial hash values H, …). Scaffolding-suppression
   * plan Phase A Slice A1.
   *
   * The runtime materializes each entry into `aux[name]` once, before
   * walking the step tree — so a leaf reads a constant the same way it
   * reads any other aux value (`aux-load-bytes@1`), and the four
   * standalone "constant loader" leaves (`generic.aux-load@1` /
   * `constant-load@1`) that used to inject these by hand disappear from
   * the spec. The constant becomes a single editable source of truth:
   * editing `cipherConstants["H"]` moves every consumer in lockstep,
   * which is why H's two roles (working-vars seed + final add) both read
   * the materialized `aux["H"]` rather than a hardcoded `params.bytes`.
   *
   * Optional + additive: legacy specs omit it and behave exactly as
   * before (no entries → the materialization loop is a no-op). Persisted
   * hex-encoded in `CipherDocument` (additive, no `schemaVersion` bump).
   */
  readonly cipherConstants?: Record<string, Uint8Array>;
  /**
   * **Cipher exit port — scaffolding-suppression plan Phase A Slice A3a.**
   * Names the port whose bytes become the trace's `finalState`. When set, the
   * runtime resolves this binding against the top-scope `nodeOutputs` after
   * walking the tree and decodes the bytes into `finalState` via the spec's
   * `stateShape`. This retires the terminal `bytes-to-state@1` "final.out"
   * bridge leaf that used to convert the assembled output bytes back into the
   * cipher's state shape.
   *
   * The entry counterpart is `INPUT_SOURCE_ID` (`$input`): entry is a reserved
   * runtime-seeded source; exit is an author-declared binding to whatever leaf
   * produced the final bytes (SHA-256 A3a: `{ node: "final.assemble", port:
   * "output" }`). Optional + additive (no `schemaVersion` bump). When absent,
   * `finalState` is the walk's exit `state`, exactly as before.
   */
  readonly outputFrom?: PortBinding;
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
  // Phase 5 Slice 5.3e Batch 4 (2026-05-31) retired the per-frame
  // `stateBefore`/`stateAfter` State snapshots. The honest per-step bytes now
  // ride `portInputs`/`portOutputs` (every port-flow leaf names its primary
  // payload `"state"`); the cipher's seed + result live on `Trace.initialState`
  // / `Trace.finalState`. The runtime still threads a `State` internally (the
  // `state` variable, `cloneState`) — it's just no longer published per frame.
  // A leaf with no `"state"` port (SHA-256 primitives, native-AES `xor`/
  // `byte-substitute`) therefore has no frame-level state reading at all; the
  // cipher-agnostic surfaces (step strip, value inspector) show "(no state)"
  // there — user-accepted, since PortFlowView reads the real ports directly.
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
   * Port inputs / outputs captured at frame-emit time on the port-native
   * dispatch path (Slice 2.9a of the universal-port-dataflow plan —
   * `docs/plans/slice-2-9-port-aware-provenance.md`).
   *
   * Present for every leaf frame — whether PURE port-native (no meta —
   * `xor@1`, `add-mod-32@1`) or HYBRID (meta present for `auxReadPorts` /
   * `stateInputPort` — `aux-load-bytes@1`, the `state-to-bytes@1` /
   * `bytes-to-state@1` bridges, AddRoundKey's `xor-with-aux@1`, the
   * key-schedules). Both carry honest port I/O. (Historically the capture
   * was gated on `legacy === undefined` to exclude lifted-legacy frames; the
   * legacy executor contract was retired in Phase C / universal-port Phase 5,
   * so every frame is now port-captured and the gate is gone.)
   *
   * `portInputs` carries POST-coercion bytes (after the Slice 1.12
   * `__coerce__` morph). This matches what the executor actually saw,
   * not what the wiring upstream produced. Don't "fix" this to
   * pre-coercion — the post-coercion bytes are the honest record of the
   * step's input.
   *
   * Map values are not defensively cloned — the runtime owns the
   * underlying Uint8Array buffers and does not mutate them after the
   * frame is pushed. Consumers must not mutate.
   */
  readonly portInputs?: ReadonlyMap<string, Uint8Array>;
  readonly portOutputs?: ReadonlyMap<string, Uint8Array>;
};

export type Trace = {
  readonly frames: readonly TraceFrame[];
  /**
   * The cipher's seed state — `runSpec`'s `cloneState(input.initialState)`.
   * The symmetric counterpart of `finalState`: the input pill / input-end
   * edge resolve to it (Slice 5.3c), replacing the old read of
   * `frames[0].stateBefore`. That field-based read couldn't survive 5.3e's
   * deletion of `stateBefore`/`stateAfter` — and `frames[0]`'s `"state"`
   * input port is not always the plaintext (SHA-256's first frame is a
   * constant-load), so the port-first helper can't answer the endpoint
   * either. Runtime-only: NOT persisted in `CipherDocument` (the trace is
   * re-derived by re-running), so no `schemaVersion` bump.
   */
  readonly initialState: State;
  readonly finalState: State;
  readonly finalAux: Aux;
};

// ─── Executor contract ────────────────────────────────────────────────────

export type StepContext = {
  readonly stepId: string;
  readonly path: readonly string[];
  readonly aux: Aux;
};

// (`StepResult` + `StepExecutor` — the legacy single-thread executor contract
//  `(state, params, ctx) → StepResult` — were retired in Phase C / universal-port
//  Phase 5 along with the legacy dispatch path. Every step type is now a
//  `PortedExecutor`; `StepContext` survives because the ported contract reuses it.)

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

// (`StepDefinition` — the legacy `{ executor, doc? }` registration shape — was
//  retired in Phase C / universal-port Phase 5. Step types now register as a
//  `StepRegistration` (below), the single port-native contract.)

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
 * Per-step-type metadata the runtime uses to project the threaded `State` /
 * `Aux` onto a hybrid-ported step's named ports (and reconstruct them back),
 * so key-schedules / padding / aux primitives run port-native without the spec
 * author having to wire every port explicitly. (Pre-Phase-C it also drove
 * `liftLegacyExecutor`, which lifted a legacy `StepExecutor` into a
 * `PortedExecutor`; that bridge retired with the legacy contract.)
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
  /** Name of the input port the runtime projects the incoming threaded state
   *  into. Convention: "state". (Pre-5.3e this carried the frame's
   *  `stateBefore`; that field retired in Slice 5.3e Batch 4.) */
  readonly stateInputPort?: string;
  /** Name of the output port the runtime reconstructs the outgoing threaded
   *  state from. Convention: "state". (Pre-5.3e this carried `stateAfter`.) */
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
 * The unit a `StepRegistry` stores per step type: the universal port-based
 * execution contract `(inputs, params, ctx) → outputs`, with `shape:
 * PortContract` declaring the named port surface and (optionally) `meta:
 * ProjectionMetadata` carrying the binding rules the runtime uses to project
 * the threaded `State` / `Aux` onto named ports for hybrid-ported steps.
 *
 * Historically this was a discriminated union over a `kind: "legacy"`
 * single-thread `StepExecutor` and this `kind: "ported"` contract — the two
 * coexisted through the universal-port-dataflow migration (Phase 1's lift +
 * dual-dispatch parity matrix). **Phase C / universal-port Phase 5 retired the
 * legacy contract:** the `kind: "legacy"` arm and the per-entry `legacy`
 * fallback executor are gone, so the type can no longer express a legacy
 * registration and the runtime runs every step on the single port-native path.
 * The `kind: "ported"` literal is kept as a single-member tag — every
 * registration literal and `registration.kind === "ported"` read across the
 * codebase compiles unchanged, and dropping the discriminator entirely is a
 * purely cosmetic follow-up not worth folding into the contract retirement.
 *
 * `doc` is REQUIRED — a step type is a deliberately authored unit, so there's
 * no excuse for it to lack documentation. `meta` is OPTIONAL: pure port-native
 * steps (their inputs come entirely from the spec edge graph) omit it; hybrid-
 * ported steps (key-schedules, padding, aux) declare it to project state/aux
 * onto ports without explicit spec wiring.
 */
export type StepRegistration = {
  readonly kind: "ported";
  readonly executor: PortedExecutor;
  readonly shape: PortContract;
  readonly doc: StepDocumentation;
  readonly meta?: ProjectionMetadata;
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
 * Scope (Phase 5 / Slice 5.1, 2026-05-30): `MatrixState` was retired with
 * the test-only matrix AES primitives, so the ONLY surviving State shape is
 * `bytes` (raw). The `matrix4x4-bytes` / `bitvec` / `bigint` variants and
 * their reconstruction fields are gone. A future cipher needing a
 * bit-aligned, matrix, or bignum state shape handles it INSIDE the executor
 * and exchanges `Uint8Array` at the port boundary (see
 * `feedback_all_specs_port_native` — specialized math never crosses a port
 * as a non-bytes value), so `LayoutTags` stays bytes-only.
 */
export type LayoutTags = {
  /**
   * The State shape the runtime reconstructs threaded state into across a
   * ported step's projection. Post-Slice-5.1 this is always `"bytes"` — the
   * field is retained for the surviving hybrid-ported steps (padding, aux,
   * key-schedules) until the legacy contract is fully retired. (Pre-5.3e it
   * described the shape the frame's `stateBefore`/`stateAfter` carried; those
   * fields retired in Slice 5.3e Batch 4.)
   */
  readonly stateLayout: StateShape;
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
