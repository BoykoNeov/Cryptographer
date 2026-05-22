/**
 * Aux-graph derivation: turn a (spec, trace) pair into a directed graph
 * suitable for the upcoming 2D visual editor. Nodes are the spec's leaves,
 * containers are its groups and iterates, and edges encode two kinds of
 * dataflow:
 *
 *   - **Aux edges** (trace-derived) — round-key fan-out, IV chaining in
 *     CBC, keystream blocks in CTR, etc. Annotations on the cipher's
 *     primary dataflow.
 *   - **State edges** (spec-derived) — the implicit `(state, params) →
 *     state` thread through consecutive leaves. The headline pedagogical
 *     spine of the graph: students see the SubBytes → ShiftRows →
 *     MixColumns → AddRoundKey progression as a continuous chain.
 *
 * The graph is DERIVED, not stored. The spec already encodes the structural
 * tree; the trace's `TraceFrame.auxRead` / `auxWritten` (`types.ts`) already
 * encode aux dataflow; the executor contract `(state, params) → state` makes
 * the state spine inferable from spec structure alone. This file is the pure
 * function that combines them into one shape the renderer can lay out.
 *
 * Three key correctness pieces — invisible if you only walk frames naively:
 *
 *   1. **`:b{i}` collapse.** The runtime suffixes every per-iteration step id
 *      so the flat trace stays uniquely keyed (`runtime.ts:119`). For the
 *      logical graph, `round.1.sub-bytes:b0` and `round.1.sub-bytes:b15`
 *      are the SAME node — `key-expansion → round.1.add-round-key` is one
 *      edge, not sixteen. We strip the `:b\d+$` suffix during dedup.
 *
 *   2. **Iterate-mediated aux.** The runtime moves three aux values across
 *      the iterate boundary itself, NOT via any step's `auxWrites`:
 *        - reads `aux[countFromAux]` (`runtime.ts:48`)
 *        - reads `aux[blocksFromAux]` and substitutes `state = blocks[i]`
 *          per iteration (`runtime.ts:81`)
 *        - writes `aux[outBlocksAux]` after the loop completes
 *          (`runtime.ts:86`)
 *      A naive frame-walk leaves all three of these edges dangling — which
 *      is exactly the pedagogical "ECB is a graph of N parallel AES copies"
 *      story we exist to tell. We synthesize the edges using the iterate's
 *      id as the participant: the iterate node itself becomes a node-like
 *      participant in the edge list.
 *
 *   3. **Iterates terminate the spine at their boundary.** State edges
 *      connect DFS-consecutive leaves at the same scope; groups are
 *      transparent (DFS through); iterates open a separate scope for
 *      their body (per-iteration chain emitted by recursion) AND have
 *      the parent spine STOP at their boundary on both sides. Concretely:
 *      `[A, B, iter, C, D]` at root scope emits only `A→B` and `C→D`;
 *      no `B→iter`, no `iter→C`, no bridging `B→C`. The aux arrows
 *      (`blocksFromAux` coming in, `outBlocksAux` going out) ARE the
 *      handoff at this boundary; the spine has nothing to add because
 *      the runtime overwrites state from aux at iteration entry and
 *      publishes the per-iteration output into aux at iteration exit.
 *      Surfaced 2026-05-17: the previously-rendered phantom `compute-
 *      block-count → ecb-blocks` state edge resolved to the plaintext
 *      bytes (compute-block-count's passthrough stateAfter), which the
 *      iterate doesn't actually consume — confusing pedagogically. See
 *      `inferStateEdges`'s function-level docstring for the full
 *      design decision and the iterate-suppression invariant.
 *
 *      **Feistel future**: when a Feistel-style cipher with branching
 *      state lands, the "DFS-consecutive leaves share state" assumption
 *      breaks (left/right halves evolve independently inside a round).
 *      Both this derivation-time inference AND any future runtime-recorded
 *      state lineage need revisiting then.
 *
 * Note on `rootIds`: the plan's `rootContainers: ContainerNode[]` would lose
 * top-level leaves (e.g. `aes128EcbSpec` has `key-expansion`, `split-blocks`,
 * `compute-block-count`, the iterate, AND `concat-blocks` at the top level).
 * `rootIds: string[]` is a conscious deviation — it preserves leaf-and-
 * container interleave at the root.
 */

import { canonicalStepId } from "./step-id";
import type {
  CipherSpec,
  FeistelRoundGroup,
  IterateGroup,
  StateShape,
  StepNode,
  Trace,
} from "./types";

// ─── Public types ─────────────────────────────────────────────────────────

export type GraphNode = {
  /** Canonical step id with any `:b{i}` iteration suffix stripped. */
  readonly stepId: string;
  readonly stepType: string;
  /** Short human-readable label. Today = stepId; renderers can prettify. */
  readonly label: string;
  /** Ancestor container ids, root-first. Matches `TraceFrame.path` order. */
  readonly containerPath: readonly string[];
  /**
   * Number of iterations this leaf was replicated across (undefined if the
   * leaf is outside any iterate, or the iterate had zero iterations).
   */
  readonly blockSpan?: number;
  /**
   * Set on replica nodes produced by `replicateHighFanoutSources`: the
   * canonical stepId this replica points at. The renderer routes clicks
   * through this so a replica still scrubs to the source's trace frame.
   * Undefined for the original (non-replica) nodes.
   */
  readonly replicaOf?: string;
  /**
   * Synthetic-endpoint marker (Slice 1 of the graph-narrative plan).
   * Set to `"input"` on the plaintext / ciphertext pill at the canvas's
   * left edge; `"output"` on the pill at the right edge. Undefined for
   * every ordinary leaf and for every replica.
   *
   * Endpoint pills are NOT spec nodes — they don't round-trip through
   * Save/Share, they aren't drop-anchored, they aren't click-scrubbable,
   * they aren't deletable. They exist only to make the cipher's I/O
   * self-evident on the canvas.
   */
  readonly endpointSide?: "input" | "output";
  /**
   * Block-chip marker (Slice 6 of the graph-narrative plan). When set,
   * this node is one of N synthetic chips representing a single block
   * iteration of the collapsed iterate identified by this field. The
   * value is the iterate container's id — used by the renderer to
   * route clicks back to a sensible scrub target (currently a no-op,
   * matching today's "click a collapsed iterate chip" behavior).
   *
   * Why a separate field from `replicaOf`: aux replicas use the
   * `isReplica` machinery in `GraphView`'s layout passes to be
   * auto-positioned ABOVE their consumer. Block chips need to lay out
   * NORMALLY in the rootIds sequence at the iterate's old slot — they
   * can't share `replicaOf` without also being pulled into that auto-
   * placement loop. Keeping the marker distinct keeps the layout
   * machinery untouched while still letting the renderer suppress
   * drag/delete/drop the same way it does for replicas.
   *
   * Block chips are NOT spec nodes — they don't round-trip through
   * Save/Share, they aren't drop-anchored as their own ids, they
   * aren't draggable, they don't accept Delete. The user's
   * "expand the iterate" action restores the original chip.
   */
  readonly blockChipOf?: string;
  /**
   * Synthetic-node marker for `feistel-round` containers (Phase 2 +
   * Phase 6b-ii of the DES + branching primitive plan).
   *
   *   - `"rejoin"` — combine-step chip at the round's bottom/right
   *     edge. Frame: yes (runtime emits one with the 4-arg snapshots
   *     in params). StepId: `{roundId}:rejoin`. Click scrubs to the
   *     rejoin frame + opens the 4-arg inspector.
   *   - `"passthrough"` — per-track stand-in for an EMPTY track
   *     (Phase 6b-ii). Frame: no — the passthrough is the identity
   *     (`L_in === L_out`); emitting a frame would carry zero new
   *     information at ×16 cost per DES run. StepId:
   *     `{roundId}:passthrough-{trackIdx}` (trackIdx, not name, so
   *     N-way Feistel scales cleanly; `feistelTrackNames[trackIdx]`
   *     supplies the human label). Click scrubs to the round's
   *     rejoin frame (the nearest semantic anchor) + opens the
   *     inspector. **Why id-bearing instead of pure-visual** (user
   *     pick 2026-05-20): Phase 6d's per-track drop gutters get a
   *     natural anchor, the chip is hoverable/clickable for
   *     provenance like any other leaf, and the L track IS a real
   *     algorithmic step (it carries `L_in` through the round).
   *
   * Why a separate discriminator (analogous to `endpointSide` and
   * `blockChipOf`): synthetic chips render differently (no
   * `data-drop-anchor`, no DeleteGlyph, no drag, no warnings overlay),
   * is not click-deletable, click-routing dispatches off the marker.
   * Widening from `"rejoin"` to `"rejoin" | "passthrough"` in Phase
   * 6b-ii — audit `synthetic === "rejoin"` checks before adding
   * passthrough-specific behavior.
   */
  readonly synthetic?: "rejoin" | "passthrough";
  /**
   * Spine-replica marker (replica-scope-aware-layout fix, 2026-05-17).
   * Set ONLY on the (source, spineSuccessor) replica produced by
   * `replicateHighFanoutSources` — i.e. the single replica per
   * fully-replicated source whose outgoing edge carries the state
   * spine through the now-removed source. False/undefined on every
   * non-replica node AND on aux-fan-out replicas (`${src}@->${c}` for
   * c ≠ spineSuccessor).
   *
   * **Why a flag separate from `replicaOf`**: the spine-replica's
   * pedagogical role is "stand-in for the removed source on the main
   * canvas row" — it should NOT be lifted above its consumer like an
   * aux-fan-out replica. The flag tells `GraphView`'s layout passes
   * to FLOW the chip as a regular leaf at the source's old spec slot
   * instead of stacking it in the lift gutter above the consumer.
   * `replicaOf` stays set so the renderer still applies replica
   * styling (chip background, hover-source highlight) and click
   * routes through to the source's trace frame.
   *
   * Slice 7b context: every fully-replicated source produces both a
   * spine-replica AND zero-or-more aux-fan-out replicas. Pre-fix all
   * replicas of a source clumped into a single column above the
   * leftmost shared consumer row (e.g. AES-128 ECB + key-expansion
   * always + collapsed iterate showed `key-expansion@->split-blocks`
   * (state-spine) clumped with `key-expansion@->{chip0..N}` (aux
   * fan-out) at the canvas top); this flag pulls the spine-replica
   * out of that column so the eye reads spine and aux as distinct
   * dataflows.
   *
   * Narrow scope by design: only ONE replica per source carries the
   * flag (the spineSuccessor's replica). Aux-fan-out replicas keep
   * their current consumer-anchored placement — the user explicitly
   * picked the NARROW interpretation when offered narrow-vs-broad.
   */
  readonly isSpineReplica?: true;
};

export type ContainerNode = {
  /**
   * Container shape discriminator:
   *   - `"group"` — transparent labeled wrapper (e.g. AES "Round 3"). DFS
   *     is transparent; the spine threads through.
   *   - `"iterate"` — multi-block replicator (ECB/CBC iterate). Spine
   *     terminates at the boundary; per-iteration body chain emitted
   *     separately. Aux-mediated handoff via `blocksFromAux` / `outBlocksAux`.
   *   - `"feistel"` — Feistel branching primitive. The single `childIds`
   *     list combines the round's direct children: each track's first
   *     child appears (in track order), interleaved as the renderer will
   *     stack them. Track membership is preserved by `feistelTracks` below.
   *     Spine fans into N edges (one per track first leaf); rejoin
   *     synthetic node is `{id}:rejoin` and exits the spine forward.
   */
  readonly kind: "group" | "iterate" | "feistel";
  readonly id: string;
  readonly label: string;
  /** Ancestor container ids, root-first (excludes this container itself). */
  readonly containerPath: readonly string[];
  /** Direct children's ids (leaves and nested containers, in spec order). */
  readonly childIds: readonly string[];
  /** Iterate's iteration count from the trace (undefined for groups). */
  readonly blockSpan?: number;
  /**
   * Per-track child-id lists, set on `kind === "feistel"` containers only.
   * `feistelTracks[t]` is the ordered list of stepIds/container-ids that
   * live inside track `t` in spec order. The flat `childIds` (above)
   * concatenates these for renderer code that doesn't care about tracks
   * (e.g. drop-anchor numbering). Phase 2 ships 2-track Feistel; a future
   * 4-way Twofish would set `feistelTracks.length === 4`.
   */
  readonly feistelTracks?: readonly (readonly string[])[];
  /** Per-track `BranchTrack.name` (or stringified index) for renderer use. */
  readonly feistelTrackNames?: readonly string[];
  /** `CombineKind` string for `kind === "feistel"` containers; undefined elsewhere. */
  readonly feistelCombineKind?: string;
};

/**
 * Edge classification.
 *
 *   - `"aux"`: a value flowing through `frame.auxRead` / `auxWritten` — round
 *     keys, S-box, IV, keystream, etc. Annotations on the cipher's dataflow.
 *   - `"state"`: the implicit `(state, params) → state` thread through
 *     consecutive same-parent leaves. Inferred from spec structure (no aux
 *     entry carries it). Renderer treats these as the SPINE — thicker,
 *     darker, less translucent — so the eye reads the cipher's dataflow
 *     before the round-key fan-out annotations.
 *
 * Today's `deriveAuxGraph` only produces `"aux"` edges; commit-2 of this
 * sequence adds state-edge inference. The field exists already so the
 * renderer's marker/styling work in commit 1 has a stable hook.
 */
export type EdgeKind = "aux" | "state";

export type GraphEdge = {
  /** Producer id (a leaf's stepId, or an iterate container's id). */
  readonly from: string;
  /** Consumer id (a leaf's stepId, or an iterate container's id). */
  readonly to: string;
  /** Aux key that flows along this edge. For `kind: "state"` this is
   * the sentinel `"state"`. */
  readonly auxKey: string;
  /** Edge classification — see EdgeKind. */
  readonly kind: EdgeKind;
};

export type CipherGraph = {
  readonly nodes: readonly GraphNode[];
  readonly containers: readonly ContainerNode[];
  readonly edges: readonly GraphEdge[];
  /**
   * Ordered ids of top-level children of the spec (mix of leaf stepIds and
   * container ids). Renderers walk this for the root layer; each container's
   * `childIds` gives nesting from there.
   */
  readonly rootIds: readonly string[];
};

// ─── Edge bundling (visual decongestion at render time) ───────────────────

/**
 * A group of edges that share the same `(from, to, kind, isFeedback)` tuple,
 * collapsed for rendering. The motivation is the AES-128 key-expansion case:
 * after `replicateHighFanoutSources` produces a local chip, that chip emits
 * one aux edge per consumed round key — 11 distinct `auxKey`s flowing
 * `key-expansion@->iterate → iterate`. Pre-bundling, that's 11 parallel
 * arrows fanning into the iterate's top edge; users read the visual as noise
 * even though every edge is semantically correct.
 *
 * Why the key includes `isFeedback`: the dashed iterate-feedback style
 * applies to the WHOLE rendered edge, not per-auxKey. A bundle containing
 * mixed feedback flags would have to either render half-dashed (visually
 * confusing) or pick a winner (silently lossy). No spec today produces
 * mixed-feedback same-pair edges, but the invariant is cheap to maintain
 * and prevents a future Feistel/AEAD surprise.
 *
 * Singleton bundles (`auxKeys.length === 1`) are the common case — the
 * threshold for "bundle decoration" (thicker stroke + ×N label) is
 * `auxKeys.length >= 2`, applied at render time. The bundling pass itself
 * is uniform across N=1 and N>1 so renderers walk a single list and the
 * data-edge-key format stays consistent.
 */
export type EdgeBundle = {
  readonly from: string;
  readonly to: string;
  readonly kind: EdgeKind;
  readonly isFeedback: boolean;
  /**
   * All aux keys flowing on this edge group, in encounter order from the
   * source graph. For state-kind bundles the value is `["state"]` (the
   * sentinel auxKey on state edges — `GraphEdge.auxKey` docs).
   */
  readonly auxKeys: readonly string[];
  /**
   * A `GraphEdge` carrying this bundle's `(from, to, kind)` and
   * `auxKeys[0]`. Used by render-time helpers that key off edge
   * IDENTITY (port-spreading's `slotOf`, replica-row lookups) — those
   * helpers were written for the pre-bundle world and look up by
   * `GraphEdge` reference, so passing them a bundle requires a stable
   * representative to consult. The renderer also builds the port
   * assignment from these representatives, NOT from `graph.edges`, so
   * each bundle counts as one incoming edge at its consumer (correctly
   * centering an 11-auxKey bundle that pre-bundling would spread across
   * 11 slots).
   */
  readonly representativeEdge: GraphEdge;
};

/**
 * A `CipherGraph` view with same-(from, to, kind, isFeedback) aux edges
 * collapsed into `EdgeBundle`s. State edges pass through as singleton
 * bundles (each spec-derived spine edge has exactly one between any two
 * leaves), so the renderer can walk one list — there's no second pass
 * over the raw `edges` array.
 *
 * The original `edges` field is preserved unchanged so callers that index
 * by raw GraphEdge identity (`validateGraph`, the spec-shape validator,
 * any future test fixture) continue to work without rewrite.
 */
export type BundledGraph = {
  readonly nodes: readonly GraphNode[];
  readonly containers: readonly ContainerNode[];
  /** Same edges as the source graph, untouched. */
  readonly edges: readonly GraphEdge[];
  /** Bundled view of `edges` for the renderer. */
  readonly bundles: readonly EdgeBundle[];
  readonly rootIds: readonly string[];
};

/**
 * Collapse same-`(from, to, kind, isFeedback)` edges into `EdgeBundle`s.
 * Pure — no I/O, deterministic.
 *
 * @param graph - the input graph (typically post-`replicateHighFanoutSources`,
 *   so the bundling sees the replica chip's outgoing fan-out rather than the
 *   pre-replication "one source, N consumers" case).
 * @param isFeedback - predicate from `buildIterateFeedbackPredicate(graph)`.
 *   Threaded as a parameter (rather than computed inside) so the renderer
 *   can build the predicate once per graph and reuse it; also keeps this
 *   function easy to unit-test with a stub.
 *
 * Encounter order is preserved both BETWEEN bundles (first-edge-encounter
 * order in the source `edges` array) AND WITHIN each bundle's `auxKeys`
 * (same encounter order). For aux edges originating from
 * `key-expansion@->initial.add-round-key` the result is
 * `["roundKey.0", "roundKey.1", ..., "roundKey.10"]`, which the inspector
 * panel renders as a stable, human-readable list.
 */
export const bundleEdges = (
  graph: CipherGraph,
  isFeedback: (edge: GraphEdge) => boolean,
): BundledGraph => {
  const bundleKey = (e: GraphEdge, fb: boolean): string =>
    // `\0` separator is safe — no spec id contains a null byte.
    `${e.from}\0${e.to}\0${e.kind}\0${fb ? "1" : "0"}`;

  const bundles: EdgeBundle[] = [];
  const byKey = new Map<string, { bundle: EdgeBundle; auxKeys: string[] }>();

  for (const edge of graph.edges) {
    const fb = isFeedback(edge);
    const key = bundleKey(edge, fb);
    const existing = byKey.get(key);
    if (existing) {
      existing.auxKeys.push(edge.auxKey);
      continue;
    }
    // Fresh bundle. `auxKeys` is a mutable working array; we replace the
    // bundle with a frozen-by-readonly view at the end of the pass.
    const auxKeys: string[] = [edge.auxKey];
    // For singletons, reuse the source GraphEdge as the representative so
    // any caller that was passing the raw edge in pre-bundling still
    // sees IDENTITY-stable references. For multi-edge bundles we'd
    // happily synthesize one, but since `auxKeys[0]` already matches
    // this first edge by construction, reusing it is cheaper and keeps
    // ports / inspector keys identical to the pre-bundle path when N=1.
    const bundle: EdgeBundle = {
      from: edge.from,
      to: edge.to,
      kind: edge.kind,
      isFeedback: fb,
      auxKeys,
      representativeEdge: edge,
    };
    bundles.push(bundle);
    byKey.set(key, { bundle, auxKeys });
  }

  return {
    nodes: graph.nodes,
    containers: graph.containers,
    edges: graph.edges,
    bundles,
    rootIds: graph.rootIds,
  };
};

// ─── Synthetic endpoint pills (Slice 1) ───────────────────────────────────

/**
 * Canonical id of the plaintext-side endpoint pill. Held as a single
 * exported constant so consumers (renderer, test fixtures, validators) all
 * agree on the spelling. The leading + trailing `__` and the `cipher_`
 * prefix are chosen so the id can't collide with any spec id (spec ids
 * use lowercase + dots + dashes only) and so a future grep for
 * `__cipher_` finds every site that participates in endpoint handling.
 */
export const CIPHER_INPUT_ID = "__cipher_input__";
/** Canonical id of the ciphertext-side endpoint pill. See `CIPHER_INPUT_ID`. */
export const CIPHER_OUTPUT_ID = "__cipher_output__";
/** Sentinel `stepType` set on synthetic endpoint nodes. Never registered in
 *  the step registry — the renderer dispatches off `endpointSide` instead. */
const ENDPOINT_STEP_TYPE = "__endpoint__";

/** True iff `id` is one of the two synthetic endpoint pills. Cheap branch
 *  test reused by `buildIterateFeedbackPredicate` and `validateGraph` to
 *  short-circuit any edge that touches a pill. */
export const isEndpointId = (id: string): boolean =>
  id === CIPHER_INPUT_ID || id === CIPHER_OUTPUT_ID;

// ─── Feistel passthrough synthetic (Phase 6b-ii) ───────────────────────

/** Sentinel `stepType` set on synthetic passthrough nodes. Never registered
 *  in the step registry — the renderer dispatches off `synthetic === "passthrough"`
 *  instead. Mirrors `__rejoin__` and `__endpoint__`. */
const PASSTHROUGH_STEP_TYPE = "__passthrough__";

/**
 * Canonical synthetic id for an empty-track passthrough chip inside a
 * `feistel-round`. Shared by `walkSpec` (which materializes the node into
 * `ctx.nodes` + the per-track child list) and `processFeistelRound`
 * (which routes `predecessor → passthrough → rejoin` edges through it).
 * Centralizing here keeps both producers + edge-emitters agreeing on
 * the spelling — and a future Twofish-style N-way Feistel scales by
 * `trackIdx` (0/1/2/3) rather than re-encoding track names.
 */
export const feistelPassthroughId = (roundId: string, trackIdx: number): string =>
  `${roundId}:passthrough-${trackIdx}`;

// ─── Internal helpers ──────────────────────────────────────────────────────

/**
 * Strip the runtime's `:b<digits>` per-iteration suffix from a step id.
 * Phase 2 of the DES + branching primitive plan extended frame stepIds
 * with two more suffix families (`:t{name}` for track membership inside
 * a `feistel-round`, `:rejoin` for synthetic rejoin frames). The full
 * canonicalization lives in `@/core/step-id`; this thin wrapper preserves
 * the local name for the dedup call sites below.
 */
const stripBlockSuffix = (stepId: string): string => canonicalStepId(stepId);

type BuildContext = {
  readonly nodes: GraphNode[];
  readonly containers: ContainerNode[];
  /** All iterate definitions indexed by id, for the edge-synthesis pass. */
  readonly iteratesById: Map<string, IterateGroup>;
  /**
   * All feistel-round definitions indexed by id, for state-spine inference
   * + rejoin-synthetic placement. Phase 2 addition.
   */
  readonly feistelsById: Map<string, FeistelRoundGroup>;
  /** Canonical leaf stepIds indexed for blockSpan annotation. */
  readonly leafIndex: Map<string, number>;
  /** Iterate-container indices, also for blockSpan annotation. */
  readonly containerIndex: Map<string, number>;
};

/**
 * Walk the spec recursively to materialize the structural tree. Produces:
 *   - one GraphNode per leaf (`:b{i}` is irrelevant; spec ids never carry it)
 *   - one ContainerNode per group / iterate
 *   - the iteratesById map for the edge-synthesis pass
 *   - childIds lists on each container, preserving spec order
 *   - rootIds (returned to the caller separately)
 */
const walkSpec = (
  nodes: readonly StepNode[],
  containerPath: readonly string[],
  ctx: BuildContext,
): string[] => {
  const childIds: string[] = [];

  for (const node of nodes) {
    if (node.kind === "step") {
      const idx = ctx.nodes.length;
      ctx.leafIndex.set(node.id, idx);
      ctx.nodes.push({
        stepId: node.id,
        stepType: node.type,
        label: node.id,
        containerPath,
      });
      childIds.push(node.id);
      continue;
    }

    // feistel-round: own branch — walks per-track children and adds a
    // synthetic rejoin node inside the container's scope. Track membership
    // is preserved on the ContainerNode via `feistelTracks`.
    //
    // Phase 6b-ii: empty tracks (DES's L track in every round, today) get
    // a per-track synthetic passthrough node injected into the track's
    // child list. The passthrough is id-bearing (`{roundId}:passthrough-{trackIdx}`)
    // so subsequent passes (layout, render, edge-routing) treat it like
    // any other leaf — `processFeistelRound`'s `predecessor → passthrough
    // → rejoin` chain replaces the prior `predecessor → rejoin` shortcut,
    // so the L column's "carries L_in through unchanged" role becomes a
    // first-class graph entity instead of being implicit in the edge skip.
    // Passthrough nodes have no trace frame (the identity adds zero info);
    // the renderer's click handler scrubs to the rejoin frame as the
    // nearest semantic anchor.
    if (node.kind === "feistel-round") {
      const nestedPath = [...containerPath, node.id];
      const perTrackChildIds: string[][] = [];
      const flatChildIds: string[] = [];
      node.tracks.forEach((track, trackIdx) => {
        const trackChildren = walkSpec(track.children, nestedPath, ctx);
        if (trackChildren.length === 0) {
          // Empty track — synthesize a passthrough chip so the L
          // column reads as "carries L_in through unchanged" instead
          // of empty space. Layout treats it as a regular leaf in
          // the column.
          const ptId = feistelPassthroughId(node.id, trackIdx);
          ctx.nodes.push({
            stepId: ptId,
            stepType: PASSTHROUGH_STEP_TYPE,
            label: ptId,
            containerPath: nestedPath,
            synthetic: "passthrough",
          });
          trackChildren.push(ptId);
        } else if (trackIdx === 1 && node.combineKind === "feistel-standard") {
          // UX-D candidate (b), 2026-05-22 — populated R-track in a
          // `feistel-standard` round (DES rounds 1..15) gets a PARALLEL
          // passthrough chip at the head of the R-column, representing
          // R_in flowing unchanged to the rejoin alongside the F-stack.
          // The chip is the visual anchor for the Feistel SWAP
          // (`new_L = R_in`): a clickable element labelled with R_in's
          // bytes, two outgoing arrows (one to expand-R / the F-stack,
          // one directly to rejoin) that show R_in's two destinations.
          //
          // Candidate (a) — synthesize an arrow expand-R → rejoin — was
          // tried first (commit `83502de`) and reverted because the
          // arrow visually suggested expand-R PRODUCED R_in, whereas
          // expand-R CONSUMES it (and produces E(R)). The chip moves
          // the arrow's origin off expand-R, restoring "R_in flows to
          // rejoin" as the pedagogy without putting it on top of the
          // wrong node.
          //
          // We reuse the empty-track chip's id (`:passthrough-1`) and
          // synthetic kind. Semantically the chip represents the same
          // thing in both cases — R_in carried unchanged. The
          // `lookupPassthroughBytes` regex in edge-value-lookup keys
          // off `:passthrough-(\d+)` and maps trackIdx 1 → `R_in` from
          // the rejoin frame's params, so the chip's value lookup
          // works for free in either case. (No id collision is
          // possible: only one branch fires per round — empty track
          // produces the chip via the IF above, populated track
          // produces it via this ELSE IF.)
          //
          // The chip is NOT added to `trackChildren` (and therefore
          // NOT in the spec walker's view of the R-track), so the
          // chain edges in `processFeistelRound` still run
          // predecessor → expand-R → … → p-permute → rejoin
          // unchanged. The chip's edges are emitted by
          // `processFeistelRound` separately, gated on the same
          // (combineKind, R-track populated) condition. We DO
          // prepend the chip to `perTrackChildIds[1]` so the
          // renderer lays it out at the top of the R-column;
          // `feistelTracks[1]` becomes `[chip, expand-R, …]`.
          const rBypassId = feistelPassthroughId(node.id, 1);
          ctx.nodes.push({
            stepId: rBypassId,
            stepType: PASSTHROUGH_STEP_TYPE,
            label: rBypassId,
            containerPath: nestedPath,
            synthetic: "passthrough",
          });
          trackChildren.unshift(rBypassId);
        }
        perTrackChildIds.push(trackChildren);
        flatChildIds.push(...trackChildren);
      });

      // Rejoin synthetic node — clickable for the 4-arg inspector;
      // NOT a spec leaf. Lives inside the round container's scope so
      // collapse/expand pulls it along with the round.
      const rejoinId = `${node.id}:rejoin`;
      ctx.nodes.push({
        stepId: rejoinId,
        stepType: "__rejoin__",
        label: rejoinId,
        containerPath: nestedPath,
        synthetic: "rejoin",
      });
      flatChildIds.push(rejoinId);

      ctx.feistelsById.set(node.id, node);
      const cIdx = ctx.containers.length;
      ctx.containerIndex.set(node.id, cIdx);
      ctx.containers.push({
        kind: "feistel",
        id: node.id,
        label: node.label ?? node.id,
        containerPath,
        childIds: flatChildIds,
        feistelTracks: perTrackChildIds,
        feistelTrackNames: node.tracks.map((t, i) => t.name ?? String(i)),
        feistelCombineKind: node.combineKind,
      });
      childIds.push(node.id);
      continue;
    }

    // group or iterate: descend with this node's id appended to the path.
    const nestedPath = [...containerPath, node.id];
    const grandChildIds = walkSpec(node.children, nestedPath, ctx);

    if (node.kind === "iterate") {
      ctx.iteratesById.set(node.id, node);
      const cIdx = ctx.containers.length;
      ctx.containerIndex.set(node.id, cIdx);
      ctx.containers.push({
        kind: "iterate",
        id: node.id,
        label: node.label ?? node.id,
        containerPath,
        childIds: grandChildIds,
      });
    } else {
      ctx.containers.push({
        kind: "group",
        id: node.id,
        label: node.label,
        containerPath,
        childIds: grandChildIds,
      });
    }
    childIds.push(node.id);
  }

  return childIds;
};

/**
 * Walk the trace and build edges. Two kinds:
 *
 *   - **Natural aux edges.** For each frame, every `auxRead` key is an
 *     incoming edge from the most-recent frame that wrote that key
 *     (`writerByAuxKey`). We canonicalize stepIds (strip `:b{i}`) and dedup
 *     by the full `(from, to, auxKey)` triple — so iteration replicas
 *     collapse into one edge per logical pair.
 *
 *   - **Iterate-mediated edges.** On entry into iterate `I` (first frame
 *     whose `path` contains `I.id` after a frame that did not), we emit
 *     edges for `countFromAux` and `blocksFromAux` from their producers to
 *     `I.id`. On exit (first frame outside `I` after frames inside), we set
 *     `writerByAuxKey[I.outBlocksAux] = I.id` so the next frame that reads
 *     it (typically `concat-blocks`) gets a natural edge from `I.id`.
 */
const deriveEdges = (trace: Trace, ctx: BuildContext): GraphEdge[] => {
  const writerByAuxKey = new Map<string, string>();
  const seenEdgeKeys = new Set<string>();
  const edges: GraphEdge[] = [];

  // All edges produced by trace-walking are aux flows. State edges
  // (the implicit per-leaf state thread) are synthesized in a separate
  // pass - see commit 2 of this sequence.
  const addEdge = (from: string, to: string, auxKey: string): void => {
    const dedupKey = `aux ${from} ${to} ${auxKey}`;
    if (seenEdgeKeys.has(dedupKey)) return;
    seenEdgeKeys.add(dedupKey);
    edges.push({ from, to, auxKey, kind: "aux" });
  };

  // Per-iterate body tracking for the structural-feedback synthesis pass
  // below. As the trace walk visits each frame, we record which canonical
  // stepIds wrote / read each aux key WHILE the frame was inside that
  // iterate. After the walk completes, we cross-reference: any (writer,
  // reader) pair in the same iterate that share an auxKey AND where the
  // writer comes AFTER the reader in body spec order is a cross-iteration
  // feedback dependency. If the trace had ≥ 2 iterations the natural-edge
  // pass already emitted it (via `writerByAuxKey` at iteration N's end →
  // iteration N+1's read); if the trace had only 1 iteration the natural
  // pass never sees the cross-iteration handoff and the edge is missing.
  // Synthesizing it from body topology restores parity between 1-block
  // and N-block traces — pedagogically critical for CBC/OFB/CFB/CTR demos
  // where the default 16-byte plaintext rounds to exactly one iteration.
  // See the `// ─── Cross-iteration feedback synthesis ───` block below.
  const bodyWritersByIterate = new Map<string, Map<string, Set<string>>>();
  const bodyReadersByIterate = new Map<string, Map<string, Set<string>>>();

  let prevIterateIdsInPath: ReadonlySet<string> = new Set();

  for (const frame of trace.frames) {
    // Snapshot which iterate containers the current frame lives inside.
    // Filtering against iteratesById keeps plain `group` ids out of the set.
    const currentIterateIdsInPath = new Set<string>();
    for (const id of frame.path) {
      if (ctx.iteratesById.has(id)) currentIterateIdsInPath.add(id);
    }

    // Iterate entry: emit count + blocks edges from their current writers.
    // (These two reads are performed by the runtime itself in runtime.ts,
    // not by any leaf, so they have no frame to carry them.)
    for (const iid of currentIterateIdsInPath) {
      if (prevIterateIdsInPath.has(iid)) continue;
      const iter = ctx.iteratesById.get(iid);
      if (!iter) continue;
      for (const auxKey of [iter.countFromAux, iter.blocksFromAux]) {
        const producer = writerByAuxKey.get(auxKey);
        if (producer !== undefined) addEdge(producer, iid, auxKey);
      }
    }

    // Iterate exit: stamp the iterate as the writer of its outBlocksAux so
    // the next frame's auxRead picks up a natural edge from `iid → reader`.
    for (const iid of prevIterateIdsInPath) {
      if (currentIterateIdsInPath.has(iid)) continue;
      const iter = ctx.iteratesById.get(iid);
      if (!iter) continue;
      writerByAuxKey.set(iter.outBlocksAux, iid);
    }

    prevIterateIdsInPath = currentIterateIdsInPath;

    // Natural aux flow for this leaf frame.
    const consumer = stripBlockSuffix(frame.stepId);
    for (const auxKey of frame.auxRead.keys()) {
      const producer = writerByAuxKey.get(auxKey);
      if (producer !== undefined) addEdge(producer, consumer, auxKey);
    }
    for (const auxKey of frame.auxWritten.keys()) {
      writerByAuxKey.set(auxKey, consumer);
    }

    // Body-tracking for the cross-iteration feedback-synthesis pass below.
    // Mark this frame's writes and reads under EACH iterate ancestor it
    // currently lives in (nested iterates accumulate independently). The
    // canonical stepId (`consumer`, already post-`:b{i}`-strip) collapses
    // multiple iterations of the same body step to one set entry — exactly
    // what the post-pass pair-up wants.
    if (currentIterateIdsInPath.size > 0) {
      for (const iid of currentIterateIdsInPath) {
        let writersMap = bodyWritersByIterate.get(iid);
        if (writersMap === undefined) {
          writersMap = new Map();
          bodyWritersByIterate.set(iid, writersMap);
        }
        let readersMap = bodyReadersByIterate.get(iid);
        if (readersMap === undefined) {
          readersMap = new Map();
          bodyReadersByIterate.set(iid, readersMap);
        }
        for (const auxKey of frame.auxWritten.keys()) {
          let writerSet = writersMap.get(auxKey);
          if (writerSet === undefined) {
            writerSet = new Set();
            writersMap.set(auxKey, writerSet);
          }
          writerSet.add(consumer);
        }
        for (const auxKey of frame.auxRead.keys()) {
          let readerSet = readersMap.get(auxKey);
          if (readerSet === undefined) {
            readerSet = new Set();
            readersMap.set(auxKey, readerSet);
          }
          readerSet.add(consumer);
        }
      }
    }
  }

  // Drain still-active iterates at trace end. No more frames to read their
  // outBlocksAux, so this is a no-op for edge count today — but it keeps
  // writerByAuxKey in a sane state if a future caller chains derivations.
  for (const iid of prevIterateIdsInPath) {
    const iter = ctx.iteratesById.get(iid);
    if (!iter) continue;
    writerByAuxKey.set(iter.outBlocksAux, iid);
  }

  // ─── Cross-iteration feedback synthesis ──────────────────────────────────
  // For each iterate whose body the trace visited, look for `(writer, reader)`
  // pairs that share an aux key AND where the writer comes AFTER the reader
  // in body spec order. That's the structural fingerprint of cross-iteration
  // feedback (e.g. CBC's `cbc-snapshot → cbc-xor` on `chain`): the writer at
  // end-of-body provides the value the reader at start-of-body consumes on
  // the next iteration. When the trace has ≥ 2 iterations the natural-edge
  // pass already emits this edge (and `addEdge`'s dedup turns synthesis into
  // a no-op); when the trace has only 1 iteration the natural pass never
  // sees the handoff, so the edge would be missing without this synthesis —
  // breaking BOTH the renderer's feedback arc AND `validateGraph`'s
  // unused-write check (which sees the writer with no `(writer, key)` entry
  // in `producerEdges` and emits a false-positive warning).
  //
  // **Determinism.** We walk `iteratesById` in insertion order (a `Map`
  // preserves insertion order in JS), which mirrors `walkSpec`'s DFS spec
  // order. Inside each iterate we walk its `children` recursively in spec
  // order so `bodyOrder` is also deterministic. Pair iteration uses two
  // nested `for…of` over `Set`s — Set iteration order is insertion order,
  // and we inserted entries in trace-frame order, which is the natural
  // chronological order for the cipher under test. Synthesized edges land
  // at the end of the `edges` array, AFTER all natural edges; downstream
  // code that depends on edge order (bundling first-encounter, port-
  // assignment row sort) will see them last, which keeps them out of the
  // "first occurrence wins" slot competitions.
  //
  // **The synthesized edge is plain `kind: "aux"`** — `isFeedback` is
  // stamped by `buildIterateFeedbackPredicate` (called from the bundling
  // pass and from `validateGraph`'s cycle filter); that predicate already
  // returns `true` for any aux edge whose endpoints share a deepest-common
  // iterate AND go backwards in spec order, which is exactly the shape we
  // synthesize here. No isFeedback work needed at this site.
  if (bodyWritersByIterate.size > 0) {
    for (const [iid, writersMap] of bodyWritersByIterate) {
      const readersMap = bodyReadersByIterate.get(iid);
      if (readersMap === undefined || readersMap.size === 0) continue;
      const iter = ctx.iteratesById.get(iid);
      if (iter === undefined) continue;
      // Pre-order DFS spec position INSIDE this iterate's body. We index
      // leaves (which is what shows up in `writersMap` / `readersMap` —
      // post-`stripBlockSuffix` consumer ids) plus nested iterate ids
      // (so a writer/reader that's an inner iterate's `outBlocksAux`
      // pseudo-id participates in ordering correctly). Containers that
      // aren't iterates don't appear in writersMap/readersMap, so the
      // simpler "leaves + iterates only" position map is sufficient.
      const bodyOrder = new Map<string, number>();
      let nextOrder = 0;
      const walkBody = (children: readonly StepNode[]): void => {
        for (const child of children) {
          if (child.kind === "step") {
            bodyOrder.set(child.id, nextOrder++);
          } else if (child.kind === "feistel-round") {
            // Feistel-round inside an iterate body — assign the round's id
            // a position, then descend through each track's children so
            // any leaf within either track gets ordering relative to the
            // rest of the body (matters when a future track reads /
            // writes an aux key the body cares about).
            bodyOrder.set(child.id, nextOrder++);
            for (const track of child.tracks) walkBody(track.children);
          } else {
            // group or iterate — assign the container id a position too
            // (only iterates surface in the read/write maps via the
            // outBlocksAux stamp, but assigning groups doesn't hurt and
            // keeps the walk symmetric with `walkSpec`).
            bodyOrder.set(child.id, nextOrder++);
            walkBody(child.children);
          }
        }
      };
      walkBody(iter.children);
      // Pair up writers × readers per shared aux key; emit a feedback edge
      // where the writer comes after the reader in body order. The
      // `addEdge` dedup means a 2-block (or longer) trace's natural edge
      // is preserved unchanged — synthesis is purely additive for the
      // 1-iteration case.
      for (const [auxKey, writerSet] of writersMap) {
        const readerSet = readersMap.get(auxKey);
        if (readerSet === undefined || readerSet.size === 0) continue;
        for (const writer of writerSet) {
          const writerOrder = bodyOrder.get(writer);
          if (writerOrder === undefined) continue;
          for (const reader of readerSet) {
            if (reader === writer) continue;
            const readerOrder = bodyOrder.get(reader);
            if (readerOrder === undefined) continue;
            if (writerOrder > readerOrder) {
              addEdge(writer, reader, auxKey);
            }
          }
        }
      }
    }
  }

  return edges;
};

/** Sentinel aux key carried on every state edge. Real aux keys never
 * collide with this value (they come from step `auxWrites` and are
 * domain-specific — "roundKey.0", "blockCount", "input-blocks", etc.). */
const STATE_AUX_KEY = "state";

/**
 * Spec-walk pass: emit a `kind: "state"` edge between every DFS-consecutive
 * pair of sibling leaves within the same iterate-scope.
 *
 * Scope rules:
 *   - **Filled groups are transparent.** DFS descends into them and their
 *     leaves join the parent scope's spine. The spine therefore crosses
 *     round-group boundaries (e.g. `round.1.add-round-key →
 *     round.2.sub-bytes`) — exactly the pedagogical "the cipher's primary
 *     dataflow runs through every round in order" story.
 *   - **Empty groups participate in the spine as nodes.** A group whose
 *     subtree contains no leaves and no iterates contributes its OWN id
 *     to the leaf chain. This keeps a round visible on the canvas connected
 *     to the dataflow when the user clears its body via the visual editor;
 *     without this, deleting all of a round's steps left the round box
 *     stranded with no incoming or outgoing edges — and dropping a new
 *     step on it appeared to "do nothing" because the empty round was
 *     visually disconnected from the chain. The full transparent-group
 *     semantics return as soon as the user adds any leaf back.
 *   - **Iterates terminate the spine at their boundary.** The iterate's
 *     body becomes its own scope (per-iteration spine emitted by recursing
 *     into the body), but the parent spine is BROKEN at the iterate — no
 *     state edge enters the iterate from its predecessor, and no state
 *     edge leaves the iterate toward its successor. Concretely: in
 *     `[A, B, iter, C, D]` at root scope, the parent emits only `A→B`
 *     and `C→D`; the predecessor-to-iterate (`B→iter`), iterate-to-
 *     successor (`iter→C`), and bridging (`B→C`) edges are all
 *     deliberately absent.
 *
 *     **Why suppress.** Today's iterate runtime contract is aux-mediated:
 *     at iteration ENTRY the runtime sets `state = aux[blocksFromAux][i]`
 *     (the predecessor's stateAfter is discarded); at iteration EXIT it
 *     appends `state` to `aux[outBlocksAux]` (the successor reads its
 *     data from that aux array, NOT from the iterate's final state). The
 *     "spine value at the boundary" is therefore dead — drawing a white
 *     arrow there showed the plaintext "flowing into" the iterate while
 *     the truth was "the per-block payload arrives via `aux[input-
 *     blocks]`." The aux arrows are the honest depiction of the handoff;
 *     the spine has nothing to add at this boundary.
 *
 *     Surfaced 2026-05-17: user clicking the previously-rendered phantom
 *     state edge saw the plaintext value and asked "where am I wrong? The
 *     plaintext isn't passed forward as plaintext in the cipher; it is
 *     passed already split into blocks." Right. The fix lives in
 *     `emitChain`'s iterate-suppression check.
 *
 *     **Feistel future**: a Feistel-style iterate (branching state, not
 *     aux-mediated) would carry meaningful spine information across the
 *     boundary and need an opt-out flag. Today every shipped iterate
 *     (ECB / CBC iterate) is aux-mediated, so the rule is unconditional.
 *
 * The function reads only `spec`, never the trace. State edges therefore
 * appear on the structural skeleton before any run, while aux edges remain
 * trace-derived. This matches the rendering goal: the spine is what the
 * user reads as "this is what the cipher does", and it should be visible
 * the moment they load a spec.
 */
const inferStateEdges = (spec: CipherSpec): GraphEdge[] => {
  const edges: GraphEdge[] = [];

  // Track every iterate's id so the spine-chain emitter can suppress
  // phantom state edges that would otherwise appear to flow INTO or
  // OUT OF an iterate. The runtime contract for an IterateGroup is:
  //   - at iteration ENTRY it sets `state = aux[blocksFromAux][i]`,
  //     overwriting whatever the predecessor's stateAfter was;
  //   - at iteration EXIT it appends `state` to `aux[outBlocksAux]`,
  //     and the successor step reads its data from that aux array, NOT
  //     from the iterate's final state.
  // So the spine value at the iterate's boundary is dead — it still
  // exists as a passthrough, but no downstream step actually consumes
  // it. Rendering it as a white arrow into the iterate misled users
  // ("the plaintext flows here") while the truth is "the per-block
  // payload arrives via aux[input-blocks]." Suppressing the edges is
  // the pedagogically honest answer: the iterate's *aux* arrows ARE
  // the handoff; the spine simply doesn't reach across this boundary.
  //
  // Surfaced 2026-05-17 manual smoke ("the plaintext isn't passed
  // forward as plaintext in the cipher. It is passed already split
  // into blocks"). Every IterateGroup we ship today (ECB / CBC iterate)
  // is aux-mediated, so the rule is unconditional. A future Feistel-
  // style iterate with branching state would need an opt-out flag if
  // its spine carries meaningful information across the boundary.
  const iterateIds = new Set<string>();
  /**
   * Feistel-round container ids. Used by `emitChain` to suppress any direct
   * `predecessor → roundId` edge — the spine fans into each track's first
   * leaf instead, and resumes from `{roundId}:rejoin` onto the round's
   * successor. (The rejoin synthetic id, not the round id itself, is what
   * the parent chain sees as the round's "tail.")
   */
  const feistelRoundIds = new Set<string>();
  const collectIterates = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      if (node.kind === "iterate") {
        iterateIds.add(node.id);
        collectIterates(node.children);
      } else if (node.kind === "feistel-round") {
        feistelRoundIds.add(node.id);
        for (const track of node.tracks) collectIterates(track.children);
      } else if (node.kind === "group") {
        collectIterates(node.children);
      }
    }
  };
  collectIterates(spec.steps);

  const emitChain = (leaves: readonly string[]): void => {
    for (let i = 0; i + 1 < leaves.length; i++) {
      const from = leaves[i];
      const to = leaves[i + 1];
      if (from === undefined || to === undefined) continue;
      // Suppress the phantom edges into / out of aux-mediated iterates
      // (see the iterateIds doc-block above). Leaves the chain
      // STRUCTURALLY split — A→B→iter→C→D produces only A→B and C→D,
      // no bridging A→C edge, because no spine value actually crosses
      // the iterate boundary either way.
      if (iterateIds.has(from) || iterateIds.has(to)) continue;
      // Suppress edges TO a feistel-round id — the fan-in to each track's
      // first leaf is emitted explicitly by `processFeistelRound`. (Edges
      // FROM a feistel-round id can't arise here because the round
      // doesn't appear in any flat chain; the rejoin synthetic id takes
      // its place — see `processScope` below.)
      if (feistelRoundIds.has(to)) continue;
      edges.push({ from, to, auxKey: STATE_AUX_KEY, kind: "state" });
    }
  };

  /**
   * Find the first spine-bearing id in a track's children (or any subtree).
   * Spine-bearing = a leaf, an iterate id (becomes a boundary marker), a
   * feistel-round id (treated as round id for fan-in), or an empty group
   * (participates as its own id when its subtree is empty). Returns null
   * for a truly empty children list (e.g. an L track with `children: []`).
   */
  const firstSpineId = (nodes: readonly StepNode[]): string | null => {
    for (const node of nodes) {
      if (node.kind === "step") return node.id;
      if (node.kind === "iterate") return node.id;
      if (node.kind === "feistel-round") return node.id;
      if (node.kind === "group") {
        if (hasSpineContent(node.children)) {
          const inner = firstSpineId(node.children);
          if (inner !== null) return inner;
        } else {
          return node.id;
        }
      }
    }
    return null;
  };

  /** Symmetric helper to `firstSpineId` — returns the last spine-bearing
   *  id in a track's children. Walks the subtree right-to-left semantics
   *  by recursing through siblings and remembering the last hit. */
  const lastSpineId = (nodes: readonly StepNode[]): string | null => {
    let last: string | null = null;
    for (const node of nodes) {
      if (node.kind === "step") {
        last = node.id;
      } else if (node.kind === "iterate" || node.kind === "feistel-round") {
        last = node.id;
      } else if (node.kind === "group") {
        if (hasSpineContent(node.children)) {
          const inner = lastSpineId(node.children);
          if (inner !== null) last = inner;
        } else {
          last = node.id;
        }
      }
    }
    return last;
  };

  /**
   * True iff the subtree contains at least one leaf, iterate, or
   * feistel-round — i.e. anything that would visibly contribute to the
   * spine if walked. A group is treated as "empty" (eligible to
   * participate as a spine node via its own id) when this returns false
   * for its children. Nested empty groups recursively count as empty.
   */
  function hasSpineContent(nodes: readonly StepNode[]): boolean {
    for (const node of nodes) {
      if (node.kind === "step") return true;
      if (node.kind === "iterate") return true;
      if (node.kind === "feistel-round") return true;
      if (hasSpineContent(node.children)) return true;
    }
    return false;
  }

  /**
   * Process a Feistel round atomically. The parent chain segment ending
   * at `predecessor` flushes BEFORE this is called; the new chain segment
   * resumes from `{node.id}:rejoin` AFTER. Edges emitted directly:
   *
   *   - For each track with spine content:
   *       - `predecessor → firstSpineId(track.children)` (fan-in, if predecessor present)
   *       - The track's internal chain (via a nested `processScope` over
   *         the track's children).
   *       - `lastSpineId(track.children) → {node.id}:rejoin` (fan-out)
   *   - For each empty track (Phase 6b-ii):
   *       - `predecessor → {node.id}:passthrough-{trackIdx}` (fan-in, if predecessor present)
   *       - `{node.id}:passthrough-{trackIdx} → {node.id}:rejoin` (fan-out)
   *
   * Empty-track passthroughs replace the Phase-6a `predecessor → rejoin`
   * shortcut — the L column now reads as a real link in the spine instead
   * of an arrow that visually skips the column entirely. The synthetic
   * passthrough node itself is materialized by `walkSpec`; this function
   * only routes the edges. Per-track-id consistency is enforced by both
   * sites calling `feistelPassthroughId(node.id, trackIdx)`.
   *
   * No edge is ever drawn to or from the round's own id — the rejoin
   * synthetic id replaces the round in the parent chain.
   */
  const processFeistelRound = (
    node: {
      readonly id: string;
      readonly tracks: readonly { readonly children: readonly StepNode[] }[];
      readonly combineKind: string;
    },
    predecessor: string | undefined,
  ): void => {
    const rejoinId = `${node.id}:rejoin`;
    const canEdgeFromPredecessor =
      predecessor !== undefined &&
      !iterateIds.has(predecessor) &&
      !feistelRoundIds.has(predecessor);
    node.tracks.forEach((track, trackIdx) => {
      const trackFirst = firstSpineId(track.children);
      const trackLast = lastSpineId(track.children);
      if (trackFirst === null) {
        // Empty track — route through the synthetic passthrough chip
        // `walkSpec` synthesized for this (round, trackIdx) pair. Two
        // edges: predecessor → passthrough (if predecessor present),
        // and passthrough → rejoin (always — the chip's outgoing link
        // is invariant). The chip's identity-of-state semantic is
        // implicit in the absence of a transform between the two edges.
        const ptId = feistelPassthroughId(node.id, trackIdx);
        if (canEdgeFromPredecessor && predecessor !== undefined) {
          edges.push({ from: predecessor, to: ptId, auxKey: STATE_AUX_KEY, kind: "state" });
        }
        edges.push({ from: ptId, to: rejoinId, auxKey: STATE_AUX_KEY, kind: "state" });
        return;
      }
      // UX-D candidate (b), 2026-05-22 — populated R-track in a
      // `feistel-standard` round (DES rounds 1..15) carries an
      // R-bypass passthrough chip at the head of the column. The chip
      // is materialized in `walkSpec` and prepended to
      // `perTrackChildIds[1]` for layout, but it's NOT in
      // `track.children` (the spec). We splice it into the chain here
      // so the user sees:
      //
      //   predecessor → chip → trackFirst (= expand-R for DES)
      //                       → trackFirst → … → trackLast → rejoin
      //                  chip → rejoin (the bypass)
      //
      // The chip "owns" R_in: it has one incoming arrow (from
      // predecessor) and two outgoing arrows (into the F-stack head,
      // and direct to rejoin). Both outgoing values resolve to the
      // 4-byte R_in via `lookupPassthroughBytes` (which keys off
      // `:passthrough-1` → `params.R_in` on the rejoin frame).
      //
      // Candidate (a) — synthesize an arrow expand-R → rejoin — was
      // tried first (commit `83502de`) and reverted because the
      // arrow visually suggested expand-R PRODUCED R_in, whereas
      // expand-R CONSUMES it (and produces E(R)). Putting the chip
      // upstream of expand-R restores the honest pedagogy.
      const useRBypassChip =
        trackIdx === 1 && node.combineKind === "feistel-standard" && track.children.length > 0;
      const chainHead = useRBypassChip ? feistelPassthroughId(node.id, 1) : trackFirst;
      // Fan-in edge: predecessor → chain head. With the chip, that's
      // predecessor → chip; without, predecessor → trackFirst (the
      // pre-candidate-(b) shape). Suppressed when the predecessor is
      // a boundary node (iterate / feistel) — their boundary
      // semantics already mark "no spine value crosses here."
      if (canEdgeFromPredecessor && predecessor !== undefined) {
        edges.push({
          from: predecessor,
          to: chainHead,
          auxKey: STATE_AUX_KEY,
          kind: "state",
        });
      }
      if (useRBypassChip) {
        // Chip → trackFirst (chain continues into the F-stack) AND
        // chip → rejoin (the bypass — R_in flows directly to become
        // new_L).
        edges.push({
          from: chainHead,
          to: trackFirst,
          auxKey: STATE_AUX_KEY,
          kind: "state",
        });
        edges.push({
          from: chainHead,
          to: rejoinId,
          auxKey: STATE_AUX_KEY,
          kind: "state",
        });
      }
      // Process the track's internal spine as its own sub-scope.
      processScope(track.children);
      // Fan-out edge: last spine id of this track → rejoin synthetic.
      if (trackLast !== null && !iterateIds.has(trackLast) && !feistelRoundIds.has(trackLast)) {
        edges.push({
          from: trackLast,
          to: rejoinId,
          auxKey: STATE_AUX_KEY,
          kind: "state",
        });
      }
    });
  };

  /**
   * Process one iterate-scope: collect its DFS leaves into a single chain
   * (recursing through filled groups, treating empty groups as spine
   * nodes, BRIDGING OVER iterates without breaking the chain), and recurse
   * into each iterate body as its own scope. Returns after emitting all
   * edges generated by this scope and its nested iterate scopes.
   *
   * Feistel-round breaks the linear-chain model: it has fan-in (parent →
   * N tracks) and fan-out (N tracks → rejoin). We FLUSH the current
   * linear segment when encountering one, call `processFeistelRound`
   * inline, then start a new segment seeded with the rejoin id.
   */
  const processScope = (siblings: readonly StepNode[]): void => {
    let segment: string[] = [];
    const flush = (): void => {
      emitChain(segment);
      segment = [];
    };
    const walk = (nodes: readonly StepNode[]): void => {
      for (const node of nodes) {
        if (node.kind === "step") {
          segment.push(node.id);
        } else if (node.kind === "group") {
          if (hasSpineContent(node.children)) {
            // Filled group — transparent, descend.
            walk(node.children);
          } else {
            // Empty group — push its own id so the spine doesn't
            // leapfrog over it. Preserves "a visible round stays
            // connected to the chain even while the user is mid-edit
            // with its body cleared out."
            segment.push(node.id);
          }
        } else if (node.kind === "iterate") {
          // Iterate boundary — recurse into the body as its own scope
          // (the per-iteration spine is a separate chain) AND push the
          // iterate's id onto the parent chain so the chain has a
          // recognizable boundary marker. `emitChain` then SUPPRESSES
          // any state edge whose endpoint is an iterate id (see the
          // iterateIds doc-block above). The result: the parent spine
          // stops at the leaf BEFORE the iterate, and resumes at the
          // leaf AFTER it, with NO white arrow crossing the boundary
          // and no bridging edge over the iterate. The iterate's own
          // aux arrows (input-blocks coming in, output-blocks going
          // out) are the honest depiction of what data crosses the
          // boundary; the spine has nothing to add.
          processScope(node.children);
          segment.push(node.id);
        } else {
          // Feistel-round — break the linear chain. The current segment's
          // tail is the predecessor; flush the segment up to it, process
          // the round (which emits fan-in/fan-out directly), then start
          // a new segment from the rejoin synthetic id so the successor
          // gets a clean `rejoin → successor` edge.
          const predecessor = segment.length > 0 ? segment[segment.length - 1] : undefined;
          flush();
          processFeistelRound(node, predecessor);
          segment.push(`${node.id}:rejoin`);
        }
      }
    };
    walk(siblings);
    flush();
  };

  processScope(spec.steps);
  return edges;
};

/**
 * Compute `blockSpan` for every leaf inside an iterate and for every
 * iterate container. The runtime stamps `frame.blockIndex` on each frame
 * emitted inside an iterate, so blockSpan = max(blockIndex) + 1 over
 * frames whose stepId / containerPath matches.
 *
 * Nodes are mutated in place (within this builder's lifetime — the array
 * is fresh and not yet exposed). The output graph remains immutable from
 * the caller's perspective.
 */
const annotateBlockSpans = (trace: Trace, ctx: BuildContext): void => {
  // First pass: per iterate container, find max blockIndex.
  const maxBlockIndexByIterate = new Map<string, number>();
  for (const frame of trace.frames) {
    if (frame.blockIndex === undefined) continue;
    for (const id of frame.path) {
      if (!ctx.iteratesById.has(id)) continue;
      const prev = maxBlockIndexByIterate.get(id);
      if (prev === undefined || frame.blockIndex > prev) {
        maxBlockIndexByIterate.set(id, frame.blockIndex);
      }
    }
  }
  for (const [iid, maxIdx] of maxBlockIndexByIterate) {
    const cIdx = ctx.containerIndex.get(iid);
    if (cIdx === undefined) continue;
    const existing = ctx.containers[cIdx];
    if (!existing) continue;
    ctx.containers[cIdx] = { ...existing, blockSpan: maxIdx + 1 };
  }

  // Second pass: every leaf inside an iterate inherits that iterate's span.
  // If multiple iterates nest, the innermost wins (last one in containerPath
  // that's an iterate).
  for (let i = 0; i < ctx.nodes.length; i++) {
    const node = ctx.nodes[i];
    if (!node) continue;
    let span: number | undefined;
    for (const id of node.containerPath) {
      const candidate = maxBlockIndexByIterate.get(id);
      if (candidate !== undefined) span = candidate + 1;
    }
    if (span !== undefined) ctx.nodes[i] = { ...node, blockSpan: span };
  }
};

// ─── Collapse (view-time transform) ────────────────────────────────────────

/**
 * View-time transform: hide every leaf and container that lives inside a
 * collapsed container, redirect edges that crossed the boundary to terminate
 * at the collapsed container itself, and dedup the resulting edge set.
 *
 * **Why this is separate from `deriveAuxGraph`.** Collapse is a renderer
 * concern, not a spec/trace concern; mixing them risks regressing Slice 1's
 * "graph is derived purely from (spec, trace)" contract. By keeping
 * `collapseGraph` as a pure pipeline stage AFTER `deriveAuxGraph`, the
 * caller (today: `GraphView`) gets the view it needs while the raw graph
 * test suite continues to pin the pre-collapse shape.
 *
 * Semantics:
 *   - A container in `collapsedIds` survives in `containers` (the renderer
 *     still draws it, just as a single chip with no child rendering).
 *     Its `childIds` is cleared to `[]` so the renderer's layout walk
 *     treats it as leaf-like.
 *   - Leaves and containers whose `containerPath` includes ANY collapsed
 *     ancestor are removed entirely.
 *   - Edges are remapped: any endpoint hidden by a collapse is replaced by
 *     the OUTERMOST collapsed ancestor on that endpoint's path. Self-loops
 *     produced by this remap (e.g. an aux that stays entirely inside a
 *     collapsed round) are dropped. Remaining edges are deduped by
 *     `(from, to, auxKey)`.
 *   - `rootIds` is filtered to only entries that still exist.
 */
export const collapseGraph = (
  graph: CipherGraph,
  collapsedIds: ReadonlySet<string>,
): CipherGraph => {
  if (collapsedIds.size === 0) return graph;

  /**
   * For any node/container id, find the outermost collapsed ancestor on its
   * path (or itself if collapsed). Returns the original id when nothing on
   * the path is collapsed.
   */
  const collapseTarget = (id: string, path: readonly string[]): string => {
    // Outermost wins: walk root-first and return the first collapsed hit.
    for (const ancestorId of path) {
      if (collapsedIds.has(ancestorId)) return ancestorId;
    }
    // The id itself might be a collapsed container.
    if (collapsedIds.has(id)) return id;
    return id;
  };

  const nodePathById = new Map<string, readonly string[]>();
  for (const n of graph.nodes) nodePathById.set(n.stepId, n.containerPath);
  const containerPathById = new Map<string, readonly string[]>();
  for (const c of graph.containers) containerPathById.set(c.id, c.containerPath);

  /** Lookup for the "what does this id map to after collapse?" question. */
  const remap = (id: string): string => {
    const nodePath = nodePathById.get(id);
    if (nodePath !== undefined) return collapseTarget(id, nodePath);
    const cPath = containerPathById.get(id);
    if (cPath !== undefined) return collapseTarget(id, cPath);
    // Unknown id (shouldn't happen for a (spec, trace)-derived graph) —
    // leave it alone rather than crash; the renderer will skip dangling refs.
    return id;
  };

  // Keep visible leaves only (a leaf is hidden if its remap target ≠ itself).
  const newNodes = graph.nodes.filter((n) => remap(n.stepId) === n.stepId);

  // Containers: keep a container if it's not nested inside a collapsed ancestor.
  // A collapsed container itself is kept (renderer shows the collapsed chip).
  const newContainers = graph.containers
    .filter((c) => {
      if (collapsedIds.has(c.id)) return true;
      return !c.containerPath.some((a) => collapsedIds.has(a));
    })
    .map((c) =>
      // Collapsed container's children stop rendering; clear childIds so the
      // layout walk treats it as a leaf-sized rectangle.
      collapsedIds.has(c.id) ? { ...c, childIds: [] as readonly string[] } : c,
    );

  // Edges: remap both endpoints, drop self-loops, dedup.
  //
  // Dedup key includes `kind` so a future state edge between the same
  // (from, to) as an existing aux edge is preserved as a distinct edge.
  // Practically harmless today (state edges carry auxKey "state", which
  // never collides with real aux keys), but cheap defense in depth.
  const seen = new Set<string>();
  const newEdges: GraphEdge[] = [];
  for (const edge of graph.edges) {
    const from = remap(edge.from);
    const to = remap(edge.to);
    if (from === to) continue;
    const key = `${edge.kind} ${from} ${to} ${edge.auxKey}`;
    if (seen.has(key)) continue;
    seen.add(key);
    newEdges.push({ from, to, auxKey: edge.auxKey, kind: edge.kind });
  }

  // rootIds: keep the entries that still resolve to a visible leaf or container.
  const visibleLeafIds = new Set(newNodes.map((n) => n.stepId));
  const visibleContainerIds = new Set(newContainers.map((c) => c.id));
  const newRootIds = graph.rootIds.filter(
    (id) => visibleLeafIds.has(id) || visibleContainerIds.has(id),
  );

  return {
    nodes: newNodes,
    containers: newContainers,
    edges: newEdges,
    rootIds: newRootIds,
  };
};

// ─── Aux-only state-edge suppression ────────────────────────────────────

/**
 * Drop every `kind: "state"` edge whose endpoint id is in `auxOnlyIds`.
 *
 * **Why this transform is its own stage.** `inferStateEdges` walks the spec
 * in DFS order and chains every leaf to its successor — including aux-only
 * leaves like `aes.key-expansion@1`. For those leaves the runtime contract
 * `(state, params) → state` produces an identity passthrough (key-expansion
 * reads `state` but doesn't modify it), so the emitted edge represents a
 * pedagogically misleading "data flows from here into the next step" arrow.
 * The renderer pairs every aux-only root with a `__cipher_input__` pill
 * arrow that lands on the FIRST state-consuming leaf, making the spine edge
 * out of the aux-only leaf redundant.
 *
 * **Pipeline placement: BEFORE `replicateHighFanoutSources`.** That matters
 * because Slice 7b (2026-05-17) made replication rewrite the `from` of
 * state edges to the source's spine-entry replica id when the source is
 * fully replicated. If this filter runs AFTER replication, the rewritten
 * edge slips through (its `from` is no longer the original aux-only id but
 * `${src}@->${consumer}`) and the user sees a phantom state arrow from the
 * tiny replica chip into the first state consumer — exactly the regression
 * the user reported. Running the filter BEFORE replication keeps the
 * suppression centered on the original spec ids, where the union check is
 * trivial and Slice 7b's redirect logic naturally falls through to its
 * aux-target fallback (documented at `replicateHighFanoutSources`'s
 * `spineSuccessorOf` block) without losing the spine-entry replica.
 *
 * **Bidirectional check** so an aux-only leaf at the END of the spec (no
 * shipped cipher has one today, but a future hash/MAC might) also gets
 * its incoming spine edge suppressed. One-sided would only handle the
 * usual leading-`key-expansion` case.
 *
 * **Identity short-circuit** when `auxOnlyIds` is empty OR no state edge
 * touches one — returns the input by reference so the createMemo chain in
 * `GraphView` short-circuits cheaply for ciphers without aux-only roots.
 *
 * Aux edges are never filtered — those represent real producer→consumer
 * data flow (the round-key fan-out from key-expansion); the user wants
 * to SEE those edges, that's the whole pedagogical point. Only the spine
 * passthrough is misleading.
 *
 * Validation (`validateGraph`) consumes the pre-filter graph, so dropping
 * these edges from the display doesn't change the warning surface.
 */
export const dropAuxOnlyStateEdges = (
  graph: CipherGraph,
  auxOnlyIds: ReadonlySet<string>,
): CipherGraph => {
  if (auxOnlyIds.size === 0) return graph;
  const filteredEdges = graph.edges.filter((e) => {
    if (e.kind !== "state") return true;
    return !auxOnlyIds.has(e.from) && !auxOnlyIds.has(e.to);
  });
  if (filteredEdges.length === graph.edges.length) return graph;
  return { ...graph, edges: filteredEdges };
};

// ─── Collapsed-iterate block-chip expansion (Slice 6) ────────────────────

/**
 * Sentinel `stepType` set on synthetic block-chip nodes. Never registered in
 * the step registry — the renderer dispatches off `blockChipOf` instead.
 * The id is used in the leaf's `<title>` tooltip so a hovering user gets
 * a hint that the chip isn't a real spec step.
 */
const BLOCK_CHIP_STEP_TYPE = "__block_chip__";

/**
 * Cap on how many chips render for a collapsed iterate. With N ≤ CAP, all
 * N chips render; with N > CAP, the first (CAP - 1) chips render plus one
 * `+M more blocks` ellipsis chip — total visible items always ≤ CAP. The
 * cap exists because pathological N (a 16KB file under AES-128 = 1024
 * blocks) would otherwise tile the canvas with chips and obscure the
 * pedagogical point.
 */
const BLOCK_CHIP_CAP = 6;

/**
 * Suffix appended to an iterate id to form the i-th block chip's id.
 * The leading `@` is shared with replica ids (`${src}@->${cons}`) — both
 * use a character that never appears in spec ids (which are dot-and-dash
 * lowercase). A future grep for `@block` finds every block-chip site.
 */
const blockChipId = (iterateId: string, i: number): string => `${iterateId}@block${i}`;
/** Companion id for the ellipsis chip (one per collapsed-iterate that overflows). */
const blockMoreChipId = (iterateId: string): string => `${iterateId}@blockMore`;

/**
 * View-time transform: expand each collapsed iterate into N parallel
 * "block-chip" nodes representing the N per-block iterations the runtime
 * walked. Pedagogical purpose — keeps the "ECB is N parallel AES copies"
 * story visible when the user collapses the iterate body. Without this
 * transform the collapsed iterate becomes a single `×N` chip and the
 * narrative collapses to a number.
 *
 * Pipeline placement: AFTER `collapseGraph` (so it sees collapsed-set
 * info), BEFORE `replicateHighFanoutSources` (so the chips become
 * replication candidates: `key-expansion` set to `"always"` plus this
 * transform produces one tiny key-expansion replica next to each chip,
 * which is pedagogically excellent — the user sees N tiny key-expansion
 * chips feeding N tiny block chips, perfect for the "schedule fans out"
 * story).
 *
 * Semantics:
 *   - For each iterate container in `collapsedIds` whose `blockSpan` is
 *     a known positive integer (i.e. the trace has run): replace it.
 *   - "Replace" means:
 *     1. Drop the iterate container from `containers`.
 *     2. Splice its slot in either `rootIds` or its parent's `childIds`
 *        with the chip ids (in spec order at that slot).
 *     3. Add `min(N, CAP)` chip nodes — but if `N > CAP`, the last is an
 *        ellipsis chip labeled `+${N - (CAP - 1)} more blocks`.
 *     4. For every edge with the iterate as endpoint, fan to one edge
 *        per chip (each chip becomes the endpoint in its own copy of
 *        the edge). The ellipsis chip collectively represents the
 *        edges of the (N - CAP + 1) blocks it stands for.
 *   - Untouched cases: non-iterate containers, iterates not in
 *     `collapsedIds`, iterates whose `blockSpan` is undefined (pre-run
 *     or trace without `blockIndex` stamps), iterates whose `blockSpan`
 *     is 0. Those pass through identically — the collapsed iterate
 *     keeps its today's `×N` chip behavior or stays expanded.
 *   - Identity short-circuit: when no iterate qualifies, return the
 *     input by reference. Keeps the createMemo chain in GraphView
 *     cheap for the common single-block-cipher case.
 *
 * Why chips are nodes (not containers): a container with `childIds: []`
 * already exists as a layout primitive (collapsed-iterate chip), but
 * containers carry header bands and click-to-expand semantics we don't
 * want here. A chip is conceptually a leaf — a small clickable thing
 * representing one parallel computation. Modeling it as a `GraphNode`
 * with `blockChipOf` set lets it ride the existing leaf-rendering path
 * with no new SVG component.
 *
 * Why fan EVERY edge (not just aux): defensive. Today only aux edges
 * touch the iterate id (count, blocks-in, blocks-out from
 * `deriveAuxGraph`'s iterate-mediated synthesis), so the rule reduces
 * to "fan aux edges." But state-edge endpoint pills (Slice 1)
 * structurally CAN anchor on the iterate via the `inputAnchorId` /
 * `outputAnchorId` fallback in `deriveAuxGraph`, and a future renderer
 * change could route more state through the iterate node. Fanning all
 * kinds keeps the transform robust to those shifts without an extra
 * code path.
 *
 * Composition with `replicateHighFanoutSources`: chips become aux-edge
 * consumers (and producers, via the iterate's `outBlocksAux`). A source
 * like `key-expansion` that emitted one edge to the iterate now emits
 * N edges to N chips, which raises its outgoing-aux count. The
 * threshold check fires per existing logic; if replication is on, the
 * user sees one tiny key-expansion replica per chip. No additional
 * plumbing required.
 *
 * Future cases this transform intentionally does NOT handle:
 *   1. Nested iterates (iterate-within-iterate): if the iterate's
 *      parent itself is a collapsed iterate, the inner iterate vanishes
 *      with the outer collapse before this transform sees it (collapse
 *      hides everything inside a collapsed ancestor). No behavior to
 *      define until a cipher routinely nests iterates.
 *   2. Pathological N (1000+ blocks): chips cap at CAP regardless, so
 *      the visual stays bounded. The ellipsis chip's "+999 more"
 *      label conveys the scale without trying to draw a thousand
 *      tiny rectangles.
 */
export const expandCollapsedIterates = (
  graph: CipherGraph,
  collapsedIds: ReadonlySet<string>,
): CipherGraph => {
  if (collapsedIds.size === 0) return graph;

  // Collect target iterates: collapsed AND has a known positive blockSpan.
  // Pre-run traces leave blockSpan undefined — the collapsed `×N` chip
  // keeps its today's behavior in that case, no transform applied.
  const targets = graph.containers.filter(
    (c) =>
      c.kind === "iterate" &&
      collapsedIds.has(c.id) &&
      c.blockSpan !== undefined &&
      c.blockSpan > 0,
  );
  if (targets.length === 0) return graph;

  // Working copies — each iterate processed in turn, mutating the running
  // graph state. Order doesn't matter for non-overlapping iterates (no
  // shipped cipher nests iterates), and even hypothetical nested cases
  // resolve correctly because the inner iterate would have been hidden
  // by the outer's collapse before reaching this transform.
  //
  // Option C keeps the iterate container in place (with chips as its
  // childIds), so neither `rootIds` nor `edges` get reassigned in the
  // loop — only `containers` (rewriting the iterate's childIds) and
  // `nodes` (appending chip nodes). The other two are const spread copies
  // so the returned graph is a fresh object (input is never mutated).
  let nodes = [...graph.nodes];
  let containers = [...graph.containers];
  const edges = [...graph.edges];
  const rootIds = [...graph.rootIds];

  for (const iterate of targets) {
    const N = iterate.blockSpan ?? 0;
    if (N <= 0) continue;
    const visibleCount = N <= BLOCK_CHIP_CAP ? N : BLOCK_CHIP_CAP - 1;
    const includeEllipsis = N > BLOCK_CHIP_CAP;

    // Build chip nodes. `stepType` is a sentinel — not registered.
    // Renderer discriminates off `blockChipOf` for behavior, off
    // `node.label` for display text.
    //
    // Option C: chips' `containerPath` includes the iterate id (different
    // from Option B's "siblings of the iterate" placement). Layout's
    // iterate-kind branch reads `container.childIds` and recurses into
    // each child; the chips sit inside the iterate's body box. The
    // `isInsideIterate` leaf-render check picks them up via this path.
    const chipNodes: GraphNode[] = [];
    for (let i = 0; i < visibleCount; i++) {
      chipNodes.push({
        stepId: blockChipId(iterate.id, i),
        stepType: BLOCK_CHIP_STEP_TYPE,
        label: `block ${i + 1}`,
        containerPath: [...iterate.containerPath, iterate.id],
        blockChipOf: iterate.id,
      });
    }
    if (includeEllipsis) {
      chipNodes.push({
        stepId: blockMoreChipId(iterate.id),
        stepType: BLOCK_CHIP_STEP_TYPE,
        // Hidden-block count = N minus visible non-ellipsis chips.
        label: `+${N - visibleCount} more blocks`,
        containerPath: [...iterate.containerPath, iterate.id],
        blockChipOf: iterate.id,
      });
    }
    const chipIds = chipNodes.map((c) => c.stepId);

    // Option C — keep the iterate in `containers` and set its childIds to
    // the chip ids. `collapseGraph` cleared `childIds` to [] on the way
    // in, so the iterate would otherwise lay out as the compact `×N`
    // chip (the `childIds.length === 0` branch in `layoutNode`); rewriting
    // childIds here switches it back to the full container-with-body
    // layout. The existing header chevron stays — clicking it removes
    // the iterate from `collapsedGroups` and lets the next pass through
    // this transform short-circuit, revealing the real body.
    //
    // Edges touching the iterate are LEFT ALONE (not fanned to chips):
    // the chips are a visual representation of "what runs inside,"
    // not first-class participants in the dataflow. External arrows
    // point to/from the iterate box — one logical step, one entry, one
    // exit. Without this, every collapsed iterate would sprout N parallel
    // arrows, drowning out the rest of the graph for non-trivial N.
    containers = containers.map((c) =>
      c.id === iterate.id ? { ...c, childIds: chipIds as readonly string[] } : c,
    );

    nodes = [...nodes, ...chipNodes];
  }

  return { nodes, containers, edges, rootIds };
};

// ─── High-fanout replication (commit 4 of the graph-readability sequence) ─

/**
 * Replicate any aux-edge source whose outgoing-aux count exceeds `threshold`,
 * with per-source overrides via `modes`.
 *
 * Why: AES-128's `key-expansion` produces 11 outgoing roundKey edges that
 * fan out to all 11 AddRoundKey consumers, dominating the canvas with long
 * cross-pipeline lines. Replicating moves each edge to a short local hop:
 * a tiny `key-expansion` chip lands next to each consumer, the long lines
 * disappear, the eye reads the round body before the schedule.
 *
 * Semantics:
 *   - **Eligibility counts only `kind: "aux"` edges.** State edges are 1-to-1
 *     between consecutive same-parent leaves (no fanout possible) so they're
 *     a meaningless threshold input. A source qualifies only by its outgoing
 *     aux fanout (or by an explicit `"always"` override).
 *   - **All outgoing edges of a qualifying source are rerouted, regardless
 *     of kind** (Slice 7b, 2026-05-17). A high-fanout source's outgoing
 *     STATE edges fan through replicas the same way its aux edges do, and
 *     the original source is REMOVED entirely from the graph (no longer
 *     duplicates the spine chip next to its consumers). Incoming edges
 *     whose `to` is a fully-replicated source are redirected to that
 *     source's "spine entry" replica — defined as the replica generated
 *     for the source's spine successor (first outgoing state edge's target,
 *     with fallback to first outgoing aux edge's target if the iterate-
 *     boundary suppression has eaten the only state-out — see
 *     `inferStateEdges` for the suppression rule). Linear-list sidebar
 *     click-to-scrub continues working because that view reads the trace,
 *     not the graph; click-to-scrub on any replica still works via the
 *     `replicaOf` field. See `feedback_state_spine_no_phantoms.md` for the
 *     pedagogical principle that motivated the change.
 *   - A "source" is any id appearing in `edge.from` for at least one aux
 *     edge. Both leaves and iterate containers can be sources (the
 *     iterate boundary participates in synthetic edges; see
 *     deriveAuxGraph's "iterate-mediated aux" note).
 *   - Per-source override (commit 5):
 *       - `modes[src] === "always"` → replicate regardless of count.
 *       - `modes[src] === "never"`  → don't replicate, even at high fanout.
 *       - absent / "auto"           → replicate iff `count > threshold`.
 *     Master-switch semantic: a caller that wants replication globally OFF
 *     passes `threshold <= 0` AND an empty modes object; per-node `"always"`
 *     entries fire ONLY if at least one source is selected. The GraphView
 *     enforces "global off = no replicas, period" by short-circuiting the
 *     transform call entirely; this function honors `"always"` regardless
 *     so unit tests can drive it in isolation without needing the toggle.
 *   - One replica per (source, consumer) pair, even if multiple aux keys
 *     flow source → consumer. The replica gets all those edges; visually
 *     this reads as a single local chip with N tiny edges to its
 *     consumer, which is still much less cluttered than N long edges
 *     fanning from the original.
 *   - Replica id format: `${sourceId}@->${consumerId}` (the `@->` infix is
 *     unique enough to never collide with a real spec id; spec ids use
 *     dots and dashes only).
 *   - Replicas inherit the source's stepType + label so the user reads
 *     them as visual references to the source. `replicaOf` carries the
 *     source's canonical stepId so click handlers can navigate to the
 *     source's trace frame.
 *   - Replicas land in `containerPath` matching the consumer's, then are
 *     inserted as siblings immediately before the consumer in the parent's
 *     `childIds` (or `rootIds` if the consumer is at the root). Fully-
 *     replicated source ids are filtered out of `nodes`, `rootIds`, and
 *     every container's `childIds` after the insertion splice runs — the
 *     splice runs first so each replica lands relative to where the
 *     original consumer used to sit, then the removal pass strips the
 *     dead ids.
 *   - `threshold <= 0` with no `"always"` overrides → return the input
 *     graph by reference. Identity short-circuit keeps the createMemo
 *     chain in GraphView cheap when replication is off.
 */
export const replicateHighFanoutSources = (
  graph: CipherGraph,
  threshold: number,
  modes?: { readonly [sourceId: string]: "always" | "never" },
): CipherGraph => {
  const modesObj = modes ?? {};
  // Early exit when there's no possible work: threshold below 1 disables
  // auto-replication, AND no per-source "always" override is present. This
  // is the GraphView's master-switch case when the user has turned the
  // global toggle off without setting any explicit overrides.
  const hasAnyAlwaysOverride = Object.values(modesObj).some((m) => m === "always");
  if (threshold <= 0 && !hasAnyAlwaysOverride) return graph;

  // Container ids — index up front so the per-source loop can no-op
  // container sources without re-walking `graph.containers`. Containers
  // (groups + iterates) are themselves visible decongestion devices;
  // replicating one produces a chip near the consumer that duplicates
  // the existing state-spine arrow AND overflows the chip (container
  // labels are typically long, e.g. "ECB blocks (per-block AES)"). The
  // user can still set a container to "always" in the panel — the toggle
  // is preserved; this loop just silently skips it. Specific motivation:
  // post-Option-C, a collapsed iterate stays in the graph as a source
  // with one outgoing aux edge to its successor (e.g. `concat-blocks`),
  // and toggling it "always" in the panel produced exactly the duplicate
  // arrow + overflowing-chip the user reported.
  const containerIds = new Set<string>();
  for (const c of graph.containers) containerIds.add(c.id);

  // Count outgoing aux edges per source. State edges are excluded.
  const fanoutBySrc = new Map<string, number>();
  for (const e of graph.edges) {
    if (e.kind !== "aux") continue;
    fanoutBySrc.set(e.from, (fanoutBySrc.get(e.from) ?? 0) + 1);
  }

  const highFanoutSrcs = new Set<string>();
  for (const [srcId, count] of fanoutBySrc) {
    if (containerIds.has(srcId)) continue;
    const m = modesObj[srcId];
    if (m === "never") continue;
    if (m === "always") {
      highFanoutSrcs.add(srcId);
      continue;
    }
    // Auto: threshold check. `threshold <= 0` was already handled by the
    // early-exit above unless an "always" override exists somewhere else
    // in the modes map; in that case auto sources still respect the
    // threshold (a 0 threshold means "no auto replication").
    if (threshold > 0 && count > threshold) highFanoutSrcs.add(srcId);
  }

  if (highFanoutSrcs.size === 0) return graph;

  // Index source nodes by id so replicas can inherit stepType + label.
  // Containers can also be sources (iterate aux), so check both maps.
  const nodeById = new Map<string, GraphNode>();
  for (const n of graph.nodes) nodeById.set(n.stepId, n);
  const containerById = new Map<string, ContainerNode>();
  for (const c of graph.containers) containerById.set(c.id, c);

  // Slice 7b: every qualifying source IS fully replicated by construction
  // (we walk EVERY outgoing edge below, regardless of kind). So the
  // "fully replicated" set equals `highFanoutSrcs` exactly. Naming it
  // separately keeps the redirect / removal sites readable.
  const fullyReplicated = highFanoutSrcs;

  // Spine successor for each fully-replicated source — used to redirect
  // incoming edges whose `to` lands on a dead source id. Definition:
  //   1. First outgoing STATE edge's target (pre-replication graph).
  //   2. Fallback to first outgoing AUX edge's target if (1) doesn't
  //      exist. The fallback handles sources whose only state output
  //      was suppressed by the iterate-boundary rule in `inferStateEdges`
  //      — e.g. `compute-block-count` set to `"always"` in AES-128 ECB,
  //      where the spine edge → `ecb-blocks` (the iterate) is dropped,
  //      leaving only the aux edge → `ecb-blocks` for `blockCount`.
  // The spine-successor's replica (`${src}@->${spineSuccessor}`) is the
  // canonical "spine entry" for the removed source. Every qualifying
  // source has at least one outgoing aux edge (that's how it qualified),
  // so the fallback is always defined.
  const spineSuccessorOf = new Map<string, string>();
  for (const src of fullyReplicated) {
    let stateTarget: string | undefined;
    let auxTarget: string | undefined;
    for (const e of graph.edges) {
      if (e.from !== src) continue;
      if (e.kind === "state" && stateTarget === undefined) stateTarget = e.to;
      if (e.kind === "aux" && auxTarget === undefined) auxTarget = e.to;
      if (stateTarget !== undefined && auxTarget !== undefined) break;
    }
    const successor = stateTarget ?? auxTarget;
    if (successor !== undefined) spineSuccessorOf.set(src, successor);
  }

  // Walk every edge, build:
  //   - newEdges: rewritten with replica `from` where applicable AND
  //     redirected `to` where the consumer was fully replicated
  //   - replicas: (srcId, ORIGINAL-consumerId) → replica node
  //   - insertionsByParent: parent container id (or "" for root) →
  //       (ORIGINAL-consumerId → [replicaIds]) in encounter order
  const newEdges: GraphEdge[] = [];
  const replicaKey = (srcId: string, consumerId: string) => `${srcId}@->${consumerId}`;
  const replicas = new Map<string, GraphNode>(); // replicaId → node

  // Redirect target for incoming edges whose `to` is fully replicated.
  // Returns the spine-entry replica id (= the replica generated for the
  // source's spine successor), or undefined when there's no successor —
  // which can't happen for any source in `fullyReplicated` per the
  // qualifies-by-aux-fanout argument above, but the helper returns
  // undefined defensively so the call site can drop the edge instead of
  // emitting a dangling reference.
  const firstReplicaOf = (srcId: string): string | undefined => {
    const successor = spineSuccessorOf.get(srcId);
    if (successor === undefined) return undefined;
    return replicaKey(srcId, successor);
  };

  const insertionsByParent = new Map<string, Map<string, string[]>>();
  const ensureInsertionMap = (parentKey: string): Map<string, string[]> => {
    let m = insertionsByParent.get(parentKey);
    if (!m) {
      m = new Map();
      insertionsByParent.set(parentKey, m);
    }
    return m;
  };

  for (const edge of graph.edges) {
    const fromIsReplicated = fullyReplicated.has(edge.from);
    const toIsReplicated = fullyReplicated.has(edge.to);

    // Determine the effective `to`: if the consumer is fully replicated,
    // point at its spine-entry replica instead. Drop the edge entirely
    // when no redirect target is computable (should be unreachable, see
    // `firstReplicaOf`).
    let effectiveTo = edge.to;
    if (toIsReplicated) {
      const redirected = firstReplicaOf(edge.to);
      if (redirected === undefined) continue;
      effectiveTo = redirected;
    }

    if (!fromIsReplicated) {
      // Pass-through edge (possibly with a rewritten `to`).
      newEdges.push(effectiveTo === edge.to ? edge : { ...edge, to: effectiveTo });
      continue;
    }

    // High-fanout source: rewrite the edge through a replica node. The
    // replica id and the insertion slot key off the ORIGINAL consumer
    // (`edge.to`) so the splice + filter pipeline below lands each
    // replica where the original consumer used to sit, and replicas of
    // a source pointed at a fully-replicated consumer still get inserted
    // in that consumer's pre-replication slot. The OUTGOING edge from
    // the replica targets `effectiveTo`, which may be the consumer's
    // spine-entry replica if the consumer is also fully replicated.
    const rId = replicaKey(edge.from, edge.to);
    if (!replicas.has(rId)) {
      // Determine the consumer's parent container (last in containerPath)
      // and lookup its inherited fields from the source node/container.
      const consumerNode = nodeById.get(edge.to);
      const consumerContainer = containerById.get(edge.to);
      const consumerPath = consumerNode?.containerPath ?? consumerContainer?.containerPath ?? [];
      const sourceNode = nodeById.get(edge.from);
      const sourceContainer = containerById.get(edge.from);
      const sourcePath = sourceNode?.containerPath ?? sourceContainer?.containerPath ?? [];
      const stepType = sourceNode?.stepType ?? sourceContainer?.kind ?? "replica";
      const label = sourceNode?.label ?? sourceContainer?.label ?? edge.from;
      // Replica-scope-aware layout (2026-05-17, narrow interpretation):
      // the (source, spineSuccessor) replica is the SPINE replica — it
      // takes over the source's role on the canvas main row. It lives
      // in SOURCE's parent scope (not consumer's) and gets a flag the
      // layout passes consume to skip the lift-above-consumer treatment.
      //
      // Anchor key (2026-05-20 fix, DES surfaced): the splice helper
      // below scans each parent's `childIds` for the anchor key and
      // prepends the queued replicas before it. For NON-SPINE replicas
      // the anchor is the consumer's id (replica sits in consumer's
      // parent, just before the consumer). For the SPINE replica the
      // anchor must be the SOURCE'S id, because the spine replica
      // lives in source's parent scope — and `edge.to` (consumer's id)
      // is not in source's parent's childIds when source.parent ≠
      // consumer.parent (e.g., DES key-schedule at root vs. round.1.xor-K
      // inside the "rounds" group). Anchoring on source.id lands the
      // spine-replica at source's old spec slot; stripDead then removes
      // the source by id, leaving the spine-replica as its replacement.
      //
      // Byte-equivalent for shipped ciphers (AES, Speck, Serpent) where
      // source.parent === consumer.parent: in those, source.id appears
      // immediately before consumer.id in the same childIds list, so
      // both anchor choices land the spine replica at the same final
      // position after stripDead. Behavior changes only for ciphers
      // with the source/consumer-parent mismatch (DES today, and any
      // future cipher whose state-or-aux edges cross container scopes).
      // Cross-scope check: only treat the (source, spine-successor)
      // pair as a "spine replica" when source AND consumer share the
      // same parent container path. For ciphers like DES where the
      // source lives at root and the consumer lives several scopes
      // deeper (key-schedule at root, round.1.xor-K inside the Rounds
      // group → inside round.1), the source's parent scope can't host
      // a chip that visually belongs next to the consumer. Treating
      // the cross-scope case as a regular consumer-scope replica
      // lands round.1's xor-K replica in the round.1 body alongside
      // round.2..16's replicas — the symmetric placement the user
      // expects. User-flagged 2026-05-20 Phase 6e smoke ("round.1's
      // replicate is near the plaintext pill, outside Rounds group").
      const samePath =
        sourcePath.length === consumerPath.length &&
        sourcePath.every((seg, i) => seg === consumerPath[i]);
      const isSpine = spineSuccessorOf.get(edge.from) === edge.to && samePath;
      const replicaContainerPath = isSpine ? sourcePath : consumerPath;
      replicas.set(rId, {
        stepId: rId,
        stepType,
        label,
        containerPath: replicaContainerPath,
        replicaOf: edge.from,
        ...(isSpine ? { isSpineReplica: true as const } : {}),
      });
      const insertContainerPath = isSpine ? sourcePath : consumerPath;
      const parentKey =
        insertContainerPath.length > 0
          ? (insertContainerPath[insertContainerPath.length - 1] ?? "")
          : "";
      const map = ensureInsertionMap(parentKey);
      const anchorKey = isSpine ? edge.from : edge.to;
      const list = map.get(anchorKey) ?? [];
      list.push(rId);
      map.set(anchorKey, list);
    }
    newEdges.push({ from: rId, to: effectiveTo, auxKey: edge.auxKey, kind: edge.kind });
  }

  // Build replacement childIds for each affected container + rootIds.
  // Splice runs FIRST (inserts replicas before their original-consumer
  // anchor ids), THEN the dead-id filter strips fully-replicated source
  // ids. Doing it in this order means replicas land in the right
  // relative slot even when their consumer is itself fully replicated:
  //   pre-splice  : [..., A, B, ...]                  (A and B both `always`)
  //   post-splice : [..., A@->B, A, B@->C, B, ...]
  //   post-filter : [..., A@->B, B@->C, ...]          (A and B removed)
  // The resulting spine reads cleanly through the replica chain.
  const splice = (childIds: readonly string[], byConsumer: Map<string, string[]>) => {
    const out: string[] = [];
    for (const id of childIds) {
      const ins = byConsumer.get(id);
      if (ins) out.push(...ins);
      out.push(id);
    }
    return out;
  };

  const stripDead = (ids: readonly string[]): string[] =>
    ids.filter((id) => !fullyReplicated.has(id));

  const newContainers = graph.containers.map((c) => {
    const ins = insertionsByParent.get(c.id);
    const spliced = ins ? splice(c.childIds, ins) : c.childIds;
    const stripped = stripDead(spliced);
    if (stripped === c.childIds) return c;
    return { ...c, childIds: stripped };
  });

  const rootInsertions = insertionsByParent.get("");
  const rootSpliced = rootInsertions ? splice(graph.rootIds, rootInsertions) : graph.rootIds;
  const newRootIds = stripDead(rootSpliced);

  // Filter fully-replicated source nodes out of `nodes`. The original
  // chip is gone from the graph; click-to-scrub on the source's trace
  // frame still works via the linear-list sidebar (which reads the
  // trace, not the graph) and via `replicaOf` on any replica chip.
  const newNodes = graph.nodes.filter((n) => !fullyReplicated.has(n.stepId));

  return {
    nodes: [...newNodes, ...replicas.values()],
    containers: newContainers,
    edges: newEdges,
    rootIds: newRootIds,
  };
};

// ─── Validation (Slice 9) ──────────────────────────────────────────────────

/**
 * A structural issue detected on a (graph, trace) pair. Surfaced by the
 * `GraphView` as overlay warning dots so a user editing a spec via the
 * palette gets immediate feedback when their wiring is broken.
 *
 * Three variants today:
 *
 *   - **`orphaned-read`** — a step requested an aux key for which no
 *     upstream step ever produced a value. Detected from
 *     `frame.auxReadMissing` (populated by the runtime). Today's strict
 *     consumers (e.g. `add-round-key`) THROW on missing aux rather than
 *     producing a frame, so this warning will only light up once Slice 10's
 *     graceful aux primitives (`aux-xor`, `aux-copy`) land. The plumbing
 *     is in place now so the visual editor can flag the issue without
 *     waiting for those steps.
 *
 *   - **`unused-write`** — a step wrote an aux key that nothing downstream
 *     consumed. Common pedagogical mistake: drag in `key-expansion` but
 *     forget to wire any `add-round-key`. Detected by diffing each frame's
 *     `auxWritten` against the producer-set of `graph.edges`.
 *
 *   - **`cycle`** — a cycle in the directed graph of aux + state edges.
 *     Acyclic by construction for any (spec, trace) the runtime can produce
 *     (writers are timestamped forward; consumers always sit after their
 *     writer). Included for defense in depth so a future refactor that
 *     introduces edge synthesis from non-trace sources can't silently
 *     hand a malformed graph to the renderer.
 *
 *   - **`state-shape-mismatch`** — a leaf declares (via its registered
 *     `shapeContract`) that it consumes a specific `StateShape`, but the
 *     spec-inferred shape arriving at that position is something else.
 *     Detected statically by `validateShapes` in `core/spec-shapes.ts` —
 *     does NOT need a trace, so the warning lights up the moment the user
 *     drops a shape-incompatible step from the palette. Surfaces the
 *     "compute-block-count expects bytes state" runtime exception as a
 *     pre-Run advisory instead.
 *
 * `stepId` fields carry the *canonical* (post `:b{i}` strip) id, matching
 * `GraphNode.stepId`, so the renderer can index warnings by node id
 * directly. For orphaned reads inside an iterate body, the warning fires
 * once per logical step (not N times per block) thanks to the dedup.
 */
export type GraphWarning =
  | { readonly kind: "orphaned-read"; readonly stepId: string; readonly auxKey: string }
  | { readonly kind: "unused-write"; readonly stepId: string; readonly auxKey: string }
  | { readonly kind: "cycle"; readonly stepIds: readonly string[] }
  | {
      readonly kind: "state-shape-mismatch";
      readonly stepId: string;
      readonly expected: StateShape | "any";
      readonly got: StateShape;
    };

/**
 * Walk a directed adjacency list and return the first cycle found via
 * iterative DFS with a recursion-stack set. Returns the ordered sequence
 * of node ids that form the cycle (start == end is implicit; the start id
 * appears once at the head).
 *
 * Iterative (not recursive) because deeply nested specs would blow the JS
 * stack on a recursive walker. The trade-off is a tiny bit more state to
 * shuttle (an explicit `stack` of `{node, childIndex}` pairs), but it caps
 * memory at O(graph depth) regardless of engine.
 */
const findFirstCycle = (adjacency: ReadonlyMap<string, readonly string[]>): string[] | null => {
  const VISITING = 1;
  const DONE = 2;
  const color = new Map<string, number>();
  // Parent pointer for reconstructing the cycle path when a back-edge is found.
  const parent = new Map<string, string | null>();

  for (const startNode of adjacency.keys()) {
    if (color.get(startNode) === DONE) continue;
    // Stack frame: [node, iterator over its children's indices].
    const stack: { node: string; childIdx: number }[] = [{ node: startNode, childIdx: 0 }];
    color.set(startNode, VISITING);
    parent.set(startNode, null);

    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      if (!top) break;
      const children = adjacency.get(top.node) ?? [];
      if (top.childIdx >= children.length) {
        // No more children — pop and mark DONE.
        color.set(top.node, DONE);
        stack.pop();
        continue;
      }
      const child = children[top.childIdx++];
      if (child === undefined) continue;
      const childColor = color.get(child);
      if (childColor === VISITING) {
        // Back-edge: walk the parent chain from `top.node` back up until
        // we hit `child` (which is somewhere on the active stack). The
        // resulting sequence, reversed, is the cycle.
        const cycle: string[] = [child];
        let cursor: string | null = top.node;
        while (cursor !== null && cursor !== child) {
          cycle.push(cursor);
          cursor = parent.get(cursor) ?? null;
        }
        cycle.reverse();
        return cycle;
      }
      if (childColor === DONE) continue;
      color.set(child, VISITING);
      parent.set(child, top.node);
      stack.push({ node: child, childIdx: 0 });
    }
  }

  return null;
};

/**
 * Build a predicate that classifies an edge as "iterate feedback" — the
 * cross-iteration aux flow inherent to chaining modes like CBC/OFB/CFB.
 * After the runtime's `:b{i}` suffix stripping during graph derivation,
 * an aux write from `cbc-snapshot:b0` to `aux[chain]` followed by a read
 * by `cbc-xor:b1` collapses to a single canonical edge `cbc-snapshot →
 * cbc-xor` — and that edge goes BACKWARDS in spec order, since
 * `cbc-snapshot` is the body's last leaf and `cbc-xor` is its first.
 *
 * Two consumers share this predicate:
 *
 *   1. **`validateGraph`** — uses it to exclude feedback edges from cycle
 *      detection so the legitimate iterate-feedback edge plus the forward
 *      state spine inside the same body don't trigger a false "cycle"
 *      warning. The filter rule is exact, not heuristic: with the
 *      executor contract `(state, params) → state` and aux writes
 *      happening in spec order, the ONLY way an edge `writer → reader`
 *      can exist with `writer` AFTER `reader` in spec order is the
 *      `:b{i}` collapse case.
 *
 *   2. **The graph renderer** (`src/ui/components/GraphView.tsx`) — uses
 *      it to render feedback edges with a distinctive style (dashed
 *      stroke + lower opacity). Without this, users see "snapshot
 *      points back to xor" rendered as an ordinary forward arrow and
 *      can mistake it for a bug. OFB/CFB will hit the same pattern when
 *      they land, so shared detection here is the seam.
 *
 * Returned predicate is pure over the snapshotted graph indexes; safe to
 * call inside a Solid `createMemo` and reuse across all edges in a render
 * pass. State edges always return false — they're forward-only by
 * construction.
 */
export const buildIterateFeedbackPredicate = (
  graph: CipherGraph,
): ((edge: GraphEdge) => boolean) => {
  // Pre-order DFS spec-order: parent < children < parent's next sibling.
  // We need this so `cbc-blocks < cbc-xor < ... < cbc-snapshot`, which
  // makes the backwards edge `cbc-snapshot → cbc-xor` correctly trigger
  // `fromOrder > toOrder`. Walking rootIds + each container's childIds
  // preserves spec order because both are populated in spec order during
  // `walkSpec` and `deriveAuxGraph`.
  const specOrder = new Map<string, number>();
  const containerById = new Map<string, ContainerNode>();
  for (const c of graph.containers) containerById.set(c.id, c);
  {
    let order = 0;
    const orderWalk = (ids: readonly string[]): void => {
      for (const id of ids) {
        specOrder.set(id, order++);
        const c = containerById.get(id);
        if (c) orderWalk(c.childIds);
      }
    };
    orderWalk(graph.rootIds);
  }

  // containerPath + iterate-id lookups. Both leaves and iterate containers
  // can participate in edges (the iterate-mediated aux synthesis makes the
  // container an edge participant).
  const pathById = new Map<string, readonly string[]>();
  for (const n of graph.nodes) pathById.set(n.stepId, n.containerPath);
  for (const c of graph.containers) pathById.set(c.id, c.containerPath);

  const iterateIds = new Set<string>();
  for (const c of graph.containers) {
    if (c.kind === "iterate") iterateIds.add(c.id);
  }

  // Deepest common iterate ancestor of two containerPaths. Returns undefined
  // when none — those edges are eligible for normal cycle detection.
  // "Deepest common" not "any common": two nodes sharing a `group` ancestor
  // but not an iterate ancestor is a legitimate cycle scope (a real cycle
  // there should be flagged).
  const deepestCommonIterate = (a: readonly string[], b: readonly string[]): string | undefined => {
    const maxLen = Math.min(a.length, b.length);
    let deepest: string | undefined;
    for (let i = 0; i < maxLen; i++) {
      const ai = a[i];
      if (ai === undefined || ai !== b[i]) break;
      if (iterateIds.has(ai)) deepest = ai;
    }
    return deepest;
  };

  return (edge: GraphEdge): boolean => {
    // State edges are forward-only by construction; never feedback.
    if (edge.kind !== "aux") return false;
    // Synthetic endpoint pills (Slice 1) carry kind:"state" edges to the
    // first/last state-consumer leaf. Today the predicate already short-
    // circuits state edges above, but a future renderer change that
    // re-classifies endpoint edges as aux would silently pull them
    // through the feedback styling — the explicit guard makes the
    // exclusion intent visible and survives refactors.
    if (isEndpointId(edge.from) || isEndpointId(edge.to)) return false;
    const fromPath = pathById.get(edge.from);
    const toPath = pathById.get(edge.to);
    if (fromPath === undefined || toPath === undefined) return false;
    if (deepestCommonIterate(fromPath, toPath) === undefined) return false;
    const fromOrder = specOrder.get(edge.from);
    const toOrder = specOrder.get(edge.to);
    if (fromOrder === undefined || toOrder === undefined) return false;
    return fromOrder > toOrder;
  };
};

/**
 * Static analysis of a derived graph + the trace it came from. Pure
 * function — no I/O, no side effects, deterministic.
 *
 * Why two inputs (graph + trace) rather than just the graph as the plan
 * sketched: orphaned-read detection needs the per-frame `auxReadMissing`
 * info, which isn't preserved in the graph's edges (the graph deliberately
 * stores only realized dataflow). Splitting it out into a second arg keeps
 * the graph itself a clean "what actually happened" snapshot.
 *
 * Returns warnings in a stable order:
 *   1. orphaned-reads in trace-frame order
 *   2. unused-writes in trace-frame order
 *   3. cycles (at most one in practice; the search returns on first hit)
 *
 * Calling on an empty trace produces no warnings — the graph is
 * structure-only and we have no read/write events to inspect.
 */
export const validateGraph = (graph: CipherGraph, trace: Trace): GraphWarning[] => {
  const warnings: GraphWarning[] = [];

  // ─── Orphaned reads ──────────────────────────────────────────────────────
  // The runtime stamps `auxReadMissing` on any frame whose step requested an
  // aux key with no upstream producer. Dedup by (canonical stepId, auxKey)
  // so multi-block iterates don't flag the same logical issue 16 times.
  const seenOrphan = new Set<string>();
  for (const frame of trace.frames) {
    if (!frame.auxReadMissing || frame.auxReadMissing.length === 0) continue;
    const stepId = stripBlockSuffix(frame.stepId);
    for (const auxKey of frame.auxReadMissing) {
      const key = `${stepId}\x00${auxKey}`;
      if (seenOrphan.has(key)) continue;
      seenOrphan.add(key);
      warnings.push({ kind: "orphaned-read", stepId, auxKey });
    }
  }

  // ─── Unused writes ───────────────────────────────────────────────────────
  // For each aux-key write, check whether the writer participates in at
  // least one outgoing aux edge for that key. If not, the value sat
  // unconsumed in the aux map — surface it.
  //
  // The graph's edges record (from, auxKey) pairs after `:b{i}` collapse,
  // so we look up by the canonical stepId. Indexing the producer set once
  // costs O(edges); each lookup is O(1).
  const producerEdges = new Set<string>();
  for (const edge of graph.edges) {
    if (edge.kind !== "aux") continue;
    producerEdges.add(`${edge.from}\x00${edge.auxKey}`);
  }
  const seenUnused = new Set<string>();
  for (const frame of trace.frames) {
    if (frame.auxWritten.size === 0) continue;
    const stepId = stripBlockSuffix(frame.stepId);
    for (const auxKey of frame.auxWritten.keys()) {
      const key = `${stepId}\x00${auxKey}`;
      if (seenUnused.has(key)) continue;
      seenUnused.add(key);
      if (!producerEdges.has(key)) {
        warnings.push({ kind: "unused-write", stepId, auxKey });
      }
    }
  }

  // ─── Cycles ──────────────────────────────────────────────────────────────
  // Build an adjacency list over BOTH aux and state edges (a future Feistel
  // branching primitive could in principle create a cycle that crosses the
  // state thread; cheap to include both today). Search; surface the first
  // cycle found.
  //
  // **Iterate-feedback exclusion.** The runtime emits per-iteration frames
  // with `:b{i}`-suffixed stepIds; deriveAuxGraph strips that suffix so
  // iteration replicas collapse into one canonical node per logical leaf.
  // That collapse also collapses cross-iteration aux flow: in CBC,
  // `cbc-snapshot:b0` writes `aux[chain]` and `cbc-xor:b1` reads it; after
  // the strip both endpoints canonicalize to `cbc-snapshot` and `cbc-xor`,
  // producing an edge `cbc-snapshot → cbc-xor` that goes BACKWARDS in the
  // iterate body's spec order. Combined with the forward state spine
  // (`cbc-xor → ... → cbc-snapshot`), the cycle detector would flag the
  // entire iterate body. That's a false positive — the real dataflow is
  // acyclic when per-iteration ordering is respected.
  //
  // The filter rule is exact, not heuristic: with the executor contract
  // `(state, params) → state` and aux writes happening in spec order, the
  // ONLY way an edge `writer → reader` can exist with `writer` downstream
  // of `reader` is the `:b{i}`-collapse case above. So we suppress any aux
  // edge that (a) has its endpoints inside the same iterate ancestor AND
  // (b) goes backwards in spec order within that iterate. State edges are
  // never filtered — `inferStateEdges` only emits forward edges by
  // construction, and a backwards state edge would indicate a real bug.
  //
  // The edge stays in `graph.edges`, so the renderer still draws it (the
  // user wants to see the chain feedback). Only the cycle detector
  // ignores it. A future renderer feature could draw feedback edges with
  // a distinctive style (curved arrow, dashed); tracked in the graph-view
  // UX polish memory entry.

  const isIterateFeedback = buildIterateFeedbackPredicate(graph);

  const adjacency = new Map<string, string[]>();
  for (const edge of graph.edges) {
    if (isIterateFeedback(edge)) continue;
    const list = adjacency.get(edge.from) ?? [];
    list.push(edge.to);
    adjacency.set(edge.from, list);
  }
  const cycle = findFirstCycle(adjacency);
  if (cycle !== null) {
    warnings.push({ kind: "cycle", stepIds: cycle });
  }

  return warnings;
};

// ─── Public entry point ────────────────────────────────────────────────────

/**
 * Caller-supplied configuration for synthetic plaintext/ciphertext pills.
 * When this options object is omitted, `deriveAuxGraph` produces no
 * endpoint pills — the graph stays exactly as it was before Slice 1.
 *
 * Why this is opt-in: every existing test calls `deriveAuxGraph(trace,
 * spec)` and asserts node counts; injecting pills unconditionally would
 * break ~50 sites. The renderer opts in by passing labels + anchors;
 * tests can opt in as needed.
 *
 * `inputAnchorId` / `outputAnchorId` are the canonical ids (leaf stepId
 * or container id) where the input / output state edges terminate. When
 * a caller doesn't have a registry handy and can't compute the
 * first-state-consumer anchor, they can pass `undefined` and the
 * function falls back to `rootIds[0]` / `rootIds[rootIds.length - 1]`.
 * The renderer (`GraphView.tsx`) walks the registry to skip aux-only
 * leaves like `aes.key-expansion@1` so the pedagogical arrow lands on
 * the first leaf that actually reads state.
 */
export type EndpointOptions = {
  readonly inputLabel: string;
  readonly outputLabel: string;
  readonly inputAnchorId?: string;
  readonly outputAnchorId?: string;
};

/**
 * Derive an aux-flow graph from a spec + trace.
 *
 * The spec contributes structure (nodes, containers, child relationships,
 * rootIds). The trace contributes data flow (edges) and `blockSpan` on
 * iterate-body nodes. Passing an empty trace returns a structure-only graph
 * with no edges and no blockSpans — the natural state before the first run.
 *
 * When `opts.endpoints` is provided, two synthetic endpoint pills
 * (`__cipher_input__` and `__cipher_output__`) are appended to `nodes`
 * and `kind: "state"` edges connect them to the configured anchors.
 * The pills are prepended/appended to `rootIds` so the layout pass
 * places them at the canvas extremes naturally.
 */
export const deriveAuxGraph = (
  trace: Trace,
  spec: CipherSpec,
  opts?: { readonly endpoints?: EndpointOptions },
): CipherGraph => {
  const ctx: BuildContext = {
    nodes: [],
    containers: [],
    iteratesById: new Map(),
    feistelsById: new Map(),
    leafIndex: new Map(),
    containerIndex: new Map(),
  };

  const rootIds = walkSpec(spec.steps, [], ctx);
  annotateBlockSpans(trace, ctx);
  // Aux edges come from trace-walking (empty trace → empty list); state
  // edges come from spec-walking (always present, even pre-run). Append
  // state edges AFTER aux edges so existing tests that index the edge
  // list by position continue to work, and so a reader scanning the
  // dataflow sees the annotations first and the spine last.
  const edges = [...deriveEdges(trace, ctx), ...inferStateEdges(spec)];

  // ─── Optional endpoint pill injection (Slice 1) ──────────────────────────
  //
  // Order matters relative to the consumers downstream:
  //   - `collapseGraph` runs after this. Endpoints have `containerPath: []`
  //     so they're never hidden by a collapsed ancestor — safe.
  //   - `replicateHighFanoutSources` runs after collapse. It only counts
  //     `kind: "aux"` edges as candidates, so the endpoint state edges
  //     can't trigger replication — safe.
  //   - The renderer prepends/appends endpoint ids to `rootIds` so the
  //     layout's left-to-right walk naturally places them at the extremes.
  //
  // If `rootIds` is empty (empty spec), endpoint injection is suppressed
  // — there's nothing to anchor to, and a floating "plaintext" pill
  // would be confusing.
  if (opts?.endpoints && rootIds.length > 0) {
    const ep = opts.endpoints;
    const inputAnchor = ep.inputAnchorId ?? rootIds[0];
    const outputAnchor = ep.outputAnchorId ?? rootIds[rootIds.length - 1];

    const endpointNodes: GraphNode[] = [
      {
        stepId: CIPHER_INPUT_ID,
        stepType: ENDPOINT_STEP_TYPE,
        label: ep.inputLabel,
        containerPath: [],
        endpointSide: "input",
      },
      {
        stepId: CIPHER_OUTPUT_ID,
        stepType: ENDPOINT_STEP_TYPE,
        label: ep.outputLabel,
        containerPath: [],
        endpointSide: "output",
      },
    ];

    // kind:"state" so the renderer styles the endpoint edges as spine
    // (thicker, darker, less translucent) — matching how a viewer reads
    // "this is the cipher's primary dataflow" through the rest of the
    // pipeline. State edges are forward-only and never feedback; the
    // explicit guards in `buildIterateFeedbackPredicate` and validation
    // back this up so a future re-classification can't silently regress.
    if (inputAnchor !== undefined) {
      edges.push({
        from: CIPHER_INPUT_ID,
        to: inputAnchor,
        auxKey: STATE_AUX_KEY,
        kind: "state",
      });
    }
    if (outputAnchor !== undefined) {
      edges.push({
        from: outputAnchor,
        to: CIPHER_OUTPUT_ID,
        auxKey: STATE_AUX_KEY,
        kind: "state",
      });
    }

    return {
      nodes: [...ctx.nodes, ...endpointNodes],
      containers: ctx.containers,
      edges,
      rootIds: [CIPHER_INPUT_ID, ...rootIds, CIPHER_OUTPUT_ID],
    };
  }

  return {
    nodes: ctx.nodes,
    containers: ctx.containers,
    edges,
    rootIds,
  };
};
