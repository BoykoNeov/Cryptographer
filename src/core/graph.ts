/**
 * Aux-graph derivation: turn a (spec, trace) pair into a directed graph
 * suitable for the upcoming 2D visual editor. Nodes are the spec's leaves,
 * containers are its groups and iterates, and edges encode two kinds of
 * dataflow:
 *
 *   - **Aux edges** (trace-derived) — round-key fan-out, IV chaining in
 *     CBC, keystream blocks in CTR, etc. Annotations on the cipher's
 *     primary dataflow.
 *   - **State edges** (spec-derived) — the cipher's primary dataflow
 *     spine, derived from each leaf's declared `portInputs` wiring
 *     (`inferPortEdges`). The headline pedagogical spine of the graph:
 *     students see the SubBytes → ShiftRows → MixColumns → AddRoundKey
 *     progression as a continuous chain. (Until Slice 5.3e this spine was
 *     inferred from the implicit `(state, params) → state` thread between
 *     consecutive leaves; every shipped spec is now port-wired, so the
 *     spine IS the declared port flow.)
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
 *   3. **Iterate boundaries are port-mediated.** The spine is derived from
 *      declared `portInputs` (`inferPortEdges`), so an iterate's body
 *      connects to the surrounding pipeline through its explicit
 *      `seedInput` / `chainInput` / `chainFeedback` port bindings (the
 *      byte-native ECB/CBC modes wire `seedInput = port($input, …)`), and
 *      its per-iteration body is its own port-flow scope. There is no
 *      bridging `B→C` edge across an iterate because no leaf declares a
 *      `portInputs` binding that reaches across the boundary; the aux
 *      arrows (`blocksFromAux` in, `outBlocksAux` out) ARE the handoff.
 *      (Until Slice 5.3e this was enforced negatively by `inferStateEdges`
 *      SUPPRESSING a consecutive-leaf bridge — the 2026-05-17 phantom
 *      `compute-block-count → ecb-blocks` edge that resolved to the
 *      plaintext bytes the iterate never consumed. With the legacy
 *      inference retired, the port-flow spine simply has nothing to draw
 *      there unless a binding says so.)
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

import type { StepRegistry } from "./registry";
import { canonicalStepId } from "./step-id";
import type { CipherSpec, IterateGroup, PortBinding, StateShape, StepNode, Trace } from "./types";
import { INPUT_SOURCE_ID } from "./types";

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
   *   - `"for-each-subgraph"` — port-native iteration primitive (Slice 2.0a
   *     of `docs/plans/universal-port-phase-2-slices.md`). State threads
   *     across iterations (unlike `"iterate"`, which clobbers state from
   *     an aux array). Slice 2.0a routes it through iterate's spine-
   *     termination behavior; richer rendering (round-count badge,
   *     collapse semantics) lands in Slice 2.10. Until then the container
   *     is treated like an iterate by the spine + chain emitters; the
   *     graph view shows it as a labeled box around its children.
   *   - `"for-each-subgraph-with-history"` — per-iteration lookback
   *     primitive (Slice 2.0c). Body reads named priors from a runtime-
   *     maintained history buffer via `aux["prior-{N}"]`. Like the
   *     other two iteration kinds the container piggybacks on iterate's
   *     spine-termination semantics: the parent-scope spine treats the
   *     node as one chain boundary; per-iteration spine within the body
   *     is its own scope. Honest depiction is "aux lookback arrows from
   *     the runtime-virtual history buffer into each iteration's body
   *     leaf" — that rendering surface lands when SHA-256 graph view
   *     polish ships (Slice 2.10); until then the lookback reads
   *     surface as `aux["prior-{N}"]` keys missing a producer, which the
   *     `validateGraph` orphan-read warning catches and renders as an
   *     orange dot the user can hover for explanation.
   */
  readonly kind: "group" | "iterate" | "for-each-subgraph" | "for-each-subgraph-with-history";
  readonly id: string;
  readonly label: string;
  /** Ancestor container ids, root-first (excludes this container itself). */
  readonly containerPath: readonly string[];
  /** Direct children's ids (leaves and nested containers, in spec order). */
  readonly childIds: readonly string[];
  /** Iterate's iteration count from the trace (undefined for groups). */
  readonly blockSpan?: number;
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

/** True iff `id` is a synthetic endpoint pill. Cheap branch test reused by
 *  `buildIterateFeedbackPredicate` and `validateGraph` to short-circuit any
 *  edge that touches a pill. `INPUT_SOURCE_ID` (`$input`, scaffolding-
 *  suppression A3a) renders as the input pill for port-native specs and so
 *  joins the family. */
export const isEndpointId = (id: string): boolean =>
  id === CIPHER_INPUT_ID || id === CIPHER_OUTPUT_ID || id === INPUT_SOURCE_ID;

// ─── Internal helpers ──────────────────────────────────────────────────────

/**
 * Strip the runtime's per-iteration suffixes (`:b{i}` / `:r{i}`) from a
 * step id. The full canonicalization lives in `@/core/step-id`; this thin
 * wrapper preserves the local name for the dedup call sites below.
 */
const stripBlockSuffix = (stepId: string): string => canonicalStepId(stepId);

type BuildContext = {
  readonly nodes: GraphNode[];
  readonly containers: ContainerNode[];
  /** All iterate definitions indexed by id, for the edge-synthesis pass. */
  readonly iteratesById: Map<string, IterateGroup>;
  /** Canonical leaf stepIds indexed for blockSpan annotation. */
  readonly leafIndex: Map<string, number>;
  /** Iterate-container indices, also for blockSpan annotation. */
  readonly containerIndex: Map<string, number>;
  /**
   * Looping containers that publish their exit value into an aux scratchpad
   * via `outputAux` (scaffolding-suppression A3a), indexed by container id →
   * aux key. The runtime's `outputAux` write is silent (no `TraceFrame`), so
   * `deriveEdges` stamps the container as that aux key's writer at the
   * container's trace-exit boundary — mirroring how `iterate.outBlocksAux` is
   * stamped — so downstream `aux-load-bytes@1` reads (SHA-256's 64 rounds
   * reading `aux["W"]`) draw an edge from the container instead of orphaning.
   */
  readonly outputAuxByContainerId: Map<string, string>;
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
    } else if (node.kind === "for-each-subgraph") {
      // For-each-subgraph (Slice 2.0a). Treated as its own container kind
      // in the graph data model so future renderer polish (round-count
      // badge, collapse semantics) can switch on it. Slice 2.0a routes
      // spine + chain through the iterate-shaped branch. (The spine itself
      // comes from declared `portInputs` via `inferPortEdges`; the legacy
      // consecutive-siblings inference + its iterate-boundary termination
      // retired with `inferStateEdges` in Slice 5.3e.)
      const cIdx = ctx.containers.length;
      ctx.containerIndex.set(node.id, cIdx);
      ctx.containers.push({
        kind: "for-each-subgraph",
        id: node.id,
        label: node.label ?? node.id,
        containerPath,
        childIds: grandChildIds,
      });
    } else if (node.kind === "for-each-subgraph-with-history") {
      // For-each-subgraph-with-history (Slice 2.0c). Own container kind
      // for the same reasons as for-each-subgraph — future renderer
      // polish (lookback-arrow overlay, history-strip visualization)
      // will switch on this label. Spine + chain treatment piggybacks
      // on iterate's boundary semantics via `processScope` below.
      const cIdx = ctx.containers.length;
      ctx.containerIndex.set(node.id, cIdx);
      ctx.containers.push({
        kind: "for-each-subgraph-with-history",
        id: node.id,
        label: node.label ?? node.id,
        containerPath,
        childIds: grandChildIds,
      });
      // A3a: record the aux scratchpad this container publishes to at exit,
      // so `deriveEdges` can stamp it as that key's writer (no TraceFrame
      // carries the runtime's `outputAux` write).
      if (node.outputAux !== undefined) {
        ctx.outputAuxByContainerId.set(node.id, node.outputAux);
      }
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

  // A3a: parallel tracking for looping containers that publish to an aux
  // scratchpad via `outputAux`. On the container's trace-exit boundary we
  // stamp it as that aux key's writer, so downstream `aux-load-bytes@1` reads
  // (SHA-256's 64 rounds reading `aux["W"]`) draw a natural edge from the
  // container — the runtime's `outputAux` write carries no TraceFrame, so the
  // natural `auxWritten` pass below never sees it.
  let prevOutputAuxIdsInPath: ReadonlySet<string> = new Set();

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
      // Aux mode only — port-mode iterates (byte-native ECB, B1.4) have no
      // count/blocks aux keys; their seed/output edges are port edges drawn
      // by `inferPortEdges`.
      for (const auxKey of [iter.countFromAux, iter.blocksFromAux]) {
        if (auxKey === undefined) continue;
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
      if (iter.outBlocksAux !== undefined) writerByAuxKey.set(iter.outBlocksAux, iid);
    }

    prevIterateIdsInPath = currentIterateIdsInPath;

    // outputAux-container exit (A3a): same boundary detection as the iterate
    // `outBlocksAux` stamp above, but for FES-with-history containers that
    // publish their full history into `aux[outputAux]`. On exit, stamp the
    // container id as that aux key's writer so downstream reads (the rounds'
    // `aux["W"]` fetches) get a natural edge from the schedule container.
    const currentOutputAuxIdsInPath = new Set<string>();
    for (const id of frame.path) {
      if (ctx.outputAuxByContainerId.has(id)) currentOutputAuxIdsInPath.add(id);
    }
    for (const cid of prevOutputAuxIdsInPath) {
      if (currentOutputAuxIdsInPath.has(cid)) continue;
      const auxKey = ctx.outputAuxByContainerId.get(cid);
      if (auxKey !== undefined) writerByAuxKey.set(auxKey, cid);
    }
    prevOutputAuxIdsInPath = currentOutputAuxIdsInPath;

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
    if (iter.outBlocksAux !== undefined) writerByAuxKey.set(iter.outBlocksAux, iid);
  }
  // Symmetric drain for outputAux containers still active at trace end
  // (no-op for SHA-256, where the schedule exits before the rounds run).
  for (const cid of prevOutputAuxIdsInPath) {
    const auxKey = ctx.outputAuxByContainerId.get(cid);
    if (auxKey !== undefined) writerByAuxKey.set(auxKey, cid);
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
 * Sentinel aux key carried on every port-flow edge (Slice S2(e), 2026-05-26
 * — `docs/plans/sha-256-density-polish.md`). Tags a spine edge declared by
 * `portInputs` (real bytes from an upstream output port to a downstream
 * input port) as distinct from the only other `kind: "state"` edges: the
 * endpoint-pill edges (input/output anchors), which carry
 * `auxKey: STATE_AUX_KEY` ("state").
 *
 * Both classes share `kind: "state"` so the renderer paints them
 * identically as the cipher's primary spine. The discriminator lives on
 * `auxKey` so consumers that care about provenance can tell them apart —
 * most importantly `replicateHighFanoutSources`'s S2(i) fanout-eligibility
 * predicate, which counts a port-native source's fan-out to N consumers
 * but not the endpoint anchors.
 *
 * (Historical: the discriminator was introduced so the now-retired
 * `dropAuxOnlyStateEdges` filter could KEEP port-flow edges from lifted
 * aux-only roots — `H-constant → init-working-vars`, `final.fetch-H →
 * final.split-H` on SHA-256 — while dropping the legacy consecutive-siblings
 * passthrough edges. Both that filter and the legacy `inferStateEdges`
 * inference retired in Slice 5.3e; the auxKey tag survives for the renderer
 * + replication.)
 */
export const PORT_FLOW_AUX_KEY = "port-flow";

/**
 * Spec-walk pass: emit a `kind: "state"` edge for every `portInputs`
 * binding the spec declares (universal-port plan Phase 2 Slice S2(e),
 * 2026-05-26 — see `docs/plans/sha-256-density-polish.md`).
 *
 * For each leaf with `portInputs`, every entry `(inputPortName →
 * { node, port })` produces a single edge `{ from: node, to: leaf.id,
 * kind: "state", auxKey: PORT_FLOW_AUX_KEY }`. The kind reuses `"state"`
 * rather than introducing a new `"port"` kind so the renderer paints
 * port-flow as the spine (thicker, darker — exactly the "this is the
 * cipher's primary dataflow" reading the user expects). Since Slice 5.3e
 * this is the SOLE spine source — the legacy consecutive-siblings
 * inference (`inferStateEdges`) was retired, so every spine edge a reader
 * sees originates here.
 *
 * **Per-cipher reality (updated 2026-05-31, post-B-phase + Slice 5.2/5.3b —
 * supersedes the original S2(e) note).** EVERY shipped cipher/hash now declares
 * explicit spec `portInputs`, so their spine is composed ENTIRELY of
 * port-derived edges: SHA-256, DES, native-AES, AES-CBC, and —
 * since Slice 5.3b — Speck and Serpent. Speck/Serpent round leaves are
 * hybrid-ported (meta present) but declare `portInputs.state`; Serpent's round
 * GROUPS additionally declare `seedInput`/`bodyOutput`, so each round→round
 * handoff resolves through the group's single-hop seed to a container source.
 * With every shipped spec port-wired, this pass owns the ENTIRE spine: the
 * legacy `inferStateEdges` consecutive-siblings inference (and its per-edge
 * S2(f) skip-gate) was retired in Slice 5.3e. See
 * `docs/plans/phase-5-legacy-retirement.md`.
 *
 * **Why this needed to exist.** Pre-S2(e) `deriveAuxGraph` did not
 * consume `portInputs` — Slice 2.6a wired the runtime + spec-shapes
 * validator to honor declared port edges, but the graph derivation
 * was missed. Symptom on SHA-256: `final.s_0` (which reads from
 * `split-wv.output0` AND `split-H.output0`) showed zero or one
 * incoming edge instead of two; `final.assemble` showed one instead
 * of eight; `H-constant` showed no outgoing edges at all. The visible
 * "state" edges in port-native scopes came from the legacy
 * consecutive-siblings rule and were mislabeled — they represented
 * port-flow, not the implicit (state, params) → state thread.
 *
 * **Edge scope.** Same-scope (sibling) wiring only — runtime contract
 * documented at `runtime.ts:155-161`. The runtime throws on cross-
 * scope `portInputs` resolution; the spec-shapes validator emits
 * `port-input-unresolvable` pre-Run. By the time `deriveAuxGraph`
 * runs on a valid spec, every binding's `node` reference is a sibling
 * in the same walk frame. We emit one edge per declaration; an
 * upstream guard catches malformed ones before they reach here.
 *
 * **Container `portInputs` consciously skipped.** Types declare the
 * field on every container kind (group, iterate, for-each-subgraph,
 * for-each-subgraph-with-history) but the runtime
 * documents "no container kind reads explicit portInputs at its
 * boundary — the field is declared on every container type so the
 * schema + types are uniform, but the runtime doesn't yet consume
 * it on containers. Pure forward-compatibility" (`types.ts:144-152`).
 * Walking container portInputs here would draw edges the runtime
 * doesn't honor. Revisit when the first container kind starts
 * reading them.
 */
const inferPortEdges = (spec: CipherSpec): GraphEdge[] => {
  const edges: GraphEdge[] = [];

  // A3b: a `group` with `seedInput` injects the carried bytes into its body as
  // `port(groupId, "in")` (the runtime seeds the body scope; spec-shapes
  // mirrors it). A body leaf that reads `{ node: groupId, port: "in" }` is
  // therefore really consuming `seedInput.node`'s output, so we resolve the
  // edge source THROUGH the group's seedInput — turning the otherwise self-
  // referential `groupId → leaf` edge into a real cross-group edge. For
  // SHA-256 this IS the port-to-port round carry: `round.{t}.split` reads
  // `port("round.{t}", "in")`, which resolves to `round.{t-1}`'s published
  // exit (round 0 to `init.fetch-H`) — the connective tissue of the collapsed
  // round chain now that the `state-in`/`state-out` bridges are gone. Without
  // this the rounds would render as disconnected islands.
  const groupSeedByGroupId = new Map<string, PortBinding>();
  // B1.5 Finding 2: a port-mode `iterate` with `chainInput` (byte-native CBC,
  // B1.4b) injects a per-iteration chain value as `port(iterateId, "chain")` —
  // the IV (`chainInput`) for block 0, then `chainFeedback` thereafter. A body
  // leaf reading `port(iterateId, "chain")` (the CBC chaining XOR) is really
  // consuming `chainInput.node`'s output (`fetch-iv`), so we resolve the chain
  // edge THROUGH the iterate's `chainInput`, exactly as the `"in"` path resolves
  // through `seedInput`. Without this the edge points at the container itself
  // (the spurious "whole block body → cbc-xor" arrow) and `fetch-iv`'s output is
  // read by nobody → floats unconnected. We deliberately resolve ONLY the
  // bootstrap `chainInput`; the per-iteration `chainFeedback` recurrence is a
  // separate recurrence-visibility pass (`types.ts` defers it).
  const chainSeedByIterateId = new Map<string, PortBinding>();
  const collectGroupSeeds = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      if (node.kind === "step") continue;
      // A port-mode `iterate` (byte-native ECB, B1.4) injects its per-block
      // bytes as `port(iterateId, "in")` the same way A3b groups inject their
      // seed — so a body head reading `port(iterateId, "in")` resolves through
      // the iterate's `seedInput` to the real producer ($input / the pad),
      // rather than drawing a self-referential `iterateId → leaf` island edge.
      if ((node.kind === "group" || node.kind === "iterate") && node.seedInput !== undefined) {
        groupSeedByGroupId.set(node.id, node.seedInput);
      }
      if (node.kind === "iterate" && node.chainInput !== undefined) {
        chainSeedByIterateId.set(node.id, node.chainInput);
      }
      collectGroupSeeds(node.children);
    }
  };
  collectGroupSeeds(spec.steps);

  const walk = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      if (node.kind === "step") {
        if (node.portInputs !== undefined) {
          for (const binding of Object.values(node.portInputs)) {
            // Resolve a `port(groupId, "in")` seed reference through the
            // enclosing group's seedInput — and a `port(iterateId, "chain")`
            // reference through the iterate's chainInput (B1.5 Finding 2) — to
            // the real upstream producer; all other bindings keep their
            // declared source.
            //
            // A3b follow-up ⓕ: this resolution is deliberately SINGLE-HOP — it
            // rewrites `port(groupId,"in")` to the group's `seedInput.node`,
            // but does not chase a seed-of-a-seed (were that producer itself
            // another group's `port(_,"in")`, the chain would need walking). No
            // shipped spec nests seeds that way, so single-hop suffices.
            // Also latent (cosmetic, intentionally not fixed): we rewrite
            // `port(groupId,"in")` for ANY leaf that reads it, regardless of
            // whether the leaf actually lives in that group's body — a
            // hand-malformed cross-scope read would draw an unreachable edge
            // here. Such a spec can't run (the runtime rejects the cross-scope
            // reference first), so the stray edge is purely visual.
            const seed =
              binding.port === "in"
                ? groupSeedByGroupId.get(binding.node)
                : binding.port === "chain"
                  ? chainSeedByIterateId.get(binding.node)
                  : undefined;
            const from = seed !== undefined ? seed.node : binding.node;
            edges.push({
              from,
              to: node.id,
              // Distinct auxKey tags this as a port-flow spine edge (vs
              // the endpoint-pill edges that carry "state"). See
              // PORT_FLOW_AUX_KEY's doc-block — the tag once let the
              // retired `dropAuxOnlyStateEdges` filter spare these edges;
              // it now feeds the renderer + replication fanout-eligibility.
              auxKey: PORT_FLOW_AUX_KEY,
              kind: "state",
            });
          }
        }
        continue;
      }
      walk(node.children);
    }
  };
  walk(spec.steps);
  return edges;
};

/**
 * Shared auxKey for synthetic "history seed" edges emitted by
 * `inferHistorySeedEdges`. Single key across every lookback offset so
 * `collapseGraph`'s `(kind, from, to, auxKey)` dedup collapses all N
 * edges to one visible arrow when the FES-with-history container is
 * collapsed (msg-schedule's default-collapsed first-load shape on
 * SHA-256). When the container is expanded, the N edges resolve to
 * distinct (from, to) pairs and render as N independent arrows into
 * each body fetch.
 */
export const HISTORY_SEED_AUX_KEY = "history-seed";

/**
 * Spec-walk pass: synthesize "history seed" aux edges for every
 * `for-each-subgraph-with-history` container (Slice S2(l) of
 * `docs/plans/sha-256-density-polish.md`, 2026-05-26).
 *
 * **Why this exists.** The FES-with-history runtime auto-publishes
 * `aux["prior-{N}"]` for each `N ∈ lookbackOffsets` before each
 * iteration body runs (`runtime.ts:1170` — `aux.set(k, priorEntry)`).
 * That call is silent: no `TraceFrame` records the auto-publish, so
 * `inferAuxEdges`'s natural `auxRead → writerByAuxKey` matching finds
 * no producer for `prior-{N}` and emits no edge. The body's
 * `aux-load-bytes@1` fetch leaves end up with zero incoming arrows,
 * pedagogically reading as "values from thin air" — but the seed
 * window does have a real provenance: the FES-with-history container's
 * spine predecessor supplies the seed bytes (in SHA-256 that's
 * `seed-schedule`, the `bytes-to-state@1` that produces the 64-byte
 * padded block split into 16 four-byte history seeds).
 *
 * **Anchor rule.** When the container declares `seedInput` (scaffolding-
 * suppression A2), the edge anchors at `seedInput.node` — the explicit
 * upstream producer the runtime seeds the history from. Otherwise it falls
 * back to "spine predecessor of the FES-with-history container in spec
 * order" (the legacy `bytes-to-state@1` bridge). Both generalize to
 * SHA-512 / MD5 / any future hash using the same primitive without
 * per-cipher knowledge. If neither resolves (FES-with-history is the first
 * sibling at its scope, no `seedInput`), we skip — there's no chip to
 * anchor the edge to.
 *
 * **Targets.** Body leaves whose `type === "aux-load-bytes@1"` AND
 * whose `params.auxName` matches `prior-{N}` for some `N` in the
 * container's `lookbackOffsets`. Other primitives that might read
 * priors don't exist today; if one ships, extend this analyzer.
 *
 * **Shared auxKey.** Every emitted edge carries the same
 * `auxKey: HISTORY_SEED_AUX_KEY` so the collapse pass dedupes the N
 * edges to a single visible arrow when the container is collapsed.
 *
 * **Edge kind.** `"aux"` (not `"state"` / not `"port-flow"`). Counted
 * by `replicateHighFanoutSources`'s fanout-eligibility predicate and
 * surfaced in the replication-overrides panel's source list, so the
 * user can flip the predecessor (e.g. `seed-schedule`) to `"always"`
 * to fan replicas into the expanded body.
 *
 * **Label honesty (deferred to renderer tooltip).** The edge is
 * literally accurate for iterations 0..seedCount-1. For later
 * iterations the actual prior comes from this body's own earlier
 * exit state via the recurrence (W_t = …; W_{t-2} after t≥18 is a
 * previous body's W_{t-2}, not a seed byte). The graph is iteration-
 * agnostic; the edge stays drawn as the seed-window source and the
 * edge-inspector tooltip surfaces the recurrence story.
 *
 * **Nesting.** Walks into all container kinds so a future FES-with-
 * history nested inside an iterate or group still picks up its
 * synthetic edges. The runtime forbids FES-with-history inside another
 * FES-with-history (types.ts:448) but doesn't restrict other kinds of
 * nesting; this walk doesn't need to either.
 */
const inferHistorySeedEdges = (spec: CipherSpec): GraphEdge[] => {
  const edges: GraphEdge[] = [];
  const visitLeavesInBody = (
    bodyNodes: readonly StepNode[],
    offsetSet: ReadonlySet<number>,
    predecessorId: string,
  ): void => {
    for (const child of bodyNodes) {
      if (child.kind === "step") {
        // Only the canonical aux-load-bytes lookback fetch is matched.
        if (child.type === "aux-load-bytes@1") {
          const params = child.params as { auxName?: unknown };
          const auxName = params.auxName;
          if (typeof auxName === "string" && auxName.startsWith("prior-")) {
            const offsetStr = auxName.slice("prior-".length);
            const offset = Number(offsetStr);
            if (Number.isInteger(offset) && offsetSet.has(offset)) {
              edges.push({
                from: predecessorId,
                to: child.id,
                auxKey: HISTORY_SEED_AUX_KEY,
                kind: "aux",
              });
            }
          }
        }
        continue;
      }
      // group | iterate | for-each-subgraph | for-each-subgraph-with-history
      // all carry `children: readonly StepNode[]`.
      visitLeavesInBody(child.children, offsetSet, predecessorId);
    }
  };

  const walk = (siblings: readonly StepNode[]): void => {
    for (let i = 0; i < siblings.length; i++) {
      const node = siblings[i];
      if (node === undefined) continue;
      if (node.kind === "for-each-subgraph-with-history") {
        // Seed-edge anchor. Two sources (scaffolding-suppression A2):
        //  - Port mode: `seedInput.node` — the explicit upstream producer
        //    the runtime slices the initial history from. Used once the
        //    SHA-256 `seed-schedule` bridge is retired (A3) and the FES
        //    declares `seedInput: { node: "length-append", ... }`.
        //  - Legacy: the spine predecessor (previous sibling in spec
        //    order), which is the `bytes-to-state@1` bridge that puts the
        //    seed bytes into state. If absent (FES-with-history is the
        //    first sibling) there's no chip to anchor to; skip.
        const anchorId =
          node.seedInput !== undefined
            ? node.seedInput.node
            : i > 0
              ? siblings[i - 1]?.id
              : undefined;
        if (anchorId !== undefined) {
          const offsetSet = new Set<number>(node.lookbackOffsets);
          visitLeavesInBody(node.children, offsetSet, anchorId);
        }
        // Recurse into the body for any nested FES-with-history (rare
        // but the type system permits, runtime contract aside).
        walk(node.children);
        continue;
      }
      if (node.kind !== "step") {
        walk(node.children);
      }
    }
  };
  walk(spec.steps);
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
 *   - **Eligibility counts every aux edge plus every port-flow state edge**
 *     (Slice S2(i) of `docs/plans/sha-256-density-polish.md`, 2026-05-26).
 *     Aux edges are the original fanout vector — one source, many consumers
 *     reading the same `auxKey`. Port-flow state edges (`kind:"state"` +
 *     `auxKey === PORT_FLOW_AUX_KEY`) are the port-native equivalent: a
 *     source's output port read by N downstream `portInputs` produces N
 *     port-flow edges, structurally the same fan as N aux reads. Legacy
 *     passthrough state edges (`kind:"state"` + `auxKey === STATE_AUX_KEY`)
 *     stay excluded — they're 1-to-1 between consecutive same-parent leaves
 *     by construction (no fanout possible), so including them would
 *     over-count. The pre-S2(i) rule excluded all state edges; SHA-256
 *     surfaced the gap when `final.split-wv` / `final.split-H` (each with
 *     8 outgoing port-flow edges to `final.s_0..s_7`) failed to qualify
 *     and produced the long-line overlap the user reported. A source
 *     qualifies only by its outgoing fanout-eligible count (or by an
 *     explicit `"always"` override).
 *   - **All outgoing edges of a qualifying source are rerouted, regardless
 *     of kind** (Slice 7b, 2026-05-17). A high-fanout source's outgoing
 *     STATE edges fan through replicas the same way its aux edges do, and
 *     the original source is REMOVED entirely from the graph (no longer
 *     duplicates the spine chip next to its consumers). Incoming edges
 *     whose `to` is a fully-replicated source are redirected to that
 *     source's "spine entry" replica — defined as the replica generated
 *     for the source's spine successor (first outgoing state edge's target,
 *     with fallback to first outgoing aux edge's target if there is no
 *     outgoing state edge — e.g. an aux-only source whose only outputs
 *     are aux fan-out). Linear-list sidebar
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

  // Count outgoing fanout-eligible edges per source: every aux edge, plus
  // every port-flow state edge (kind:"state" + auxKey === PORT_FLOW_AUX_KEY).
  // Legacy passthrough state edges (kind:"state" + auxKey === STATE_AUX_KEY)
  // stay excluded — they're 1-to-1 between consecutive same-parent leaves by
  // construction and would otherwise inflate the count for every spine
  // participant. The port-flow inclusion was added 2026-05-26 (Slice S2(i)):
  // SHA-256's `final.split-wv` and `final.split-H` each emit 8 port-flow
  // edges and need to qualify for replication, but the original aux-only
  // rule scored them as fanout 0 and the long lines overlapped horizontally
  // through the s_0..s_7 row.
  const fanoutBySrc = new Map<string, number>();
  for (const e of graph.edges) {
    const eligible = e.kind === "aux" || (e.kind === "state" && e.auxKey === PORT_FLOW_AUX_KEY);
    if (!eligible) continue;
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
  //      exist. The fallback handles aux-only sources whose only outputs
  //      are aux fan-out (no port-flow spine edge) — e.g. a key-schedule
  //      flipped to `"always"`, whose round-key fan-out is its only edge set.
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
    }
  /**
   * `port-input-unwired` (universal-port plan Phase 2 Slice 2.6a) — a
   * pure port-native leaf (no `meta`) has an input port that's neither
   * declared in `portInputs` nor wired implicitly. The runtime will
   * throw if asked to run; the graph view surfaces an orange `!` so
   * the user fixes it before clicking Run.
   *
   * `port-input-unresolvable` — the leaf declared a `portInputs` entry
   * for `portName`, but the binding's `node` reference doesn't exist
   * in the same scope, or `port` isn't an output of that upstream node.
   * Catches typos + reorderings before runtime.
   */
  | {
      readonly kind: "port-input-unwired";
      readonly stepId: string;
      readonly portName: string;
    }
  | {
      readonly kind: "port-input-unresolvable";
      readonly stepId: string;
      readonly portName: string;
      readonly targetNode: string;
      readonly targetPort: string;
      readonly reason: "missing-node" | "missing-port";
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
  // never filtered — the port-flow spine (`inferPortEdges`) only emits
  // forward edges by construction, and a backwards state edge would
  // indicate a real bug.
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
 *
 * When `opts.registry` is provided, the consecutive-siblings state-
 * spine inference applies a PER-EDGE suppression rule (Slice S2(f)
 * refined — `docs/plans/sha-256-density-polish.md`, 2026-05-26): an
 * inferred state edge `predecessor → consumer` is suppressed when the
 * consumer doesn't actually read state via the state-thread (pure
 * port-native consumer; or lifted-legacy ported consumer whose
 * `meta.stateInputPort` is undefined; or lifted-legacy ported
 * consumer whose `meta.stateInputPort` is overridden by an explicit
 * `portInputs` binding — making the inferred edge redundant with the
 * port-flow edge from `inferPortEdges`). The earlier whole-spec gate
 * (suppress every inferred state edge on any port-native spec) was
 * too aggressive on 2026-05-26: SHA-256's lifted-legacy ported leaves
 * (W-publish, K-to-aux, H-to-aux, seed-schedule, init-working-vars,
 * round bodies) still rely on state-thread to receive their input,
 * so a whole-spec gate broke the visible round chain (round.0 →
 * round.1 → … → round.63 → final.state-in) the user reads as the
 * cipher's primary spine. The per-edge rule preserves those
 * handoffs while suppressing the spurious chain through parallel
 * port-native leaves (e.g. `final.s_0 → final.s_1 → … → final.s_7`
 * where the real flow is `split-wv.output_i` + `split-H.output_i`
 * → `final.s_i` via port-flow).
 * Callers that omit `opts.registry` get the pre-S2(f) behavior
 * (state-spine inference always fires, no per-edge gate) — keeps
 * existing tests byte-identical.
 */
/**
 * True iff any leaf in the spec wires an input port to the reserved
 * `$input` source (`INPUT_SOURCE_ID`, scaffolding-suppression A3a). Drives
 * whether `deriveAuxGraph` materializes the `$input` synthetic input pill.
 */
const specReferencesInputSource = (spec: CipherSpec): boolean => {
  let found = false;
  // True iff a binding wires its source to the reserved `$input` node.
  const bindsInput = (binding: PortBinding | undefined): boolean =>
    binding !== undefined && binding.node === INPUT_SOURCE_ID;
  const walk = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      if (found) return;
      if (node.kind === "step") {
        if (node.portInputs !== undefined) {
          for (const binding of Object.values(node.portInputs)) {
            if (bindsInput(binding)) {
              found = true;
              return;
            }
          }
        }
        continue;
      }
      // B1.5 Finding 1 — container kinds (group / iterate / for-each-subgraph
      // [-with-history]) can reference `$input` through their *boundary* port
      // bindings, NOT through any child leaf's `portInputs`. The port-mode
      // iterate's `seedInput = port($input, …)` (byte-native ECB/CBC) is exactly
      // this case: walking only leaf `portInputs` missed it, so `deriveAuxGraph`
      // never materialized the `$input` synthetic node — yet `inferPortEdges`
      // still resolved `port(iterate,"in") → $input` and emitted a *dangling*
      // edge to a node that was never drawn (the dangling-plaintext-pill bug).
      // Checking `chainInput`/`chainFeedback` (iterate-only, byte-native CBC)
      // too: only `seedInput` points at `$input` in shipped specs, but checking
      // all three is correct + future-proof (e.g. a mode whose IV is the
      // message head).
      if (bindsInput(node.seedInput)) {
        found = true;
        return;
      }
      if (
        node.kind === "iterate" &&
        (bindsInput(node.chainInput) || bindsInput(node.chainFeedback))
      ) {
        found = true;
        return;
      }
      walk(node.children);
    }
  };
  walk(spec.steps);
  return found;
};

export const deriveAuxGraph = (
  trace: Trace,
  spec: CipherSpec,
  opts?: {
    readonly endpoints?: EndpointOptions;
    readonly registry?: StepRegistry;
  },
): CipherGraph => {
  const ctx: BuildContext = {
    nodes: [],
    containers: [],
    iteratesById: new Map(),
    leafIndex: new Map(),
    containerIndex: new Map(),
    outputAuxByContainerId: new Map(),
  };

  const rootIds = walkSpec(spec.steps, [], ctx);
  annotateBlockSpans(trace, ctx);
  // Aux edges come from trace-walking (empty trace → empty list); the
  // spine comes from spec-walking the declared `portInputs` (always
  // present, even pre-run). Append spine edges AFTER aux edges so existing
  // tests that index the edge list by position continue to work, and so a
  // reader scanning the dataflow sees the annotations first and the spine
  // last. Port-flow edges (S2(e)) carry `kind: "state"` so the renderer
  // paints them as the spine, tagged `auxKey: "port-flow"`.
  //
  // The legacy consecutive-siblings state-thread inference (`inferStateEdges`)
  // was retired in Phase 5 Slice 5.3e (Batch 3, 2026-05-31): every shipped
  // spec is port-wired, so `inferPortEdges` owns the entire spine. `opts.registry`
  // is therefore no longer read here — it's retained on the signature for
  // caller compatibility (~110 callsites pass it).
  const portFlowEdges = inferPortEdges(spec);
  // History-seed edges (S2(l), 2026-05-26): synthesize aux edges from
  // each `for-each-subgraph-with-history` container's spine predecessor
  // to every body lookback fetch. The runtime's auto-publish of
  // `aux["prior-{N}"]` is silent (no TraceFrame), so the natural
  // `deriveEdges` pass can't see this provenance. Counted by
  // `replicateHighFanoutSources` (kind: "aux"); shared auxKey so the
  // edges dedupe to one visible arrow when the container is collapsed.
  const historySeedEdges = inferHistorySeedEdges(spec);
  const edges = [...deriveEdges(trace, ctx), ...portFlowEdges, ...historySeedEdges];

  // ─── $input synthetic source pill (scaffolding-suppression A3a) ───────────
  //
  // When the spec wires its first byte-consumers to the reserved `$input`
  // source (SHA-256's `pad` / `length-append`, replacing the deleted
  // `state-to-bytes "plaintext-source"` bridge), materialize a synthetic node
  // for it. It renders as the input pill (`endpointSide: "input"`) and the
  // real port-flow edges from `inferPortEdges` (`$input → pad`, `$input →
  // length-append`) connect it to the body — so it REPLACES the legacy
  // `CIPHER_INPUT_ID` pill for these specs (no duplicate input pill, no
  // synthetic input state edge). Materialized whenever referenced (not gated
  // on `opts.endpoints`) so direct `deriveAuxGraph` callers resolve the port
  // edges too; the label falls back to "input" when no endpoint labels exist.
  const usesInputSource = specReferencesInputSource(spec);
  const inputSourceNodes: GraphNode[] = usesInputSource
    ? [
        {
          stepId: INPUT_SOURCE_ID,
          stepType: ENDPOINT_STEP_TYPE,
          label: opts?.endpoints?.inputLabel ?? "input",
          containerPath: [],
          endpointSide: "input",
        },
      ]
    : [];
  const frontRootIds: string[] = usesInputSource ? [INPUT_SOURCE_ID] : [];

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
    const outputAnchor = ep.outputAnchorId ?? rootIds[rootIds.length - 1];

    const endpointNodes: GraphNode[] = [
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
    if (outputAnchor !== undefined) {
      edges.push({
        from: outputAnchor,
        to: CIPHER_OUTPUT_ID,
        auxKey: STATE_AUX_KEY,
        kind: "state",
      });
    }
    // Legacy input pill only for specs that DON'T use the `$input` source
    // (AES / Speck / Serpent / DES). When `$input` is in play it IS the input
    // pill and the body connects via real port edges, so we skip the
    // synthetic `CIPHER_INPUT_ID → rootIds[0]` state edge entirely.
    if (!usesInputSource) {
      const inputAnchor = ep.inputAnchorId ?? rootIds[0];
      endpointNodes.push({
        stepId: CIPHER_INPUT_ID,
        stepType: ENDPOINT_STEP_TYPE,
        label: ep.inputLabel,
        containerPath: [],
        endpointSide: "input",
      });
      if (inputAnchor !== undefined) {
        edges.push({
          from: CIPHER_INPUT_ID,
          to: inputAnchor,
          auxKey: STATE_AUX_KEY,
          kind: "state",
        });
      }
    }

    // Front-of-rootIds input id: the `$input` pill when the spec uses it,
    // else the legacy `CIPHER_INPUT_ID` pill. Both render at the canvas's
    // left edge; the output pill is appended at the right.
    const inputFrontRootIds = usesInputSource ? [INPUT_SOURCE_ID] : [CIPHER_INPUT_ID];
    return {
      nodes: [...ctx.nodes, ...inputSourceNodes, ...endpointNodes],
      containers: ctx.containers,
      edges,
      rootIds: [...inputFrontRootIds, ...rootIds, CIPHER_OUTPUT_ID],
    };
  }

  return {
    nodes: [...ctx.nodes, ...inputSourceNodes],
    containers: ctx.containers,
    edges,
    rootIds: [...frontRootIds, ...rootIds],
  };
};
