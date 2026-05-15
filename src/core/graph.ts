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
 *   3. **Iterate breaks the state thread.** State edges connect DFS-
 *      consecutive leaves WITHIN a single iterate-scope; groups are
 *      transparent (DFS through), iterates are opaque (their body is its
 *      own scope, no spine edge crosses the boundary in either direction).
 *      This matches runtime semantics — the iterate replaces `state` with
 *      `blocks[i]` per iteration and accumulates output into
 *      `aux[outBlocksAux]` rather than leaving it on `state`, so a state
 *      edge crossing the iterate boundary would be misleading. The runtime
 *      always passes a real state value at the boundary, but it's not the
 *      previous step's output state — the aux edges (blocks-in /
 *      output-blocks-out) are the honest depiction of the per-block data
 *      handoff, and the state spine should not double them.
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

import type { CipherSpec, IterateGroup, StateShape, StepNode, Trace } from "./types";

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
};

export type ContainerNode = {
  readonly kind: "group" | "iterate";
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

// ─── Internal helpers ──────────────────────────────────────────────────────

/**
 * Strip the runtime's `:b<digits>` per-iteration suffix from a step id.
 * The convention is "trailing `:b\d+` only" — middle-of-id substrings are
 * left alone (and CLAUDE.md warns against using `:b` in non-suffix positions
 * anyway).
 */
const stripBlockSuffix = (stepId: string): string => stepId.replace(/:b\d+$/, "");

type BuildContext = {
  readonly nodes: GraphNode[];
  readonly containers: ContainerNode[];
  /** All iterate definitions indexed by id, for the edge-synthesis pass. */
  readonly iteratesById: Map<string, IterateGroup>;
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
  }

  // Drain still-active iterates at trace end. No more frames to read their
  // outBlocksAux, so this is a no-op for edge count today — but it keeps
  // writerByAuxKey in a sane state if a future caller chains derivations.
  for (const iid of prevIterateIdsInPath) {
    const iter = ctx.iteratesById.get(iid);
    if (!iter) continue;
    writerByAuxKey.set(iter.outBlocksAux, iid);
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
 *   - **Groups are transparent.** DFS descends into them and their leaves
 *     join the parent scope's spine. The spine therefore crosses round-
 *     group boundaries (e.g. `round.1.add-round-key → round.2.sub-bytes`)
 *     — exactly the pedagogical "the cipher's primary dataflow runs through
 *     every round in order" story.
 *   - **Iterates are opaque boundaries.** Hitting one FLUSHES the parent
 *     scope's accumulated leaf chain (emitting whatever edges exist so
 *     far) and recurses into the iterate body as its OWN scope. After the
 *     iterate, the parent scope resumes with a fresh empty leaf chain — no
 *     state edge bridges the iterate in either direction. See item 3 in
 *     the file header for why.
 *
 * The function reads only `spec`, never the trace. State edges therefore
 * appear on the structural skeleton before any run, while aux edges remain
 * trace-derived. This matches the rendering goal: the spine is what the
 * user reads as "this is what the cipher does", and it should be visible
 * the moment they load a spec.
 */
const inferStateEdges = (spec: CipherSpec): GraphEdge[] => {
  const edges: GraphEdge[] = [];

  const emitChain = (leaves: readonly string[]): void => {
    for (let i = 0; i + 1 < leaves.length; i++) {
      const from = leaves[i];
      const to = leaves[i + 1];
      if (from === undefined || to === undefined) continue;
      edges.push({ from, to, auxKey: STATE_AUX_KEY, kind: "state" });
    }
  };

  /**
   * Process one iterate-scope: collect its DFS leaves into a single chain
   * (recursing through groups, halting at iterates), and recurse into each
   * iterate body as its own scope. Returns after emitting all edges
   * generated by this scope and its nested iterate scopes.
   */
  const processScope = (siblings: readonly StepNode[]): void => {
    let leaves: string[] = [];
    const walk = (nodes: readonly StepNode[]): void => {
      for (const node of nodes) {
        if (node.kind === "step") {
          leaves.push(node.id);
        } else if (node.kind === "group") {
          // Group is transparent — descend, its leaves join this scope.
          walk(node.children);
        } else {
          // Iterate is opaque — flush the chain so far, then recurse with
          // the body as its own scope. The parent chain resumes empty.
          emitChain(leaves);
          leaves = [];
          processScope(node.children);
        }
      }
    };
    walk(siblings);
    emitChain(leaves);
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
 *   - Counts only `kind: "aux"` edges. State edges are 1-to-1 between
 *     consecutive same-parent leaves (no fanout possible) and pass through
 *     unchanged.
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
 *     `childIds` (or `rootIds` if the consumer is at the root).
 *   - The original source node is KEPT in `nodes` so the linear-list
 *     sidebar's click-to-scrub continues to work. The source loses its
 *     replicated outgoing aux edges; if it had below-threshold outgoing
 *     aux to other consumers, those pass through unchanged.
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

  // Count outgoing aux edges per source. State edges are excluded.
  const fanoutBySrc = new Map<string, number>();
  for (const e of graph.edges) {
    if (e.kind !== "aux") continue;
    fanoutBySrc.set(e.from, (fanoutBySrc.get(e.from) ?? 0) + 1);
  }

  const highFanoutSrcs = new Set<string>();
  for (const [srcId, count] of fanoutBySrc) {
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

  // Walk aux edges, build:
  //   - newAuxEdges: the rewritten aux edges (replicas as source) + unchanged ones
  //   - replicasBySource: (srcId, consumerId) → replica node
  //   - replicaInsertBefore: parent container id (or null = root) →
  //       (consumerId → [replicaIds]) in spec-order
  const newAuxEdges: GraphEdge[] = [];
  const replicaKey = (srcId: string, consumerId: string) => `${srcId}@->${consumerId}`;
  const replicas = new Map<string, GraphNode>(); // replicaId → node

  // For each parent container id (use "" for root), and for each consumer,
  // the ordered list of replica ids to insert immediately before that
  // consumer. Order: insertion order of (src, consumer) encounters, so
  // multiple high-fanout sources pointing at the same consumer line up
  // left-to-right in encounter order.
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
    if (edge.kind !== "aux" || !highFanoutSrcs.has(edge.from)) {
      newAuxEdges.push(edge);
      continue;
    }
    // High-fanout source: rewrite the edge through a replica node.
    const rId = replicaKey(edge.from, edge.to);
    if (!replicas.has(rId)) {
      // Determine the consumer's parent container (last in containerPath)
      // and lookup its inherited fields from the source node/container.
      const consumerNode = nodeById.get(edge.to);
      const consumerContainer = containerById.get(edge.to);
      const consumerPath = consumerNode?.containerPath ?? consumerContainer?.containerPath ?? [];
      const sourceNode = nodeById.get(edge.from);
      const sourceContainer = containerById.get(edge.from);
      const stepType = sourceNode?.stepType ?? sourceContainer?.kind ?? "replica";
      const label = sourceNode?.label ?? sourceContainer?.label ?? edge.from;
      replicas.set(rId, {
        stepId: rId,
        stepType,
        label,
        containerPath: consumerPath,
        replicaOf: edge.from,
      });
      // Schedule the replica for insertion next to its consumer.
      const parentKey =
        consumerPath.length > 0 ? (consumerPath[consumerPath.length - 1] ?? "") : "";
      const map = ensureInsertionMap(parentKey);
      const list = map.get(edge.to) ?? [];
      list.push(rId);
      map.set(edge.to, list);
    }
    newAuxEdges.push({ from: rId, to: edge.to, auxKey: edge.auxKey, kind: "aux" });
  }

  // Build replacement childIds for each affected container + rootIds.
  const splice = (childIds: readonly string[], byConsumer: Map<string, string[]>) => {
    const out: string[] = [];
    for (const id of childIds) {
      const ins = byConsumer.get(id);
      if (ins) out.push(...ins);
      out.push(id);
    }
    return out;
  };

  const newContainers = graph.containers.map((c) => {
    const ins = insertionsByParent.get(c.id);
    if (!ins) return c;
    return { ...c, childIds: splice(c.childIds, ins) };
  });

  const rootInsertions = insertionsByParent.get("");
  const newRootIds = rootInsertions ? splice(graph.rootIds, rootInsertions) : graph.rootIds;

  // State edges pass through unchanged (they were never aux). Concat after
  // newAuxEdges to preserve the same ordering convention as deriveAuxGraph
  // (aux first, state second) — keeps any existing edge-indexing tests
  // unaffected.
  const stateEdges = graph.edges.filter((e) => e.kind === "state");
  const newAuxOnly = newAuxEdges.filter((e) => e.kind === "aux");

  return {
    nodes: [...graph.nodes, ...replicas.values()],
    containers: newContainers,
    edges: [...newAuxOnly, ...stateEdges],
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
