/**
 * Value lookup — resolves "what data is at THIS edge / element at the
 * current scrubber position?" for the value-inspector panel. The file
 * is named after edges for historical reasons (Slice 4 shipped
 * edges-only); the file now exports BOTH `lookupEdgeValue` and
 * `lookupNodeValue`. Same return shape, different selectors. Keep them
 * together because they share parseChipId / findIterateById /
 * findBodyFramesAt — splitting would duplicate the chip-resolution
 * surface area.
 *
 * Pure functions over (spec, trace, target, currentBlockIndex). The
 * renderer in `GraphView` reads the selected target from the
 * `view-value-inspector` store, calls the matching lookup, and formats
 * the result with the user-selected ByteFormat. No Solid signals, no
 * DOM — all the complexity lives here so the lookups are testable
 * against canned traces without spinning up a renderer.
 *
 * Five branches the result can take, captured by the `status` field:
 *
 *   1. `"endpoint"` — synthetic plaintext/ciphertext pill (Slice 1).
 *      The pills surface the actual cipher I/O: input pill →
 *      `trace.initialState`, output pill → `trace.finalState` (the
 *      symmetric pair; Slice 5.3c moved the input pill off the old
 *      `frames[0].stateBefore` read). The
 *      panel formats `value` like any other state row and badges the
 *      kind as "input pill" / "output pill" via `endpointSide`. Any
 *      caption a future a11y / tooltip surface needs should be built
 *      at the call site from `endpointSide` + the active cipher mode
 *      (which swaps "plaintext"/"ciphertext" on decrypt) — the lookup
 *      result deliberately stops at the side discriminator + value so
 *      no consumer can render encrypt-mode copy in decrypt mode by
 *      mistake. Pre-run pill clicks collapse to `"no-trace"` (branch 2)
 *      so the empty-trace copy is uniform across every selectable
 *      element.
 *
 *   2. `"no-trace"` — `trace === null`. The user hasn't run the cipher
 *      yet. The panel shows a "Run the cipher to see edge values" hint.
 *
 *   3. `"missing"` — the trace exists but no frame answered the lookup.
 *      Typical causes: the user collapsed an iterate and is hovering a
 *      chip whose blockIndex exceeds the runtime's iteration count (a
 *      pre-run / partial-trace state), OR the consumer never produced a
 *      frame because an earlier step threw. `reason` carries a short
 *      human description for the panel.
 *
 *   4. `"value"` — got it. `value` is the `AuxValue` (a State, a
 *      Uint8Array, a number, a bigint, or a `readonly State[]`). The
 *      panel renders this via `src/core/format.ts` for byte-y values and
 *      via plain `String()` for numerics. `displayKind` is a UI hint:
 *      `"state"` for the spine value, `"aux"` for a roundKey-style aux
 *      flow, `"block-payload"` for the per-block matrix flowing in/out
 *      of a block-chip via the iterate's `blocksFromAux`/`outBlocksAux`
 *      aux. Block-chip incoming/outgoing state edges also resolve to
 *      `"block-payload"` because the value IS the per-block matrix —
 *      identical to what the iterate's blocksFromAux/outBlocksAux holds
 *      at the chip's index. Surfacing that explicitly in the UI helps
 *      the user read "this is the payload for block i," not the generic
 *      "this is the spine state" label that would be misleading inside
 *      a multi-block context.
 *
 * Block-chip handling (Slice 6 composition) is the non-obvious surface
 * area. Chips are synthetic graph nodes with ids `${iterateId}@block${i}`
 * (or `@blockMore` for the ellipsis chip) that never appear in any trace
 * frame's stepId. Edges fanning into/out of chips need explicit
 * resolution:
 *
 *   - **State edge into a chip**: the chip's "incoming state" is what
 *     the runtime sets `state` to at the start of iteration i — i.e.
 *     `blocks[i]` from the iterate's `blocksFromAux`. We read this
 *     directly from any iterate-body frame at `blockIndex === i` via
 *     `frame.stateBefore` on the first body frame in iteration order.
 *
 *   - **State edge out of a chip**: the iterate body's final
 *     `stateAfter` at `blockIndex === i`, equivalent to
 *     `aux[outBlocksAux][i]`. The runtime appends this to the
 *     `outBlocksAux` array, but the last body frame's stateAfter holds
 *     the same matrix and is cheaper to find.
 *
 *   - **Aux edge into a chip with auxKey === iterate.blocksFromAux**:
 *     special-cased to `blocks[i]` rather than the full array. This is
 *     the `split-blocks → chip_i` edge in ECB — pedagogically the chip
 *     consumes ONE block, not the whole array, so we slice.
 *
 *   - **Aux edge out of a chip with auxKey === iterate.outBlocksAux**:
 *     `outBlocks[i]` — the per-iteration output written into the
 *     accumulator. Equivalent to "last body frame's stateAfter at
 *     blockIndex=i" but expressed in aux terms.
 *
 *   - **Aux edge into a chip with other auxKey** (e.g. a roundKey
 *     consumed by an internal body step): look for any body frame at
 *     `blockIndex === i` whose `auxRead.get(auxKey)` is defined,
 *     returning that value. Round keys are identical across blocks, so
 *     any frame's auxRead is fine; the per-block view exists so the
 *     hover-then-scrub-blockIndex flow naturally tracks the chip's
 *     iteration.
 *
 * The "regular leaf" branches (no chip involvement) are simpler: pick
 * the consumer's frame at the current scrubber's blockIndex (undefined
 * matches undefined — frames outside any iterate). State edges fall
 * back to the predecessor's stateAfter at the same blockIndex when the
 * consumer has no recorded stateBefore (rare; defensive).
 */

import { frameStateInBytes, frameStateOutBytes } from "./frame-state";
import { CIPHER_INPUT_ID, CIPHER_OUTPUT_ID, type GraphEdge, isEndpointId } from "./graph";
import { canonicalStepId } from "./step-id";
import type {
  AuxValue,
  BytesState,
  CipherSpec,
  IterateGroup,
  StepNode,
  Trace,
  TraceFrame,
} from "./types";
import { INPUT_SOURCE_ID } from "./types";

/** Pattern matching a block-chip's synthetic id. Captures (iterateId, index). */
const BLOCK_CHIP_RE = /^(.+)@block(\d+)$/;
/** Suffix used for the ellipsis chip — represents N-CAP+1 blocks at once,
 *  so we can't resolve a single per-block value for it. The lookup returns
 *  a `"missing"` with a descriptive reason in this case. */
const BLOCK_MORE_SUFFIX = "@blockMore";
/** Delimiter used in fan-out replica node ids. Replicas have ids of the
 *  form `${sourceId}@->${consumerId}` produced by
 *  `replicateHighFanoutSources`. The delimiter is intentionally
 *  unmistakable (no real stepId contains `@->`), so we can detect and
 *  unwrap by string-search. */
const REPLICA_DELIM = "@->";

/**
 * Re-wrap port-resolved bytes as the `BytesState` the inspector `value`
 * field (an `AuxValue`) expects. Slice 5.3c migrated the state-edge / leaf
 * value reads off `frame.stateBefore` / `stateAfter` onto the shared
 * `frameStateInBytes` / `frameStateOutBytes` helpers (which return raw
 * `Uint8Array`); this restores the `{ shape: "bytes", bytes }` envelope the
 * renderer formats. State is bytes-only since Slice 5.1, so this is the only
 * envelope a state value ever takes.
 */
const asBytesState = (bytes: Uint8Array): BytesState => ({ shape: "bytes", bytes });

/** Parsed chip-id structure when the input is a recognized chip. */
type ChipId = { readonly iterateId: string; readonly blockIndex: number };

/**
 * Decompose `${iterateId}@block${i}` into its parts. Returns `null` for
 * non-chip ids (regular leaves, container ids, replicas with `@->`).
 * Specifically returns `null` for the `@blockMore` ellipsis sentinel —
 * callers fall through to the "missing" path so the panel can say
 * "ellipsis chip represents multiple blocks; pick a numbered chip."
 *
 * Replica-id rejection is critical: a replica id like
 * `key-expansion@->ecb-blocks@block1` ends in `@block1`, so the
 * (otherwise greedy) regex would WRONGLY match it as a chip with
 * `iterateId === "key-expansion@->ecb-blocks"`. That id isn't in
 * the spec, so the chip branch would return
 * `"iterate ... not found in spec — graph and spec out of sync"`.
 * Detecting `@->` early keeps replica ids out of the chip branch
 * entirely; the caller's regular-aux branches then handle them
 * correctly via producer-side fallback.
 */
const parseChipId = (id: string): ChipId | null => {
  if (id.endsWith(BLOCK_MORE_SUFFIX)) return null;
  if (id.includes(REPLICA_DELIM)) return null;
  const m = BLOCK_CHIP_RE.exec(id);
  if (!m) return null;
  const iterateId = m[1] ?? "";
  const idxStr = m[2] ?? "";
  const blockIndex = Number.parseInt(idxStr, 10);
  if (!Number.isFinite(blockIndex) || blockIndex < 0) return null;
  return { iterateId, blockIndex };
};

/**
 * Unwrap a replica node id to its underlying source stepId. Replicas
 * are synthetic graph nodes (no trace frame), so any lookup that
 * needs to walk back to a real producer must call this first.
 *
 * Returns the input unchanged for non-replica ids, so it's safe to
 * call unconditionally on any edge.from.
 */
const unwrapReplicaSource = (id: string): string => {
  const idx = id.indexOf(REPLICA_DELIM);
  return idx >= 0 ? id.substring(0, idx) : id;
};

/** Recursively search a spec tree for an IterateGroup by id. */
const findIterateById = (steps: readonly StepNode[], id: string): IterateGroup | null => {
  for (const node of steps) {
    if (node.kind === "iterate") {
      if (node.id === id) return node;
      const inside = findIterateById(node.children, id);
      if (inside !== null) return inside;
    } else if (node.kind === "group") {
      const inside = findIterateById(node.children, id);
      if (inside !== null) return inside;
    }
  }
  return null;
};

// Canonicalization (strip `:b{i}` / `:t{name}` / `:rejoin` / `:swap` runtime
// suffixes off a frame stepId) lives in `@/core/step-id`. Centralized in
// Phase 2 of the DES + branching primitive plan so all sites that resolve
// frame stepId → spec leaf id can't drift on suffix handling.

/**
 * Find iterate-body frames at a specific block index. Used by every
 * chip-edge branch to resolve "what state did this block see at start /
 * end of the body?"
 *
 * Returns the frames in trace order (which is also iteration order
 * within an iterate body). Empty array when no frame matches — caller
 * surfaces a "missing" result.
 */
const findBodyFramesAt = (
  trace: Trace,
  iterate: IterateGroup,
  blockIndex: number,
): readonly TraceFrame[] => {
  const out: TraceFrame[] = [];
  for (const f of trace.frames) {
    if (f.blockIndex !== blockIndex) continue;
    if (!f.path.includes(iterate.id)) continue;
    out.push(f);
  }
  return out;
};

/**
 * Find the consumer's frame for a regular (non-chip) edge target.
 *
 * Prefers a frame at the current scrubber's blockIndex (so hovering an
 * edge while the scrubber is on block 2 shows block 2's value, not
 * block 0's). Falls back to ANY frame matching the canonical stepId if
 * the preferred blockIndex didn't land a match — covers the case where
 * the user is hovering an edge whose consumer is outside the iterate
 * but the scrubber is currently inside one.
 */
const findConsumerFrame = (
  trace: Trace,
  consumerStepId: string,
  preferredBlockIndex: number | undefined,
): TraceFrame | null => {
  // Canonicalize BOTH the frame's stepId AND the lookup id. Callers
  // sometimes pass the literal synthetic id (e.g. `round.1:rejoin` from a
  // graph chip's onClick handler) and sometimes pass an already-stripped
  // form. Canonicalizing one side only made the asymmetric case
  // ("round.1:rejoin" against a frame whose canonical is "round.1") miss,
  // surfacing as "no frame found for step round.1:rejoin" in the value
  // inspector for rejoin chip clicks (2026-05-20 Phase 6e smoke finding).
  // The suffix regex in `canonicalStepId` is idempotent so this is a
  // no-op for every existing call site that already passes the canonical
  // form (regular leaves, AES `aes.sub-bytes`-style ids).
  const lookupCanonical = canonicalStepId(consumerStepId);
  let fallback: TraceFrame | null = null;
  for (const f of trace.frames) {
    if (canonicalStepId(f.stepId) !== lookupCanonical) continue;
    if (preferredBlockIndex !== undefined && f.blockIndex === preferredBlockIndex) {
      return f;
    }
    if (fallback === null) fallback = f;
  }
  return fallback;
};

/**
 * Find the producer's frame for a state-edge fallback (when the
 * consumer has no recorded `auxRead`-equivalent for the incoming state).
 * Same scrubber-blockIndex preference as `findConsumerFrame`.
 */
const findProducerFrame = (
  trace: Trace,
  producerStepId: string,
  preferredBlockIndex: number | undefined,
): TraceFrame | null => findConsumerFrame(trace, producerStepId, preferredBlockIndex);

/**
 * Result of an edge-value lookup. The renderer pattern-matches on
 * `status` and formats accordingly:
 *
 *   - `"endpoint"`: format `value` (the cipher's plaintext for the input
 *     pill in encrypt mode / ciphertext in decrypt mode, and the inverse
 *     for the output pill) with the active ByteFormat, and badge with
 *     "input pill" / "output pill" via `endpointSide`. Only emitted when
 *     the trace is non-null; pre-run endpoint clicks return `"no-trace"`
 *     instead so the panel reads consistently with every other un-run
 *     row.
 *   - `"no-trace"`: render the hint string ("Run the cipher to see…").
 *   - `"missing"`: render the `reason` muted, no value.
 *   - `"value"`: format `value` with the active ByteFormat. `displayKind`
 *     drives the kind-badge in the panel header.
 */
export type EdgeValueLookup =
  | {
      readonly status: "endpoint";
      readonly endpointSide: "input" | "output";
      readonly value: AuxValue;
    }
  | { readonly status: "no-trace" }
  | { readonly status: "missing"; readonly reason: string }
  | {
      readonly status: "value";
      readonly value: AuxValue;
      readonly displayKind: "state" | "aux" | "block-payload";
      /** The auxKey for aux/block-payload kinds; "state" sentinel for state. */
      readonly auxKey: string;
      /**
       * Block index this lookup resolved against, when meaningful. Set when
       * the resolved frame had a `blockIndex` (inside an iterate) OR the
       * chip-id branch fixed the value. Undefined for non-iterate edges.
       * The panel renders this as a "(block i)" suffix on the kind badge.
       */
      readonly blockIndex?: number;
    };

/**
 * Look up the value flowing through `edge` at the current scrubber
 * position. See the module docstring for the full branch table.
 *
 * The `currentBlockIndex` argument is the scrubber's current iterate-
 * body block index (undefined when the scrubber is on a non-iterate
 * frame OR no scrubber position is meaningful). It influences only the
 * "regular-leaf" branches — chip edges always use the chip's own
 * blockIndex from its id.
 */
export const lookupEdgeValue = (
  edge: GraphEdge,
  spec: CipherSpec,
  trace: Trace | null,
  currentBlockIndex: number | undefined,
): EdgeValueLookup => {
  // ── Endpoint pills ─────────────────────────────────────────────────
  // 2026-05-17: pills now carry the actual cipher I/O value (plaintext
  // for input pill, ciphertext for output pill — labels swap on decrypt
  // but the resolution rule is symmetric: input = first frame's
  // stateBefore, output = trace.finalState). Pre-run clicks return
  // `"no-trace"` instead of a label-only `"endpoint"` row, matching the
  // rest of the inspector's empty-trace handling.
  //
  // (`buildIterateFeedbackPredicate` already filters endpoint edges
  // out of the feedback-edge classification, so kind is always "state"
  // here in practice, but the branch doesn't depend on that.)
  const isInputEnd = edge.from === CIPHER_INPUT_ID || isEndpointId(edge.from);
  const isOutputEnd = edge.to === CIPHER_OUTPUT_ID || isEndpointId(edge.to);
  if (isInputEnd || isOutputEnd) {
    if (trace === null) return { status: "no-trace" };
    const side: "input" | "output" = isInputEnd ? "input" : "output";
    if (side === "input") {
      // The cipher's plaintext input = `trace.initialState` (Slice 5.3c),
      // symmetric with the output pill's `trace.finalState` below. Replaces
      // the old `frames[0].stateBefore` read, which 5.3e's field deletion
      // would break and which `frames[0]`'s `"state"` port can't answer
      // (the first frame isn't always the plaintext consumer).
      return {
        status: "endpoint",
        endpointSide: "input",
        value: trace.initialState,
      };
    }
    return {
      status: "endpoint",
      endpointSide: "output",
      value: trace.finalState,
    };
  }

  if (trace === null) return { status: "no-trace" };

  // ── Block-chip resolution ──────────────────────────────────────────
  // Chips never appear in trace stepIds; we route via the iterate's
  // body frames at the chip's blockIndex. Either endpoint may be a chip
  // (in_edge: prev → chip_i; out_edge: chip_i → next); both ends being
  // chips is structurally not produced today (chips don't link to other
  // chips) but the branches stay independent so a future N×M layout
  // doesn't need re-plumbing.
  const fromChip = parseChipId(edge.from);
  const toChip = parseChipId(edge.to);

  if (fromChip !== null) {
    const iterate = findIterateById(spec.steps, fromChip.iterateId);
    if (iterate === null) {
      return {
        status: "missing",
        reason: `iterate "${fromChip.iterateId}" not found in spec — graph and spec out of sync`,
      };
    }
    return lookupChipOutgoing(edge, iterate, fromChip.blockIndex, trace);
  }

  if (toChip !== null) {
    const iterate = findIterateById(spec.steps, toChip.iterateId);
    if (iterate === null) {
      return {
        status: "missing",
        reason: `iterate "${toChip.iterateId}" not found in spec — graph and spec out of sync`,
      };
    }
    return lookupChipIncoming(edge, iterate, toChip.blockIndex, trace);
  }

  // ── Ellipsis chip (`@blockMore`) ───────────────────────────────────
  // Represents N-CAP+1 blocks collectively, so there's no single value
  // to display. The panel shows the reason verbatim.
  if (edge.from.endsWith(BLOCK_MORE_SUFFIX) || edge.to.endsWith(BLOCK_MORE_SUFFIX)) {
    return {
      status: "missing",
      reason: "this edge represents multiple blocks — pick a numbered block-chip to inspect",
    };
  }

  // ── Regular (non-chip) edges ───────────────────────────────────────
  if (edge.kind === "aux") {
    return lookupRegularAux(edge, trace, currentBlockIndex);
  }
  return lookupRegularState(edge, trace, currentBlockIndex);
};

// ─── Branch helpers ────────────────────────────────────────────────────

const lookupChipIncoming = (
  edge: GraphEdge,
  iterate: IterateGroup,
  blockIndex: number,
  trace: Trace,
): EdgeValueLookup => {
  const bodyFrames = findBodyFramesAt(trace, iterate, blockIndex);
  if (bodyFrames.length === 0) {
    return {
      status: "missing",
      reason: `no body frames found for block ${blockIndex} of iterate "${iterate.id}"`,
    };
  }

  if (edge.kind === "state") {
    // What flowed INTO the chip = the iterate's per-block input, read from
    // the first body frame's `"state"` input port (port-first, Slice 5.3c;
    // falls back to the threaded state field until 5.3e retires it).
    // biome-ignore lint/style/noNonNullAssertion: bodyFrames.length > 0 checked above
    const inBytes = frameStateInBytes(bodyFrames[0]!);
    if (inBytes === null) {
      return {
        status: "missing",
        reason: `block ${blockIndex} of iterate "${iterate.id}" has no resolvable incoming state`,
      };
    }
    return {
      status: "value",
      value: asBytesState(inBytes),
      displayKind: "block-payload",
      auxKey: "state",
      blockIndex,
    };
  }

  // Aux edge into a chip. If the aux key matches the iterate's
  // `blocksFromAux`, slice to `blocks[i]` for the per-block view. Same
  // visual as the state-edge branch above, different aux-key semantics.
  if (edge.auxKey === iterate.blocksFromAux) {
    // biome-ignore lint/style/noNonNullAssertion: bodyFrames.length > 0 checked above
    const inBytes = frameStateInBytes(bodyFrames[0]!);
    if (inBytes === null) {
      return {
        status: "missing",
        reason: `block ${blockIndex} of iterate "${iterate.id}" has no resolvable incoming state`,
      };
    }
    return {
      status: "value",
      value: asBytesState(inBytes),
      displayKind: "block-payload",
      auxKey: edge.auxKey,
      blockIndex,
    };
  }
  // Generic aux read by some body step (e.g. roundKey_5 consumed by
  // round.5.add-round-key). Round keys etc. are identical across
  // iterations, so the first body frame that auxRead the key is fine.
  for (const f of bodyFrames) {
    const v = f.auxRead.get(edge.auxKey);
    if (v !== undefined) {
      return {
        status: "value",
        value: v,
        displayKind: "aux",
        auxKey: edge.auxKey,
        blockIndex,
      };
    }
  }
  // No body frame read the aux. Canonical case: a fan-out replica of
  // a root-level aux producer (e.g. compute-block-count) targeted a
  // chip — the runtime's iterate consumes the aux at the iterate
  // level, NOT inside any body step's auxRead. The producer DID write
  // the value into its own auxWritten, so unwrap any replica id and
  // resolve through the producer side. Stamp blockIndex with the
  // chip's index so the panel still labels "(block i)" correctly.
  const producerStepId = unwrapReplicaSource(edge.from);
  const producer = findProducerFrame(trace, producerStepId, undefined);
  if (producer !== null) {
    const v = producer.auxWritten.get(edge.auxKey);
    if (v !== undefined) {
      return {
        status: "value",
        value: v,
        displayKind: "aux",
        auxKey: edge.auxKey,
        blockIndex,
      };
    }
  }
  return {
    status: "missing",
    reason: `no body frame at block ${blockIndex} read aux "${edge.auxKey}"`,
  };
};

const lookupChipOutgoing = (
  edge: GraphEdge,
  iterate: IterateGroup,
  blockIndex: number,
  trace: Trace,
): EdgeValueLookup => {
  const bodyFrames = findBodyFramesAt(trace, iterate, blockIndex);
  if (bodyFrames.length === 0) {
    return {
      status: "missing",
      reason: `no body frames found for block ${blockIndex} of iterate "${iterate.id}"`,
    };
  }
  const lastFrame = bodyFrames[bodyFrames.length - 1];
  if (!lastFrame) {
    return {
      status: "missing",
      reason: `no body frames found for block ${blockIndex} of iterate "${iterate.id}"`,
    };
  }

  // What flowed OUT of the chip = the body's per-block result, read from
  // the last body frame's `"state"` output port (port-first, Slice 5.3c;
  // falls back to the threaded state field until 5.3e retires it).
  const outBytes = frameStateOutBytes(lastFrame);
  if (edge.kind === "state") {
    if (outBytes === null) {
      return {
        status: "missing",
        reason: `block ${blockIndex} of iterate "${iterate.id}" has no resolvable outgoing state`,
      };
    }
    return {
      status: "value",
      value: asBytesState(outBytes),
      displayKind: "block-payload",
      auxKey: "state",
      blockIndex,
    };
  }

  // Aux edge out of a chip — typically the iterate's `outBlocksAux`
  // flowing into concat-blocks. Slice to the chip's index.
  if (edge.auxKey === iterate.outBlocksAux) {
    if (outBytes === null) {
      return {
        status: "missing",
        reason: `block ${blockIndex} of iterate "${iterate.id}" has no resolvable outgoing state`,
      };
    }
    return {
      status: "value",
      value: asBytesState(outBytes),
      displayKind: "block-payload",
      auxKey: edge.auxKey,
      blockIndex,
    };
  }
  // Generic aux write (a body step wrote some aux key consumed
  // downstream). Find the body frame that wrote it.
  for (let i = bodyFrames.length - 1; i >= 0; i--) {
    const v = bodyFrames[i]?.auxWritten.get(edge.auxKey);
    if (v !== undefined) {
      return {
        status: "value",
        value: v,
        displayKind: "aux",
        auxKey: edge.auxKey,
        blockIndex,
      };
    }
  }
  return {
    status: "missing",
    reason: `no body frame at block ${blockIndex} wrote aux "${edge.auxKey}"`,
  };
};

/**
 * Producer-side aux fallback. Scans the trace for the producer's own
 * frame and reads `auxWritten.get(edge.auxKey)`. Used when the consumer
 * side can't answer — the canonical case is an aux edge whose `to` is
 * an iterate container (e.g. `compute-block-count → ecb-blocks` or
 * `split-blocks → ecb-blocks`). The runtime reads
 * `aux[countFromAux]` / `aux[blocksFromAux]` *before* setting up body
 * frames, so no body frame has those reads in `auxRead`. The producer
 * IS a leaf and DID write the value, so its `auxWritten` is the
 * authoritative source.
 *
 * Returns null when no producer frame writes this aux key. Lets the
 * caller emit a richer "missing" reason than the producer-side branch
 * could on its own.
 */
const lookupAuxFromProducer = (
  edge: GraphEdge,
  trace: Trace,
  currentBlockIndex: number | undefined,
): EdgeValueLookup | null => {
  // Unwrap replica ids (`${src}@->${consumer}`) — the synthetic
  // replica node has no trace frame, but the underlying source step
  // does. Replicas are visual duplicates of an aux flow; the value
  // along the replica's outgoing edge is identical to what the source
  // wrote into auxWritten.
  const producerStepId = unwrapReplicaSource(edge.from);
  const producer = findProducerFrame(trace, producerStepId, currentBlockIndex);
  if (producer === null) return null;
  const v = producer.auxWritten.get(edge.auxKey);
  if (v === undefined) return null;
  return producer.blockIndex !== undefined
    ? {
        status: "value",
        value: v,
        displayKind: "aux",
        auxKey: edge.auxKey,
        blockIndex: producer.blockIndex,
      }
    : {
        status: "value",
        value: v,
        displayKind: "aux",
        auxKey: edge.auxKey,
      };
};

const lookupRegularAux = (
  edge: GraphEdge,
  trace: Trace,
  currentBlockIndex: number | undefined,
): EdgeValueLookup => {
  const frame = findConsumerFrame(trace, edge.to, currentBlockIndex);
  if (frame === null) {
    // Consumer has no leaf frame in the trace. The canonical case is
    // an aux edge whose `to` is an iterate container — iterate ids
    // never appear as a leaf frame's stepId (only their body steps do).
    // The runtime DOES read `aux[countFromAux]` / `aux[blocksFromAux]`
    // off the iterate, but those reads happen on the runtime side
    // before any body frame is emitted, so they're not recorded as
    // `auxRead` on any frame. Fall back to the producer's `auxWritten`,
    // which IS captured (the producer is always a leaf step that
    // writes the aux to be consumed downstream).
    const fromProducer = lookupAuxFromProducer(edge, trace, currentBlockIndex);
    if (fromProducer !== null) return fromProducer;
    return {
      status: "missing",
      reason: `no frame found for consumer "${edge.to}"`,
    };
  }
  const v = frame.auxRead.get(edge.auxKey);
  if (v === undefined) {
    // Consumer frame exists but didn't actually read this aux. Try the
    // producer side first — same rationale as the no-consumer-frame
    // branch above; this also covers the rare case where graph
    // derivation paired a writer→reader at the spec level but the
    // runtime's runSpec didn't surface it on this frame.
    const fromProducer = lookupAuxFromProducer(edge, trace, currentBlockIndex);
    if (fromProducer !== null) return fromProducer;
    return {
      status: "missing",
      reason: `consumer "${edge.to}" did not read aux "${edge.auxKey}" at frame ${frame.index}`,
    };
  }
  return frame.blockIndex !== undefined
    ? {
        status: "value",
        value: v,
        displayKind: "aux",
        auxKey: edge.auxKey,
        blockIndex: frame.blockIndex,
      }
    : {
        status: "value",
        value: v,
        displayKind: "aux",
        auxKey: edge.auxKey,
      };
};

const lookupRegularState = (
  edge: GraphEdge,
  trace: Trace,
  currentBlockIndex: number | undefined,
): EdgeValueLookup => {
  // The pedagogically right value for a state edge `prev → next` is
  // `prev.stateAfter` (= `next.stateBefore`, by the runtime contract).
  // Resolve from the producer side first; fall back to the consumer
  // when the producer has no frame (defensive — happens if the producer
  // is a container id like an iterate, whose state edges are handled by
  // chip branches above but a non-chip iterate-targeted state edge can
  // still reach here pre-Slice-6 when the iterate isn't collapsed).
  const producer = findProducerFrame(trace, edge.from, currentBlockIndex);
  if (producer !== null) {
    // Default state-edge value: the producer's `"state"` output port
    // (port-first, Slice 5.3c; falls back to the threaded state field
    // until 5.3e). `prev.stateAfter == next.stateBefore` by the runtime
    // contract for every wired leaf.
    const outBytes = frameStateOutBytes(producer);
    if (outBytes !== null) {
      return producer.blockIndex !== undefined
        ? {
            status: "value",
            value: asBytesState(outBytes),
            displayKind: "state",
            auxKey: "state",
            blockIndex: producer.blockIndex,
          }
        : {
            status: "value",
            value: asBytesState(outBytes),
            displayKind: "state",
            auxKey: "state",
          };
    }
    // Producer frame exists but exposes no state bytes — fall through to
    // the consumer side rather than emitting a value-less "value".
  }
  const consumer = findConsumerFrame(trace, edge.to, currentBlockIndex);
  if (consumer !== null) {
    // Consumer's `"state"` input port (port-first, Slice 5.3c; field
    // fallback until 5.3e).
    const inBytes = frameStateInBytes(consumer);
    if (inBytes !== null) {
      return consumer.blockIndex !== undefined
        ? {
            status: "value",
            value: asBytesState(inBytes),
            displayKind: "state",
            auxKey: "state",
            blockIndex: consumer.blockIndex,
          }
        : {
            status: "value",
            value: asBytesState(inBytes),
            displayKind: "state",
            auxKey: "state",
          };
    }
  }
  return {
    status: "missing",
    reason: `no frame found for either endpoint of state edge "${edge.from}" → "${edge.to}"`,
  };
};

// ─── Node-side lookup ──────────────────────────────────────────────────
//
// `lookupNodeValue` answers "what value sits AT this node at the current
// scrubber position?" The selector is a single id — a leaf stepId, an
// endpoint-pill id, or a synthetic block-chip id — and the return shape
// reuses `EdgeValueLookup` so the renderer can switch on `status`
// without caring whether the click was on an edge or a node.
//
// Semantics by node kind:
//
//   - **Endpoint pills** (`__cipher_input__` / `__cipher_output__`):
//     same `"endpoint"` branch as `lookupEdgeValue`. Resolves to the
//     trace's primary I/O: input pill → `trace.frames[0].stateBefore`
//     (the cipher's plaintext for encrypt mode, ciphertext for decrypt);
//     output pill → `trace.finalState` (ciphertext for encrypt,
//     plaintext for decrypt). Pre-run pills return `"no-trace"` so the
//     panel's empty-state copy matches every other row.
//     (Pre-2026-05-17 the pills were descriptive-only and rendered just
//     a "cipher input (plaintext)" label; the user's feedback then was
//     that the pill click should surface the actual value the way the
//     spine arrows do for intermediate leaves. The descriptive label
//     was carried on the lookup result as a `label` field for a release
//     and then dropped once it was clear no consumer read it AND the
//     hardcoded "plaintext"/"ciphertext" copy would have been wrong in
//     decrypt mode anyway — any future caption builds from
//     `endpointSide` + the active cipher mode at the call site.)
//
//   - **Block chips** (`${iterateId}@block${i}`): the chip's "value" is
//     the per-block ciphertext after that iteration completes — i.e.
//     the iterate body's last frame stateAfter at `blockIndex === i`,
//     equivalent to `outBlocks[i]`. We pick "after" rather than
//     "before" because the chip pedagogically REPRESENTS one block's
//     trip through the body; the natural answer to "what's at this
//     chip" is the output of that trip, not the unencrypted input
//     (which is already what the chip's incoming aux edge from
//     `split-blocks` would show via the edge lookup).
//
//   - **Ellipsis chip** (`@blockMore`): can't resolve to a single
//     value; returns `"missing"` with a "pick a numbered chip" hint
//     mirroring the edge-side message.
//
//   - **Regular leaves**: the user's chosen contract is "the state at
//     the leaf's own frame" — `frame.stateAfter` for the trace frame
//     whose stepId canonicalizes to the leaf's id. When the leaf has
//     multiple frames (it lives inside an iterate), we prefer the
//     frame at the scrubber's `currentBlockIndex` so the panel tracks
//     the scrub position naturally; fall back to the first matching
//     frame when no preferred index matches.
//
// `displayKind` follows the edge convention: chips → `"block-payload"`
// to emphasize per-block semantics; regular leaves → `"state"` (the
// spine value at that point in the pipeline).

/**
 * Look up the value AT the given graph node at the current scrubber
 * position. See the inline branch comments above for semantics by node
 * kind. Returns the same shape as `lookupEdgeValue` so the renderer
 * dispatches on `status` regardless of whether the user selected an
 * edge or a node.
 *
 * @param nodeId    Leaf stepId, endpoint-pill id, or block-chip id.
 * @param spec      Active cipher spec — used to resolve iterate ids
 *                  on chip lookups.
 * @param trace     Active trace, or null when the user hasn't run yet.
 * @param currentBlockIndex  Scrubber's current iterate-body block
 *                  index. Influences regular-leaf frame selection only
 *                  — endpoint pills ignore it, chips use their own
 *                  embedded blockIndex.
 */
export const lookupNodeValue = (
  nodeId: string,
  spec: CipherSpec,
  trace: Trace | null,
  currentBlockIndex: number | undefined,
): EdgeValueLookup => {
  // ── Endpoint pills ─────────────────────────────────────────────────
  // 2026-05-17: pills surface their actual I/O value in the inspector.
  // Input pill → `trace.initialState` (= the cipher's plaintext for encrypt,
  // ciphertext for decrypt); output pill → `trace.finalState` (= the cipher's
  // ciphertext for encrypt, plaintext for decrypt). Pre-run clicks fall
  // through to `"no-trace"` so the empty-trace copy is consistent with every
  // other inspector row. (Slice 5.3c moved the input pill off the old
  // `frames[0].stateBefore` read onto the symmetric `initialState`.)
  // INPUT_SOURCE_ID (`$input`) is the scaffolding-suppression A3a synthetic
  // input source; it renders as the input pill for port-native specs, so it
  // resolves to the same `trace.initialState` value as CIPHER_INPUT_ID.
  if (nodeId === CIPHER_INPUT_ID || nodeId === INPUT_SOURCE_ID) {
    if (trace === null) return { status: "no-trace" };
    return {
      status: "endpoint",
      endpointSide: "input",
      value: trace.initialState,
    };
  }
  if (nodeId === CIPHER_OUTPUT_ID) {
    if (trace === null) return { status: "no-trace" };
    return {
      status: "endpoint",
      endpointSide: "output",
      value: trace.finalState,
    };
  }

  if (trace === null) return { status: "no-trace" };

  // ── Block chips ────────────────────────────────────────────────────
  // Synthetic ids of the form `${iterateId}@block${i}`. The chip's
  // value is `outBlocks[i]` — the per-block payload after the body has
  // run once for block i. Same path as `lookupChipOutgoing` with a
  // state edge, factored inline because we don't have a `GraphEdge` at
  // this entry point.
  const chip = parseChipId(nodeId);
  if (chip !== null) {
    const iterate = findIterateById(spec.steps, chip.iterateId);
    if (iterate === null) {
      return {
        status: "missing",
        reason: `iterate "${chip.iterateId}" not found in spec — graph and spec out of sync`,
      };
    }
    const bodyFrames = findBodyFramesAt(trace, iterate, chip.blockIndex);
    const lastFrame = bodyFrames[bodyFrames.length - 1];
    if (!lastFrame) {
      return {
        status: "missing",
        reason: `no body frames found for block ${chip.blockIndex} of iterate "${iterate.id}"`,
      };
    }
    // The chip's value = the body's per-block result, read from the last
    // body frame's `"state"` output port (port-first, Slice 5.3c; field
    // fallback until 5.3e).
    const outBytes = frameStateOutBytes(lastFrame);
    if (outBytes === null) {
      return {
        status: "missing",
        reason: `block ${chip.blockIndex} of iterate "${iterate.id}" has no resolvable state`,
      };
    }
    return {
      status: "value",
      value: asBytesState(outBytes),
      displayKind: "block-payload",
      auxKey: "state",
      blockIndex: chip.blockIndex,
    };
  }

  // ── Ellipsis chip ──────────────────────────────────────────────────
  // Represents N-CAP+1 blocks; no single value to display.
  if (nodeId.endsWith(BLOCK_MORE_SUFFIX)) {
    return {
      status: "missing",
      reason: "this chip represents multiple blocks — pick a numbered block-chip to inspect",
    };
  }

  // ── Regular leaf ───────────────────────────────────────────────────
  // "State at the leaf's own frame": find the trace frame for this
  // stepId at the scrubber's preferred blockIndex (when meaningful),
  // and return its stateAfter. `findConsumerFrame` already implements
  // this preference: scrubber-blockIndex first, fallback to any
  // matching frame.
  const frame = findConsumerFrame(trace, nodeId, currentBlockIndex);
  if (frame === null) {
    return {
      status: "missing",
      reason: `no frame found for step "${nodeId}"`,
    };
  }
  // State at the leaf's own frame = its `"state"` output port (port-first,
  // Slice 5.3c; field fallback until 5.3e).
  const outBytes = frameStateOutBytes(frame);
  if (outBytes === null) {
    return {
      status: "missing",
      reason: `step "${nodeId}" has no resolvable state at frame ${frame.index}`,
    };
  }
  return frame.blockIndex !== undefined
    ? {
        status: "value",
        value: asBytesState(outBytes),
        displayKind: "state",
        auxKey: "state",
        blockIndex: frame.blockIndex,
      }
    : {
        status: "value",
        value: asBytesState(outBytes),
        displayKind: "state",
        auxKey: "state",
      };
};
