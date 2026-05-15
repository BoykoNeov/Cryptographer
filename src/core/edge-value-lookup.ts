/**
 * Edge value lookup — resolves "what data flows through THIS edge at the
 * current scrubber position?" for the value-inspector panel.
 *
 * Pure function over (spec, trace, edge, currentBlockIndex). The renderer
 * in `GraphView` reads the selected edge from the
 * `view-value-inspector` store, calls this, and formats the result with
 * the user-selected ByteFormat. No Solid signals, no DOM — all the
 * complexity lives here so the lookup is testable against canned traces
 * without spinning up a renderer.
 *
 * Five branches the result can take, captured by the `status` field:
 *
 *   1. `"endpoint"` — synthetic plaintext/ciphertext pill (Slice 1). The
 *      pills have no trace frame, so we return a literal label ("cipher
 *      input" / "cipher output") and skip value formatting. The panel
 *      renders this as descriptive text, not a hex/decimal dump.
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

import { CIPHER_INPUT_ID, CIPHER_OUTPUT_ID, type GraphEdge, isEndpointId } from "./graph";
import type { AuxValue, CipherSpec, IterateGroup, StepNode, Trace, TraceFrame } from "./types";

/** Pattern matching a block-chip's synthetic id. Captures (iterateId, index). */
const BLOCK_CHIP_RE = /^(.+)@block(\d+)$/;
/** Suffix used for the ellipsis chip — represents N-CAP+1 blocks at once,
 *  so we can't resolve a single per-block value for it. The lookup returns
 *  a `"missing"` with a descriptive reason in this case. */
const BLOCK_MORE_SUFFIX = "@blockMore";

/** Parsed chip-id structure when the input is a recognized chip. */
type ChipId = { readonly iterateId: string; readonly blockIndex: number };

/**
 * Decompose `${iterateId}@block${i}` into its parts. Returns `null` for
 * non-chip ids (regular leaves, container ids, replicas with `@->`).
 * Specifically returns `null` for the `@blockMore` ellipsis sentinel —
 * callers fall through to the "missing" path so the panel can say
 * "ellipsis chip represents multiple blocks; pick a numbered chip."
 */
const parseChipId = (id: string): ChipId | null => {
  if (id.endsWith(BLOCK_MORE_SUFFIX)) return null;
  const m = BLOCK_CHIP_RE.exec(id);
  if (!m) return null;
  const iterateId = m[1] ?? "";
  const idxStr = m[2] ?? "";
  const blockIndex = Number.parseInt(idxStr, 10);
  if (!Number.isFinite(blockIndex) || blockIndex < 0) return null;
  return { iterateId, blockIndex };
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

/** Strip the runtime's `:b<digits>` suffix iterate-body frames carry, so a
 *  chip-id lookup against canonical spec stepIds works. Mirrors the helper
 *  with the same logic in `core/graph.ts` and `ui/stores/trace.ts` — kept
 *  local so this module doesn't pull a UI dep. */
const canonicalStepId = (frameStepId: string): string => frameStepId.replace(/:b\d+$/, "");

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
  let fallback: TraceFrame | null = null;
  for (const f of trace.frames) {
    if (canonicalStepId(f.stepId) !== consumerStepId) continue;
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
 *   - `"endpoint"`: render `label` as plain text inside the panel.
 *   - `"no-trace"`: render the hint string ("Run the cipher to see…").
 *   - `"missing"`: render the `reason` muted, no value.
 *   - `"value"`: format `value` with the active ByteFormat. `displayKind`
 *     drives the kind-badge in the panel header.
 */
export type EdgeValueLookup =
  | {
      readonly status: "endpoint";
      readonly endpointSide: "input" | "output";
      readonly label: string;
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
  // Synthetic — no trace frame, return a literal label. Both endpoint-
  // input and endpoint-output get this treatment regardless of edge
  // kind. (`buildIterateFeedbackPredicate` already filters these out of
  // the feedback-edge classification, so kind is always "state" here in
  // practice, but the branch doesn't depend on that.)
  if (edge.from === CIPHER_INPUT_ID) {
    return { status: "endpoint", endpointSide: "input", label: "cipher input (plaintext)" };
  }
  if (edge.to === CIPHER_OUTPUT_ID) {
    return { status: "endpoint", endpointSide: "output", label: "cipher output (ciphertext)" };
  }
  // Defensive: an edge whose OTHER endpoint is an endpoint pill is
  // structurally legal too (e.g. if a future renderer attaches the
  // pill at a non-rootIds[0] position). Treat the same way.
  if (isEndpointId(edge.from) || isEndpointId(edge.to)) {
    const side: "input" | "output" = isEndpointId(edge.from) ? "input" : "output";
    return {
      status: "endpoint",
      endpointSide: side,
      label: side === "input" ? "cipher input (plaintext)" : "cipher output (ciphertext)",
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
    // What flowed INTO the chip = the iterate's `blocks[i]`, captured
    // as the first body frame's `stateBefore`. Both equivalent; using
    // the frame keeps the lookup local and avoids re-walking aux maps.
    return {
      status: "value",
      // biome-ignore lint/style/noNonNullAssertion: bodyFrames.length > 0 checked above
      value: bodyFrames[0]!.stateBefore,
      displayKind: "block-payload",
      auxKey: "state",
      blockIndex,
    };
  }

  // Aux edge into a chip. If the aux key matches the iterate's
  // `blocksFromAux`, slice to `blocks[i]` for the per-block view. Same
  // visual as the state-edge branch above, different aux-key semantics.
  if (edge.auxKey === iterate.blocksFromAux) {
    return {
      status: "value",
      // biome-ignore lint/style/noNonNullAssertion: bodyFrames.length > 0 checked above
      value: bodyFrames[0]!.stateBefore,
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

  if (edge.kind === "state") {
    return {
      status: "value",
      value: lastFrame.stateAfter,
      displayKind: "block-payload",
      auxKey: "state",
      blockIndex,
    };
  }

  // Aux edge out of a chip — typically the iterate's `outBlocksAux`
  // flowing into concat-blocks. Slice to the chip's index.
  if (edge.auxKey === iterate.outBlocksAux) {
    return {
      status: "value",
      value: lastFrame.stateAfter,
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

const lookupRegularAux = (
  edge: GraphEdge,
  trace: Trace,
  currentBlockIndex: number | undefined,
): EdgeValueLookup => {
  const frame = findConsumerFrame(trace, edge.to, currentBlockIndex);
  if (frame === null) {
    return {
      status: "missing",
      reason: `no frame found for consumer "${edge.to}"`,
    };
  }
  const v = frame.auxRead.get(edge.auxKey);
  if (v === undefined) {
    // Consumer frame exists but didn't actually read this aux — happens
    // when the graph derivation paired a writer→reader at the spec
    // level but the runtime's runSpec didn't surface it on this frame
    // (rare). Fall through to "missing" rather than silently showing
    // a stale value from an earlier iteration.
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
    return producer.blockIndex !== undefined
      ? {
          status: "value",
          value: producer.stateAfter,
          displayKind: "state",
          auxKey: "state",
          blockIndex: producer.blockIndex,
        }
      : {
          status: "value",
          value: producer.stateAfter,
          displayKind: "state",
          auxKey: "state",
        };
  }
  const consumer = findConsumerFrame(trace, edge.to, currentBlockIndex);
  if (consumer !== null) {
    return consumer.blockIndex !== undefined
      ? {
          status: "value",
          value: consumer.stateBefore,
          displayKind: "state",
          auxKey: "state",
          blockIndex: consumer.blockIndex,
        }
      : {
          status: "value",
          value: consumer.stateBefore,
          displayKind: "state",
          auxKey: "state",
        };
  }
  return {
    status: "missing",
    reason: `no frame found for either endpoint of state edge "${edge.from}" → "${edge.to}"`,
  };
};
