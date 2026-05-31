/**
 * Sidebar step list. Renders the spec tree — *not* the flat trace frames —
 * so groups (and Feistel rounds with their tracks) can be collapsed.
 *
 * Behavior:
 *   - Groups are collapsed by default
 *   - The group containing the active step (and its ancestors) auto-expand
 *   - Manually collapsing a group sticks until the active step moves to a
 *     different group (then the new active group auto-expands)
 *   - Clicking a leaf navigates the timeline to that step's frame
 *   - Disabled (greyed out) leaves indicate the spec contains a step that
 *     never produced a frame — shouldn't happen for valid runs
 *
 * Node-kind dispatch (see `NodeRow`):
 *   - `step`           → LeafRow (clickable, scrubs to frame)
 *   - `feistel-round`  → FeistelRow (round + per-track sub-rows). Tracks
 *     have no spec id of their own; their auto-expand fires when a child
 *     id intersects `activeAncestors`. Lands with DES (Phase 5 of
 *     `docs/plans/des-feistel.md`); FeistelRoundGroup's `.tracks` shape
 *     is incompatible with GroupRow's `.children` access, so a separate
 *     renderer was required to avoid a `Cannot read properties of
 *     undefined` crash when the active frame is inside a round body.
 *   - `group` / `iterate` → GroupRow (both expose `.children` with the
 *     same shape; iterate's iteration semantics are runtime concerns
 *     and don't change the sidebar's "collapsible tree of leaves" view)
 */

import { canonicalStepId } from "@/core/step-id";
import type { StepNode } from "@/core/types";
import { For, Show, createEffect, createMemo, createSignal } from "solid-js";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useFrameIndex, useTraceVersion } from "../stores/trace";

export const StepList = () => {
  const spec = useSpec();
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  // Map step id → frame index. Re-keyed when the trace is replaced
  // (post-edit) or the spec changes — both can shift indices around.
  //
  // Spec-leaf id → frame index. Built so a leaf's spec id (no runtime
  // suffix) resolves to the FIRST matching frame, even when the runtime
  // emits multiple frames per leaf with suffixes:
  //   - `:b{i}` for per-iteration frames in ECB/CBC iterates (block 0 wins)
  //   - `:t{name}` for per-track frames inside a feistel-round (e.g. DES's
  //     `round.1.expand-R:tR` resolves to spec leaf `round.1.expand-R`)
  //   - both at once for a feistel-round nested inside an iterate
  //
  // `canonicalStepId` from `@/core/step-id` is the single source of truth
  // for stripping every suffix family — keeps this code from drifting as
  // new suffix families are added (`:rejoin` already, `:swap` reserved).
  const frameIndexByStepId = createMemo(() => {
    void version();
    const map = new Map<string, number>();
    const t = getTrace();
    if (t) {
      for (const f of t.frames) {
        map.set(f.stepId, f.index);
        const canonical = canonicalStepId(f.stepId);
        if (canonical !== f.stepId && !map.has(canonical)) {
          // First-wins so the leaf points at the earliest matching
          // frame (block 0, track 0, etc.).
          map.set(canonical, f.index);
        }
      }
    }
    return map;
  });

  // The active step's group path, including the step's own canonical id
  // at the end. Used by NodeRow / FeistelTrackRow to decide which
  // containers auto-expand.
  //
  // Strip ALL runtime suffixes via `canonicalStepId` so the lookup
  // matches the spec leaf id regardless of whether the frame is per-block,
  // per-track, both, or a synthetic rejoin (which canonicalizes to the
  // round id — keeping the round container highlighted when scrubbed).
  const activeAncestors = createMemo<readonly string[]>(() => {
    void version();
    const t = getTrace();
    const f = t?.frames[frameIndex()];
    if (!f) return [];
    return [...f.path, canonicalStepId(f.stepId)];
  });

  return (
    <div class="step-tree">
      <For each={spec().steps}>
        {(node) => (
          <NodeRow
            node={node}
            depth={0}
            frameIndexByStepId={frameIndexByStepId()}
            activeFrameIndex={frameIndex()}
            activeAncestors={activeAncestors()}
          />
        )}
      </For>
    </div>
  );
};

// ─── Recursive node row ──────────────────────────────────────────────────

type NodeRowProps = {
  node: StepNode;
  depth: number;
  frameIndexByStepId: Map<string, number>;
  activeFrameIndex: number;
  activeAncestors: readonly string[];
};

/**
 * Dispatch by node.kind. The two rendered cases:
 *   - "step"           → LeafRow (single button, scrubs to frame)
 *   - "group" / "iterate" / "for-each-subgraph[-with-history]" → GroupRow
 *     (all carry a `.children: readonly StepNode[]` shape, so the same
 *     renderer handles them; iteration semantics are runtime concerns, not
 *     sidebar concerns)
 *
 * Read `node.kind` inline (not into a captured `const`) so Solid's reactivity
 * picks up spec edits that swap a leaf into a group, etc.
 */
const NodeRow = (props: NodeRowProps) => (
  <Show
    when={props.node.kind === "step"}
    fallback={
      <GroupRow
        {...(props as NodeRowProps & {
          node: Extract<StepNode, { kind: "group" | "iterate" }>;
        })}
      />
    }
  >
    <LeafRow {...(props as NodeRowProps & { node: Extract<StepNode, { kind: "step" }> })} />
  </Show>
);

const LeafRow = (props: NodeRowProps & { node: Extract<StepNode, { kind: "step" }> }) => {
  const frameIdx = (): number | undefined => props.frameIndexByStepId.get(props.node.id);
  // Active when this leaf's spec id is in the active path. Works across
  // iterate boundaries because `activeAncestors` strips the `:b{i}`
  // suffix from the current frame's stepId. Without this, an iterated
  // leaf would never appear active (block-0 frame index ≠ current frame
  // index for any block other than 0).
  const isActive = (): boolean => props.activeAncestors.includes(props.node.id);
  // Show the last segment of the dotted id as the user-friendly name.
  // Full id remains available via the tooltip (title attr).
  const shortName = (): string => props.node.id.split(".").pop() ?? props.node.id;

  return (
    <button
      type="button"
      class="step-row"
      classList={{ active: isActive(), disabled: frameIdx() === undefined }}
      disabled={frameIdx() === undefined}
      style={{ "padding-left": `${props.depth * 12 + 8}px` }}
      title={`${props.node.id}\n${props.node.type}`}
      onClick={() => {
        const i = frameIdx();
        if (i !== undefined) setFrame(i);
      }}
    >
      <span class="step-row-name">{shortName()}</span>
      <span class="step-row-type">{props.node.type}</span>
    </button>
  );
};

const GroupRow = (
  props: NodeRowProps & { node: Extract<StepNode, { kind: "group" | "iterate" }> },
) => {
  // Initially expanded if this group is on the active path. A user-driven
  // collapse sticks until activeAncestors actually changes again.
  const [expanded, setExpanded] = createSignal(props.activeAncestors.includes(props.node.id));

  // Auto-expand whenever the active step moves into this group.
  // We deliberately don't auto-collapse when the active step leaves —
  // less jarring; the next click into another group expands that one,
  // and the user can manually collapse anything they don't want open.
  createEffect(() => {
    if (props.activeAncestors.includes(props.node.id)) {
      setExpanded(true);
    }
  });

  return (
    <>
      <button
        type="button"
        class="group-row"
        classList={{ "on-path": props.activeAncestors.includes(props.node.id) }}
        style={{ "padding-left": `${props.depth * 12 + 8}px` }}
        onClick={() => setExpanded(!expanded())}
      >
        <span class="group-chevron">{expanded() ? "▼" : "▶"}</span>
        <span class="group-label">{props.node.label}</span>
        <span class="group-count muted">{props.node.children.length}</span>
      </button>
      <Show when={expanded()}>
        <For each={props.node.children}>
          {(child) => (
            <NodeRow
              node={child}
              depth={props.depth + 1}
              frameIndexByStepId={props.frameIndexByStepId}
              activeFrameIndex={props.activeFrameIndex}
              activeAncestors={props.activeAncestors}
            />
          )}
        </For>
      </Show>
    </>
  );
};
