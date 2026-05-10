/**
 * Sidebar step list. Renders the spec tree (groups + leaves) — *not* the
 * flat trace frames — so groups can be collapsed.
 *
 * Behavior:
 *   - Groups are collapsed by default
 *   - The group containing the active step (and its ancestors) auto-expand
 *   - Manually collapsing a group sticks until the active step moves to a
 *     different group (then the new active group auto-expands)
 *   - Clicking a leaf navigates the timeline to that step's frame
 *   - Disabled (greyed out) leaves indicate the spec contains a step that
 *     never produced a frame — shouldn't happen for valid runs
 */

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
  const frameIndexByStepId = createMemo(() => {
    void version();
    const map = new Map<string, number>();
    const t = getTrace();
    if (t) for (const f of t.frames) map.set(f.stepId, f.index);
    return map;
  });

  // The active step's group path, including the step's own id at the end.
  // Used by NodeRow to decide which groups to auto-expand.
  const activeAncestors = createMemo<readonly string[]>(() => {
    void version();
    const t = getTrace();
    const f = t?.frames[frameIndex()];
    if (!f) return [];
    return [...f.path, f.stepId];
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

const NodeRow = (props: NodeRowProps) => (
  <Show
    when={props.node.kind === "step"}
    fallback={
      <GroupRow {...(props as NodeRowProps & { node: Extract<StepNode, { kind: "group" }> })} />
    }
  >
    <LeafRow {...(props as NodeRowProps & { node: Extract<StepNode, { kind: "step" }> })} />
  </Show>
);

const LeafRow = (props: NodeRowProps & { node: Extract<StepNode, { kind: "step" }> }) => {
  const frameIdx = (): number | undefined => props.frameIndexByStepId.get(props.node.id);
  const isActive = (): boolean => frameIdx() === props.activeFrameIndex;
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

const GroupRow = (props: NodeRowProps & { node: Extract<StepNode, { kind: "group" }> }) => {
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
