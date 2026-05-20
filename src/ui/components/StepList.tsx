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
import type { FeistelRoundGroup, StepNode } from "@/core/types";
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
 * Dispatch by node.kind. The three rendered cases:
 *   - "step"           → LeafRow (single button, scrubs to frame)
 *   - "feistel-round"  → FeistelRow (round header + per-track sub-groups)
 *   - "group" / "iterate" → GroupRow (both have a `.children: readonly StepNode[]`
 *     shape, so the same renderer handles them; iterate's iteration semantics
 *     are runtime concerns, not sidebar concerns)
 *
 * Read `node.kind` inline (not into a captured `const`) so Solid's reactivity
 * picks up spec edits that swap a leaf into a group, etc.
 */
const NodeRow = (props: NodeRowProps) => (
  <Show
    when={props.node.kind === "step"}
    fallback={
      <Show
        when={props.node.kind === "feistel-round"}
        fallback={
          <GroupRow
            {...(props as NodeRowProps & {
              node: Extract<StepNode, { kind: "group" | "iterate" }>;
            })}
          />
        }
      >
        <FeistelRow {...(props as NodeRowProps & { node: FeistelRoundGroup })} />
      </Show>
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

/**
 * `feistel-round` sidebar row. Renders the round header (collapsible)
 * containing one sub-row per track plus a synthetic "rejoin" row at the
 * end. Tracks themselves act as nested groups labelled "{name} track"
 * (e.g. "L track", "R track" for DES); a track's children are the
 * F-internal leaves (E-expand, XOR-K, S-boxes, P-permute on DES's R
 * track) or empty (DES's L passthrough).
 *
 * Why a nested-track sub-group, not a flat list: Phase 5 of the
 * docs/plans/des-feistel.md plan surfaces L/R track membership in every
 * other linear-mode component (track-context panel, mini diagram, rejoin
 * view, scrubber badges). The sidebar should match — flattening the
 * tracks would contradict the pedagogy that "L and R evolve independently
 * inside a round body."
 *
 * Why a clickable rejoin row: the rejoin frame is a synthetic runtime
 * emission (stepId `{roundId}:rejoin`, no spec node behind it), so it
 * has no natural home in a spec-tree walk. Without an entry here, the
 * user can only reach the rejoin frame by scrubbing the slider linearly
 * — every other surface (`<FeistelMiniDiagram />`, scrubber timeline ⇄
 * badge, RejoinFrameView in the main pane) presupposes the user knows
 * to navigate there. Treating rejoin as a "synthetic last child of the
 * round" matches how the runtime models it (frame index sits between
 * the last R-track frame and the next round's first frame).
 *
 * Auto-expand:
 *   - Round expands when its `id` is in `activeAncestors` (same rule as
 *     GroupRow), so picking a frame inside the round opens it. The
 *     rejoin frame's canonical id IS the round's id (per
 *     `canonicalStepId`), so scrubbing onto a rejoin frame still
 *     auto-expands its parent round.
 *   - Track expands by default whenever its parent round is expanded
 *     (see FeistelTrackRow). Per user request 2026-05-20: requiring
 *     a second click to reach the F-stack was friction.
 *
 * Empty tracks (DES's L) render with a "passthrough" hint in place of a
 * child list so users see the track exists but had no children to run.
 */
const FeistelRow = (props: NodeRowProps & { node: FeistelRoundGroup }) => {
  const [expanded, setExpanded] = createSignal(props.activeAncestors.includes(props.node.id));

  createEffect(() => {
    if (props.activeAncestors.includes(props.node.id)) {
      setExpanded(true);
    }
  });

  // Total leaf count across all tracks — shown next to the round label
  // to mirror GroupRow's `children.length` count chip.
  const totalLeafCount = (): number =>
    props.node.tracks.reduce((sum, t) => sum + t.children.length, 0);

  // Frame index of the round's rejoin frame. The runtime emits one per
  // round with stepId `{roundId}:rejoin`; we look it up by that exact
  // form rather than via canonicalStepId (which would also match the
  // round id — works today but is the wider regex, so the explicit
  // lookup is safer against future suffix additions). Returns undefined
  // when no rejoin frame exists (toy specs that don't run, partial
  // traces, etc.) — the row then renders disabled.
  const rejoinFrameIdx = (): number | undefined =>
    props.frameIndexByStepId.get(`${props.node.id}:rejoin`);

  // Rejoin row is "active" when the scrubber currently sits on it.
  // activeAncestors carries the canonical form, which for rejoin frames
  // equals the round's id — exactly what we'd otherwise check, so reuse
  // the same predicate the round-header uses.
  const isRejoinActive = (): boolean => {
    const idx = rejoinFrameIdx();
    if (idx === undefined) return false;
    return idx === props.activeFrameIndex;
  };

  return (
    <>
      <button
        type="button"
        class="group-row feistel-round-row"
        classList={{ "on-path": props.activeAncestors.includes(props.node.id) }}
        style={{ "padding-left": `${props.depth * 12 + 8}px` }}
        onClick={() => setExpanded(!expanded())}
        title={`${props.node.id}\nfeistel-round (${props.node.combineKind})`}
      >
        <span class="group-chevron">{expanded() ? "▼" : "▶"}</span>
        <span class="group-label">{props.node.label ?? props.node.id}</span>
        <span class="group-count muted">{totalLeafCount()}</span>
      </button>
      <Show when={expanded()}>
        <For each={props.node.tracks}>
          {(track, trackIdx) => (
            <FeistelTrackRow
              node={props.node}
              track={track}
              trackIndex={trackIdx()}
              depth={props.depth + 1}
              frameIndexByStepId={props.frameIndexByStepId}
              activeFrameIndex={props.activeFrameIndex}
              activeAncestors={props.activeAncestors}
            />
          )}
        </For>
        {/* Synthetic rejoin entry. Styled like a leaf (uses .step-row)
            but with a discriminating .feistel-rejoin-row class so it
            can be tested for separately and styled with the ⇄ glyph
            the scrubber timeline + mini diagram both use. Disabled
            when no rejoin frame exists in the current trace. */}
        <button
          type="button"
          class="step-row feistel-rejoin-row"
          classList={{
            active: isRejoinActive(),
            disabled: rejoinFrameIdx() === undefined,
          }}
          disabled={rejoinFrameIdx() === undefined}
          style={{ "padding-left": `${(props.depth + 1) * 12 + 8}px` }}
          title={`${props.node.id}:rejoin\n4-arg combine (${props.node.combineKind})`}
          onClick={() => {
            const i = rejoinFrameIdx();
            if (i !== undefined) setFrame(i);
          }}
        >
          <span class="step-row-name">
            <span class="feistel-rejoin-glyph" aria-hidden="true">
              ⇄
            </span>{" "}
            rejoin
          </span>
          <span class="step-row-type">{props.node.combineKind}</span>
        </button>
      </Show>
    </>
  );
};

/**
 * One track's sub-group inside a `feistel-round` row. Tracks have no spec
 * id of their own; auto-expand is computed by intersecting child ids with
 * `activeAncestors`. The "L track"/"R track" label uses `track.name` when
 * present (DES declares both), falling back to "track {index}" for
 * unnamed tracks (kept for forward compat with toy specs).
 */
const FeistelTrackRow = (props: {
  node: FeistelRoundGroup;
  track: FeistelRoundGroup["tracks"][number];
  trackIndex: number;
  depth: number;
  frameIndexByStepId: Map<string, number>;
  activeFrameIndex: number;
  activeAncestors: readonly string[];
}) => {
  // Set of child ids on this track. Any membership match flips the track
  // open. Recompute lazily to react to spec edits (a track gaining/losing
  // a leaf should re-derive the set).
  const childIds = createMemo<ReadonlySet<string>>(
    () => new Set(props.track.children.map((c) => c.id)),
  );
  const containsActive = (): boolean => {
    const ids = childIds();
    for (const ancestor of props.activeAncestors) {
      if (ids.has(ancestor)) return true;
    }
    return false;
  };

  // Default expanded for ALL tracks (empty L passthrough, populated R).
  //
  // Rationale (user request 2026-05-20): expanding the parent round and
  // then having to click the R track to see the F-stack felt like double
  // work — the user's intent in expanding a round is almost always
  // "show me what's inside", and "what's inside" is the track's leaves.
  //
  // Tracks aren't gated on `containsActive()` for initial state because
  // they're already conditionally rendered (the parent FeistelRow only
  // mounts them when its own `expanded()` is true). So defaulting true
  // means "tracks open whenever their round is open", which is the
  // desired UX. Manual collapse still sticks within the same mount; the
  // `createEffect` below re-opens the track on scrubs into it.
  const [expanded, setExpanded] = createSignal(true);

  createEffect(() => {
    if (containsActive()) setExpanded(true);
  });

  const trackLabel = (): string => `${props.track.name ?? `track ${props.trackIndex}`} track`;

  return (
    <>
      <button
        type="button"
        class="group-row feistel-track-row"
        classList={{ "on-path": containsActive() }}
        style={{ "padding-left": `${props.depth * 12 + 8}px` }}
        onClick={() => setExpanded(!expanded())}
        title={`${props.node.id} · ${trackLabel()}`}
      >
        <span class="group-chevron">{expanded() ? "▼" : "▶"}</span>
        <span class="group-label">{trackLabel()}</span>
        <span class="group-count muted">{props.track.children.length}</span>
      </button>
      <Show when={expanded()}>
        <Show
          when={props.track.children.length > 0}
          fallback={
            <div
              class="step-row-passthrough muted small"
              style={{ "padding-left": `${(props.depth + 1) * 12 + 8}px` }}
            >
              (passthrough — no steps)
            </div>
          }
        >
          <For each={props.track.children}>
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
      </Show>
    </>
  );
};
