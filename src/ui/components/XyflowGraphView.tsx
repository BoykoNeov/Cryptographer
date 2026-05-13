/**
 * Experimental fourth view mode: render the cipher graph using xyflow's
 * React component, mounted inside a Solid wrapper.
 *
 * Phase 2 of the xyflow spike layers the SVG view's readability tricks
 * onto Phase 1's bare-bones render:
 *
 *   1. **Collapse** — `collapseGraph(graph, collapsedSet)` runs before
 *      the adapter so collapsed containers render as chips and edges
 *      crossing the boundary terminate at the chip.
 *   2. **High-fanout replication** — when the global toggle is on,
 *      `replicateHighFanoutSources` rewrites high-fanout aux edges into
 *      local replicas next to each consumer. AES-128's `key-expansion`
 *      stops fanning 11 long lines across the canvas.
 *   3. **View density** — leaf/gap/padding constants scale by the
 *      `view-density` preset (compact / normal / spacious) so the same
 *      view ergonomics apply here as in the SVG view.
 *   4. **Drag-to-pin** — root-level containers and leaves are
 *      `draggable`; xyflow handles the visual drag, `onNodeDragStop`
 *      persists the final position via `setNodePosition`. Nested
 *      children stay locked inside their parent's bounding box,
 *      matching the SVG view's Slice 6 container-only-drag scope.
 *   5. **Collapse / expand** — double-click a container to fire
 *      `toggleCollapse(specId, containerId)`. Matches the SVG view's
 *      chevron click semantically; we use double-click here because
 *      xyflow's default node component doesn't carry a chevron and
 *      adding one would require a full custom node component.
 *
 * It coexists with the hand-rolled SVG GraphView via the view-mode tab
 * strip; nothing here replaces or modifies the SVG implementation that
 * ships from `main`.
 *
 * Interop pattern: Solid owns the lifecycle; React renders the canvas.
 *
 *   1. The Solid component returns one `<div ref>` that becomes the
 *      mount point.
 *   2. `onMount` creates a React root via `react-dom/client.createRoot`
 *      and seeds it with an initial render derived from the current spec.
 *   3. `createEffect` tracks Solid signals (spec, traceVersion,
 *      layoutMap, viewDensity, replicationEnabled) and calls
 *      `root.render(...)` on every change; React reconciles the new
 *      node/edge arrays internally.
 *   4. `onCleanup` unmounts the React root.
 *
 * Why `React.createElement` instead of JSX: this file is `.tsx`, which
 * vite-plugin-solid parses as Solid JSX. Writing React JSX in here would
 * require splitting plugins by file extension (or adding
 * `@vitejs/plugin-react` with `include`/`exclude` scoping). The
 * `createElement` API is verbose but lives entirely inside this one
 * file's render function — a fair price to avoid the plugin rabbit hole.
 */

import { collapseGraph, deriveAuxGraph, replicateHighFanoutSources } from "@/core/graph";
import { Background, Controls, type Edge, MiniMap, type Node, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as React from "react";
import * as ReactDOMClient from "react-dom/client";
import { createEffect, on, onCleanup, onMount } from "solid-js";
import { cipherGraphToXyflow, scaleXyflowConstants } from "../graph/cipher-to-xyflow";
import { setNodePosition, toggleCollapse, useLayoutMap } from "../stores/layout";
import { useSpec } from "../stores/spec";
import { getTrace, useTraceVersion } from "../stores/trace";
import { DENSITY_SCALE, useViewDensity } from "../stores/view-density";
import { REPLICATION_THRESHOLD, useReplicationEnabled } from "../stores/view-replication";

/**
 * Empty trace placeholder. The graph view can mount BEFORE any run has
 * happened (user clicks the xyflow tab on app load); `deriveAuxGraph`
 * accepts a frames-empty trace and returns a structure-only graph, which
 * is the right pre-run state to render. Mirrors the same fallback shape
 * GraphView.tsx uses for the SVG view's pre-run case.
 */
const EMPTY_TRACE = {
  frames: [] as const,
  finalState: { shape: "bytes" as const, bytes: new Uint8Array(0) },
  finalAux: new Map(),
};

/**
 * xyflow's drag-stop handler signature is `(event, node, nodes) => void`.
 * We narrow the relevant fields locally so the file doesn't need to
 * import `@xyflow/react`'s public event types — keeps the React surface
 * in this file minimal.
 */
type DraggedNode = { readonly id: string; readonly position: { x: number; y: number } };

export const XyflowGraphView = () => {
  let containerRef: HTMLDivElement | undefined;
  let reactRoot: ReactDOMClient.Root | undefined;

  const spec = useSpec();
  const traceVersion = useTraceVersion();
  const layoutMap = useLayoutMap();
  const density = useViewDensity();
  const replicationEnabled = useReplicationEnabled();

  /**
   * Build the React element tree and hand it to the existing root.
   *
   * Reads Solid signals (spec, trace, layoutMap, density, replication)
   * at call time. Safe to call from `onMount` (after `reactRoot` is set)
   * and from `createEffect`. A call before mount is silently skipped so
   * the effect can register dependencies cleanly without needing a
   * `ready` signal.
   */
  const render = (): void => {
    if (!reactRoot) return;

    // Pull all view inputs at render time. Reading them inside this
    // function (rather than in a memo) keeps the effect's dependency
    // set authoritative — every signal read here registers as a dep.
    const currentSpec = spec();
    const trace = getTrace() ?? EMPTY_TRACE;
    const map = layoutMap();
    const activeLayout = map[currentSpec.id];

    // ── Apply the SVG view's transform pipeline ──────────────────────
    // 1. Derive raw aux graph from (trace, spec).
    // 2. Collapse user-selected containers (drops their children from
    //    the rendered surface; remaps boundary-crossing edges).
    // 3. Replicate high-fanout sources when the global toggle is on
    //    (rewrites long aux fan-out into local chips next to each
    //    consumer). Per-source override map from the layout sidecar
    //    threads through unchanged.
    const rawGraph = deriveAuxGraph(trace, currentSpec);
    const collapsedSet = new Set(activeLayout?.collapsedGroups ?? []);
    const collapsedG = collapseGraph(rawGraph, collapsedSet);
    const replicationModes = activeLayout?.replicationModes ?? {};
    const finalG = replicationEnabled()
      ? replicateHighFanoutSources(collapsedG, REPLICATION_THRESHOLD, replicationModes)
      : collapsedG;

    // Pinned positions: stored as { [nodeId]: {x,y} } on the layout
    // sidecar. Convert to Map for adapter ingestion. Only root-level
    // ids are honored by the adapter (matches SVG view's container-
    // only-drag scope) — non-root entries in the map are silently
    // ignored, never throw.
    const pinnedPositions = new Map<string, { x: number; y: number }>();
    for (const [id, p] of Object.entries(activeLayout?.positions ?? {})) {
      pinnedPositions.set(id, p);
    }

    const constants = scaleXyflowConstants(DENSITY_SCALE[density()]);
    const { nodes, edges } = cipherGraphToXyflow(finalG, {
      constants,
      pinnedPositions,
    });

    // Container ids — needed inside drag/dblclick handlers to gate
    // semantics (only containers toggle collapse; both containers and
    // root leaves can pin via drag).
    const containerIds = new Set(finalG.containers.map((c) => c.id));

    /**
     * Drag-stop handler. xyflow handles the in-drag visuals
     * internally; we only persist the final position. The Solid
     * setter triggers our `layoutMap` signal, which fires this same
     * effect again — xyflow then renders the same position (no
     * visible flicker because the post-drop position matches).
     *
     * Why drag-STOP and not drag-IN-PROGRESS: spamming
     * `setNodePosition` on every pointermove would write to
     * localStorage on each tick. SVG view writes every move because
     * it manages the drag visuals itself; xyflow does the visuals,
     * so we can wait for the commit.
     */
    const handleDragStop = (
      _event: unknown,
      node: DraggedNode,
      _nodes: readonly DraggedNode[],
    ): void => {
      setNodePosition(currentSpec.id, node.id, node.position.x, node.position.y);
    };

    /**
     * Double-click handler. On a container, toggles collapsed state.
     * On a leaf, no-op for now — the SVG view's leaf double-click
     * isn't a thing either, and a leaf "expand" would be ill-defined.
     */
    const handleNodeDoubleClick = (_event: unknown, node: { id: string }): void => {
      if (containerIds.has(node.id)) {
        toggleCollapse(currentSpec.id, node.id);
      }
    };

    reactRoot.render(
      React.createElement(
        ReactFlow as React.ComponentType<{
          nodes: readonly Node[];
          edges: readonly Edge[];
          fitView?: boolean;
          // Global default — per-node `draggable` overrides this. We
          // leave it `true` so the per-node flag's `false` case wins
          // for nested nodes (xyflow's resolution: node-level wins).
          nodesDraggable?: boolean;
          nodesConnectable?: boolean;
          elementsSelectable?: boolean;
          panOnDrag?: boolean;
          minZoom?: number;
          onNodeDragStop?: (event: unknown, node: DraggedNode, nodes: DraggedNode[]) => void;
          onNodeDoubleClick?: (event: unknown, node: { id: string }) => void;
          children?: React.ReactNode;
        }>,
        {
          nodes,
          edges,
          fitView: true,
          nodesDraggable: true,
          nodesConnectable: false,
          elementsSelectable: true,
          panOnDrag: true,
          minZoom: 0.1,
          onNodeDragStop: handleDragStop,
          onNodeDoubleClick: handleNodeDoubleClick,
        },
        // Children: built-in xyflow chrome. Background = dotted grid;
        // Controls = zoom/fit/lock toolbar; MiniMap = navigation overview.
        React.createElement(Background, { gap: 16, size: 1 }),
        React.createElement(Controls, { showInteractive: false }),
        React.createElement(MiniMap, { pannable: true, zoomable: true }),
      ),
    );
  };

  onMount(() => {
    if (!containerRef) return;
    reactRoot = ReactDOMClient.createRoot(containerRef);
    render();
  });

  // Re-render on spec edits, trace re-runs, layout changes (collapse +
  // drag commits), density flips, and replication toggle flips.
  // `defer: true` skips the initial firing — `onMount`'s explicit
  // `render()` already covers that and runs at the right time (after
  // the React root exists).
  createEffect(
    on([spec, traceVersion, layoutMap, density, replicationEnabled], render, { defer: true }),
  );

  onCleanup(() => {
    if (reactRoot) {
      reactRoot.unmount();
      reactRoot = undefined;
    }
  });

  return (
    <div
      ref={containerRef}
      class="xyflow-graph-view"
      style={{
        width: "100%",
        // Explicit pixel height: xyflow's canvas collapses to 0px in a
        // flex parent that doesn't propagate a sized height to its
        // children, so we ground it here. Matches the visual budget of
        // the existing SVG GraphView's main canvas.
        height: "700px",
        border: "1px solid #cbd5e1",
        "border-radius": "6px",
        background: "#f8fafc",
      }}
    />
  );
};
