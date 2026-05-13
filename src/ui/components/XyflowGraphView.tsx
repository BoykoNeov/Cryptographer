/**
 * Experimental fourth view mode: render the cipher graph using xyflow's
 * React component, mounted inside a Solid wrapper.
 *
 * This is a SPIKE component. The goal is a Phase 1 answer to "can xyflow
 * render our 3-level nesting (root → iterate → round-group → leaves) with
 * two visually distinct edge kinds, at the cost of carrying React +
 * ReactDOM in the bundle." It coexists with the hand-rolled SVG GraphView
 * via the view-mode tab strip; nothing here replaces or modifies the SVG
 * implementation that ships from `main`.
 *
 * Interop pattern: Solid owns the lifecycle; React renders the canvas.
 *
 *   1. The Solid component returns one `<div ref>` that becomes the
 *      mount point.
 *   2. `onMount` creates a React root via `react-dom/client.createRoot`
 *      and seeds it with an initial render derived from the current spec.
 *   3. `createEffect` tracks Solid signals (`useSpec`, `useTraceVersion`)
 *      and calls `root.render(...)` on every change; React reconciles
 *      the new node/edge arrays internally.
 *   4. `onCleanup` unmounts the React root.
 *
 * Why `React.createElement` instead of JSX: this file is `.tsx`, which
 * vite-plugin-solid parses as Solid JSX. Writing React JSX in here would
 * require splitting plugins by file extension (or adding
 * `@vitejs/plugin-react` with `include`/`exclude` scoping). The
 * `createElement` API is verbose but lives entirely inside this one
 * file's render function — a fair price to avoid the plugin rabbit hole.
 *
 * Layout: skip the existing layout/collapse/replication stores. The
 * adapter (`cipher-to-xyflow.ts`) runs a naive DFS-cursor layout that
 * exercises 3-level nesting; the SVG view's hand-tuned readability
 * tricks (orthogonal-axis replicas, density rescale) are out of scope
 * for the spike.
 */

import { deriveAuxGraph } from "@/core/graph";
import {
  Background,
  Controls,
  type Edge,
  MiniMap,
  type Node,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { createEffect, on, onCleanup, onMount } from "solid-js";
import * as React from "react";
import * as ReactDOMClient from "react-dom/client";
import { cipherGraphToXyflow } from "../graph/cipher-to-xyflow";
import { useSpec } from "../stores/spec";
import { getTrace, useTraceVersion } from "../stores/trace";

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

export const XyflowGraphView = () => {
  let containerRef: HTMLDivElement | undefined;
  let reactRoot: ReactDOMClient.Root | undefined;

  const spec = useSpec();
  const traceVersion = useTraceVersion();

  /**
   * Build the React element tree and hand it to the existing root.
   *
   * Reads Solid signals (spec, trace) at call time. Safe to call from
   * `onMount` (after `reactRoot` is set) and from `createEffect`. A
   * call before mount is silently skipped so the effect can register
   * dependencies cleanly without needing a `ready` signal.
   */
  const render = (): void => {
    if (!reactRoot) return;
    const trace = getTrace() ?? EMPTY_TRACE;
    const graph = deriveAuxGraph(trace, spec());
    const { nodes, edges } = cipherGraphToXyflow(graph);
    reactRoot.render(
      React.createElement(
        ReactFlow as React.ComponentType<{
          nodes: readonly Node[];
          edges: readonly Edge[];
          fitView?: boolean;
          nodesDraggable?: boolean;
          nodesConnectable?: boolean;
          elementsSelectable?: boolean;
          panOnDrag?: boolean;
          minZoom?: number;
          children?: React.ReactNode;
        }>,
        {
          nodes,
          edges,
          fitView: true,
          // Spike scope: read-only, no interaction beyond pan/zoom.
          nodesDraggable: false,
          nodesConnectable: false,
          elementsSelectable: true,
          panOnDrag: true,
          minZoom: 0.1,
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

  // Re-render on spec edits AND on trace re-runs. `defer: true` skips the
  // initial firing — `onMount`'s explicit `render()` already covers that
  // and runs at the right time (after the React root exists).
  createEffect(on([spec, traceVersion], render, { defer: true }));

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
        "border": "1px solid #cbd5e1",
        "border-radius": "6px",
        background: "#f8fafc",
      }}
    />
  );
};
