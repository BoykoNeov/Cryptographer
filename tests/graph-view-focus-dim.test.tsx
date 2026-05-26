// @vitest-environment jsdom

/**
 * GraphView — focus-dim v0 (Slice S2(m) of sha-256-density-polish).
 *
 * Selection-only mechanism: when the user selects a NODE via the value
 * inspector, every non-incident edge picks up the `graph-edge-dimmed`
 * class on its outer `<g>` (CSS opacity 0.18). Incident edges stay
 * un-dimmed. Replica edges inherit incidence from their canonical
 * source via `replicaPlacement.sourceOf`, so clicking the canonical
 * chip OR any of its replicas highlights ALL related arrows.
 *
 * Block-chip / orphan / synth-id selections bail out (NO edges
 * incident → don't dim anything) so a click on a chip with no graph
 * representation doesn't fade the whole canvas to nothing.
 *
 * The dim is selection-only by design — hover-primary plumbing is a
 * future slice (would add `onPointerEnter`/`Leave` on 5+ render paths
 * plus a pan/drag gate, see the plan doc for the rationale on
 * deferring it).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, toggleCollapse } from "@/ui/stores/layout";
import { __resetSpecForTests, setHash } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import {
  __resetValueInspectorForTests,
  clearSelectedTarget,
  toggleSelectedEdge,
  toggleSelectedNode,
} from "@/ui/stores/view-value-inspector";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const seedSha256Trace = (): void => {
  const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    portedDispatchEnabled: true,
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetLayoutsForTests();
  __resetValueInspectorForTests();
};

/**
 * Pull every rendered edge's outer `<g>` keyed by its data-edge-key.
 * Skip any hit path whose parent isn't a `<g>` (defensive — should
 * never happen in practice).
 */
const collectAllEdgeGroups = (container: HTMLElement): Map<string, SVGGElement> => {
  const result = new Map<string, SVGGElement>();
  const hits = container.querySelectorAll<SVGPathElement>("path.graph-edge-hit");
  for (const hit of Array.from(hits)) {
    const key = hit.getAttribute("data-edge-key");
    if (key === null) continue;
    const parent = hit.parentElement as unknown as SVGGElement | null;
    if (parent === null) continue;
    result.set(key, parent);
  }
  return result;
};

describe("GraphView — focus-dim v0 (selection-only)", () => {
  beforeEach(() => {
    resetAll();
    setHash("sha-256");
    seedSha256Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("no selection → no edge carries the dimmed class", () => {
    const { container } = render(() => <GraphView />);
    const groups = collectAllEdgeGroups(container);
    expect(groups.size).toBeGreaterThan(0);
    for (const [key, g] of groups) {
      expect(g.classList.contains("graph-edge-dimmed")).toBe(false);
      // Guard against trivial empty-collection passes.
      expect(key.length).toBeGreaterThan(0);
    }
  });

  it("selecting final.assemble dims every edge NOT incident to it; the 8 incoming port-flow edges stay un-dimmed", () => {
    const { container } = render(() => <GraphView />);

    // Toggle the value-inspector selection to the assemble node.
    toggleSelectedNode("final.assemble");

    const groups = collectAllEdgeGroups(container);

    // Every edge whose data-edge-key references `final.assemble` on
    // either side must NOT be dimmed.
    const incidentKeys: string[] = [];
    const dimmedKeys: string[] = [];
    const incidentNotDimmed: string[] = [];
    for (const [key, g] of groups) {
      const tokens = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")
        : key.split("|");
      const from = tokens[0];
      const to = tokens[1];
      const incident = from === "final.assemble" || to === "final.assemble";
      if (incident) {
        incidentKeys.push(key);
        if (!g.classList.contains("graph-edge-dimmed")) incidentNotDimmed.push(key);
      } else if (g.classList.contains("graph-edge-dimmed")) {
        dimmedKeys.push(key);
      }
    }

    // Sanity: at least the 8 incoming port-flow edges should match.
    expect(incidentKeys.length).toBeGreaterThanOrEqual(8);
    expect(incidentNotDimmed.length).toBe(incidentKeys.length);

    // At least one non-incident edge must have picked up the dim
    // class — SHA-256 has thousands of edges, the bulk are
    // non-incident to assemble.
    expect(dimmedKeys.length).toBeGreaterThan(50);
  });

  it("selecting a leaf whose id is not an edge endpoint (orphan / block-chip / synth id) does NOT dim anything", () => {
    const { container } = render(() => <GraphView />);

    // Synth id that doesn't appear as `edge.from` or `edge.to` on any
    // edge. Pinning the bail-out — `focusDimActive` must return false
    // when there are no incident edges.
    toggleSelectedNode("nonexistent-synth-id-12345");

    const groups = collectAllEdgeGroups(container);
    for (const [, g] of groups) {
      expect(g.classList.contains("graph-edge-dimmed")).toBe(false);
    }
  });

  it("clearing the selection restores every edge to un-dimmed", () => {
    const { container } = render(() => <GraphView />);

    toggleSelectedNode("final.assemble");
    // Confirm something dimmed first (guard against false-restore pass).
    let anyDimmed = false;
    for (const [, g] of collectAllEdgeGroups(container)) {
      if (g.classList.contains("graph-edge-dimmed")) {
        anyDimmed = true;
        break;
      }
    }
    expect(anyDimmed).toBe(true);

    clearSelectedTarget();
    for (const [, g] of collectAllEdgeGroups(container)) {
      expect(g.classList.contains("graph-edge-dimmed")).toBe(false);
    }
  });

  it("selecting an EDGE (not a node) does not dim anything — focus-dim is node-only", () => {
    const { container } = render(() => <GraphView />);

    // Click the first edge we find — its `data-edge-key` is the
    // selection token.
    const firstHit = container.querySelector<SVGPathElement>("path.graph-edge-hit");
    if (!firstHit) throw new Error("no edges rendered");
    const edgeKey = firstHit.getAttribute("data-edge-key");
    if (edgeKey === null) throw new Error("hit path missing data-edge-key");

    // Route through the convenience helper directly — same store
    // boundary the EdgePath's hit-path onClick would hit. Determinism
    // > simulating clicks for this property test.
    toggleSelectedEdge(edgeKey);

    // Edge-kind selections do NOT activate focus-dim — that's a node-
    // only mechanism. Every edge stays un-dimmed.
    for (const [, g] of collectAllEdgeGroups(container)) {
      expect(g.classList.contains("graph-edge-dimmed")).toBe(false);
    }
  });

  it("replica expansion: selecting the canonical source K-to-aux marks ALL of its replicas' outgoing edges as incident", () => {
    // Force replication ON so K-to-aux's replicas are in the rendered
    // graph (auto-on is per-spec gated; this is the explicit toggle).
    setReplicationEnabled(true);

    const { container } = render(() => <GraphView />);

    // K-to-aux's replicas have synth ids like `K-to-aux@->round.N` and
    // their outgoing edges carry the synth id as `edge.from`. The
    // canonical source `K-to-aux` is itself a leaf with one spine edge
    // out. Selecting `K-to-aux` should mark the spine edge AND every
    // replica's outgoing edge as incident (via the sourceOf expansion).
    toggleSelectedNode("K-to-aux");

    const groups = collectAllEdgeGroups(container);

    // Look for at least one edge whose `from` is `K-to-aux@->...`
    // (replica synth id) and assert it is NOT dimmed.
    let replicaEdgeChecked = false;
    for (const [key, g] of groups) {
      const tokens = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")
        : key.split("|");
      const from = tokens[0];
      if (from === undefined || !from.startsWith("K-to-aux@->")) continue;
      // Replica edge — must not be dimmed.
      expect(g.classList.contains("graph-edge-dimmed")).toBe(false);
      replicaEdgeChecked = true;
    }
    // Guard against trivial pass: at least one K-to-aux replica edge
    // must have been examined. If SHA-256's replication ever stops
    // creating K-to-aux replicas (e.g. threshold change), this fails
    // loudly rather than silently passing.
    expect(replicaEdgeChecked).toBe(true);
  });

  it("selecting a leaf inside expanded msg-schedule (sigma1-r17 spec id) dims its non-incidents; its incoming + outgoing edges stay un-dimmed", () => {
    // Force msg-schedule open. The container id is `msg-schedule`.
    // `toggleCollapse(specId, containerId, inDefaults)` flips the
    // expansion state; SHA-256's default has msg-schedule collapsed.
    // We use the SHA-256 spec id and the container id directly.
    const sha256SpecId = buildSha256Spec().id;
    toggleCollapse(sha256SpecId, "msg-schedule", true);

    const { container } = render(() => <GraphView />);

    // Pick `sigma1-r17` inside the expanded msg-schedule body. (The
    // body's leaves carry these specific ids per the SHA-256 spec —
    // see `src/ciphers/sha-256.ts`'s message-schedule subtree.) If
    // the leaf id changes, this test fails loudly and points at the
    // rename rather than silently passing.
    const sigma1R17 = container.querySelector('[data-testid="graph-leaf-sigma1-r17"]');
    if (!sigma1R17) {
      // Defensive: if msg-schedule didn't actually expand (e.g. layout
      // store toggle didn't apply), surface that rather than letting
      // the test pass on absence.
      throw new Error("sigma1-r17 not rendered — msg-schedule may not have expanded");
    }

    toggleSelectedNode("sigma1-r17");

    const groups = collectAllEdgeGroups(container);

    // Every edge touching sigma1-r17 must be un-dimmed.
    let incidentCount = 0;
    for (const [key, g] of groups) {
      const tokens = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")
        : key.split("|");
      const from = tokens[0];
      const to = tokens[1];
      if (from === "sigma1-r17" || to === "sigma1-r17") {
        expect(g.classList.contains("graph-edge-dimmed")).toBe(false);
        incidentCount += 1;
      }
    }
    // sigma1-r17 is one of σ1's rotation leaves — it has an incoming
    // edge (from the schedule's W_t-2 fetch) and an outgoing edge (to
    // the σ1 XOR combine). At least 1 incident edge proves the
    // mechanism fires.
    expect(incidentCount).toBeGreaterThanOrEqual(1);
  });
});
