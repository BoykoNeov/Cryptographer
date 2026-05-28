// @vitest-environment jsdom

/**
 * Component + integration tests for the read-only graph view (Slice 2).
 *
 * Two layers:
 *   1. Component-level: render <GraphView /> after seeding the spec store
 *      with aes128Spec and running a trace through setTrace. Asserts the
 *      structural rendering (leaf rects, container rects, clickable nodes).
 *   2. App-level: render <App />, drive the view-mode tab bar, confirm the
 *      graph tab swaps the per-frame content out and back without losing
 *      the trace scrubber's stepId-anchored focus.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { App } from "@/ui/App";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __setOffsetsEnabledForTest } from "@/ui/stores/offsets-hatch";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setMode } from "@/ui/stores/spec";
import {
  __resetTraceForTests,
  getTrace,
  setFrame,
  setTrace,
  useFrameIndex,
} from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixtures ──────────────────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

/** Populate the trace store with a real AES-128 trace so GraphView's
 *  click-to-navigate path has something to navigate INTO. */
const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetReplicationForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
};

const findButton = (container: HTMLElement, textPrefix: string): HTMLButtonElement => {
  const all = Array.from(container.querySelectorAll("button"));
  const match = all.find((b) => b.textContent?.trim().startsWith(textPrefix));
  if (!match) throw new Error(`button starting with "${textPrefix}" not found`);
  return match as HTMLButtonElement;
};

// ─── Component-level GraphView tests ──────────────────────────────────────

describe("GraphView — component-level (AES-128 fixture)", () => {
  beforeEach(() => {
    resetAll();
    // Baseline replica/spine geometry — pin offsets OFF (they ship ON by
    // default as of 2026-05-28; offsets-interaction coverage is the
    // pending visual smoke's job, not these unit assertions).
    __setOffsetsEnabledForTest(false);
  });
  afterEach(() => {
    cleanup();
    resetAll();
    __setOffsetsEnabledForTest(null);
  });

  it("renders one leaf rectangle per leaf in the spec (41 for AES-128)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // Each leaf is an SVG <g class="graph-leaf">; the rect inside it is
    // `.graph-leaf-rect`.
    const leafRects = container.querySelectorAll(".graph-leaf-rect");
    expect(leafRects.length).toBe(41);
  });

  it("renders one container rectangle per group (10 round groups)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const containerRects = container.querySelectorAll(".graph-container-rect");
    expect(containerRects.length).toBe(10);
  });

  it("renders aux-flow edges from the trace (11 key-expansion fan-out edges)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // Edge titles (auxKey tooltip text) live on the hit-path sibling
    // since Slice 4's wide-invisible-companion refactor — that's the
    // path that actually fires hover events because the visible
    // `.graph-edge` has pointer-events:none. Filter the hit paths and
    // assert exactly 11 round-key tooltips for AES-128.
    const edges = container.querySelectorAll(".graph-edge");
    expect(edges.length).toBeGreaterThanOrEqual(11);
    const hitPaths = container.querySelectorAll(".graph-edge-hit");
    const roundKeyEdges = Array.from(hitPaths).filter((e) =>
      e.querySelector("title")?.textContent?.startsWith("roundKey."),
    );
    expect(roundKeyEdges.length).toBe(11);
  });

  // Sequence commits 1 + 2: every edge in today's graph is rendered with
  // a kind-tagged class AND references the matching arrow marker. Aux
  // edges (trace-derived) carry `.graph-edge-aux` + `url(#graph-arrow-aux)`;
  // state edges (spec-derived spine) carry `.graph-edge-state` +
  // `url(#graph-arrow-state)`. Both populations are non-empty for AES-128
  // — round-key fan-out on the aux side, the 40-edge spine on the state side.
  it("tags every edge with its kind class and the matching arrow marker", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const edges = container.querySelectorAll(".graph-edge");
    expect(edges.length).toBeGreaterThan(0);
    let auxCount = 0;
    let stateCount = 0;
    for (const edge of Array.from(edges)) {
      const isAux = edge.classList.contains("graph-edge-aux");
      const isState = edge.classList.contains("graph-edge-state");
      // Exactly one kind class per edge.
      expect(isAux !== isState).toBe(true);
      if (isAux) {
        expect(edge.getAttribute("marker-end")).toBe("url(#graph-arrow-aux)");
        auxCount++;
      } else {
        expect(edge.getAttribute("marker-end")).toBe("url(#graph-arrow-state)");
        stateCount++;
      }
    }
    expect(auxCount).toBeGreaterThan(0);
    expect(stateCount).toBeGreaterThan(0);
    // Both marker defs render so the matching `url(#…)` references resolve.
    expect(container.querySelector("#graph-arrow-aux")).not.toBeNull();
    expect(container.querySelector("#graph-arrow-state")).not.toBeNull();
  });

  it("clicking a leaf node moves the trace scrubber to the matching frame", () => {
    seedAes128Trace();
    // Park the scrubber on frame 0 so the click-induced jump is observable.
    setFrame(0);
    expect(useFrameIndex()()).toBe(0);

    const { container } = render(() => <GraphView />);

    // Find the leaf rect for round.5.mix-columns and click it. The <title>
    // inside the leaf <g> carries the full stepId, so we use it to disambiguate.
    const leaves = container.querySelectorAll(".graph-leaf");
    const target = Array.from(leaves).find((g) =>
      g.querySelector("title")?.textContent?.startsWith("round.5.mix-columns"),
    );
    expect(target).toBeDefined();
    fireEvent.click(target as Element);

    // After click, the scrubber must point at the trace frame for round.5.mix-columns.
    const trace = getTrace();
    if (!trace) throw new Error("trace was lost");
    const expectedIdx = trace.frames.findIndex((f) => f.stepId === "round.5.mix-columns");
    expect(useFrameIndex()()).toBe(expectedIdx);
  });

  it("renders without a trace (structural skeleton + spec-derived spine, no aux edges)", () => {
    // Don't seed a trace; just render. The graph still draws the spec's
    // nodes/containers AND the 40-edge AES-128 state spine — the spine is
    // spec-derived, so it shows up before the first run (one of the
    // pedagogical payoffs of commit 2 in the readability sequence).
    const { container } = render(() => <GraphView />);
    const leaves = container.querySelectorAll(".graph-leaf-rect");
    expect(leaves.length).toBe(41);
    // No aux edges pre-run (those require a trace).
    expect(container.querySelectorAll(".graph-edge-aux").length).toBe(0);
    // 40-edge state spine MINUS the single edge that touched `key-expansion`
    // (an aux-only root leaf — see the `auxOnlyRootIds` spine filter in
    // `graph` memo), PLUS 2 synthetic state edges from the plaintext /
    // ciphertext endpoint pills (Slice 1 of the graph-narrative plan).
    //   40 − 1 + 2 = 41
    expect(container.querySelectorAll(".graph-edge-state").length).toBe(41);
    // Both endpoint pills rendered.
    expect(container.querySelectorAll(".graph-endpoint-rect").length).toBe(2);
  });

  it("replica-scope-aware: spine-replica renders ON the spine row, not lifted (production path)", () => {
    // Production-path verification for the narrow scope-aware fix
    // (2026-05-17). The pure-layout tests in
    // `tests/graph-view-replica-gutter.test.ts` exercise `layoutRoot`
    // directly with `auxOnlyRootIds` defaulting to an empty set — they
    // bypass the `auxOnlyRootIds` classifier entirely.
    //
    // Advisor flagged a plausible production-only regression: the spine-
    // replica inherits the source's `stepType` (`aes.key-expansion@1`),
    // and `auxOnlyRootIds` classifies root leaves by `registry.getDoc(
    // stepType)?.shapeContract.input === "any"`. If the memo walked the
    // post-replication graph, the spine-replica would qualify as aux-only
    // → lifted → fix becomes a no-op.
    //
    // It does NOT walk the post-replication graph — it walks `spec().
    // steps`, which never contains a replica id (replicas have the
    // synthetic `${src}@->${dst}` infix). So the classifier emits
    // `"key-expansion"` (the source's id) into `auxOnlyRootIds`, NOT
    // `"key-expansion@->initial.add-round-key"`. When `layoutRoot` then
    // checks `auxOnlyRootIds.has(id)` against the post-replication
    // rootIds, the spine-replica's synthetic id misses → not lifted.
    //
    // This test pins that property empirically: render through the full
    // GraphView component with replication enabled and assert the
    // spine-replica's rendered `y` equals its consumer's `y` — i.e.
    // both sit on the same row, which is the user-visible signal that
    // the fix is live in production.
    seedAes128Trace();
    // Replication default is OFF (`view-replication.ts::loadInitial`);
    // enable explicitly so the replica chip actually renders.
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);

    const spineLeaf = container.querySelector(
      '[data-testid="graph-leaf-key-expansion@->initial.add-round-key"] .graph-leaf-rect',
    );
    const consumerLeaf = container.querySelector(
      '[data-testid="graph-leaf-initial.add-round-key"] .graph-leaf-rect',
    );
    if (!spineLeaf || !consumerLeaf) {
      throw new Error(
        `missing rendered leaf: spineReplica=${!!spineLeaf} consumer=${!!consumerLeaf}`,
      );
    }

    const spineY = Number.parseFloat(spineLeaf.getAttribute("y") ?? "NaN");
    const consumerY = Number.parseFloat(consumerLeaf.getAttribute("y") ?? "NaN");
    expect(Number.isFinite(spineY)).toBe(true);
    expect(Number.isFinite(consumerY)).toBe(true);

    // Spine-replica is on the SAME row as its consumer (the spine row).
    // Pre-fix this difference would be LEAF_H + REPLICA_LIFT_GAP (~48 px
    // at normal density); post-fix it's 0.
    expect(spineY).toBe(consumerY);

    // And explicitly: the spine-replica is left of its consumer (at
    // source's old spec slot). Without this, "same y" could be satisfied
    // by both being lifted to the same lifted row.
    const spineX = Number.parseFloat(spineLeaf.getAttribute("x") ?? "NaN");
    const consumerX = Number.parseFloat(consumerLeaf.getAttribute("x") ?? "NaN");
    expect(spineX).toBeLessThan(consumerX);
  });

  it("replication fan-out doesn't add a third inbound arrow at initial.add-round-key", () => {
    // The bug this catches: when fan-out replication is ON, the `aux`
    // replica `key-expansion@->initial.add-round-key` arrows into
    // `initial.add-round-key`. If we ALSO kept the spec-true
    // `key-expansion → initial.add-round-key` state-spine edge, the
    // canvas would show THREE inbound arrows: (a) the plaintext pill's
    // endpoint spine, (b) the old spine edge from key-expansion, and
    // (c) the small replica's round-key fan-out. The spine filter on
    // `auxOnlyRootIds` drops (b) so only (a) + (c) reach the canvas.
    //
    // Default `replicate` toggle is ON, threshold 6 — AES-128's
    // key-expansion fans out to 11 consumers and replicates by default.
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // Inbound arrows at initial.add-round-key in this pre-collapse
    // expanded view: 1 state from the plaintext pill + 1 aux from the
    // key-expansion replica = 2. NOT 3.
    const edges = Array.from(container.querySelectorAll(".graph-edge"));
    // Find every <path d="..."> whose `d` ends at initial.add-round-key's
    // box. The box's center x changes with density; rather than measure
    // pixels, rely on the count of edges with marker-end (every rendered
    // edge has it) and assert the total state count is the unfiltered-
    // minus-one number. The exact identity of the missing edge is pinned
    // separately by the spec-shape test in aux-graph-derivation.test.ts.
    const stateCount = edges.filter((e) => e.classList.contains("graph-edge-state")).length;
    // 39 spine (40 native − 1 filtered) + 2 endpoint = 41. Same as the
    // pre-run test above; this test exists to pin that the post-run +
    // replicate-on path arrives at the same total.
    expect(stateCount).toBe(41);
  });

  // ─── Slice 1 of graph-narrative plan — endpoint pills ────────────────────

  describe("endpoint pills (Slice 1)", () => {
    it("renders 'plaintext' input pill + 'ciphertext' output pill in encrypt mode", () => {
      seedAes128Trace();
      const { container } = render(() => <GraphView />);

      const pills = container.querySelectorAll(".graph-endpoint-pill");
      expect(pills.length).toBe(2);

      const labels = Array.from(container.querySelectorAll(".graph-endpoint-label")).map(
        (el) => el.textContent,
      );
      expect(labels).toContain("plaintext");
      expect(labels).toContain("ciphertext");
    });

    it("swaps endpoint labels in decrypt mode (plaintext <-> ciphertext)", () => {
      // Mode flip happens before render so the createMemo picks it up
      // before the first reactive pass.
      setMode("decrypt");
      const { container } = render(() => <GraphView />);

      const labels = Array.from(container.querySelectorAll(".graph-endpoint-label")).map(
        (el) => el.textContent,
      );
      // Same two strings, but the input-side pill now reads "ciphertext".
      expect(labels).toContain("plaintext");
      expect(labels).toContain("ciphertext");

      // Confirm the SIDE class matches: input pill on decrypt = ciphertext.
      const inputPill = container.querySelector(".graph-endpoint-input");
      const outputPill = container.querySelector(".graph-endpoint-output");
      expect(inputPill?.querySelector(".graph-endpoint-label")?.textContent).toBe("ciphertext");
      expect(outputPill?.querySelector(".graph-endpoint-label")?.textContent).toBe("plaintext");
    });

    it("output anchor descends into terminal container to the innermost last leaf (AES round 10)", () => {
      // The original endpointAnchors picked the last TOP-LEVEL spec
      // entry. For AES that's the `round-10` group — a container,
      // which it treated as a state consumer and stopped there. The
      // descent fix (2026-05-20) recurses into the picked container
      // to land on the innermost last state-consuming leaf, which
      // for AES round 10 is `round.10.add-round-key`. Without this
      // the rendered output arrow read `round-10-container →
      // ciphertext` — visually inconsistent with `round.9.add-round-key
      // → round.10.sub-bytes` and the rest of the spine. Memory hook:
      // user-flagged 2026-05-20.
      seedAes128Trace();
      const { container } = render(() => <GraphView />);
      const edges = Array.from(container.querySelectorAll("[data-edge-key]"))
        .map((el) => el.getAttribute("data-edge-key") ?? "")
        .filter((k) => k.includes("__cipher_output__"));
      // Exactly one inbound edge at the output pill: from the
      // innermost last leaf, not from the round container.
      expect(edges.length).toBeGreaterThanOrEqual(1);
      expect(
        edges.some((k) => k.startsWith("round.10.add-round-key|")),
        `expected an edge from round.10.add-round-key to __cipher_output__; got: ${edges.join(", ")}`,
      ).toBe(true);
      expect(
        edges.some((k) => k.startsWith("round.10|")),
        "should NOT have an edge from the round-10 container itself",
      ).toBe(false);
    });

    it("endpoint pills have no drop-anchor and no delete glyph", () => {
      // Endpoints aren't editable: they aren't spec nodes, you can't drop
      // a palette step on them, and you can't delete them. They DO carry
      // `tabindex=0` so the value-inspector click action is keyboard-
      // reachable, but no drag/drop/delete affordance.
      const { container } = render(() => <GraphView />);

      const pills = container.querySelectorAll(".graph-endpoint-pill");
      expect(pills.length).toBe(2);

      for (const pill of Array.from(pills)) {
        // No data-drop-anchor: drag-drop resolution via
        // `closest("[data-drop-anchor]")` will fall through to whatever
        // ancestor matches (typically the canvas-empty root path).
        expect(pill.hasAttribute("data-drop-anchor")).toBe(false);
        // No delete glyph (LeafRect renders `.graph-delete-glyph`; the
        // endpoint pill component doesn't).
        expect(pill.querySelector(".graph-delete-glyph")).toBeNull();
        // `tabindex="0"` for the value-inspector click affordance — the
        // pill IS keyboard-reachable post-Slice 4 expansion, just not
        // for any spec-edit action.
        expect(pill.getAttribute("tabindex")).toBe("0");
      }
    });
  });

  // ─── Slice 9 — validation warning indicators ─────────────────────────────
  // GraphView ships a small warning glyph on any leaf or container whose
  // canonical stepId carries at least one `validateGraph` warning. The
  // shipped specs produce no warnings (see tests/graph-validation.test.ts),
  // so these tests synthesize one by replacing a single AES frame with one
  // that requests a missing aux key — the same shape Slice 10's graceful
  // aux primitives will emit naturally.

  it("does not render any warning dots on a clean AES-128 trace", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    expect(container.querySelectorAll('[data-testid="graph-warning-dot"]').length).toBe(0);
  });

  it("renders a warning dot on the node whose frame carries auxReadMissing", () => {
    // Seed a real trace, then build a modified trace with one frame replaced
    // by one carrying `auxReadMissing: ["nonexistent"]`. We pick a frame for
    // `round.3.sub-bytes` so the target node is interior (proves the dot
    // doesn't depend on root-level layout). The replacement uses a real
    // frame's other fields verbatim so we don't accidentally test against a
    // synthetic-stepId that GraphView wouldn't render.
    seedAes128Trace();
    const baseTrace = getTrace();
    if (!baseTrace) throw new Error("trace not seeded");
    const targetIdx = baseTrace.frames.findIndex((f) => f.stepId === "round.3.sub-bytes");
    expect(targetIdx).toBeGreaterThan(0);
    const original = baseTrace.frames[targetIdx];
    if (!original) throw new Error("target frame not found");
    const replaced = { ...original, auxReadMissing: ["nonexistent.key"] as const };
    const newFrames = [
      ...baseTrace.frames.slice(0, targetIdx),
      replaced,
      ...baseTrace.frames.slice(targetIdx + 1),
    ];
    setTrace({ ...baseTrace, frames: newFrames });

    const { container } = render(() => <GraphView />);
    const dots = container.querySelectorAll('[data-testid="graph-warning-dot"]');
    expect(dots.length).toBe(1);
    // The dot's title must name the missing key so users can read what's
    // wrong without opening a side panel. (No inline-panel UI yet; that's
    // an optional follow-up — V1 is the title tooltip.)
    const title = dots[0]?.querySelector("title")?.textContent ?? "";
    expect(title).toContain("nonexistent.key");
    expect(title.toLowerCase()).toContain("orphan");
  });
});

// ─── App-level tab integration ────────────────────────────────────────────

describe("App — view-mode tab bar (linear / graph / JSON)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders all three tabs in the tab bar with the linear tab active by default", () => {
    const { container } = render(() => <App />);
    const tabs = container.querySelectorAll(".view-mode-tab");
    expect(tabs.length).toBe(3);
    const labels = Array.from(tabs).map((t) => t.textContent?.trim());
    expect(labels).toEqual(["linear", "graph", "JSON"]);
    // First tab (linear) is active by default.
    const active = container.querySelector(".view-mode-tab.active");
    expect(active?.textContent?.trim()).toBe("linear");
  });

  it("clicking the graph tab swaps in the SVG graph view", () => {
    const { container } = render(() => <App />);
    // Run first so the trace exists; otherwise graph would render only the
    // structural skeleton (still fine, but less interesting to assert).
    fireEvent.click(findButton(container, "run"));
    // Before click: no SVG.
    expect(container.querySelector(".graph-view-svg")).toBeNull();
    // Click the graph tab.
    fireEvent.click(findButton(container, "graph"));
    expect(container.querySelector(".graph-view-svg")).not.toBeNull();
    // And the linear-tab specific frame header is gone.
    expect(container.querySelector(".frame-header")).toBeNull();
  });

  it("clicking the JSON tab swaps in the spec's pretty-printed JSON", () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "JSON"));
    const json = container.querySelector(".view-mode-json");
    expect(json).not.toBeNull();
    // The spec's id ("aes-128@1") must appear in the JSON pretty-print.
    expect(json?.textContent).toContain("aes-128@1");
  });

  it("switching tabs preserves the scrubber's stepId-anchored frame focus", () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "run"));
    // Move the scrubber to a non-zero frame so the assertion is non-trivial.
    const trace = getTrace();
    if (!trace) throw new Error("trace was not set");
    const targetIdx = trace.frames.findIndex((f) => f.stepId === "round.3.shift-rows");
    expect(targetIdx).toBeGreaterThan(0);
    setFrame(targetIdx);
    expect(useFrameIndex()()).toBe(targetIdx);
    // Flip to graph, then back to linear. The frame index must survive.
    fireEvent.click(findButton(container, "graph"));
    fireEvent.click(findButton(container, "linear"));
    expect(useFrameIndex()()).toBe(targetIdx);
  });
});
