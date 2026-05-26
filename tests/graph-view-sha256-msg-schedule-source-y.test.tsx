// @vitest-environment jsdom

/**
 * GraphView — SHA-256 expanded `msg-schedule` source-side y-spread (Case B).
 *
 * Slice S2(k) of `docs/plans/sha-256-density-polish.md`. SHA-256's
 * `msg-schedule` `for-each-subgraph-with-history` body contains three
 * multi-input combine leaves (`sigma1` 3-in, `sigma0` 3-in, `w-t` 4-in).
 * In horizontal-regime flow (sources sit immediately to the left of the
 * consumer on the same row), pre-S2(k) every incoming arrow EXITED its
 * source chip at `sy = fromCy` (source center y) — three or four arrows
 * leaving sibling chips at the same row centerline. The arrows only
 * diverged at the consumer's left edge (slot offsets ±13 / ±15 etc), so
 * for most of their path they traveled along the same y. Adjacent-source
 * arrows visually overlapped despite distinct endpoint slots.
 *
 * Post-S2(k): `EdgePath` accepts a `sourceYOffset` prop that mirrors
 * `targetYOffset`. The same per-edge `consumerPortOffset` value drives
 * BOTH endpoints — source exits at `fromCy + slot_offset`, target enters
 * at `toCy + slot_offset` — so each arrow becomes a near-straight
 * parallel-shifted line at its slot's y. Adjacent-source arrows fan out
 * from the start, giving each one a visibly distinct trajectory through
 * the inter-chip corridor.
 *
 * Pinned behavior here:
 *   - The 3 incoming edges of `sigma1` (3-input xor) produce 3 distinct
 *     source-y values, each clamped within the source's `from.h / 2 − 4`
 *     window.
 *   - The 4 incoming edges of `w-t` (4-input add) produce 4 distinct
 *     source-y values.
 *   - Each edge's source-y offset equals its target-y offset (parallel
 *     shift — same magnitude, same sign).
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
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SHA256_SPEC_ID = "sha-256@1";

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
};

/**
 * Parse `(sx, sy, tx, ty)` from an EdgePath's horizontal-regime path data.
 * Format: `M sx sy C c1x sy, c2x ty, tx ty`. We want indices 1 (sx), 2 (sy),
 * and the last pair (tx, ty).
 */
const parsePath = (d: string): { sx: number; sy: number; tx: number; ty: number } => {
  const tokens = d.trim().split(/[\s,]+/);
  // Tokens: [M, sx, sy, C, c1x, sy_again, c2x, ty_at_c2, tx, ty]
  const sx = Number(tokens[1]);
  const sy = Number(tokens[2]);
  const tx = Number(tokens[tokens.length - 2]);
  const ty = Number(tokens[tokens.length - 1]);
  if (![sx, sy, tx, ty].every((n) => Number.isFinite(n))) {
    throw new Error(`bad path data: ${d}`);
  }
  return { sx, sy, tx, ty };
};

/**
 * Collect every rendered hit-path edge whose `data-edge-key` describes an
 * incoming port-flow edge into the named consumer leaf. Singleton key form
 * is `${from}|${to}|${auxKey}|${kind}`; bundles aren't expected for these
 * port-flow edges (each is a singleton aux-key "port-flow"), but the
 * bundle prefix is handled defensively.
 */
const incomingEdgesTo = (container: HTMLElement, consumerId: string): SVGPathElement[] => {
  const all = container.querySelectorAll<SVGPathElement>("path.graph-edge-hit");
  const out: SVGPathElement[] = [];
  for (const edge of Array.from(all)) {
    const key = edge.getAttribute("data-edge-key");
    if (key === null) continue;
    // Match both singleton (X|consumerId|port-flow|state) and bundle
    // (bundle:X|consumerId|state|...) forms. We anchor on the consumer
    // id appearing in the SECOND segment so unrelated edges that happen
    // to mention the consumer id elsewhere in the key don't match.
    const stripped = key.startsWith("bundle:") ? key.substring("bundle:".length) : key;
    const segments = stripped.split("|");
    if (segments[1] !== consumerId) continue;
    out.push(edge);
  }
  return out;
};

describe("GraphView — SHA-256 msg-schedule source-side y-spread (Slice S2(k))", () => {
  beforeEach(() => {
    resetAll();
    setHash("sha-256");
    seedSha256Trace();
    // `msg-schedule` is `defaultCollapsed: true`; force expansion so the
    // body leaves (sigma1, sigma0, w-t, fetches, rotations) all render
    // as individual chips with their own incoming port-flow edges.
    toggleCollapse(SHA256_SPEC_ID, "msg-schedule", true);
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("sigma1's 3 incoming edges leave their sources at 3 DISTINCT source-y values", () => {
    const { container } = render(() => <GraphView />);
    const edges = incomingEdgesTo(container, "sigma1");
    expect(edges.length).toBe(3);

    // Parse every edge's path data; collect source y's.
    const sys = edges.map((e) => {
      const d = e.getAttribute("d");
      if (d === null) throw new Error("edge missing d attribute");
      return parsePath(d).sy;
    });

    // Distinctness (0.5 px buckets — well below the slot pitch of
    // `LEAF_H/4 = 7` at default density).
    const buckets = new Set(sys.map((y) => Math.round(y * 2) / 2));
    expect(buckets.size).toBe(3);
  });

  it("w-t's 4 incoming edges leave their sources at 4 DISTINCT source-y values", () => {
    const { container } = render(() => <GraphView />);
    const edges = incomingEdgesTo(container, "w-t");
    expect(edges.length).toBe(4);

    const sys = edges.map((e) => {
      const d = e.getAttribute("d");
      if (d === null) throw new Error("edge missing d attribute");
      return parsePath(d).sy;
    });

    const buckets = new Set(sys.map((y) => Math.round(y * 2) / 2));
    expect(buckets.size).toBe(4);
  });

  it("source-y offset equals target-y offset for each sigma1 incoming edge (parallel shift)", () => {
    // For each edge: `sy - fromCy` should equal `ty - toCy` (modulo the
    // independent clamps on source-cap vs target-cap, which match for
    // leaf-shape consumer + leaf-shape sources at the same density).
    // Both endpoints are leaves with the same height, so the two clamps
    // collapse to the same value and the offsets land identical.
    const { container } = render(() => <GraphView />);
    const edges = incomingEdgesTo(container, "sigma1");
    expect(edges.length).toBe(3);

    // Look up sigma1's center y (the consumer).
    const consumerLeaf = container.querySelector('[data-testid="graph-leaf-sigma1"]');
    if (!consumerLeaf) throw new Error("sigma1 leaf not rendered");
    const consumerRect = consumerLeaf.querySelector("rect.graph-leaf-rect");
    if (!consumerRect) throw new Error("sigma1 has no rect");
    const consumerY = Number(consumerRect.getAttribute("y"));
    const consumerH = Number(consumerRect.getAttribute("height"));
    if (!Number.isFinite(consumerY) || !Number.isFinite(consumerH)) {
      throw new Error("sigma1 rect missing geometry");
    }
    const toCy = consumerY + consumerH / 2;

    // For each incoming edge: parse path, find the source leaf, compute
    // both offsets, assert equal.
    for (const edge of edges) {
      const key = edge.getAttribute("data-edge-key");
      if (key === null) throw new Error("edge missing data-edge-key");
      const stripped = key.startsWith("bundle:") ? key.substring("bundle:".length) : key;
      const sourceId = stripped.split("|")[0];
      if (sourceId === undefined) throw new Error(`bad edge key: ${key}`);

      const sourceLeaf = container.querySelector(`[data-testid="graph-leaf-${sourceId}"]`);
      if (!sourceLeaf) throw new Error(`source leaf ${sourceId} not rendered`);
      const sourceRect = sourceLeaf.querySelector("rect.graph-leaf-rect");
      if (!sourceRect) throw new Error(`${sourceId} has no rect`);
      const sourceRectY = Number(sourceRect.getAttribute("y"));
      const sourceH = Number(sourceRect.getAttribute("height"));
      if (!Number.isFinite(sourceRectY) || !Number.isFinite(sourceH)) {
        throw new Error(`${sourceId} rect missing geometry`);
      }
      const fromCy = sourceRectY + sourceH / 2;

      const d = edge.getAttribute("d");
      if (d === null) throw new Error("edge missing d");
      const { sy, ty } = parsePath(d);

      const sourceOffset = sy - fromCy;
      const targetOffset = ty - toCy;
      // Equal to within 0.5 px (rounding noise from the integer-px
      // clamp inside EdgePath).
      expect(sourceOffset).toBeCloseTo(targetOffset, 0);
    }
  });
});
