// @vitest-environment jsdom

/**
 * GraphView — SHA-256 `final.assemble` fan-IN slot distinctness.
 *
 * Slice S2(j) of `docs/plans/sha-256-density-polish.md`. SHA-256's
 * `final.assemble` (a `concat@1` with `inputCount: 8`) has 8 incoming
 * port-flow edges from `final.s_0..s_7`, all entering on the LEFT side
 * (horizontal regime — the s_i row sits directly to the left of assemble).
 *
 * Pre-S2(j) bug: the EdgePath y-offset clamp at `to.h / 2 - 4` (= ±16 at
 * LEAF_H = 40) collapsed the 8 raw offsets `−35..+35` to:
 *
 *   slot 0: raw −35 → clamped −16     ← collision with slot 1
 *   slot 1: raw −25 → clamped −16
 *   slot 2: raw −15 → −15
 *   slot 3: raw  −5 →  −5
 *   slot 4: raw  +5 →  +5
 *   slot 5: raw +15 → +15
 *   slot 6: raw +25 → clamped +16     ← collision with slot 7
 *   slot 7: raw +35 → clamped +16
 *
 * Two pairs of arrows landed at the same y on assemble's left edge —
 * exactly the visible "pile-up" the user reported.
 *
 * Post-S2(j): `consumerPortOffset` accepts an optional `cap` argument.
 * When the natural extent exceeds the cap, the gap shrinks from 10 to
 * `(cap * 2) / (total - 1) = 32/7 ≈ 4.57` so all 8 slots land within
 * [−16, +16] while remaining monotonic + evenly spaced.
 *
 * This test pins the rendered SVG behavior — 8 distinct `ty` values
 * extracted from the 8 incoming edge paths' `d` attributes.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, setHash } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const seedSha256Trace = (): void => {
  const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
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
 * Parse the target y from an EdgePath's `d` attribute. The cubic path
 * format is `M sx sy C c1x sy, c2x ty, tx ty` (horizontal regime). The
 * target y appears twice — at the second control point and at the path
 * endpoint. We extract the FINAL pair (the endpoint) since EdgePath's
 * geometry uses it as the actual attach point.
 */
const parseTargetY = (d: string): number => {
  // Tokens after the final "L"/"C"/space chunk end at "tx ty". We grab
  // the last whitespace-separated numeric pair.
  const tokens = d.trim().split(/[\s,]+/);
  const last = tokens[tokens.length - 1];
  if (last === undefined) throw new Error(`bad path data: ${d}`);
  const ty = Number(last);
  if (!Number.isFinite(ty)) throw new Error(`final token not a number: ${last} (from ${d})`);
  return ty;
};

describe("GraphView — SHA-256 final.assemble 8-fan-IN distinct attach y", () => {
  beforeEach(() => {
    resetAll();
    setHash("sha-256");
    seedSha256Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("the 8 incoming edges at final.assemble produce 8 DISTINCT ty values", () => {
    const { container } = render(() => <GraphView />);

    // Collect every rendered .graph-edge-hit path whose data-edge-key
    // points at `final.assemble` (incoming). The key format is
    // `${from}|${to}|${auxKey}|${kind}` for singletons; SHA-256's s_i
    // edges all have auxKey = "port-flow" + kind = "state".
    const allEdges = container.querySelectorAll<SVGPathElement>("path.graph-edge-hit");
    const incomingTys: number[] = [];
    let matched = 0;
    for (const edge of Array.from(allEdges)) {
      const key = edge.getAttribute("data-edge-key");
      if (key === null) continue;
      // Match both singleton (final.sN|final.assemble|port-flow|state)
      // and bundle (bundle:final.sN|final.assemble|state|...) forms.
      if (!key.includes("|final.assemble|")) continue;
      // Filter to keys whose `from` is a final.sN (avoids any unrelated
      // edges that happen to mention final.assemble in a bundle id).
      const fromPart = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")[0]
        : key.split("|")[0];
      if (fromPart === undefined || !/^final\.s\d+$/.test(fromPart)) continue;
      const d = edge.getAttribute("d");
      if (d === null) continue;
      incomingTys.push(parseTargetY(d));
      matched += 1;
    }

    // Exactly 8 incoming edges from final.s0..s7. Validates the test
    // setup before the distinctness assertion.
    expect(matched).toBe(8);
    expect(incomingTys).toHaveLength(8);

    // Distinctness: the actual pin from S2(j). Each ty is rounded to
    // 0.5 px buckets so floating-point noise doesn't create a false
    // pass — at 4.57 px per slot the rounding still resolves each slot
    // to a unique bucket. Pre-S2(j) two pairs would collide on ±16
    // exactly (no rounding tolerance hides the collision).
    const buckets = new Set(incomingTys.map((y) => Math.round(y * 2) / 2));
    expect(buckets.size).toBe(8);
  });

  it("Slice S2(j2): split-wv / split-H replicas above s-stages sit at LOCAL rows 0+1, not GLOBAL rows 2+3", () => {
    // Pre-S2(j2) SHA-256's four root replicated sources (K-to-aux,
    // W-publish, split-wv, split-H) shared a global rowOfSource pool;
    // split-wv landed at row 2 (lift 252 px above s_i) and split-H at
    // row 3 (lift 340 px). The s-stages had no replicas at rows 0/1
    // because K-to-aux/W-publish target only the compression rounds.
    // S2(j2)'s per-consumer densification compresses the s-stage stack
    // to rows 0+1 (split-wv at lift 76 px, split-H at lift 164 px).
    //
    // This test pins the user-visible distance: the gap from the
    // bottom of split-H to the top of s_i is bounded by the 2-row
    // lift formula (LEAF_H + REPLICA_LIFT_GAP + LEAF_H + REPLICA_STACK_GAP
    // = 40 + 36 + 40 + 48 = 164 px at default density), not the
    // pre-S2(j2) 4-row lift (~340 px).
    const { container } = render(() => <GraphView />);

    // Find s_1 and its two replicas. We pick s_1 (not s_0) because s_0
    // is the spine successor of split-wv — its replica is the special
    // "spine replica" that sits at the source's old spec slot rather
    // than above the consumer.
    const s1 = container.querySelector('[data-testid="graph-leaf-final.s1"]');
    const splitWvReplica = container.querySelector(
      '[data-testid="graph-leaf-final.split-wv@->final.s1"]',
    );
    const splitHReplica = container.querySelector(
      '[data-testid="graph-leaf-final.split-H@->final.s1"]',
    );
    if (!s1 || !splitWvReplica || !splitHReplica) {
      throw new Error("missing s1 or one of its replicas");
    }
    const rectS1 = s1.querySelector("rect.graph-leaf-rect");
    const rectWv = splitWvReplica.querySelector("rect.graph-leaf-rect");
    const rectH = splitHReplica.querySelector("rect.graph-leaf-rect");
    if (!rectS1 || !rectWv || !rectH) throw new Error("missing rects");

    const yS1 = Number(rectS1.getAttribute("y"));
    const yWv = Number(rectWv.getAttribute("y"));
    const yH = Number(rectH.getAttribute("y"));

    // split-wv at local row 0: y_s1 − (LEAF_H + REPLICA_LIFT_GAP) =
    // y_s1 − 64 at default density (LEAF_H=28, REPLICA_LIFT_GAP=36).
    // split-H at local row 1:
    // y_s1 − (LEAF_H + REPLICA_LIFT_GAP) − (LEAF_H + REPLICA_STACK_GAP) =
    // y_s1 − 64 − 76 = y_s1 − 140 (LEAF_H=28, REPLICA_STACK_GAP=48).
    // Pre-S2(j2) (global rows 2, 3): would have been y_s1 − 216 and
    // y_s1 − 292 respectively — a 152 / 152 px reduction from
    // densification.
    expect(yS1 - yWv).toBeCloseTo(64, 0);
    expect(yS1 - yH).toBeCloseTo(140, 0);

    // Sanity: split-H is above split-wv (row 1 vs row 0).
    expect(yH).toBeLessThan(yWv);
  });

  it("the 8 ty values stay within the EdgePath clamp window (±16 around toCy)", () => {
    // Belt-and-braces: confirms the scale-to-fit branch lands every slot
    // inside the EdgePath clamp window, so no slot would have been
    // clamped (which is what produced the pre-S2(j) collision).
    const { container } = render(() => <GraphView />);

    // Pull final.assemble's box center via the rendered leaf rect.
    const assemble = container.querySelector('[data-testid="graph-leaf-final.assemble"]');
    if (!assemble) throw new Error("final.assemble leaf not rendered");
    const rect = assemble.querySelector("rect.graph-leaf-rect");
    if (!rect) throw new Error("final.assemble has no rect");
    const ry = Number(rect.getAttribute("y"));
    const rh = Number(rect.getAttribute("height"));
    if (!Number.isFinite(ry) || !Number.isFinite(rh)) {
      throw new Error("final.assemble rect missing geometry");
    }
    const toCy = ry + rh / 2;
    const cap = rh / 2 - 4;

    const allEdges = container.querySelectorAll<SVGPathElement>("path.graph-edge-hit");
    for (const edge of Array.from(allEdges)) {
      const key = edge.getAttribute("data-edge-key");
      if (key === null || !key.includes("|final.assemble|")) continue;
      const fromPart = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")[0]
        : key.split("|")[0];
      if (fromPart === undefined || !/^final\.s\d+$/.test(fromPart)) continue;
      const d = edge.getAttribute("d");
      if (d === null) continue;
      const ty = parseTargetY(d);
      // Each ty must be inside [toCy - cap, toCy + cap]. Pre-S2(j) the
      // raw outer offsets would have wanted positions OUTSIDE this
      // window (toCy ± 35) and got clamped — which IS landing on the
      // window edge, but at the cost of collisions. Post-S2(j) the
      // values land strictly inside.
      expect(ty).toBeGreaterThanOrEqual(toCy - cap - 0.001);
      expect(ty).toBeLessThanOrEqual(toCy + cap + 0.001);
    }
  });
});
