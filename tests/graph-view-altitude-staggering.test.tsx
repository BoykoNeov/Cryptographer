// @vitest-environment jsdom

/**
 * GraphView — curve-altitude staggering on the SHA-256 `final.assemble`
 * 8-fan-IN corridor.
 *
 * S2-next of `docs/plans/sha-256-density-polish.md` (the queued sibling
 * of S2(m) focus-dim, motivated by the acknowledged limitation that
 * focus-dim doesn't fix steady-state crowding — see plan lines
 * 1154–1158 for the deliberation).
 *
 * **The mechanic.** `EdgePath` already accepts per-edge endpoint port-
 * spreading offsets (`targetXOffset`/`targetYOffset`/`sourceXOffset`/
 * `sourceYOffset`) that distribute the *endpoints* of sibling edges
 * across each consumer's edge. Pre-S2-next those siblings still bowed
 * at the same curve-pull magnitude — parallel curves in a shared
 * corridor still piled up visually. S2-next introduces `pullSlot` /
 * `pullSlotTotal` props sourced from the SAME `ConsumerPortAssignment`
 * the port-spreading offsets read, and applies a centred multiplier
 * `1 + PULL_STAGGER_STEP × (slot − (total − 1) / 2)` to the cubic
 * Bezier pull magnitude in the vertical and horizontal regimes.
 *
 * **What this test pins.** SHA-256's `final.assemble` consumer receives
 * 8 incoming port-flow edges (state kind, auxKey = PORT_FLOW_AUX_KEY)
 * from `final.s_0 .. s_7`. They render in the horizontal regime —
 * `M sx sy C c1x sy, c2x ty, tx ty`. The cubic's first control x
 * (`c1x = sx + pull` since the consumer sits rightward of every s_i)
 * directly reveals the per-edge pull magnitude. With staggering the 8
 * `c1x` values must land in 8 distinct buckets — i.e. the corridor
 * shows 8 visibly-distinct altitudes. Pre-S2-next they would all
 * share one base pull (`Math.max(20, |tx − sx| / 2)` deterministic per
 * (from, to) pair → identical for sibling rows, since `sx` is the
 * same source-right-edge x and `tx` is the same consumer-left-edge x
 * per edge; `sy/ty` differ but don't enter the pull formula).
 *
 * Pinned together with `graph-view-sha256-assemble-fan-in.test.tsx`
 * (which pins endpoint spread). Together they confirm: 8 endpoint
 * slots × 8 altitude slots — sibling parallel curves are visually
 * distinct at both ends AND through the middle of the corridor.
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
 * Parse the horizontal-regime cubic's first control x.
 *
 * Format: `M sx sy C c1x sy, c2x ty, tx ty` → tokens after splitting on
 * whitespace+comma are `[M, sx, sy, C, c1x, sy, c2x, ty, tx, ty]`. The
 * cubic-Bezier first control x sits at token index 4.
 */
const parseHorizontalC1X = (d: string): number => {
  const tokens = d.trim().split(/[\s,]+/);
  if (tokens.length < 10) {
    throw new Error(`bad path data (need 10+ tokens for cubic, got ${tokens.length}): ${d}`);
  }
  if (tokens[3] !== "C") {
    throw new Error(`expected cubic Bezier ('C' at index 3), got '${tokens[3]}': ${d}`);
  }
  const raw = tokens[4];
  if (raw === undefined) throw new Error(`missing c1x token: ${d}`);
  const c1x = Number(raw);
  if (!Number.isFinite(c1x)) throw new Error(`c1x not a number: ${raw} (from ${d})`);
  return c1x;
};

describe("GraphView — curve-altitude staggering on SHA-256 final.assemble 8-fan-IN", () => {
  beforeEach(() => {
    resetAll();
    setHash("sha-256");
    seedSha256Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("the 8 incoming edges at final.assemble produce 8 DISTINCT curve altitudes", () => {
    const { container } = render(() => <GraphView />);

    // Collect every rendered .graph-edge-hit path whose data-edge-key
    // matches `final.sN → final.assemble`. Pattern lifted from
    // `graph-view-sha256-assemble-fan-in.test.tsx` (the endpoint-
    // distinctness test) — keeping the selector identical so the two
    // tests pin the SAME set of 8 edges from different angles.
    const allEdges = container.querySelectorAll<SVGPathElement>("path.graph-edge-hit");
    const c1xs: number[] = [];
    let matched = 0;
    for (const edge of Array.from(allEdges)) {
      const key = edge.getAttribute("data-edge-key");
      if (key === null) continue;
      if (!key.includes("|final.assemble|")) continue;
      const fromPart = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")[0]
        : key.split("|")[0];
      if (fromPart === undefined || !/^final\.s\d+$/.test(fromPart)) continue;
      const d = edge.getAttribute("d");
      if (d === null) continue;
      c1xs.push(parseHorizontalC1X(d));
      matched += 1;
    }

    // Pin the test setup: exactly 8 incoming edges (s_0..s_7). If this
    // fails the test fixture has drifted, not the staggering mechanic.
    expect(matched).toBe(8);
    expect(c1xs).toHaveLength(8);

    // Distinctness. Round to 0.5 px buckets so floating-point noise
    // doesn't manufacture a false pass. With PULL_STAGGER_STEP = 0.18
    // and 8 slots, adjacent multipliers differ by 0.18 → adjacent
    // pulls differ by 0.18 × basePull. At SHA-256's `final.assemble`
    // basePull ≈ 100 px the adjacent-slot gap is ~18 px — comfortably
    // above the 0.5 px bucket. Pre-S2-next the 8 c1x values would
    // coincide exactly (single base pull per (from, to) pair → same
    // pull → same c1x).
    const buckets = new Set(c1xs.map((x) => Math.round(x * 2) / 2));
    expect(buckets.size).toBe(8);
  });

  it("the 8 curve altitudes are monotonic by slot index", () => {
    // The slot index for each `final.sN → final.assemble` edge follows
    // `buildConsumerPortAssignment`'s deterministic sort: primary key is
    // visual source x (set by the layout via `sourceXOf`), with row /
    // source-id / aux-key / kind as tiebreakers. For the SHA-256 final
    // fan-IN, all 8 s_i sources sit on the same row at distinct x's, so
    // the slot order matches the s_i index order (s_0 leftmost → slot 0,
    // s_7 rightmost → slot 7). After centring at total=8, slot 0
    // multiplier = 0.37 → smallest pull → smallest c1x (= sx + 0.37 ×
    // basePull). Slot 7 multiplier = 1.63 → biggest pull → biggest c1x.
    // c1x is therefore strictly monotone in slot index.
    //
    // Why pin this. Distinctness alone says "8 different altitudes" but
    // could be satisfied by a chaotic order. Monotonicity says "the
    // ordering matches the row order" — i.e. as the eye walks down the
    // s_i column on the left, the corridor curves get progressively
    // higher. That's the pedagogy the slice is shipping; if a future
    // refactor reorders the slot sort, this test catches it loudly.
    const { container } = render(() => <GraphView />);

    const allEdges = container.querySelectorAll<SVGPathElement>("path.graph-edge-hit");
    const bySIndex = new Map<number, number>();
    for (const edge of Array.from(allEdges)) {
      const key = edge.getAttribute("data-edge-key");
      if (key === null) continue;
      if (!key.includes("|final.assemble|")) continue;
      const fromPart = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")[0]
        : key.split("|")[0];
      if (fromPart === undefined) continue;
      const match = fromPart.match(/^final\.s(\d+)$/);
      if (match === null) continue;
      const idx = match[1];
      if (idx === undefined) continue;
      const sIdx = Number(idx);
      const d = edge.getAttribute("d");
      if (d === null) continue;
      bySIndex.set(sIdx, parseHorizontalC1X(d));
    }
    expect(bySIndex.size).toBe(8);

    // Monotonic: c1x at s_i strictly less than c1x at s_(i+1).
    for (let i = 0; i < 7; i += 1) {
      const lower = bySIndex.get(i);
      const upper = bySIndex.get(i + 1);
      if (lower === undefined || upper === undefined) {
        throw new Error(`missing slot ${i} or ${i + 1}`);
      }
      expect(upper).toBeGreaterThan(lower);
    }
  });

  it("excluded edges (no slot) keep multiplier 1.0 — predicate scope", () => {
    // The predicate (`kind === "state" && auxKey === PORT_FLOW_AUX_KEY`,
    // mirroring `sourceYOffset`'s scope at GraphView.tsx ~4729) returns
    // undefined for any non-port-flow edge, so `pullMultiplier` short-
    // circuits to 1.0 and the cubic pull formula is byte-identical to
    // pre-slice. We assert this property on the SHA-256 view itself:
    // SHA-256's graph contains BOTH port-flow state edges (the targets
    // of this slice) AND aux/legacy-state edges (key-schedule outputs,
    // boundary connections). The aux edges must continue to use the
    // un-staggered formula `pull = Math.max(20, |tx − sx| / 2)`.
    //
    // Pinning this directly catches a regression where a future
    // refactor accidentally drops the predicate from the `pullSlot`
    // memo — every edge would then get a slot and aux edges would
    // tilt off-axis. Pre-S2-next + post-S2-next this assertion holds;
    // a broken post-S2-next refactor would fail it.
    const { container } = render(() => <GraphView />);

    const allEdges = container.querySelectorAll<SVGPathElement>("path.graph-edge-hit");
    let pinned = 0;
    for (const edge of Array.from(allEdges)) {
      const key = edge.getAttribute("data-edge-key");
      if (key === null) continue;
      // Aux-keyed edges only (skip port-flow edges — those are the
      // staggered ones). Singleton key format: `from|to|auxKey|kind`.
      // Bundle key format: `bundle:from|to|kind|...auxKeys...`.
      const tokens = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")
        : key.split("|");
      // Singleton fourth token is the kind; bundle third token is the
      // kind. Skip both encodings if kind === "state" AND auxKey ===
      // "port-flow" (the staggered class).
      if (!key.startsWith("bundle:")) {
        // Singleton: tokens[3] is kind, tokens[2] is auxKey.
        if (tokens[3] === "state" && tokens[2] === "port-flow") continue;
      }
      const d = edge.getAttribute("d");
      if (d === null) continue;
      const dTokens = d.trim().split(/[\s,]+/);
      if (dTokens.length < 10 || dTokens[3] !== "C") continue;
      const sx = Number(dTokens[1]);
      const sy = Number(dTokens[2]);
      const c1x = Number(dTokens[4]);
      const c1y = Number(dTokens[5]);
      const tx = Number(dTokens[8]);
      const ty = Number(dTokens[9]);
      if (!Number.isFinite(sx) || !Number.isFinite(sy) || !Number.isFinite(c1x)) continue;
      if (!Number.isFinite(c1y) || !Number.isFinite(tx) || !Number.isFinite(ty)) continue;
      // Horizontal regime gate: c1y === sy (within FP tolerance) AND
      // c1x !== sx (vertical-regime cubics have c1x === sx).
      if (Math.abs(c1y - sy) > 0.0001) continue;
      if (Math.abs(c1x - sx) < 0.0001) continue;
      const expectedPullMag = Math.max(20, Math.abs(tx - sx) / 2);
      const actualPullMag = Math.abs(c1x - sx);
      // Tolerance 4 decimal places — handles fp noise but catches any
      // multiplicative offset (a stray 1.18× would produce a >0.1 mag
      // mismatch on basePull ≥ 20).
      expect(actualPullMag).toBeCloseTo(expectedPullMag, 4);
      pinned += 1;
      if (pinned >= 3) break; // Three samples confirms the formula.
    }
    // Sanity: SHA-256 should render at least one aux-keyed horizontal-
    // regime cubic edge in jsdom. If not, the predicate fence is
    // un-exercised; surface it loudly rather than silently passing.
    expect(pinned).toBeGreaterThan(0);
  });
});
