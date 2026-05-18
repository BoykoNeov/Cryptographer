// @vitest-environment jsdom

/**
 * Feedback-edge "overhead" routing regression (2026-05-18).
 *
 * Problem: In CBC baseline (replicates OFF), the feedback edge
 * `cbc-snapshot → cbc-xor` is a horizontal-regime edge (its source and
 * target are same-row siblings in the iterate body). The pre-fix
 * geometry had the feedback arrowhead enter `cbc-xor`'s RIGHT edge at
 * right-center — the SAME point where the forward state spine
 * `cbc-xor → add-round-key` DEPARTS. Two arrows then shared one tiny
 * region on `cbc-xor`'s right edge (head + tail), and the box
 * congested visually. User surfaced this after the z-order fix
 * (commit `80cf29a`) shipped.
 *
 * Fix: route feedback edges in horizontal regime OVER THE TOP — exit
 * source's top edge, arc up, enter target's top edge from above. This
 * structurally separates the feedback head (top edge) from the forward
 * spine tail (right edge) AND reinforces the dashed "cross-iteration
 * loop" narrative the styling already conveys.
 *
 * What this file pins:
 *   1. The feedback path's start point sits on `cbc-snapshot`'s top
 *      edge (sy ≈ source.y, sx ≈ source horizontal center).
 *   2. The feedback path's end point sits just above `cbc-xor`'s top
 *      edge (ty ≈ target.y − ARROW_INSET, tx ≈ target horizontal
 *      center). NOT on the right edge.
 *   3. The forward state spine `cbc-xor → add-round-key` is unchanged
 *      — still departs `cbc-xor`'s right edge — so the rerouting is
 *      asymmetric: feedback moves, forward edges don't.
 */

import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode, setMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { __resetValueInspectorForTests } from "@/ui/stores/view-value-inspector";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// SP 800-38A §F.2.1 keys. Two-block plaintext so the trace produces
// the feedback edge `cbc-snapshot → cbc-xor` (the edge exists as a
// canonical spec-level arrow regardless of block count, but a single-
// block trace would still walk the iterate body once — keeping two
// blocks here matches the manual-smoke scenario the user reported).
const KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const IV = "000102030405060708090a0b0c0d0e0f";
const PLAINTEXT_2_BLOCKS = "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51";

const seedAes128Cbc = (direction: "encrypt" | "decrypt" = "encrypt"): void => {
  // `setCipher` + `setCipherMode` rebuild both encrypt + decrypt slots
  // from canonical; `setMode` then flips which slot is the active spec
  // the GraphView reads. Decrypt's feedback edge has different endpoint
  // ids (`cbc-snapshot-input` / `cbc-advance-chain` flow into `cbc-xor`
  // per `aes-cbc-builder.ts`), but the overhead-routing CONTRACT — exit
  // top, arc up, enter top — must hold regardless of direction since
  // the fix is gated purely on `props.isFeedback`.
  setCipher("aes-128");
  setCipherMode("cbc");
  setMode(direction);
  const spec: CipherSpec = direction === "decrypt" ? aes128CbcDecryptSpec : aes128CbcSpec;
  // The decrypt spec's plaintext field is actually ciphertext bytes;
  // either way the trace just needs to run a 2-block iterate, so we
  // pass the same 32-byte buffer and let it interpret as it will. Test
  // is structural (geometry), not pedagogical (round-trip semantics).
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(PLAINTEXT_2_BLOCKS)),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex(KEY)],
      ["iv", bytesFromHex(IV)],
    ]),
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
 * Read the rendered box (x, y, w, h) of a leaf by its stepId via the
 * `<rect class="graph-leaf-rect">` inside `data-testid="graph-leaf-${id}"`.
 * Returns undefined if not rendered (e.g. mistyped id).
 */
const leafBox = (
  container: ParentNode,
  stepId: string,
): { x: number; y: number; w: number; h: number } | undefined => {
  const leaf = container.querySelector<SVGGElement>(`[data-testid="graph-leaf-${stepId}"]`);
  if (leaf === null) return undefined;
  const rect = leaf.querySelector<SVGRectElement>("rect.graph-leaf-rect");
  if (rect === null) return undefined;
  // `getAttribute` returns the literal source value; SVG renders these
  // unparsed in jsdom, so we parse with `Number` (which handles ints +
  // decimals + scientific notation uniformly).
  const x = Number(rect.getAttribute("x"));
  const y = Number(rect.getAttribute("y"));
  const w = Number(rect.getAttribute("width"));
  const h = Number(rect.getAttribute("height"));
  return { x, y, w, h };
};

/**
 * Parse a cubic-Bezier-only SVG path `d` into a list of `(x, y)` points
 * in order: start, control1, control2, end (and repeats if multiple `C`
 * segments — feedback paths today have exactly one). Returns the FIRST
 * point (start) and the LAST point (end) which is all the geometry
 * assertions below need.
 *
 * The path format produced by `EdgePath`'s feedback branch is
 *   `M sx sy C c1x c1y, c2x c2y, tx ty`
 * with commas and/or whitespace separators. We tokenize on either.
 */
const parseEndpoints = (
  d: string,
): { start: { x: number; y: number }; end: { x: number; y: number } } => {
  // Strip commands, split on whitespace + commas. After stripping `M`
  // and `C` the remainder is a flat list of numeric tokens.
  const tokens = d
    .replace(/[MC]/g, " ")
    .trim()
    .split(/[\s,]+/)
    .map(Number);
  // First two tokens = M's (sx, sy). Last two tokens = C's final (tx, ty).
  // For the feedback overhead path: tokens.length === 8 (2 + 6).
  const sx = tokens[0];
  const sy = tokens[1];
  const tx = tokens[tokens.length - 2];
  const ty = tokens[tokens.length - 1];
  if (sx === undefined || sy === undefined || tx === undefined || ty === undefined) {
    throw new Error(`Could not parse endpoints from path d="${d}"`);
  }
  return { start: { x: sx, y: sy }, end: { x: tx, y: ty } };
};

/**
 * Find the leaf whose top edge is at `expectedY` (within `yTol`) AND
 * whose horizontal center is at `expectedX` (within `xTol`). Used by
 * the decrypt test to identify the feedback source/target leaves
 * generically — decrypt's feedback edge has different endpoint ids
 * than encrypt's, so a stepId-based lookup would couple the test to
 * `aes-cbc-builder`'s internal naming. This shape-based matcher pins
 * the geometric contract: "the M point lands on SOME leaf's top edge
 * center, and the C end lands `ARROW_INSET` above SOME leaf's top edge
 * center." Returns undefined when nothing matches (so the calling
 * `expect(...).toBeDefined()` fails with a useful message).
 */
const findLeafByTopEdgeCenter = (
  container: ParentNode,
  expectedX: number,
  expectedY: number,
  xTol = 2,
  yTol = 2,
): { x: number; y: number; w: number; h: number } | undefined => {
  const rects = Array.from(
    container.querySelectorAll<SVGRectElement>("g.graph-leaf rect.graph-leaf-rect"),
  );
  for (const rect of rects) {
    const x = Number(rect.getAttribute("x"));
    const y = Number(rect.getAttribute("y"));
    const w = Number(rect.getAttribute("width"));
    const h = Number(rect.getAttribute("height"));
    const cx = x + w / 2;
    if (Math.abs(cx - expectedX) <= xTol && Math.abs(y - expectedY) <= yTol) {
      return { x, y, w, h };
    }
  }
  return undefined;
};

describe("GraphView — feedback-edge overhead routing (CBC)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("routes `cbc-snapshot → cbc-xor` over the top — exits source top edge, enters target top edge", () => {
    seedAes128Cbc();
    const { container } = render(() => <GraphView />);

    const snapshotBox = leafBox(container, "cbc-snapshot");
    const xorBox = leafBox(container, "cbc-xor");
    expect(snapshotBox).toBeDefined();
    expect(xorBox).toBeDefined();
    if (snapshotBox === undefined || xorBox === undefined) return;

    // Sanity: in CBC baseline both leaves sit in the same iterate chip
    // row → they share a y (within rounding). This is the precondition
    // that makes the bug possible. If a future layout change separates
    // them on y, this test still passes for the right reason (top-edge
    // entry is still correct) — and the precondition assertion catches
    // the layout drift so the test maintainer knows to revisit.
    expect(Math.abs(snapshotBox.y - xorBox.y)).toBeLessThan(2);

    // Find the visible feedback path (carries `.graph-edge-feedback`;
    // hit path is a sibling without the class — see z-order test for
    // the same idiom).
    const feedbackPaths = Array.from(
      container.querySelectorAll<SVGPathElement>("path.graph-edge.graph-edge-feedback"),
    );
    expect(feedbackPaths.length).toBe(1);
    const fbPath = feedbackPaths[0];
    if (fbPath === undefined) return;
    const d = fbPath.getAttribute("d");
    expect(d).not.toBeNull();
    if (d === null) return;

    const { start, end } = parseEndpoints(d);

    // (1) Start point sits on `cbc-snapshot`'s TOP edge.
    //     sy should equal snapshotBox.y (the top y).
    //     sx should be near snapshotBox.x + snapshotBox.w / 2 (center).
    expect(start.y).toBeCloseTo(snapshotBox.y, 0);
    expect(start.x).toBeCloseTo(snapshotBox.x + snapshotBox.w / 2, 0);

    // (2) End point sits just ABOVE `cbc-xor`'s top edge — `ty` is the
    //     top edge minus `ARROW_INSET` (6 px). Loose tolerance ±2 to
    //     absorb any future inset tweak without re-pinning this test.
    expect(end.y).toBeLessThan(xorBox.y);
    expect(xorBox.y - end.y).toBeLessThan(10);
    expect(end.x).toBeCloseTo(xorBox.x + xorBox.w / 2, 0);

    // (3) Confirm the head DID NOT land on `cbc-xor`'s right edge
    //     (the pre-fix behaviour). Right-edge x would equal
    //     xorBox.x + xorBox.w; the pre-fix `tx` was that minus 6 px
    //     (inset) on the rightward branch, or plus 6 px on the
    //     leftward branch. Either way, the new end.x sits near
    //     xorBox.x + xorBox.w / 2 — well inside the box, far from
    //     the right edge.
    const xorRightEdge = xorBox.x + xorBox.w;
    expect(Math.abs(end.x - xorRightEdge)).toBeGreaterThan(xorBox.w / 4);
  });

  it("the forward state spine `cbc-xor → add-round-key` is unchanged — still exits cbc-xor's RIGHT edge", () => {
    // The fix is asymmetric: feedback edges reroute, non-feedback
    // (forward state spine) edges do not. This test pins that the
    // first-round forward spine still uses the horizontal regime,
    // departing `cbc-xor`'s right-center as the original design intends.
    // Without this assertion, a future regression that accidentally
    // gated the overhead routing on all edges (not just feedback)
    // would silently slip through.
    seedAes128Cbc();
    const { container } = render(() => <GraphView />);

    const xorBox = leafBox(container, "cbc-xor");
    expect(xorBox).toBeDefined();
    if (xorBox === undefined) return;

    // Forward spine edges carry NO `.graph-edge-feedback` class. The
    // spine from `cbc-xor` is the state-kind arrow whose start sits at
    // `cbc-xor`'s right-edge midline (rightward horizontal regime
    // exit). We don't need to know the exact consumer id — any non-
    // feedback path whose start matches `cbc-xor`'s right-center is
    // the spine we're looking for.
    const allPaths = Array.from(
      container.querySelectorAll<SVGPathElement>("path.graph-edge.graph-edge-state"),
    );
    const xorRightEdge = xorBox.x + xorBox.w;
    const xorMidY = xorBox.y + xorBox.h / 2;

    const spineDepartures = allPaths.filter((p) => {
      if (p.classList.contains("graph-edge-feedback")) return false;
      const d = p.getAttribute("d");
      if (d === null) return false;
      try {
        const { start } = parseEndpoints(d);
        // Within 1.5 px of the right-edge x AND within 2 px of mid-y.
        return Math.abs(start.x - xorRightEdge) < 1.5 && Math.abs(start.y - xorMidY) < 2;
      } catch {
        return false;
      }
    });
    expect(spineDepartures.length).toBeGreaterThanOrEqual(1);
  });

  it("routes the decrypt-direction feedback edge over the top too (direction-agnostic contract)", () => {
    // Decrypt CBC has its own iterate body shape:
    //   cbc-snapshot-input → ... → cbc-xor → cbc-advance-chain
    // The cross-iteration feedback (advance-chain writes aux["chain"]
    // for the next iteration's cbc-xor read) is a different (from, to)
    // pair than encrypt's. The fix is gated purely on `props.isFeedback`
    // with no direction reads, so the contract MUST hold here too. If
    // a future direction-sensitive change to `isFeedback` stamping or
    // the bundling pipeline silently broke decrypt, this assertion
    // catches it. The exact endpoint ids are NOT asserted — looked up
    // by box geometry instead — so the test stays robust to internal
    // builder renames.
    seedAes128Cbc("decrypt");
    const { container } = render(() => <GraphView />);

    const feedbackPaths = Array.from(
      container.querySelectorAll<SVGPathElement>("path.graph-edge.graph-edge-feedback"),
    );
    expect(feedbackPaths.length).toBeGreaterThanOrEqual(1);
    const fbPath = feedbackPaths[0];
    if (fbPath === undefined) return;
    const d = fbPath.getAttribute("d");
    expect(d).not.toBeNull();
    if (d === null) return;

    const { start, end } = parseEndpoints(d);

    // (1) Start point sits on SOME leaf's top edge. The matcher checks
    //     `cx ≈ start.x AND y ≈ start.y` so we don't have to name the
    //     source leaf. If no leaf matches → undefined → the assertion
    //     below fails with the (x, y) tuple, which is enough debug
    //     info to identify the mismatched leaf.
    const sourceLeaf = findLeafByTopEdgeCenter(container, start.x, start.y);
    expect(sourceLeaf, `no leaf matches start point (${start.x}, ${start.y})`).toBeDefined();

    // (2) End point sits ABOVE SOME leaf's top edge by ~ARROW_INSET
    //     (6 px). Search for a leaf whose top edge is just below the
    //     end point. The window 5..10 px catches the inset (6) with
    //     a ±2 tolerance for any future inset tweak.
    const rects = Array.from(
      container.querySelectorAll<SVGRectElement>("g.graph-leaf rect.graph-leaf-rect"),
    );
    const targetMatches = rects.filter((rect) => {
      const ry = Number(rect.getAttribute("y"));
      const rx = Number(rect.getAttribute("x"));
      const rw = Number(rect.getAttribute("width"));
      const rcx = rx + rw / 2;
      const yDelta = ry - end.y;
      return yDelta >= 4 && yDelta <= 10 && Math.abs(rcx - end.x) <= 2;
    });
    expect(
      targetMatches.length,
      `no leaf top-edge is 4..10 px below feedback end point (${end.x}, ${end.y})`,
    ).toBeGreaterThanOrEqual(1);
  });
});
