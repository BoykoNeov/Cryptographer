// @vitest-environment jsdom

/**
 * Z-order regression for cross-iteration feedback edges (2026-05-18).
 *
 * Problem: SVG paints in document order, so the canvas body is laid out
 * as `containers → edges → leaves` precisely so leaves cover the edge
 * tails/heads that tuck under their box fills (clean arrowhead
 * alignment for the 95%+ of edges). Cross-iteration feedback edges —
 * today only CBC's `cbc-snapshot → cbc-xor`, future OFB/CFB the same
 * shape — arc backwards across the round body to reach an earlier
 * consumer, and any unrelated node they cross obscures the dashed
 * line. The manual smoke that surfaced this used AES-128 CBC: the
 * feedback arrow passed behind `round.0.add-round-key` and reappeared
 * at the `cbc-xor` consumer.
 *
 * Fix: partition `bundledGraph().bundles` into non-feedback (rendered
 * before leaves, current position — tuck preserved) and feedback
 * (rendered AFTER leaves so they paint on top of any nodes they
 * cross).
 *
 * What this file pins: the feedback `<path>` is positioned AFTER every
 * `<g class="graph-leaf">` in DOM order within the SVG body, so SVG
 * paint order puts the dashed line above the leaf rectangles.
 */

import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { __resetValueInspectorForTests } from "@/ui/stores/view-value-inspector";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// SP 800-38A §F.2.1 test vector keys; we don't need the ciphertext here,
// only a valid trace that produces the feedback edge `cbc-snapshot → cbc-xor`.
const KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const IV = "000102030405060708090a0b0c0d0e0f";
// Two blocks is enough — CBC's feedback edge appears once we have a
// second iteration, but the spec-level edge after `:b{i}` strip is
// independent of block count.
const PLAINTEXT_2_BLOCKS = "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51";

const seedAes128Cbc = (): void => {
  // Same setCipher / setCipherMode dance as the other graph-view jsdom
  // suites — both signals need flipping or the spec store won't rebuild
  // the canonical CBC pair before render.
  setCipher("aes-128");
  setCipherMode("cbc");
  const trace = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
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

describe("GraphView — feedback-edge z-order (CBC)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the feedback `<path>` AFTER every leaf in DOM order so it paints on top", () => {
    seedAes128Cbc();
    const { container } = render(() => <GraphView />);

    // The visible feedback `<path>` carries `.graph-edge-feedback`
    // (applied in EdgePath via classList when `props.isFeedback`).
    // We pick the visible path rather than the hit path because the
    // hit path is a thicker transparent overlay sibling that does NOT
    // carry the feedback class.
    const feedbackPaths = Array.from(
      container.querySelectorAll<SVGPathElement>("path.graph-edge.graph-edge-feedback"),
    );
    expect(feedbackPaths.length).toBeGreaterThan(0);

    // Every leaf rectangle group — `.graph-leaf` is set on the outer
    // `<g>` wrapping a leaf's rect + label + warnings + delete glyph.
    const leaves = Array.from(container.querySelectorAll<SVGGElement>("g.graph-leaf"));
    expect(leaves.length).toBeGreaterThan(0);

    // SVG document order = paint order. A feedback path that appears
    // BEFORE a leaf in document order would be painted under that
    // leaf and disappear behind it. `compareDocumentPosition` returns
    // a bitmask: `Node.DOCUMENT_POSITION_FOLLOWING` (0x04) when the
    // ARGUMENT follows the receiver. So `leaf.compareDocumentPosition
    // (feedbackPath) & FOLLOWING` is truthy iff the feedback path is
    // later (i.e. paints on top of) the leaf.
    const FOLLOWING = Node.DOCUMENT_POSITION_FOLLOWING;
    for (const feedbackPath of feedbackPaths) {
      for (const leaf of leaves) {
        const rel = leaf.compareDocumentPosition(feedbackPath);
        expect(rel & FOLLOWING).toBeTruthy();
      }
    }
  });

  it("does NOT lift non-feedback edges into the post-leaves pass (forward edges keep their tuck-under)", () => {
    seedAes128Cbc();
    const { container } = render(() => <GraphView />);

    // Forward (non-feedback) edges should remain BEFORE the leaves so
    // their arrowheads still tuck under the consumer leaf's box fill
    // — the deliberate visual that the partition is careful not to
    // break for the 95%+ of edges. We assert that EVERY non-feedback
    // path precedes EVERY leaf in document order; the looser "at
    // least one precedes the first leaf" form would pass trivially
    // (it's true by construction whenever any non-feedback bundle
    // exists), so it wouldn't actually detect a regression where the
    // partition spilled forward edges into the post-leaf pass.
    const leaves = Array.from(container.querySelectorAll<SVGGElement>("g.graph-leaf"));
    expect(leaves.length).toBeGreaterThan(0);

    const allEdgePaths = Array.from(container.querySelectorAll<SVGPathElement>("path.graph-edge"));
    const nonFeedbackPaths = allEdgePaths.filter(
      (p) => !p.classList.contains("graph-edge-feedback"),
    );
    expect(nonFeedbackPaths.length).toBeGreaterThan(0);

    // FOLLOWING (0x04) — the argument FOLLOWS the receiver. So a
    // non-feedback path precedes a leaf iff `nfPath.compareDocument
    // Position(leaf) & FOLLOWING`. Every (path, leaf) pair must
    // satisfy this for the forward-edge layer to remain intact.
    const FOLLOWING = Node.DOCUMENT_POSITION_FOLLOWING;
    for (const nfPath of nonFeedbackPaths) {
      for (const leaf of leaves) {
        const rel = nfPath.compareDocumentPosition(leaf);
        expect(rel & FOLLOWING).toBeTruthy();
      }
    }
  });
});
