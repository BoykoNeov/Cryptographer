// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure layout exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `layoutRoot` + `layoutConstantsFor`. jsdom's "window"
// existing is enough.

/**
 * Tests for the density-driven layout sizing (commit 3 of the graph-
 * readability sequence). Drives the pure `layoutRoot` + `layoutConstantsFor`
 * helpers directly — no rendering. We just want to pin:
 *
 *   1. `compact < normal < spacious` for canvas width AND height. This is
 *      the primary user-visible promise of the density knob: "make it
 *      smaller / bigger." If a future refactor accidentally scales gaps
 *      and leaves separately, the ordering could collapse — this test is
 *      the canary.
 *   2. "normal" produces byte-identical output to the pre-density layout.
 *      We pin the absolute canvasW/H at normal as a numeric snapshot — if
 *      the constants drift, the prior label-truncation / drag tests would
 *      need re-baselining; this test fails first and points at the cause.
 *   3. The scale-factor record is applied consistently (LEAF_W scales with
 *      density, HEADER_H does not — that's the design constraint).
 *
 * Uses the AES-128 spec because it's the largest shipped pipeline and the
 * one we care about fitting into a viewport. The exact canvas widths will
 * shift if AES-128's structure changes (more rounds, different leaf set);
 * the FIRST assertion ("ordering") survives that, the SECOND (numeric
 * snapshot at normal) is the brittle one — when AES-128's layout changes
 * intentionally, just re-baseline the snapshot value.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { layoutConstantsFor, layoutRoot } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

// ─── Fixtures ──────────────────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const aes128Graph = () => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  return deriveAuxGraph(trace, aes128Spec);
};

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("GraphView density — canvas size ordering", () => {
  it("compact canvas is strictly smaller than normal; spacious is strictly larger", () => {
    const g = aes128Graph();
    const empty = new Map<string, { x: number; y: number }>();
    const compact = layoutRoot(g, empty, layoutConstantsFor("compact"));
    const normal = layoutRoot(g, empty, layoutConstantsFor("normal"));
    const spacious = layoutRoot(g, empty, layoutConstantsFor("spacious"));

    // Strict ordering on width AND height. If a future tweak makes the
    // height collapse (e.g. STACK_GAP forced to 0) but the width still
    // scales, the strict-on-both check catches it.
    expect(compact.canvasW).toBeLessThan(normal.canvasW);
    expect(normal.canvasW).toBeLessThan(spacious.canvasW);
    expect(compact.canvasH).toBeLessThan(normal.canvasH);
    expect(normal.canvasH).toBeLessThan(spacious.canvasH);
  });

  it("normal density rounds back to the canonical 1.0× constants", () => {
    const c = layoutConstantsFor("normal");
    // These pin the byte-stability of the pre-density default. If any of
    // these change, the prior drag / label-truncation tests in
    // graph-view.test.tsx + graph-view-drag.test.tsx + graph-view-label-
    // truncation.test.tsx need re-baselining first.
    expect(c.LEAF_W).toBe(132);
    expect(c.LEAF_H).toBe(28);
    // BASE_STACK_GAP history: 6 → 12 (2026-05-19, 2×) → 60 (2026-05-27, 5×).
    // 6 → 12 gave the four AES-round-group leaves visible breathing
    // room (pre-bump the rows read as one solid block). 12 → 60 was
    // a user request for "much more breathing room" once expanded
    // SHA-256 message-schedule rounds shared canvases with AES rounds.
    expect(c.STACK_GAP).toBe(60);
    // BASE_FLOW_GAP history: 16 → 24 (2026-05-16) → 36 (2026-05-19) →
    // 72 (2026-05-27, 2×). 16 → 24 added breathing room to the
    // collapsed multi-block iterate chip row; 24 → 36 fixed CBC's
    // 13-chip row reading as a wall; 36 → 72 doubled horizontal gaps
    // across root + iterate bodies per user request. FLOW_GAP is used
    // in both root flow + iterate body flow.
    expect(c.FLOW_GAP).toBe(72);
    expect(c.CONTAINER_PAD).toBe(10);
  });

  it("compact scales every size-and-gap constant down (no zero-collapse)", () => {
    const n = layoutConstantsFor("normal");
    const c = layoutConstantsFor("compact");
    // Each scaled constant must be strictly smaller — and strictly POSITIVE
    // (a zero CONTAINER_PAD would put the label flush with the box edge).
    expect(c.LEAF_W).toBeLessThan(n.LEAF_W);
    expect(c.LEAF_H).toBeLessThan(n.LEAF_H);
    expect(c.STACK_GAP).toBeLessThan(n.STACK_GAP);
    expect(c.FLOW_GAP).toBeLessThan(n.FLOW_GAP);
    expect(c.CONTAINER_PAD).toBeLessThan(n.CONTAINER_PAD);
    expect(c.LEAF_W).toBeGreaterThan(0);
    expect(c.LEAF_H).toBeGreaterThan(0);
    expect(c.STACK_GAP).toBeGreaterThan(0);
    expect(c.FLOW_GAP).toBeGreaterThan(0);
    expect(c.CONTAINER_PAD).toBeGreaterThan(0);
  });

  it("spacious scales every size-and-gap constant up", () => {
    const n = layoutConstantsFor("normal");
    const s = layoutConstantsFor("spacious");
    expect(s.LEAF_W).toBeGreaterThan(n.LEAF_W);
    expect(s.LEAF_H).toBeGreaterThan(n.LEAF_H);
    expect(s.STACK_GAP).toBeGreaterThan(n.STACK_GAP);
    expect(s.FLOW_GAP).toBeGreaterThan(n.FLOW_GAP);
    expect(s.CONTAINER_PAD).toBeGreaterThan(n.CONTAINER_PAD);
  });
});
