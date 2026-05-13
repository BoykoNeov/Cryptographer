// @vitest-environment jsdom
//
// jsdom (not node) because GraphView.tsx — even though we only consume its
// pure layout exports — imports `solid-js/web` at module init, which
// references `window`. The component itself is never rendered here; the
// test only calls `layoutRoot` + `layoutConstantsFor`.

/**
 * Tests for the replica side-gutter layout (placement of high-fanout
 * replicas inside vertical-stack groups).
 *
 * The bug this prevents: `replicateHighFanoutSources` splices a replica
 * into the consumer's parent `childIds` immediately BEFORE the consumer.
 * Inside a vertical-stack group (every AES round), that lands the replica
 * in the same column as state-spine-consecutive leaves (mix-columns →
 * add-round-key). The replica's box sits BETWEEN them and visually
 * obscures the state edge running through the column — the user can't
 * tell whether mix-columns feeds add-round-key or the replica does.
 *
 * The fix: in `kind === "group"` (vertical stack), partition childIds —
 * non-replicas keep the column, replicas land in a LEFT GUTTER at their
 * consumer's y. The state-spine column is unobstructed; the aux arrow
 * from replica → consumer is a short horizontal segment.
 *
 * Properties this test pins:
 *
 *   1. Replica.x < consumer.x (replica is in the left gutter).
 *   2. Replica.y is centered against consumer.y (visually adjacent).
 *   3. The group's box widens by approximately LEAF_W + FLOW_GAP to make
 *      room for the gutter (only when a replica is present).
 *   4. Non-replicated rounds (none today in default AES-128 since EVERY
 *      round consumes a round key, but iterated against the principle)
 *      keep their original width.
 *
 * Note: AES-128 has 10 round groups + initial.add-round-key at root. All
 * 11 add-round-key consumers receive a replica when replication is on.
 * `initial.add-round-key` is at ROOT level (horizontal flow), so its
 * replica lands via the existing splice-before-consumer mechanic — no
 * gutter logic involved at root. We verify the round-group cases here.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { type CipherGraph, deriveAuxGraph, replicateHighFanoutSources } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { layoutConstantsFor, layoutRoot } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

// ─── Fixtures ──────────────────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const aes128Graph = (): CipherGraph => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  return deriveAuxGraph(trace, aes128Spec);
};

const aes128ReplicatedGraph = (): CipherGraph => replicateHighFanoutSources(aes128Graph(), 6);

// AES-128-ECB exercises the iterate-body branch: `initial.add-round-key` is
// inside the iterate body, so its `key-expansion@->...` replica lands at
// iterate-body level (horizontal flow), not at root. Same orthogonal-axis
// principle as root must apply, otherwise the body-level spine arrow
// `initial.add-round-key → round.1.sub-bytes` would pass through the replica.
const ECB_PT_1_BLOCK = "6bc1bee22e409f96e93d7e117393172a";
const ECB_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const aes128EcbReplicatedGraph = (): CipherGraph => {
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PT_1_BLOCK)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(ECB_KEY)]]),
  });
  return replicateHighFanoutSources(deriveAuxGraph(trace, aes128EcbSpec), 6);
};

// Serpent exercises the FIRST-CHILD branch: every round group's `add-round-key`
// is the FIRST step (Serpent's per-round order is add-round-key → sub-bytes
// → linear-transform, opposite of AES). The inter-round state spine enters
// each round from the LEFT at `add-round-key`'s y. A LEFT-gutter replica at
// that same y would obscure the incoming arrow, so the layout LIFTS the
// column instead — placing the replica directly ABOVE `add-round-key` in
// the lifted top of the round box. AES vs Serpent both consume from
// `key-expansion`, but only Serpent triggers the lift branch.
const SERPENT128_PT = "00112233445566778899aabbccddeeff";
const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const serpent128ReplicatedGraph = (): CipherGraph => {
  const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
  });
  return replicateHighFanoutSources(deriveAuxGraph(trace, serpent128Spec), 6);
};

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("GraphView — replica side-gutter inside vertical-stack groups", () => {
  it("places each round.N replica to the LEFT of its consumer (replica.x < consumer.x)", () => {
    const g = aes128ReplicatedGraph();
    const empty = new Map<string, { x: number; y: number }>();
    const { boxes } = layoutRoot(g, empty, layoutConstantsFor("normal"));

    // Sample a handful of rounds — the property holds for every round in
    // AES-128 because every round.N.add-round-key consumes a round key.
    for (const n of [1, 5, 10]) {
      const consumerId = `round.${n}.add-round-key`;
      const replicaId = `key-expansion@->${consumerId}`;
      const consumerBox = boxes.get(consumerId);
      const replicaBox = boxes.get(replicaId);
      if (!consumerBox || !replicaBox) {
        throw new Error(
          `missing box for round.${n}: consumer=${!!consumerBox} replica=${!!replicaBox}`,
        );
      }
      // The whole point: replica sits to the left of the consumer, not
      // stacked in the same column above it.
      expect(replicaBox.x).toBeLessThan(consumerBox.x);
    }
  });

  it("vertically centers the replica against its consumer (replica.y ≈ consumer.y)", () => {
    const g = aes128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const consumerId = "round.5.add-round-key";
    const replicaId = `key-expansion@->${consumerId}`;
    const c = boxes.get(consumerId);
    const r = boxes.get(replicaId);
    if (!c || !r) throw new Error("missing box");
    // Center-y match (replica.h === consumer.h === LEAF_H, so the y
    // offsets are equal after centering). Allow 1px slack for rounding.
    const cMidY = c.y + c.h / 2;
    const rMidY = r.y + r.h / 2;
    expect(Math.abs(cMidY - rMidY)).toBeLessThanOrEqual(1);
  });

  it("widens the round group's bounding box to make room for the gutter", () => {
    const without = aes128Graph();
    const with_ = aes128ReplicatedGraph();
    const empty = new Map<string, { x: number; y: number }>();
    const consts = layoutConstantsFor("normal");
    const a = layoutRoot(without, empty, consts).boxes;
    const b = layoutRoot(with_, empty, consts).boxes;

    const r5_no = a.get("round.5");
    const r5_yes = b.get("round.5");
    if (!r5_no || !r5_yes) throw new Error("missing round.5 box");

    // The gutter adds approximately LEAF_W + FLOW_GAP to the group width.
    // Use a lower bound (≥ LEAF_W) so the test is robust against future
    // gutter-padding tweaks; just confirm the box widened MEANINGFULLY.
    expect(r5_yes.w).toBeGreaterThan(r5_no.w);
    expect(r5_yes.w - r5_no.w).toBeGreaterThanOrEqual(consts.LEAF_W);
  });

  it("the in-column children (sub-bytes / shift-rows / mix-columns / add-round-key) stay vertically aligned with each other", () => {
    // The pedagogical headline: state spine flows through one clean
    // column. After the gutter fix, the four non-replica children of
    // each round should share an x-coordinate (or share width and start)
    // — same column.
    const g = aes128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const ids = [
      "round.5.sub-bytes",
      "round.5.shift-rows",
      "round.5.mix-columns",
      "round.5.add-round-key",
    ];
    const xs = ids.map((id) => boxes.get(id)?.x);
    // All four x-coordinates are the same number (they share the column).
    expect(new Set(xs).size).toBe(1);
    // And the replica's x is strictly less than that shared column x.
    const replicaX = boxes.get("key-expansion@->round.5.add-round-key")?.x;
    expect(replicaX).toBeDefined();
    expect(replicaX).toBeLessThan(xs[0] ?? Number.POSITIVE_INFINITY);
  });

  it("a root-level replica sits ABOVE its consumer at root (orthogonal to the horizontal spine)", () => {
    // AES-128's `key-expansion → initial.add-round-key` state-spine arrow
    // runs along the root row. With the replica `key-expansion@->initial.
    // add-round-key` spliced between them in the horizontal flow, the
    // pre-fix layout placed all three at the same y — the spine arrow
    // passed THROUGH the replica box. The fix is to lift root-level
    // replicas to a row ABOVE their consumer (mirror of the LEFT gutter
    // inside vertical-stack groups).
    const g = aes128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const consumerBox = boxes.get("initial.add-round-key");
    const replicaBox = boxes.get("key-expansion@->initial.add-round-key");
    if (!consumerBox || !replicaBox) throw new Error("missing root box");
    // Replica is above the consumer (smaller y) and shares x (a clean
    // short vertical aux arrow).
    expect(replicaBox.y).toBeLessThan(consumerBox.y);
    expect(replicaBox.x).toBe(consumerBox.x);
    // The replica's y-range and the SOURCE's y-range (key-expansion) do
    // NOT overlap — that's what unblocks the state-spine arrow.
    const sourceBox = boxes.get("key-expansion");
    if (!sourceBox) throw new Error("missing key-expansion box");
    const replicaBottom = replicaBox.y + replicaBox.h;
    const sourceTop = sourceBox.y;
    const sourceBottom = sourceBox.y + sourceBox.h;
    // Either the replica is entirely above the source's y-range, or
    // entirely below it. (Today it's above; this assertion just pins
    // "no overlap" so the spine arrow's natural horizontal-regime path
    // never enters the replica box.)
    const noOverlap = replicaBottom <= sourceTop || replicaBox.y >= sourceBottom;
    expect(noOverlap).toBe(true);
  });

  it("when no replicas are present, root row stays at CANVAS_MARGIN (no spurious lift)", () => {
    const g = aes128Graph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    // CANVAS_MARGIN = 24 (module-internal constant); pin via the
    // observed top y of the leftmost root child instead of importing it.
    const keyExp = boxes.get("key-expansion");
    if (!keyExp) throw new Error("missing key-expansion");
    // Without replicas, the row should sit flush against the top margin
    // — no extra LEAF_H + STACK_GAP shift.
    expect(keyExp.y).toBe(24);
  });

  it("inside an iterate body (AES-128-ECB), replicas also lift above their consumer", () => {
    // Symmetric to the root-level test: the iterate body is also a
    // horizontal flow, so its spliced-before-consumer replicas need the
    // same orthogonal lift. AES-128-ECB's `key-expansion@->initial.add-
    // round-key` replica lands at iterate-body level (the consumer is
    // INSIDE the iterate, unlike single-block AES where it's at root).
    const g = aes128EcbReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const consumerBox = boxes.get("initial.add-round-key");
    const replicaBox = boxes.get("key-expansion@->initial.add-round-key");
    if (!consumerBox || !replicaBox) {
      throw new Error("missing iterate-body box (consumer or replica)");
    }
    expect(replicaBox.y).toBeLessThan(consumerBox.y);
    expect(replicaBox.x).toBe(consumerBox.x);
  });

  it("Serpent (consumer-is-first-child): replica is LIFTED above the column, not in LEFT gutter", () => {
    // Serpent's per-round order is add-round-key → sub-bytes → linear-transform,
    // so the consumer (add-round-key) is the FIRST non-replica child. A
    // LEFT-gutter replica at consumer.y would obscure the incoming
    // inter-round spine arrow. The dual-strategy fix places the replica
    // ABOVE the consumer at the column's x instead — directly visible as
    // the replica's x matching add-round-key's x, and y strictly less.
    const g = serpent128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    // Pick any Serpent round (they're all identically structured).
    const consumerId = "round.5.add-round-key";
    const replicaId = `key-expansion@->${consumerId}`;
    const consumerBox = boxes.get(consumerId);
    const replicaBox = boxes.get(replicaId);
    if (!consumerBox || !replicaBox) {
      throw new Error("missing Serpent box (consumer or replica)");
    }
    // Lift: replica sits above consumer at the SAME x (column).
    expect(replicaBox.x).toBe(consumerBox.x);
    expect(replicaBox.y).toBeLessThan(consumerBox.y);
    // And the replica is NOT in a left gutter — its x is the column x,
    // not less than the column x. (LEFT-gutter replicas would have
    // replicaBox.x < consumerBox.x; the lift branch avoids that.)
  });

  it("Serpent: the lifted replica's y-range does not overlap any in-column child", () => {
    // The whole point: the lifted replica must NOT sit at the same y as
    // any of add-round-key / sub-bytes / linear-transform, otherwise the
    // incoming inter-round arrow at add-round-key's y could still be
    // obscured.
    const g = serpent128ReplicatedGraph();
    const { boxes } = layoutRoot(
      g,
      new Map<string, { x: number; y: number }>(),
      layoutConstantsFor("normal"),
    );
    const replicaBox = boxes.get("key-expansion@->round.5.add-round-key");
    if (!replicaBox) throw new Error("missing replica");
    const replicaBottom = replicaBox.y + replicaBox.h;
    for (const child of [
      "round.5.add-round-key",
      "round.5.sub-bytes",
      "round.5.linear-transform",
    ]) {
      const cBox = boxes.get(child);
      if (!cBox) throw new Error(`missing ${child}`);
      const cTop = cBox.y;
      const cBottom = cBox.y + cBox.h;
      const noOverlap = replicaBottom <= cTop || replicaBox.y >= cBottom;
      expect(noOverlap).toBe(true);
    }
  });

  it("Serpent: round groups grow TALLER (not wider) because the lift, not the gutter, is active", () => {
    // AES exercises the gutter branch → group WIDENS. Serpent exercises
    // the lift branch → group HEIGHTENS. Pin both behaviors so a future
    // refactor that accidentally collapses the dual strategy fails fast.
    const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
    });
    const noRep = deriveAuxGraph(trace, serpent128Spec);
    const withRep = replicateHighFanoutSources(noRep, 6);
    const empty = new Map<string, { x: number; y: number }>();
    const consts = layoutConstantsFor("normal");
    const a = layoutRoot(noRep, empty, consts).boxes;
    const b = layoutRoot(withRep, empty, consts).boxes;
    const r5a = a.get("round.5");
    const r5b = b.get("round.5");
    if (!r5a || !r5b) throw new Error("missing round.5");
    // Width unchanged (no left gutter in Serpent's case).
    expect(r5b.w).toBe(r5a.w);
    // Height increased by LEAF_H + STACK_GAP exactly (the lift amount).
    expect(r5b.h - r5a.h).toBe(consts.LEAF_H + consts.STACK_GAP);
  });

  it("when no replicas are present, round groups keep their original (pre-gutter) width", () => {
    // Drive `layoutRoot` against the un-replicated graph — every round
    // should be sized as if the gutter logic didn't exist (the gutter
    // only opens when at least one replica child is present).
    const g = aes128Graph();
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(g, new Map<string, { x: number; y: number }>(), consts);
    const r5 = boxes.get("round.5");
    if (!r5) throw new Error("missing round.5 box");
    // Round groups in AES-128 stack 4 leaves; their natural width is
    // LEAF_W + 2*CONTAINER_PAD (the children dominate the formula). Pin
    // that exact value as a regression anchor — if the gutter
    // accidentally fires when no replicas exist, this fails.
    expect(r5.w).toBe(consts.LEAF_W + 2 * consts.CONTAINER_PAD);
  });
});
