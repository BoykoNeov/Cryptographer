/**
 * Canonical Twofish-round LAYOUT (`src/core/twofish-layout.ts`) — the pure
 * placement math behind the graph view's 4-rail Twofish cell.
 *
 * These pin the structural invariants the renderer relies on (NOT exact pixels,
 * which are free to tune): split on top, two g columns in the left band with the
 * `rolR1` rail atop g1, the PHT below the g stacks, the R2/R3 mix rails in the
 * right band, and recombine at the bottom.
 *
 * (There is deliberately NO inter-round swap-X test: Twofish rounds lay out
 * HORIZONTALLY, so a `recombine → next split` overlay would be a long diagonal
 * tangle rather than a readable X — dropped in favor of the plain carry edge +
 * the `recombine` narration. See `docs/plans/polished-imagining-bird.md`.)
 */

import { twofishSpec } from "@/ciphers/twofish";
import { findStepAndParent } from "@/core/spec-mutations";
import { twofishRoundPlacement } from "@/core/twofish-layout";
import { type TwofishRoundShape, analyzeTwofishRound } from "@/core/twofish-shape";
import type { StepGroup } from "@/core/types";
import { describe, expect, it } from "vitest";

const CONSTS = { leafW: 132, leafH: 28, isReplica: () => false, consumerOf: () => undefined };

const round0 = (): { shape: TwofishRoundShape; childIds: string[] } => {
  const located = findStepAndParent(twofishSpec, "round.0");
  if (!located || located.node.kind !== "group") throw new Error("no round.0 group");
  const group = located.node as StepGroup;
  const shape = analyzeTwofishRound(group);
  if (!shape) throw new Error("round.0 not recognized as Twofish");
  const childIds = group.children.filter((c) => c.kind === "step").map((c) => c.id);
  return { shape, childIds };
};

describe("twofishRoundPlacement — 4-rail structure", () => {
  const { shape, childIds } = round0();
  const place = twofishRoundPlacement(shape, childIds, CONSTS);
  const at = (id: string) => {
    const o = place.offsets.get(id);
    if (!o) throw new Error(`no offset for ${id}`);
    return o;
  };

  it("places every child", () => {
    for (const id of childIds) expect(place.offsets.has(id), id).toBe(true);
  });

  it("puts split at the top and recombine at the bottom", () => {
    const splitY = at(shape.splitId).dy;
    const recombineY = at(shape.recombineId).dy;
    const allYs = childIds.map((id) => at(id).dy);
    expect(splitY).toBe(Math.min(...allYs));
    expect(recombineY).toBe(Math.max(...allYs));
  });

  it("stacks each g function in its own column, g0 left of g1, both left of center", () => {
    const g0X = at(shape.g0Ids[0] as string).dx;
    const g1X = at(shape.g1Ids[0] as string).dx;
    const centerX = at(shape.splitId).dx;
    // Each g stack shares one x.
    for (const id of shape.g0Ids) expect(at(id).dx).toBe(g0X);
    for (const id of shape.g1Ids) expect(at(id).dx).toBe(g1X);
    expect(g0X).toBeLessThan(g1X);
    expect(g1X).toBeLessThan(centerX);
  });

  it("sits the rolR1 rail atop the g1 column (same x, above the g1 stack, below split)", () => {
    const rol = at(shape.rolNodeId);
    const g1Top = at(shape.g1Ids[0] as string);
    expect(rol.dx).toBe(g1Top.dx);
    expect(rol.dy).toBeLessThan(g1Top.dy);
    expect(rol.dy).toBeGreaterThan(at(shape.splitId).dy);
  });

  it("places the PHT below the g stacks (it consumes the g outputs)", () => {
    const gMaxY = Math.max(...[...shape.g0Ids, ...shape.g1Ids].map((id) => at(id).dy));
    for (const fId of shape.fIds) expect(at(fId).dy).toBeGreaterThan(gMaxY);
  });

  it("places the R2/R3 mix rails in the right band, below the PHT, feeding recombine", () => {
    const g1X = at(shape.g1Ids[0] as string).dx;
    const fMaxY = Math.max(...shape.fIds.map((id) => at(id).dy));
    for (const id of [...shape.r2MixIds, ...shape.r3MixIds]) {
      expect(at(id).dx, id).toBeGreaterThan(g1X); // right of the g band
      expect(at(id).dy, id).toBeGreaterThan(fMaxY); // below the PHT
    }
    // r2 and r3 are distinct columns.
    expect(at(shape.r2MixIds[0] as string).dx).not.toBe(at(shape.r3MixIds[0] as string).dx);
  });
});
