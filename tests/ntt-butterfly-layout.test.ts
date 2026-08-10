/**
 * **NTT butterfly placement** — `core/ntt-layout.ts`.
 *
 * The layout module is pure and knows nothing about the renderer, so what it
 * can be held to is geometry: which slot each role occupies, that no two leaves
 * overlap, and the two invariants the header says were chosen by measuring
 * rendered wires rather than by taste. Those two are the ones worth pinning,
 * because they are the ones a future tidy-up would undo:
 *
 *   - the modulus sits horizontally BETWEEN the two rails, on their row;
 *   - `advance` is the rightmost node in the cell, and `zeta` shares a column
 *     with the high rail.
 *
 * What this file explicitly does NOT claim is that the rendered wires avoid
 * every box — no unit test can see that, since the layout is never told what
 * the edge router did. That was measured in a browser (the numbers are in the
 * module header) and `feedback_visual_smoke_vs_property_tests` is why it had to
 * be. These assertions protect the geometry the measurement depended on.
 */

import { buildInverseNttSpec, buildNttSpec } from "@/ciphers/ntt-3329-256";
import { nttButterflyPlacement } from "@/core/ntt-layout";
import { type NttButterflyShape, nttButterfliesById } from "@/core/ntt-shape";
import { describe, expect, it } from "vitest";

const OPTS = { leafW: 132, leafH: 28 } as const;

const firstShape = (forward: boolean): NttButterflyShape => {
  const spec = forward ? buildNttSpec() : buildInverseNttSpec();
  const shape = [...nttButterfliesById(spec).values()][0];
  if (!shape) throw new Error("no butterfly recognized — the shape test should have caught this");
  return shape;
};

/** Placement keyed by ROLE rather than node id, which is what reads well here. */
const byRole = (shape: NttButterflyShape) => {
  const placement = nttButterflyPlacement(shape, [...shape.memberIds], OPTS);
  const out = new Map<string, { dx: number; dy: number }>();
  for (const op of shape.ops) {
    const off = placement.offsets.get(op.nodeId);
    if (off) out.set(op.role, off);
  }
  return { placement, out };
};

describe.each([
  ["forward (Cooley–Tukey)", true],
  ["inverse (Gentleman–Sande)", false],
])("NTT butterfly placement — %s", (_name, forward) => {
  const shape = firstShape(forward);
  const { placement, out } = byRole(shape);
  const at = (role: string) => {
    const o = out.get(role);
    if (!o) throw new Error(`role ${role} was not placed`);
    return o;
  };
  /** The role occupying the mid slot: the twiddle multiply, or the difference. */
  const midRole = forward ? "twist" : "diff";

  it("places every member exactly once, with no two boxes overlapping", () => {
    expect(placement.offsets.size).toBe(shape.memberIds.length);
    const seen = new Set<string>();
    for (const o of placement.offsets.values()) {
      const key = `${o.dx},${o.dy}`;
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
  });

  it("the modulus sits BETWEEN the two rails, on their row", () => {
    // The measured invariant. Move `q` outside the rails and its wire to the
    // far one settles onto that rail's y while still inside the near rail's
    // box, which reads on screen as "hi feeds lo".
    const lo = at("lo");
    const hi = at("hi");
    const q = at("modulus");
    expect(q.dy).toBe(lo.dy);
    expect(q.dy).toBe(hi.dy);
    expect(lo.dx).toBeLessThan(q.dx);
    expect(q.dx).toBeLessThan(hi.dx);
    // And they are ADJACENT columns — nothing could be slotted between them.
    expect(q.dx - lo.dx).toBe(hi.dx - q.dx);
  });

  it("the ζ pair has its own row above everything, with `advance` rightmost", () => {
    const zeta = at("zeta");
    const advance = at("advance");
    expect(zeta.dy).toBe(0);
    expect(advance.dy).toBe(0);
    expect(advance.dx).toBeGreaterThan(zeta.dx);
    for (const [role, o] of out) {
      if (role === "zeta" || role === "advance") continue;
      // Nothing else shares the ζ row...
      expect(o.dy).toBeGreaterThan(0);
      // ...and nothing reaches further right than the rotation, so the hop to
      // the next layer leaves the cell instead of crossing back over it.
      expect(o.dx).toBeLessThanOrEqual(advance.dx);
    }
  });

  it("`zeta` sits directly above the high rail — where its consumer is", () => {
    // The twiddle multiply is the mid slot going forward and the high rail
    // coming back. Sharing the high rail's column keeps the inverse's wire off
    // the split, and the forward's is a short hop one column left.
    expect(at("zeta").dx).toBe(at("hi").dx);
  });

  it("stacks the coefficients' path down the centre: split → mid → recombine", () => {
    const split = at("split");
    const mid = at(midRole);
    const rec = at("recombine");
    expect(split.dx).toBe(mid.dx);
    expect(mid.dx).toBe(rec.dx);
    expect(split.dx).toBe(at("modulus").dx);
    expect(split.dy).toBeLessThan(mid.dy);
    expect(mid.dy).toBeLessThan(at("lo").dy);
    expect(at("lo").dy).toBeLessThan(rec.dy);
  });

  it("reports a body big enough to contain every box it placed", () => {
    for (const o of placement.offsets.values()) {
      expect(o.dx + OPTS.leafW).toBeLessThanOrEqual(placement.bodyW);
      expect(o.dy + OPTS.leafH).toBeLessThanOrEqual(placement.bodyH);
    }
  });

  it("parks an unclassified child rather than dropping it", () => {
    // Unreachable through the analyzer (its partition gate refuses a body with
    // a stray), but the placement stays total so a child can never vanish.
    const withStray = nttButterflyPlacement(shape, [...shape.memberIds, "stray"], OPTS);
    const stray = withStray.offsets.get("stray");
    expect(stray).toBeDefined();
    expect(stray?.dx).toBeGreaterThan(0);
    expect(withStray.bodyW).toBeGreaterThanOrEqual((stray?.dx ?? 0) + OPTS.leafW);
  });
});

describe("NTT butterfly placement — one grid for both butterflies", () => {
  it("puts the forward and inverse cells in byte-identical positions", () => {
    // `analyzeNttButterfly` resolves the direction into ROLES, so the layout
    // needs no `kind` branch: the mid slot holds the twiddle multiply going one
    // way and the difference going the other, and the high rail holds the
    // other one. If this ever diverges, the slot table has grown a direction
    // dependence that the header says it does not have.
    const geometry = (forward: boolean): string => {
      const shape = firstShape(forward);
      const { out } = byRole(shape);
      const mid = out.get(forward ? "twist" : "diff");
      return [...out.entries()]
        .filter(([role]) => role !== "twist" && role !== "diff")
        .map(([role, o]) => `${role}:${o.dx},${o.dy}`)
        .sort()
        .concat(`mid:${mid?.dx},${mid?.dy}`)
        .join("|");
    };
    expect(geometry(true)).toBe(geometry(false));
  });
});
