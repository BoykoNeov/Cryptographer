// @vitest-environment jsdom
/**
 * Unit guard for `portArrivalPoint` — the geometry that places each input-port
 * wiring dot where its incoming arrow actually lands (2026-07-12). Reported bug:
 * the dots were pinned to the box's LEFT edge regardless of where the arrow
 * arrived, which read wrong once the canonical Feistel/Twofish cells routed flow
 * top-to-bottom.
 *
 * This pins the box-edge attach point per regime. It MUST stay in lockstep with
 * `EdgePath`'s `geom()` target-attach math (same file) — if that changes, the
 * dots drift off their arrows and these assertions catch it.
 */

import { portArrivalPoint } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

type Box = { x: number; y: number; w: number; h: number };
const NO_OFFSET = { targetXOffset: 0, targetYOffset: 0 };

describe("portArrivalPoint — box-edge attach per regime", () => {
  it("horizontal regime, source to the LEFT → arrives on the consumer's LEFT edge at vertical centre", () => {
    const from: Box = { x: 0, y: 100, w: 40, h: 40 };
    const to: Box = { x: 200, y: 100, w: 40, h: 40 }; // same row, to the right
    const p = portArrivalPoint(from, to, { isFeedback: false, ...NO_OFFSET });
    expect(p).toEqual({ x: 200, y: 120 }); // left edge (to.x), y = toCy
  });

  it("horizontal regime, source to the RIGHT → arrives on the consumer's RIGHT edge", () => {
    const from: Box = { x: 400, y: 100, w: 40, h: 40 };
    const to: Box = { x: 200, y: 100, w: 40, h: 40 }; // to the left of source
    const p = portArrivalPoint(from, to, { isFeedback: false, ...NO_OFFSET });
    expect(p).toEqual({ x: 240, y: 120 }); // right edge (to.x + to.w)
  });

  it("vertical regime, source ABOVE → arrives on the consumer's TOP edge (the canonical-cell case)", () => {
    // Boxes share x-range, no y-overlap → vertical regime, source above → downward.
    const from: Box = { x: 200, y: 0, w: 40, h: 40 };
    const to: Box = { x: 200, y: 200, w: 40, h: 40 };
    const p = portArrivalPoint(from, to, { isFeedback: false, ...NO_OFFSET });
    expect(p).toEqual({ x: 220, y: 200 }); // top edge (to.y), x = toCx — NOT the left edge
  });

  it("vertical regime, source BELOW → arrives on the consumer's BOTTOM edge", () => {
    const from: Box = { x: 200, y: 300, w: 40, h: 40 };
    const to: Box = { x: 200, y: 0, w: 40, h: 40 };
    const p = portArrivalPoint(from, to, { isFeedback: false, ...NO_OFFSET });
    expect(p).toEqual({ x: 220, y: 40 }); // bottom edge (to.y + to.h)
  });

  it("feedback edges always arrive on the TOP edge centre, regardless of source position", () => {
    const from: Box = { x: 400, y: 100, w: 40, h: 40 };
    const to: Box = { x: 200, y: 100, w: 40, h: 40 };
    const p = portArrivalPoint(from, to, { isFeedback: true, ...NO_OFFSET });
    expect(p).toEqual({ x: 220, y: 100 }); // top edge centre (toCx, to.y)
  });

  it("applies targetXOffset on the vertical regime (spread along the top edge), clamped inside the box", () => {
    const from: Box = { x: 200, y: 0, w: 40, h: 40 };
    const to: Box = { x: 200, y: 200, w: 40, h: 40 };
    // +8 shifts the dot right along the top edge; a huge value clamps to w/2 - 4 = 16.
    expect(
      portArrivalPoint(from, to, { isFeedback: false, targetXOffset: 8, targetYOffset: 0 }).x,
    ).toBe(228);
    expect(
      portArrivalPoint(from, to, { isFeedback: false, targetXOffset: 999, targetYOffset: 0 }).x,
    ).toBe(236);
  });

  it("applies targetYOffset on the horizontal regime (spread along the left edge), clamped inside the box", () => {
    const from: Box = { x: 0, y: 100, w: 40, h: 40 };
    const to: Box = { x: 200, y: 100, w: 40, h: 40 };
    expect(
      portArrivalPoint(from, to, { isFeedback: false, targetXOffset: 0, targetYOffset: 8 }).y,
    ).toBe(128);
    expect(
      portArrivalPoint(from, to, { isFeedback: false, targetXOffset: 0, targetYOffset: 999 }).y,
    ).toBe(136);
  });
});
