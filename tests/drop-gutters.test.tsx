// @vitest-environment jsdom

/**
 * Slice 5 (graph-narrative-and-zoom plan) — drop-gutter tests.
 *
 * Two layers, mirroring the Slice 8 palette tests:
 *   1. Spec-store mutator — does `insertStepIntoSpec(stepType, { kind:
 *      "before", stepId })` produce a spec with the new leaf inserted
 *      immediately before the anchor?
 *   2. GraphView render + drop pipeline — do gutter `<rect>`s appear
 *      under each non-collapsed container, do they carry the right
 *      `data-drop-gutter` encoding, and does dispatching a drop event
 *      on each flavor (at-start, between, at-end) route through the
 *      matching `insertStepBefore` / `insertStepAfter` branch?
 *
 * Real HTML5 drag-and-drop is out of scope (same rationale as
 * `step-palette.test.tsx` — jsdom's DataTransfer support is partial).
 * We feed the drop handler synthetic Events with mock DataTransfers
 * and assert against the resulting spec store state.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { findStep, findStepAndParent } from "@/core/spec-mutations";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { STEP_TYPE_DRAG_MIME } from "@/ui/components/StepPalette";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, insertStepIntoSpec, setCipherMode, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";
// AES-128-ECB test vector — same key, two 16-byte blocks so the iterate
// body actually runs (with N>1 the gutter geometry covers the multi-
// iteration case too).
const AES128_ECB_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_ECB_PT = "00112233445566778899aabbccddeeff112233445566778899aabbccddeeff00";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
  // Byte-native AES-128 (Slice B1) auto-ON's replication for ported specs,
  // which adds a key-expansion replica side-gutter and widens the round box.
  // Default this file to replication OFF so the body-tiling geometry measures
  // the bare body; the "skips replica chips" test re-enables it explicitly.
  setReplicationEnabled(false);
};

/**
 * Seed an AES-128-ECB trace AND flip the spec store to the ECB spec so
 * GraphView renders the iterate. ECB is the only shipped cipher with
 * an `iterate` node today (CBC is queued for Phase 2), so it's the
 * unique vehicle for exercising the iterate-branch of the gutter
 * geometry.
 */
const seedAes128EcbTrace = (): void => {
  setCipherMode("ecb");
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_ECB_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_ECB_KEY)]]),
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetHistoryForTests();
  __resetLayoutsForTests();
  __resetPaddingForTests();
  __resetReplicationForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetViewModeForTests();
};

/** DataTransfer shim — same shape as `step-palette.test.tsx`. */
const mockDataTransfer = (payload: { readonly [mime: string]: string }) => ({
  getData: (mime: string) => payload[mime] ?? "",
  types: Object.keys(payload),
  setData: (_mime: string, _value: string) => {},
  effectAllowed: "" as DataTransfer["effectAllowed"],
  dropEffect: "" as DataTransfer["dropEffect"],
});

const fireDropAt = (target: Element, stepType: string): void => {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: mockDataTransfer({
      [STEP_TYPE_DRAG_MIME]: stepType,
      "text/plain": stepType,
    }),
  });
  target.dispatchEvent(event);
};

// ─── insertStepIntoSpec — before-anchor branch ─────────────────────────────

describe("insertStepIntoSpec — `before` anchor", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("inserts a new leaf immediately before the named anchor leaf", () => {
    const spec = useSpec();
    // AES-128 spec has `initial.add-round-key` as the first top-level LEAF
    // (it follows the `key-schedule` group at index 0 since K1c). Insert
    // before it.
    insertStepIntoSpec("byte-substitute@1", {
      kind: "before",
      stepId: "initial.add-round-key",
    });
    const after = spec();
    const located = findStepAndParent(after, "byte-substitute-1");
    expect(located, "new leaf must be findable").not.toBeNull();
    expect(located?.parent, "new leaf's parent must be the root").toBeNull();
    // Sibling-order assertion: inserted directly before the anchor.
    const anchorLoc = findStepAndParent(after, "initial.add-round-key");
    expect(anchorLoc).not.toBeNull();
    expect(located?.indexInParent).toBe((anchorLoc?.indexInParent ?? 99) - 1);
  });

  it("inserts before a leaf nested inside a group (drop-into-first-position)", () => {
    // round.1's first body leaf is `round.1.sub-bytes`. Inserting before it
    // is the canonical "drop at start of round.1's body" case that was
    // impossible pre-Slice 5 (there was no drop anchor for that position).
    insertStepIntoSpec("byte-substitute@1", {
      kind: "before",
      stepId: "round.1.sub-bytes",
    });
    const located = findStepAndParent(useSpec()(), "byte-substitute-1");
    expect(located).not.toBeNull();
    expect(located?.parent?.id, "must land inside round.1, not at root").toBe("round.1");
    expect(located?.indexInParent, "must be the first child of round.1").toBe(0);
  });

  it("returns the generated id so the caller can route trace focus", () => {
    const newId = insertStepIntoSpec("byte-substitute@1", {
      kind: "before",
      stepId: "initial.add-round-key",
    });
    expect(newId).toBe("byte-substitute-1");
    expect(findStep(useSpec()(), "byte-substitute-1")).not.toBeNull();
  });
});

// ─── GraphView — gutter render ─────────────────────────────────────────────

describe("GraphView — drop-gutter render", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("emits at-start / between / at-end gutters for each non-collapsed group", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // round.1 has children [sub-bytes, shift-rows, mix-columns, add-round-key].
    // Expect 5 gutters: at-start, 3 between, at-end.
    const expectedEncodings = [
      "before:round.1.sub-bytes",
      "before:round.1.shift-rows",
      "before:round.1.mix-columns",
      "before:round.1.add-round-key",
      "after:round.1.add-round-key",
    ];
    for (const enc of expectedEncodings) {
      const rect = container.querySelector(`[data-drop-gutter="${enc}"]`);
      expect(rect, `expected gutter with encoding ${enc}`).not.toBeNull();
    }
  });

  it("renders gutters AFTER leaves and containers in the SVG so they win hit-testing", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const svg = container.querySelector("svg");
    if (!svg) throw new Error("graph SVG missing");
    // Collect the IMMEDIATE children of `<svg>` (which is where the
    // top-level `<For>` groups land — containers first, then edges, then
    // leaves, then gutters). The gutter rects render inline (no wrapping
    // `<g>`), so verify the LAST `<rect>` with the gutter class is
    // positioned after the last leaf `<g class="graph-leaf">`.
    const allElements = Array.from(svg.querySelectorAll("*"));
    const lastLeafIdx = allElements.reduce(
      (acc, el, i) => (el.classList.contains("graph-leaf") ? i : acc),
      -1,
    );
    const firstGutterIdx = allElements.findIndex((el) =>
      el.classList.contains("graph-drop-gutter"),
    );
    expect(lastLeafIdx, "should find at least one leaf").toBeGreaterThanOrEqual(0);
    expect(firstGutterIdx, "should find at least one gutter").toBeGreaterThanOrEqual(0);
    expect(firstGutterIdx).toBeGreaterThan(lastLeafIdx);
  });

  it("at-start / at-end group strips use CONTAINER_PAD (not STACK_GAP) so cursors don't fall through to container's outer drop-anchor", () => {
    // Regression test for a real-user-reported bug: dropping a palette
    // step into the "top of a round group" area routed to
    // `insertStepAfter(round.N)` in the parent (instead of insert-at-
    // start-of-body), because the gutter strip was only STACK_GAP tall
    // (6px at default density) — too thin to reliably hit. Cursors
    // landed in the container's CONTAINER_PAD padding ABOVE the strip,
    // resolved via `closest("[data-drop-anchor]")` to the container's
    // outer `<g>` (= insert-after-container-in-parent). Aux-shape steps
    // then landed at root and got auxOnlyRoot-lifted, severing the
    // state spine. Fix: boundary strips use CONTAINER_PAD as their
    // thickness, covering the full padded area between header / first-
    // child (top) and last-child / footer (bottom).
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const atStart = container.querySelector<SVGRectElement>(
      '[data-drop-gutter="before:round.1.sub-bytes"]',
    );
    const atEnd = container.querySelector<SVGRectElement>(
      '[data-drop-gutter="after:round.1.add-round-key"]',
    );
    expect(atStart, "at-start group gutter must render").not.toBeNull();
    expect(atEnd, "at-end group gutter must render").not.toBeNull();
    if (!atStart || !atEnd) return;
    // CONTAINER_PAD = 10 at the default `normal` density. Strip height
    // should be at least CONTAINER_PAD so the user's natural drop
    // target area is fully covered.
    expect(Number(atStart.getAttribute("height"))).toBeGreaterThanOrEqual(10);
    expect(Number(atEnd.getAttribute("height"))).toBeGreaterThanOrEqual(10);
  });

  it("body-tiling invariant — group gutters' X span covers the container's full inner body width", () => {
    // Invariant: a drop inside a container's body must never escape
    // to the parent scope via the container's outer `data-drop-anchor`.
    // For groups (vertical-flow), that means every gutter strip's X
    // span must cover the full body inner width — `cBox.x +
    // CONTAINER_PAD` to `cBox.x + cBox.w - CONTAINER_PAD`. Anything
    // less leaves a slice of body whitespace where the container's
    // outer anchor wins on hit-test.
    //
    // This pins the future-proofing decision the advisor surfaced
    // 2026-05-15: when a new cipher with an unknown body shape lands,
    // the "tile the body" invariant survives — the geometry adapts.
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // The container's `data-drop-anchor` lives on the header `<rect>`
    // post-rescope (2026-05-15), not on the outer `<g>`. Walk up from
    // the header to find the container `<g>`, then read the backing
    // outer rect for its box.
    const headerEl = container.querySelector<SVGRectElement>(
      'rect.graph-container-header[data-drop-anchor="round.1"]',
    );
    expect(headerEl, "round.1 container header must render").not.toBeNull();
    if (!headerEl) return;
    const containerEl = headerEl.closest<SVGGElement>("g.graph-container");
    expect(containerEl, "round.1 container `<g>` must wrap the header").not.toBeNull();
    if (!containerEl) return;
    const round1Strips = container.querySelectorAll<SVGRectElement>(
      '[data-drop-gutter^="before:round.1."], [data-drop-gutter^="after:round.1."]',
    );
    // round.1 has 4 children (AddRoundKey merged in F3): at-start + 3 between
    // + at-end = 5 strips.
    expect(round1Strips.length, "at-start + 3 between + at-end = 5 strips").toBe(5);
    // Read the container's box from the backing outer `<rect>` (class
    // `graph-container-rect`). `querySelector("rect")` returns the
    // FIRST rect descendant which is the outer container rect.
    const containerRect = containerEl.querySelector("rect.graph-container-rect");
    if (!containerRect) throw new Error("container backing rect missing");
    const cx = Number(containerRect.getAttribute("x"));
    const cw = Number(containerRect.getAttribute("width"));
    // CONTAINER_PAD = 10. Every strip must span from cx+10 to
    // cx+cw-10. The expected width is cw - 2*10.
    const expectedW = cw - 2 * 10;
    for (const s of round1Strips) {
      expect(Number(s.getAttribute("x"))).toBe(cx + 10);
      expect(Number(s.getAttribute("width"))).toBe(expectedW);
    }
  });

  it("body-tiling invariant — iterate gutters' Y span covers the container's full inner body height", () => {
    // Same invariant as the group case, rotated 90° for iterates
    // (horizontal flow). Strips must span the container's full
    // body inner height so cursors can't fall through the padding
    // above or below the children's row to the container's outer
    // anchor.
    //
    // The semantic check (rather than pixel-precise math): every
    // strip's Y range must START at or above the first body child's
    // Y, and END at or below the container's bottom inner edge
    // (`cy + ch - CONTAINER_PAD`). That's the surface the user's
    // cursor reaches when they aim at the iterate body — if the strip
    // doesn't reach all of it, there's a hole the container's outer
    // anchor can win on. Pixel-precise math depends on density
    // constants, root-level lift, and per-iterate lift, which a unit
    // test shouldn't redo from first principles.
    seedAes128EcbTrace();
    const { container } = render(() => <GraphView />);
    const headerEl = container.querySelector<SVGRectElement>(
      'rect.graph-container-header[data-drop-anchor="ecb-blocks"]',
    );
    expect(headerEl, "ecb-blocks iterate header must render").not.toBeNull();
    if (!headerEl) return;
    const containerEl = headerEl.closest<SVGGElement>("g.graph-container");
    expect(containerEl).not.toBeNull();
    if (!containerEl) return;
    const containerRect = containerEl.querySelector("rect.graph-container-rect");
    if (!containerRect) throw new Error("iterate container backing rect missing");
    const cy = Number(containerRect.getAttribute("y"));
    const ch = Number(containerRect.getAttribute("height"));
    // Filter to gutters that target the iterate's DIRECT body children
    // only. Nested round groups (round.N) have their OWN internal
    // gutters (e.g. `before:round.N.sub-bytes`) which we don't want
    // here — those test the round group's tiling, not the iterate's.
    // ECB encrypt body = [initial.add-round-key, round.1..round.10].
    const iterateChildIds = [
      "initial.add-round-key",
      ...Array.from({ length: 10 }, (_, i) => `round.${i + 1}`),
    ];
    const iterateStripEncodings = new Set<string>([
      ...iterateChildIds.map((id) => `before:${id}`),
      `after:${iterateChildIds[iterateChildIds.length - 1]}`,
    ]);
    const iterateStrips = Array.from(
      container.querySelectorAll<SVGRectElement>("[data-drop-gutter]"),
    ).filter((el) => iterateStripEncodings.has(el.getAttribute("data-drop-gutter") ?? ""));
    expect(
      iterateStrips.length,
      "every iterate body slot needs a strip (start + 10 between + end)",
    ).toBe(12);
    // Find the first body leaf's Y (= top of children row) by reading
    // its rendered rect. `initial.add-round-key` is the first body
    // step in the ECB encrypt iterate.
    const firstChildLeaf = container.querySelector<SVGRectElement>(
      'g.graph-leaf[data-drop-anchor="initial.add-round-key"] rect',
    );
    expect(firstChildLeaf, "first body leaf must render").not.toBeNull();
    if (!firstChildLeaf) return;
    const firstChildY = Number(firstChildLeaf.getAttribute("y"));
    // Every iterate strip must extend from at-or-above the first
    // child's Y (covers the children's row) down to at-or-below
    // `cy + ch - CONTAINER_PAD` (covers the body bottom padding).
    // If any strip's Y range doesn't reach the children's row, a
    // drop AT the child's Y in gap X would fall through to the
    // iterate's outer `data-drop-anchor` — the bug we're guarding
    // against.
    for (const s of iterateStrips) {
      const sy = Number(s.getAttribute("y"));
      const sh = Number(s.getAttribute("height"));
      expect(sy, "strip top must reach the first child's row (or above)").toBeLessThanOrEqual(
        firstChildY,
      );
      expect(
        sy + sh,
        "strip bottom must reach the body's inner bottom edge",
      ).toBeGreaterThanOrEqual(cy + ch - 10);
    }
  });

  it("skips replica chips inside childIds when building gutters", () => {
    // Byte-native AES-128 single-block has no iterate body, but each round
    // group's `xor-with-aux@1` AddRoundKey leaf pulls `roundKey.N` from the
    // high-fanout `key-expansion` source (the recorded auxRead). With replicas
    // the graph splices synthetic replica chips into childIds — gutters should
    // still be the spec-child count + 1 because the filter excludes replicas.
    seedAes128Trace();
    // This test specifically exercises the replica-skip path, so re-enable
    // replication (seedAes128Trace forced it off for the geometry tests).
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    // round.1's body has 4 spec children (sub-bytes, shift-rows, mix-columns,
    // add-round-key — merged in F3) → 3 between + start + end = 5 gutters; the
    // spliced key-expansion replica chip must NOT add a gutter.
    const round1Gutters = container.querySelectorAll(
      "[data-drop-gutter^='before:round.1.'], [data-drop-gutter^='after:round.1.']",
    );
    expect(round1Gutters.length).toBe(5);
  });
});

// ─── GraphView — drop routing ──────────────────────────────────────────────

describe("GraphView — drop on a gutter routes to insertStepBefore/After", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("drop on the at-start gutter of round.1 inserts at position 0 of round.1.children", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const gutter = container.querySelector('[data-drop-gutter="before:round.1.sub-bytes"]');
    expect(gutter, "at-start gutter must render").not.toBeNull();
    if (!gutter) return;
    fireDropAt(gutter, "byte-substitute@1");
    const located = findStepAndParent(useSpec()(), "byte-substitute-1");
    expect(located, "new leaf must exist").not.toBeNull();
    expect(located?.parent?.id, "must land inside round.1, not at root").toBe("round.1");
    expect(located?.indexInParent, "must be the first child of round.1").toBe(0);
  });

  it("drop on a between-siblings gutter inserts at that exact slot", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // The gutter between round.1.sub-bytes and round.1.shift-rows is
    // encoded as `before:round.1.shift-rows`.
    const gutter = container.querySelector('[data-drop-gutter="before:round.1.shift-rows"]');
    expect(gutter, "between-siblings gutter must render").not.toBeNull();
    if (!gutter) return;
    fireDropAt(gutter, "byte-substitute@1");
    const after = useSpec()();
    const located = findStepAndParent(after, "byte-substitute-1");
    expect(located?.parent?.id).toBe("round.1");
    const subBytesLoc = findStepAndParent(after, "round.1.sub-bytes");
    const shiftRowsLoc = findStepAndParent(after, "round.1.shift-rows");
    expect(located?.indexInParent).toBe((subBytesLoc?.indexInParent ?? -1) + 1);
    expect(located?.indexInParent).toBe((shiftRowsLoc?.indexInParent ?? -1) - 1);
  });

  it("drop on the at-end gutter of round.1 inserts after the last child of round.1", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // round.1's last child is `round.1.add-round-key`.
    const gutter = container.querySelector('[data-drop-gutter="after:round.1.add-round-key"]');
    expect(gutter, "at-end gutter must render").not.toBeNull();
    if (!gutter) return;
    fireDropAt(gutter, "byte-substitute@1");
    const after = useSpec()();
    const located = findStepAndParent(after, "byte-substitute-1");
    expect(located?.parent?.id, "must land inside round.1").toBe("round.1");
    const ark = findStepAndParent(after, "round.1.add-round-key");
    expect(located?.indexInParent).toBe((ark?.indexInParent ?? -1) + 1);
  });

  it("ignores a drop on a gutter when the payload is a non-registered step type", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const round1 = findStepAndParent(useSpec()(), "round.1");
    const beforeChildCount = round1?.node.kind === "group" ? round1.node.children.length : -1;
    const gutter = container.querySelector('[data-drop-gutter="before:round.1.sub-bytes"]');
    if (!gutter) throw new Error("test setup: at-start gutter missing");
    fireDropAt(gutter, "generic.nonexistent-type@99");
    const round1After = findStepAndParent(useSpec()(), "round.1");
    const afterChildCount =
      round1After?.node.kind === "group" ? round1After.node.children.length : -2;
    expect(afterChildCount).toBe(beforeChildCount);
  });
});

// ─── GraphView — iterate branch (AES-128-ECB) ──────────────────────────────

describe("GraphView — drop-gutter render inside an iterate", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("emits at-start / between / at-end gutters inside the ECB iterate body", () => {
    seedAes128EcbTrace();
    const { container } = render(() => <GraphView />);
    // The ECB iterate body starts with `initial.add-round-key` (a leaf)
    // and progresses through `round.1` ... `round.10` (groups). Verify
    // the iterate's three gutter flavors all render.
    const expectedEncodings = [
      "before:initial.add-round-key", // at-start
      "before:round.1", // between initial.add-round-key and round.1
      "before:round.2", // between round.1 and round.2
      "before:round.10", // between round.9 and round.10
      "after:round.10", // at-end
    ];
    for (const enc of expectedEncodings) {
      const rect = container.querySelector(`[data-drop-gutter="${enc}"]`);
      expect(rect, `expected iterate-body gutter with encoding ${enc}`).not.toBeNull();
    }
  });

  it("drop on the at-start gutter of the iterate inserts at position 0 of the iterate body", () => {
    seedAes128EcbTrace();
    const { container } = render(() => <GraphView />);
    // Byte-native ECB (B1.4; merged in F3): the iterate body's first child is
    // `initial.add-round-key` (the initial AddRoundKey), so the at-start gutter
    // is `before:initial.add-round-key`.
    const gutter = container.querySelector('[data-drop-gutter="before:initial.add-round-key"]');
    expect(gutter, "iterate at-start gutter must render").not.toBeNull();
    if (!gutter) return;
    fireDropAt(gutter, "byte-substitute@1");
    const located = findStepAndParent(useSpec()(), "byte-substitute-1");
    expect(located, "new leaf must exist").not.toBeNull();
    // The parent should be the iterate body, NOT the root. The iterate
    // node's id is `ecb-blocks`.
    expect(located?.parent?.id).toBe("ecb-blocks");
    expect(located?.indexInParent).toBe(0);
  });

  it("at-start / at-end iterate gutters clamp to CONTAINER_PAD so they don't bleed past container edges", () => {
    // FLOW_GAP (16) > CONTAINER_PAD (10) at default density. Without the
    // clamp the at-start strip would extend ~6px past the iterate's
    // left edge, giving a visible hit area outside the container the
    // gutter represents. The clamp keeps the boundary strips within
    // CONTAINER_PAD. (Between-siblings strips stay at FLOW_GAP — that's
    // the natural gap and doesn't overflow.)
    seedAes128EcbTrace();
    const { container } = render(() => <GraphView />);
    const startGutter = container.querySelector<SVGRectElement>(
      '[data-drop-gutter="before:initial.add-round-key"]',
    );
    const endGutter = container.querySelector<SVGRectElement>(
      '[data-drop-gutter="after:round.10"]',
    );
    expect(startGutter, "iterate at-start gutter must render").not.toBeNull();
    expect(endGutter, "iterate at-end gutter must render").not.toBeNull();
    if (!startGutter || !endGutter) return;
    // The width attribute should match the clamped value (CONTAINER_PAD
    // = 10 at default density), not the full FLOW_GAP.
    expect(Number(startGutter.getAttribute("width"))).toBeLessThanOrEqual(10);
    expect(Number(endGutter.getAttribute("width"))).toBeLessThanOrEqual(10);
  });
});
