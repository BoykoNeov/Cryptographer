// @vitest-environment jsdom

/**
 * Part B mechanism wire-up tests for curated default layouts
 * (graph-legibility plan, `docs/plans/toasty-zooming-harp.md`).
 *
 * The PURE half (catalogue shape + `mergeLayoutSpecs`) is pinned by
 * `default-layouts.test.ts`. This file pins the REACTIVE wiring in
 * `GraphView` — the pieces most at risk of a silent break:
 *   1. a curated default reaches RENDER when the user has no layout;
 *   2. a user edit does NOT wipe the curated arrangement (the per-node MERGE
 *      the user chose over the plan's whole-object replace);
 *   3. the reset-button SPLIT appears only when a curated default exists, with
 *      the correct enabled/disabled logic;
 *   4. "reset to default" restores curation; "reset to automatic" suppresses it
 *      (session-only), each observable in the render.
 *
 * Observable signal: a collapsed container is rewritten to a leaf-sized CHIP by
 * `collapseGraph`, so it (and any containers nested inside it) drop out of
 * `.graph-container-rect`. AES-128 ECB ships with ZERO default-collapsed
 * containers (only SHA-256 returns any from `getDefaultCollapsedContainers`), so
 * the container-rect count falls sharply (empirically 11 → 2) when a curated
 * `collapsedGroups: ["ecb-blocks"]` folds the ECB iterate — with its 10 nested
 * round groups — into one chip. Comparisons are RELATIVE (curated < baseline,
 * survives edit, restored on reset) so the assertions don't hardcode the count.
 * A curated layout is injected via `__setCuratedDefaultsForTests` so the test
 * doesn't depend on the (empty in B1) shipped catalogue.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  __resetCuratedDefaultsForTests,
  __setCuratedDefaultsForTests,
} from "@/core/default-layouts";
import type { LayoutSpec } from "@/core/document";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, StepNode } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetCuratedLayoutSuppressForTests } from "@/ui/stores/curated-layout-suppress";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, getLayoutForSpec, setNodePosition } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests, setViewDensity } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { __resetSourceColorsForTests } from "@/ui/stores/view-source-colors";
import { __resetSourceStrokesForTests } from "@/ui/stores/view-source-strokes";
import { __resetValueInspectorForTests } from "@/ui/stores/view-value-inspector";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const ECB_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a";

const seedAes128Ecb = (): void => {
  setCipher("aes-128");
  setCipherMode("ecb");
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

/** Every container (group/iterate) id in the spec, DFS pre-order. */
const collectContainerIds = (nodes: readonly StepNode[]): string[] => {
  const out: string[] = [];
  for (const n of nodes) {
    if (n.kind === "group" || n.kind === "iterate") {
      out.push(n.id);
      out.push(...collectContainerIds(n.children));
    }
  }
  return out;
};

const AES_CONTAINER_IDS = collectContainerIds(aes128EcbSpec.steps);
/** The ECB `iterate` — collapsing it folds the whole per-block body (its 10
 *  round groups) into one chip, so the `.graph-container-rect` count drops
 *  sharply (empirically 11 → 2). That large, reliable gap is the render signal
 *  the tests key on; a leaf round group's collapse renders more subtly (its
 *  rect is block-suffixed inside the iterate). */
const COLLAPSE_TARGET = "ecb-blocks";

/** A curated LayoutSpec that collapses the ECB iterate. */
const curatedCollapsingIterate = (): LayoutSpec => ({
  positions: {},
  collapsedGroups: [COLLAPSE_TARGET],
  flowDirection: "ltr",
});

const rectCount = (root: ParentNode): number =>
  root.querySelectorAll(".graph-container-rect").length;

/** The rendered `x` of a container's body rect, found by its `<title>` (which
 *  reads `${kind}: ${id}`). Used to observe that a curated POSITION reaches the
 *  layout. Returns null if the container isn't rendered. */
const containerRectX = (root: ParentNode, id: string): number | null => {
  for (const g of Array.from(root.querySelectorAll("g.graph-container"))) {
    if (g.querySelector("title")?.textContent?.includes(id)) {
      const x = g.querySelector(".graph-container-rect")?.getAttribute("x");
      return x === null || x === undefined ? null : Number(x);
    }
  }
  return null;
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
  __resetSourceColorsForTests();
  __resetSourceStrokesForTests();
  __resetCuratedDefaultsForTests();
  __resetCuratedLayoutSuppressForTests();
};

describe("GraphView — curated default layout wire-up", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    resetAll();
  });

  it("sanity: AES-128 ECB has containers and the ECB iterate is one of them", () => {
    expect(AES_CONTAINER_IDS).toContain(COLLAPSE_TARGET);
    seedAes128Ecb();
    const { container } = render(() => <GraphView />);
    expect(rectCount(container)).toBeGreaterThan(0);
  });

  it("a curated default reaches RENDER: its collapse drops container rects, with no user layout", () => {
    // Baseline (no curated).
    seedAes128Ecb();
    const baseline = render(() => <GraphView />);
    const baseCount = rectCount(baseline.container);
    cleanup();

    // With a curated default collapsing the ECB iterate: far fewer rects.
    __setCuratedDefaultsForTests({ [aes128EcbSpec.id]: curatedCollapsingIterate() });
    const curated = render(() => <GraphView />);
    expect(rectCount(curated.container)).toBeLessThan(baseCount);
    // And it was NOT persisted — the curated default is a read-time fallback.
    expect(getLayoutForSpec(aes128EcbSpec.id)).toBeNull();
  });

  it("per-node MERGE: a user edit does not wipe the curated collapse", () => {
    // The behavior the user picked over the plan's whole-object replace. The
    // user pins a position (a layout with NO collapsedGroups); under a naive
    // `user ?? curated` replace this would re-expand the iterate and the rect
    // count would jump back up. Under the merge it stays collapsed.
    __setCuratedDefaultsForTests({ [aes128EcbSpec.id]: curatedCollapsingIterate() });
    seedAes128Ecb();
    const { container } = render(() => <GraphView />);
    const collapsedCount = rectCount(container);

    setNodePosition(aes128EcbSpec.id, "key-schedule", 500, 500);
    // Curated collapse still applied after the user edit (merge, not replace).
    expect(rectCount(container)).toBe(collapsedCount);
    expect(getLayoutForSpec(aes128EcbSpec.id)).not.toBeNull();
  });

  it("a curated POSITION reaches render: the container moves to the curated coordinate", () => {
    // Positions flow rawPinnedMap → pinnedMap → layout, so a curated position
    // must move the container's rendered rect. `ecb-blocks` is the top-level
    // iterate — the container that renders a directly-pinnable body rect.
    // (collapsedGroups is the other half of the mechanism, covered above; this
    // pins the position half.)
    seedAes128Ecb();
    const baseline = render(() => <GraphView />);
    const x0 = containerRectX(baseline.container, COLLAPSE_TARGET);
    expect(x0).not.toBeNull();
    cleanup();

    const shifted = (x0 as number) + 600;
    __setCuratedDefaultsForTests({
      [aes128EcbSpec.id]: {
        positions: { [COLLAPSE_TARGET]: { x: shifted, y: 40 } },
        collapsedGroups: [],
        flowDirection: "ltr",
      },
    });
    const curated = render(() => <GraphView />);
    const x1 = containerRectX(curated.container, COLLAPSE_TARGET);
    expect(x1).not.toBeNull();
    // Moved substantially right of its auto position (exact value depends on
    // layout offsets, so assert a large shift rather than the precise pixel).
    expect(x1 as number).toBeGreaterThan((x0 as number) + 100);
  });

  it("a user edit on a curated spec persists ONLY the edited key (curated never leaks into storage)", () => {
    // The byte-stability invariant: the drag write-back baseline is the raw user
    // layout, not the curated merge, so a position edit persists exactly one key
    // — the curated positions on OTHER containers never enter localStorage.
    __setCuratedDefaultsForTests({
      [aes128EcbSpec.id]: {
        positions: { "ecb-blocks": { x: 10, y: 10 }, "round.1": { x: 20, y: 20 } },
        collapsedGroups: [],
        flowDirection: "ltr",
      },
    });
    seedAes128Ecb();
    render(() => <GraphView />);

    // setNodePosition is exactly what the drag's move handler calls on commit.
    setNodePosition(aes128EcbSpec.id, "key-schedule", 123, 456);

    const persisted = getLayoutForSpec(aes128EcbSpec.id);
    expect(persisted).not.toBeNull();
    // Exactly the edited key — NOT the curated `ecb-blocks` / `round.1` pins.
    expect(Object.keys(persisted?.positions ?? {})).toEqual(["key-schedule"]);
  });

  it("reset SPLIT: single button without a curated default, two buttons with one", () => {
    // Baseline (empty catalogue): single "reset layout".
    seedAes128Ecb();
    const plain = render(() => <GraphView />);
    expect(plain.container.querySelector('[data-testid="graph-view-layout-reset"]')).not.toBeNull();
    expect(
      plain.container.querySelector('[data-testid="graph-view-layout-reset-default"]'),
    ).toBeNull();
    cleanup();

    // With a curated default: the split appears, single disappears.
    __setCuratedDefaultsForTests({ [aes128EcbSpec.id]: curatedCollapsingIterate() });
    const curated = render(() => <GraphView />);
    expect(curated.container.querySelector('[data-testid="graph-view-layout-reset"]')).toBeNull();
    expect(
      curated.container.querySelector('[data-testid="graph-view-layout-reset-default"]'),
    ).not.toBeNull();
    expect(
      curated.container.querySelector('[data-testid="graph-view-layout-reset-automatic"]'),
    ).not.toBeNull();
  });

  it("fresh curated spec: 'reset to default' disabled (nothing to restore), 'reset to automatic' enabled", () => {
    __setCuratedDefaultsForTests({ [aes128EcbSpec.id]: curatedCollapsingIterate() });
    seedAes128Ecb();
    const { container } = render(() => <GraphView />);

    const toDefault = container.querySelector<HTMLButtonElement>(
      '[data-testid="graph-view-layout-reset-default"]',
    );
    const toAuto = container.querySelector<HTMLButtonElement>(
      '[data-testid="graph-view-layout-reset-automatic"]',
    );
    expect(toDefault?.disabled).toBe(true);
    expect(toAuto?.disabled).toBe(false);
  });

  it("'reset to automatic' suppresses the curated default (collapse re-expands); flips the disabled states", () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    __setCuratedDefaultsForTests({ [aes128EcbSpec.id]: curatedCollapsingIterate() });
    seedAes128Ecb();
    const { container } = render(() => <GraphView />);
    const collapsedCount = rectCount(container);

    fireEvent.click(
      container.querySelector(
        '[data-testid="graph-view-layout-reset-automatic"]',
      ) as HTMLButtonElement,
    );

    // Curated default suppressed for this session → auto-layout → the collapsed
    // container re-expands → more container rects than the curated view.
    expect(rectCount(container)).toBeGreaterThan(collapsedCount);
    // Now "to automatic" is the current state (disabled); "to default" restores.
    expect(
      container.querySelector<HTMLButtonElement>(
        '[data-testid="graph-view-layout-reset-automatic"]',
      )?.disabled,
    ).toBe(true);
    expect(
      container.querySelector<HTMLButtonElement>('[data-testid="graph-view-layout-reset-default"]')
        ?.disabled,
    ).toBe(false);
  });

  it("a curated POSITION rescales with density: compact renders it toward 0.75×", () => {
    // Curated layouts are authored at `normal` and never enter `layoutMap`, so
    // `rescaleAllPositions` (the density-flip rescale) never touches them —
    // `effectiveLayout()` rescales the curated layer at read time instead. A big
    // curated pin dominates the layout offset, so the compact rect x lands near
    // 0.75× the normal one. Without the read-time rescale it would stay ~equal
    // (the exact bug this chunk fixes).
    const curatedFarRight = (): LayoutSpec => ({
      positions: { [COLLAPSE_TARGET]: { x: 2000, y: 40 } },
      collapsedGroups: [],
      flowDirection: "ltr",
    });
    __setCuratedDefaultsForTests({ [aes128EcbSpec.id]: curatedFarRight() });
    seedAes128Ecb();
    const normal = render(() => <GraphView />);
    const xNormal = containerRectX(normal.container, COLLAPSE_TARGET);
    expect(xNormal).not.toBeNull();
    cleanup();

    setViewDensity("compact");
    const compact = render(() => <GraphView />);
    const xCompact = containerRectX(compact.container, COLLAPSE_TARGET);
    expect(xCompact).not.toBeNull();

    const ratio = (xCompact as number) / (xNormal as number);
    // Brackets 0.75 (DENSITY_SCALE.compact) with slack for the scaled layout
    // offset; would sit ~1.0 if the rescale were missing.
    expect(ratio).toBeGreaterThan(0.65);
    expect(ratio).toBeLessThan(0.82);
  });

  it("a user pin is NOT rescaled at compact (only the curated layer is — no double-scale)", () => {
    // User pins already live in `layoutMap` at the current density (rescaled on
    // every flip by `rescaleAllPositions`). `scaleCuratedLayout` runs on the
    // curated layer ALONE, before the merge, so a 2000 user pin at compact
    // renders near 2000 (+ a small offset), NOT the ~1500 it would show if the
    // merged result were scaled.
    seedAes128Ecb();
    setViewDensity("compact");
    setNodePosition(aes128EcbSpec.id, COLLAPSE_TARGET, 2000, 40);
    const { container } = render(() => <GraphView />);
    const x = containerRectX(container, COLLAPSE_TARGET);
    expect(x).not.toBeNull();
    // Well above the 0.75× double-scaled value (~1500).
    expect(x as number).toBeGreaterThan(1800);
  });

  it("'reset to default' restores the curated collapse after switching to automatic", () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    __setCuratedDefaultsForTests({ [aes128EcbSpec.id]: curatedCollapsingIterate() });
    seedAes128Ecb();
    const { container } = render(() => <GraphView />);
    const curatedCount = rectCount(container);

    // Go to automatic (suppress) — the iterate re-expands, so more rects.
    fireEvent.click(
      container.querySelector(
        '[data-testid="graph-view-layout-reset-automatic"]',
      ) as HTMLButtonElement,
    );
    expect(rectCount(container)).toBeGreaterThan(curatedCount);

    // Back to default (un-suppress) — the curated collapse returns.
    fireEvent.click(
      container.querySelector(
        '[data-testid="graph-view-layout-reset-default"]',
      ) as HTMLButtonElement,
    );
    expect(rectCount(container)).toBe(curatedCount);
    // Never persisted through either reset (byte-stable).
    expect(getLayoutForSpec(aes128EcbSpec.id)).toBeNull();
  });
});
