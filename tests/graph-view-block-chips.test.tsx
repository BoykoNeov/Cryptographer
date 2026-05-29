// @vitest-environment jsdom

/**
 * Slice 6 (graph-narrative-and-zoom plan) — block-chip component test.
 *
 * Pins the end-to-end render path: collapsing AES-128 ECB's `ecb-blocks`
 * iterate via the layout store should swap the single `×N` chip for N
 * synthetic block-chip leaves (`block 1`, `block 2`, …) on the canvas.
 * Cap math is unit-tested in `expand-collapsed-iterates.test.ts`; this
 * test confirms the renderer wires the transform output through the
 * `<For each={graph().nodes}>` leaf-rendering path.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests, toggleCollapse, useLayoutMap } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_ECB_KEY = "000102030405060708090a0b0c0d0e0f";
// 4-block plaintext (NIST SP 800-38A §F.1.1) → 4 ECB iterations.
const ECB_PT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const seedAes128EcbTrace = (): void => {
  setCipherMode("ecb");
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PT_4_BLOCKS)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_ECB_KEY)]]),
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
    portedDispatchEnabled: true,
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

beforeEach(() => {
  resetAll();
});

afterEach(() => {
  cleanup();
});

describe("GraphView — collapsed iterate becomes parallel block-chips", () => {
  it("renders one chip per block (4 blocks) when ecb-blocks is collapsed", () => {
    seedAes128EcbTrace();
    // Collapse the iterate via the same store API the chevron click uses.
    toggleCollapse(aes128EcbSpec.id, "ecb-blocks", false);

    const { container } = render(() => <GraphView />);

    // Pre-collapse there'd be one container chip (`ecb-blocks`); after
    // Slice 6's expansion + Option C, the iterate KEEPS its header band
    // (with the chevron) and its body becomes the chip row — 4 leaf
    // rectangles labelled `block 1` … `block 4`. Those leaves render via
    // the standard `LeafRect` path, so they appear as
    // `<text class="graph-leaf-label">` children of `.graph-leaf` groups
    // (with the replica-class for the no-tabindex / no-delete styling).
    const labels = Array.from(container.querySelectorAll("text.graph-leaf-label")).map(
      (el) => el.textContent ?? "",
    );
    for (const expected of ["block 1", "block 2", "block 3", "block 4"]) {
      expect(labels).toContain(expected);
    }
    // No ellipsis chip at N=4.
    expect(labels.find((l) => l.includes("more blocks"))).toBeUndefined();
  });

  it("does not expand a non-collapsed iterate (chips appear ONLY when collapsed)", () => {
    seedAes128EcbTrace();
    // Don't collapse — render as-is.
    const { container } = render(() => <GraphView />);

    const labels = Array.from(container.querySelectorAll("text.graph-leaf-label")).map(
      (el) => el.textContent ?? "",
    );
    // No block-chip labels when the iterate is expanded.
    expect(labels.find((l) => /^block \d+$/.test(l))).toBeUndefined();
  });

  // Regression — without retaining the iterate container, there'd be no
  // chevron to click for re-expand after a post-Run collapse. Option C's
  // explicit promise is that the iterate header + chevron remain
  // rendered and clicking the chevron removes the iterate from
  // `collapsedGroups`.
  it("keeps the iterate's chevron clickable after a post-Run collapse", () => {
    seedAes128EcbTrace();
    toggleCollapse(aes128EcbSpec.id, "ecb-blocks", false);

    const { container } = render(() => <GraphView />);
    const chevron = container.querySelector('[data-testid="graph-container-chevron-ecb-blocks"]');
    expect(chevron).not.toBeNull();

    // Sanity: the iterate is in the collapsed set before the click.
    expect(useLayoutMap()()[aes128EcbSpec.id]?.collapsedGroups.includes("ecb-blocks")).toBe(true);

    (chevron as SVGGElement).dispatchEvent(new MouseEvent("click", { bubbles: true }));

    // After un-collapsing the only customization, the layout entry is
    // dropped from the map entirely (Slice 2.6d follow-up brought
    // `toggleCollapse` into line with `clearNodePosition` /
    // `clearRelativePosition` / `setReplicationMode(null)` — all of
    // which drop empty layouts to keep `cryptographer.layouts` byte-
    // stable). So the assertion is "the id is no longer in the
    // effective collapsed set," not "the field still exists but is
    // empty." Either map entry absence or absence-from-the-field
    // satisfies this.
    const collapsedAfter = useLayoutMap()()[aes128EcbSpec.id]?.collapsedGroups ?? [];
    expect(collapsedAfter.includes("ecb-blocks")).toBe(false);
  });

  it("keeps the iterate's header label visible while collapsed (box-with-header)", () => {
    seedAes128EcbTrace();
    toggleCollapse(aes128EcbSpec.id, "ecb-blocks", false);

    const { container } = render(() => <GraphView />);
    const headerLabels = Array.from(container.querySelectorAll("text.graph-container-label")).map(
      (el) => el.textContent ?? "",
    );
    // The iterate's label is the spec's `label` field for `ecb-blocks`
    // ("ECB blocks (per-block AES)"). Asserting on a substring keeps the
    // test resilient to label-copy edits.
    expect(headerLabels.some((l) => l.toLowerCase().includes("ecb"))).toBe(true);
  });
});
