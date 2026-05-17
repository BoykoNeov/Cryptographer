// @vitest-environment jsdom

/**
 * Component-level test for the bundle inspector — Slice C of the
 * arrow-bundling work (2026-05-17). Pins the new value-inspector
 * variant that triggers when the user clicks a bundled (N ≥ 2)
 * edge instead of a singleton.
 *
 * What we pin:
 *   - Clicking a bundle's hit path selects a `kind: "bundle"` target
 *     (NOT a per-edge target).
 *   - The inspector body renders the bundle's full auxKey list, one
 *     row per key, with `data-aux-key` for test selection.
 *   - The first auxKey is the active row by default (no `setActiveBundleAuxKey`
 *     called yet).
 *   - Clicking a row sets that aux as active — confirmed via the
 *     `-active` CSS modifier on the matching `<li>`.
 *   - The canvas halo STAYS on the bundle (advisor's recommended
 *     semantic): the `<path class="graph-edge-bundle">` keeps the
 *     `graph-edge-selected` class even after the user picks a row.
 *   - Re-clicking the same bundle clears the selection (toggle).
 *   - Spec swap clears the bundle selection (no stale identity).
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, setReplicationMode, toggleCollapse } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import {
  __resetValueInspectorForTests,
  setInspectorPanelOpen,
  useSelectedTarget,
} from "@/ui/stores/view-value-inspector";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const ECB_PLAINTEXT =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const seedAes128EcbCollapsedReplicated = (): void => {
  setCipher("aes-128");
  setCipherMode("ecb");
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
  toggleCollapse(aes128EcbSpec.id, "ecb-blocks");
  setReplicationEnabled(true);
  setReplicationMode(aes128EcbSpec.id, "key-expansion", "always");
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

const findBundleHit = (container: HTMLElement): SVGPathElement | null => {
  const hits = container.querySelectorAll<SVGPathElement>("path[data-edge-key]");
  for (const p of Array.from(hits)) {
    const key = p.getAttribute("data-edge-key") ?? "";
    if (key.startsWith("bundle:key-expansion@->ecb-blocks|ecb-blocks|aux|")) return p;
  }
  return null;
};

describe("GraphView — bundle inspector (Slice C)", () => {
  beforeEach(() => {
    resetAll();
    setInspectorPanelOpen(true);
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("clicking a bundled edge selects a `bundle` target (not a per-edge target)", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    const bundleHit = findBundleHit(container as HTMLElement);
    expect(bundleHit).not.toBeNull();
    fireEvent.click(bundleHit as SVGPathElement);

    const target = useSelectedTarget()();
    expect(target).not.toBeNull();
    expect(target?.kind).toBe("bundle");
    if (target?.kind === "bundle") {
      expect(target.key).toBe("bundle:key-expansion@->ecb-blocks|ecb-blocks|aux|0");
    }
  });

  it("renders the bundle's full auxKey list with the first row active by default", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    const bundleHit = findBundleHit(container as HTMLElement);
    fireEvent.click(bundleHit as SVGPathElement);

    const list = container.querySelector('[data-testid="value-inspector-bundle-list"]');
    expect(list).not.toBeNull();
    const rows = list?.querySelectorAll<HTMLLIElement>("li[data-aux-key]") ?? [];
    // 11 round keys for AES-128.
    expect(rows.length).toBe(11);
    // First row is roundKey.0 and is marked active.
    expect(rows[0]?.getAttribute("data-aux-key")).toBe("roundKey.0");
    expect(rows[0]?.classList.contains("graph-value-inspector-bundle-row-active")).toBe(true);
    // No other row is active.
    for (let i = 1; i < rows.length; i++) {
      expect(rows[i]?.classList.contains("graph-value-inspector-bundle-row-active")).toBe(false);
    }
  });

  it("clicking a row makes that aux active (canvas halo stays on the bundle)", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    const bundleHit = findBundleHit(container as HTMLElement);
    fireEvent.click(bundleHit as SVGPathElement);

    // Click roundKey.5 in the list.
    const row5 = container.querySelector<HTMLLIElement>('li[data-aux-key="roundKey.5"]');
    expect(row5).not.toBeNull();
    const button = row5?.querySelector("button");
    expect(button).not.toBeNull();
    fireEvent.click(button as HTMLButtonElement);

    // The row is now active.
    expect(row5?.classList.contains("graph-value-inspector-bundle-row-active")).toBe(true);
    // First row is no longer active.
    const row0 = container.querySelector<HTMLLIElement>('li[data-aux-key="roundKey.0"]');
    expect(row0?.classList.contains("graph-value-inspector-bundle-row-active")).toBe(false);

    // Selected target STAYS a bundle target — the canvas halo (driven
    // by `isBundleSelected`) doesn't jump to a per-edge target.
    const target = useSelectedTarget()();
    expect(target?.kind).toBe("bundle");

    // Visible-path halo on the bundle is still present.
    const visible = bundleHit?.parentElement?.querySelector(".graph-edge");
    expect(visible?.classList.contains("graph-edge-selected")).toBe(true);
  });

  it("re-clicking the same bundle clears the selection (toggle)", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    const bundleHit = findBundleHit(container as HTMLElement);
    fireEvent.click(bundleHit as SVGPathElement);
    expect(useSelectedTarget()()).not.toBeNull();
    fireEvent.click(bundleHit as SVGPathElement);
    expect(useSelectedTarget()()).toBeNull();
  });

  it("clearing the bundle selection clears the active row too (no stale state)", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    const bundleHit = findBundleHit(container as HTMLElement);
    fireEvent.click(bundleHit as SVGPathElement);
    // Pick row 7 so the active state is non-default.
    const row7Btn = container
      .querySelector<HTMLLIElement>('li[data-aux-key="roundKey.7"]')
      ?.querySelector("button");
    fireEvent.click(row7Btn as HTMLButtonElement);
    // Toggle off the bundle selection.
    fireEvent.click(bundleHit as SVGPathElement);
    // Re-click to re-select; the default-active row should be back to row 0,
    // not row 7 (active state cleared when selection moved/cleared).
    fireEvent.click(bundleHit as SVGPathElement);
    const row0 = container.querySelector<HTMLLIElement>('li[data-aux-key="roundKey.0"]');
    expect(row0?.classList.contains("graph-value-inspector-bundle-row-active")).toBe(true);
    const row7 = container.querySelector<HTMLLIElement>('li[data-aux-key="roundKey.7"]');
    expect(row7?.classList.contains("graph-value-inspector-bundle-row-active")).toBe(false);
  });

  it("swapping the spec clears the bundle selection (no stale identity)", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    const bundleHit = findBundleHit(container as HTMLElement);
    fireEvent.click(bundleHit as SVGPathElement);
    expect(useSelectedTarget()()).not.toBeNull();
    // Swap cipherMode — same machinery clearSelectedTarget watches.
    // Cycle through then back so the spec.id watcher fires.
    setCipherMode("single-block");
    expect(useSelectedTarget()()).toBeNull();
  });
});
