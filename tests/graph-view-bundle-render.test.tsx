// @vitest-environment jsdom

/**
 * Component-level test for the bundled-edge visual (Slice B of the
 * arrow-bundling work, 2026-05-17).
 *
 * Scenario: AES-128 ECB with BOTH the iterate `ecb-blocks` and the
 * decomposed `key-schedule` group COLLAPSED (the latter is default-collapsed
 * since key-schedule-decomposition K1c). The 11 round-key aux edges now run
 * from the `key-schedule` container (the publish tail inside it remaps to the
 * container on collapse) to the `ecb-blocks` container (the AddRoundKey
 * consumers inside the iterate remap to it). Same (from, to, kind) for all
 * 11 → they collapse into ONE rendered path carrying a `×11` label. This is
 * the same "11 parallel arrows are unreadable" case the bundle work targeted;
 * no replication is needed because the container→container fan-out bundles
 * directly (and `replicateHighFanoutSources` skips container sources anyway).
 *
 * What we pin:
 *   - Bundle is reachable via the new `bundle:` prefix on the hit
 *     path's `data-edge-key`.
 *   - `data-bundle-count` reflects the auxKey count (= 11 for AES-128).
 *   - The visible path carries the `graph-edge-bundle` class.
 *   - A `×11` text label is rendered in the bundle-label group.
 *   - Singleton bundles do NOT carry the `graph-edge-bundle` class and
 *     have `data-bundle-count="1"` — no ×N label for the common case.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, toggleCollapse } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { __resetValueInspectorForTests } from "@/ui/stores/view-value-inspector";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
// SP 800-38A §F.1.1 plaintext — 4 blocks → 4 ECB iterations.
const ECB_PLAINTEXT =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const seedAes128EcbCollapsedReplicated = (): void => {
  // Swap the live cipher to AES-128 ECB so the canonical spec store
  // picks up the right (cipher, cipherMode) pair before we drive any
  // UI state.
  setCipher("aes-128");
  setCipherMode("ecb");
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
  });
  setTrace(trace);
  // Collapse the iterate — this is the user-flagged state. The toggle
  // store is keyed by spec.id; the canonical aes-128 ECB spec carries
  // a stable id that matches the collapseSet lookup. (The `key-schedule`
  // group is ALREADY default-collapsed, so we don't toggle it.)
  toggleCollapse(aes128EcbSpec.id, "ecb-blocks", false);
  // Master replication switch ON (harmless here — the only fan-out source
  // is the collapsed `key-schedule` CONTAINER, which replication skips; the
  // bundle forms from the container→container fan-out regardless).
  setReplicationEnabled(true);
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

describe("GraphView — bundled-edge render (Slice B)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("collapses 11 round-key aux edges into one bundle with a ×11 label (ECB + collapsed iterate + always-replicate)", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    // Locate the bundled hit-path by its `bundle:` data-edge-key prefix.
    const hitPaths = container.querySelectorAll<SVGPathElement>("path[data-edge-key]");
    const bundleHits = Array.from(hitPaths).filter((p) =>
      (p.getAttribute("data-edge-key") ?? "").startsWith("bundle:key-schedule|ecb-blocks|aux|"),
    );
    // Exactly one bundle path for this (source, target, kind) pair.
    expect(bundleHits.length).toBe(1);
    const bundleHit = bundleHits[0];
    if (!bundleHit) throw new Error("unreachable");
    // Count attribute reflects the auxKey count.
    expect(bundleHit.getAttribute("data-bundle-count")).toBe("11");

    // The sibling visible path (same parent <g>) should carry the
    // `graph-edge-bundle` class so the stroke is thickened.
    const visibleEdge = bundleHit.parentElement?.querySelector(".graph-edge");
    expect(visibleEdge).not.toBeNull();
    expect(visibleEdge?.classList.contains("graph-edge-bundle")).toBe(true);

    // ×11 text label rendered in the sibling label group.
    const labelGroup = bundleHit.parentElement?.querySelector(".graph-edge-bundle-label");
    expect(labelGroup).not.toBeNull();
    expect(labelGroup?.querySelector(".graph-edge-bundle-label-text")?.textContent).toBe("×11");
  });

  it("renders singleton bundles WITHOUT the bundle class or ×N label", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    // Singleton hit paths use the pre-bundle data-edge-key format
    // (no `bundle:` prefix). Pick any state edge — they're always
    // singletons because the spec spine is 1:1 between consecutive
    // leaves / containers.
    const hitPaths = Array.from(container.querySelectorAll<SVGPathElement>("path[data-edge-key]"));
    const singletonHits = hitPaths.filter((p) => {
      const key = p.getAttribute("data-edge-key") ?? "";
      return !key.startsWith("bundle:");
    });
    expect(singletonHits.length).toBeGreaterThan(0);

    for (const hit of singletonHits) {
      expect(hit.getAttribute("data-bundle-count")).toBe("1");
      const visible = hit.parentElement?.querySelector(".graph-edge");
      // No bundle class on singletons.
      expect(visible?.classList.contains("graph-edge-bundle")).toBe(false);
      // No ×N label group rendered on singletons.
      const label = hit.parentElement?.querySelector(".graph-edge-bundle-label");
      expect(label).toBeNull();
    }
  });

  it("bundle hit-path's <title> lists the auxKeys (≤6 + overflow counter)", () => {
    seedAes128EcbCollapsedReplicated();
    const { container } = render(() => <GraphView />);

    const bundleHit = Array.from(
      container.querySelectorAll<SVGPathElement>("path[data-edge-key]"),
    ).find((p) =>
      (p.getAttribute("data-edge-key") ?? "").startsWith("bundle:key-schedule|ecb-blocks|aux|"),
    );
    expect(bundleHit).not.toBeUndefined();
    const titleText = bundleHit?.querySelector("title")?.textContent ?? "";
    // Count prefix, first auxKey, and overflow indicator (11 - 6 = 5).
    expect(titleText).toContain("11 aux");
    expect(titleText).toContain("roundKey.0");
    expect(titleText).toContain("+5 more");
  });
});
