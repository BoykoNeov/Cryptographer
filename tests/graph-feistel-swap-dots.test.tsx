// @vitest-environment jsdom

/**
 * Case B of the "arrival dots on every arrow" work (2026-07-12): the inter-round
 * Feistel swap-X.
 *
 * A DES round→round carry (`round.N.recombine → round.{N+1}.split`) is suppressed
 * from the normal edge render and redrawn as two crossing wires (the swap-X).
 * Before this change the next round's `split` still showed a SINGLE input-port
 * dot — placed at the suppressed edge's geometry and coloured by `recombine`
 * (often the grey palette slot), so it sat under NEITHER visible swap wire. Now
 * each swap wire carries its rail's source hue and drops a matching landing dot
 * where it meets the split, and the redundant single port dot is suppressed.
 *
 * These pin: two swap dots per swap; the swapped-into split's port dot is NOT
 * "arrived" (the grey fallback, out of the way); and round 1's split — fed by the
 * entry seed, not a swap — keeps its normal arrival dot.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const DES_KEY = "133457799bbcdff1";
const DES_PT = "0123456789abcdef";

const seedDes = (): void => {
  setCipher("des"); // point the spec store + selector at DES
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(DES_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(DES_KEY)]]),
  });
  setTrace(trace);
  // Deterministic: no fan-out replica chips inflating the leaf/dot counts.
  setReplicationEnabled(false);
};

const resetAll = (): void => {
  __resetReplicationForTests();
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
  __resetLayoutsForTests();
};

describe("GraphView — Feistel swap-X landing dots (case B)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("draws two landing dots per inter-round swap", () => {
    seedDes();
    const { container } = render(() => <GraphView />);
    const dots = container.querySelectorAll(".graph-feistel-swap-dot");
    // DES has 15 vertically-stacked inter-round swaps (rounds 1→2 … 15→16), two
    // rails each. Round 16 has no successor → no swap. Assert the pairing
    // invariant rather than the exact 30 so a future round-count tweak in a
    // fixture doesn't spuriously fail — but there must be at least one swap.
    expect(dots.length).toBeGreaterThan(0);
    expect(dots.length % 2).toBe(0);
  });

  it("gives the two rails of a swap DISTINCT source-tinted colours", () => {
    seedDes();
    const { container } = render(() => <GraphView />);
    // The two wires of the first swap carry different producers (split vs fxor),
    // so their inline `color` differs — the whole point of "colour each dot to
    // match its rail" instead of a flat accent.
    const wires = container.querySelectorAll<SVGPathElement>(".graph-feistel-swap-wire");
    expect(wires.length).toBeGreaterThanOrEqual(2);
    const c0 = wires[0]?.getAttribute("style") ?? "";
    const c1 = wires[1]?.getAttribute("style") ?? "";
    expect(c0).toMatch(/color:/);
    expect(c1).toMatch(/color:/);
    expect(c0).not.toBe(c1);
  });

  it("suppresses the swapped-into split's single port dot, but keeps round 1's entry dot", () => {
    seedDes();
    const { container } = render(() => <GraphView />);
    // Round 2's split is fed by the round 1→2 swap → its plain input-port dot is
    // suppressed (grey fallback, not "arrived").
    const split2 = container.querySelector('[data-testid="graph-port-in-round.2.split-input"]');
    expect(split2).not.toBeNull();
    expect(split2?.classList.contains("graph-port-arrived")).toBe(false);
    // Round 1's split is fed by the round-entry seed (not a swap) → it keeps its
    // normal coloured arrival dot.
    const split1 = container.querySelector('[data-testid="graph-port-in-round.1.split-input"]');
    expect(split1).not.toBeNull();
    expect(split1?.classList.contains("graph-port-arrived")).toBe(true);
  });
});
