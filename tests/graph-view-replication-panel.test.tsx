// @vitest-environment jsdom

/**
 * Component test for the per-source replication override panel (commit 5
 * of the graph-readability sequence). Verifies the panel:
 *
 *   1. Hides when the global replication toggle is OFF (master-switch).
 *   2. Lists aux-edge sources sorted by fanout descending when ON.
 *   3. Clicking the "always" / "never" / "auto" buttons persists into the
 *      layout store, and the active button reflects the stored mode.
 *   4. The active-button reflection survives a store mutation triggered
 *      from outside the panel (programmatic `setReplicationMode`) — the
 *      reactive memo through `useLayoutMap` makes that round-trip visible.
 *
 * AES-128 is the fixture: it has exactly one aux-edge source with
 * fanout ≥ 2 (`key-expansion` with 11 outgoing roundKey edges).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, getLayoutForSpec, setReplicationMode } from "@/ui/stores/layout";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetLayoutsForTests();
};

describe("GraphView — replication override panel (commit 5)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("panel is HIDDEN when the global replication toggle is off", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // No matching row testid → panel not rendered.
    expect(container.querySelector('[data-testid="replication-row-key-expansion"]')).toBeNull();
  });

  it("panel surfaces aux-source rows when the global toggle is on", () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    const row = container.querySelector('[data-testid="replication-row-key-expansion"]');
    expect(row).not.toBeNull();
    // Row's fanout label reflects the 11 outgoing roundKey edges.
    expect(row?.textContent ?? "").toContain("11");
  });

  it('clicking "always" persists the override into the layout store', () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    const row = container.querySelector(
      '[data-testid="replication-row-key-expansion"]',
    ) as HTMLElement;
    const buttons = Array.from(row.querySelectorAll("button"));
    const alwaysBtn = buttons.find((b) => b.textContent === "always") as HTMLButtonElement;
    alwaysBtn.click();
    expect(getLayoutForSpec(aes128Spec.id)?.replicationModes).toEqual({
      "key-expansion": "always",
    });
  });

  it('clicking "auto" clears an existing override (back to implicit default)', () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    setReplicationMode(aes128Spec.id, "key-expansion", "never");
    const { container } = render(() => <GraphView />);
    const row = container.querySelector(
      '[data-testid="replication-row-key-expansion"]',
    ) as HTMLElement;
    const buttons = Array.from(row.querySelectorAll("button"));
    const autoBtn = buttons.find((b) => b.textContent === "auto") as HTMLButtonElement;
    autoBtn.click();
    // Layout entry should be gone entirely — auto with no other user
    // customization is the empty-layout case.
    expect(getLayoutForSpec(aes128Spec.id)).toBeNull();
  });

  it("the active button reflects the stored mode reactively", () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    const row = container.querySelector(
      '[data-testid="replication-row-key-expansion"]',
    ) as HTMLElement;
    const getActiveLabel = () =>
      Array.from(row.querySelectorAll("button"))
        .find((b) => b.classList.contains("active"))
        ?.textContent?.trim();
    // Initially auto (the implicit default).
    expect(getActiveLabel()).toBe("auto");
    // External setter fires; the panel's memoized currentMode re-runs.
    setReplicationMode(aes128Spec.id, "key-expansion", "always");
    expect(getActiveLabel()).toBe("always");
    setReplicationMode(aes128Spec.id, "key-expansion", "never");
    expect(getActiveLabel()).toBe("never");
  });
});
