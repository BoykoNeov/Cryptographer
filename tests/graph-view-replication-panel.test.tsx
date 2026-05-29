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
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, getLayoutForSpec, setReplicationMode } from "@/ui/stores/layout";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import {
  __resetReplicationForTests,
  setReplicationEnabled,
  setReplicationPanelOpen,
} from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    portedDispatchEnabled: true,
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
    // Panel defaults CLOSED on a spec with no overrides (the auto-open
    // effect set it false on mount). Open it AFTER render so the manual
    // setter wins; setting before render would be undone by the effect.
    setReplicationPanelOpen(true);
    const row = container.querySelector('[data-testid="replication-row-key-expansion"]');
    expect(row).not.toBeNull();
    // Row's fanout label reflects the 11 outgoing roundKey edges.
    expect(row?.textContent ?? "").toContain("11");
  });

  it('clicking "always" persists the override into the layout store', () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    setReplicationPanelOpen(true);
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
    // Pre-seeded override → effect should auto-open the panel on mount;
    // no manual setReplicationPanelOpen(true) needed here.
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
    setReplicationPanelOpen(true);
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

/**
 * Collapse-toggle tests for the replication overrides panel. The panel
 * sat permanently expanded after the fanout-≥-1 filter change — even
 * users who tuned a one-off override couldn't reclaim the ~140 px of
 * canvas they were eating. These tests pin the new behavior:
 *
 *   - Default state on a fresh spec with NO overrides: closed.
 *   - Default state on a spec WITH any user override: open (so the user
 *     can see *why* their canvas looks customized without hunting for
 *     the toggle).
 *   - Clicking the header chevron flips the state both directions and
 *     the row body appears/disappears in lock-step.
 */
describe("GraphView — replication panel collapse toggle", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("defaults CLOSED when the active spec has no per-source overrides", () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    const toggle = container.querySelector(
      '[data-testid="replication-panel-toggle"]',
    ) as HTMLButtonElement | null;
    // Toggle button is present (panel is rendered) but in closed state.
    expect(toggle).not.toBeNull();
    expect(toggle?.dataset.open).toBe("false");
    // Body rows are NOT rendered — the <Show> wrapper hides them when
    // the panel is closed.
    expect(container.querySelector('[data-testid="replication-row-key-expansion"]')).toBeNull();
  });

  it("defaults OPEN when the active spec carries a user override at render time", () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    // Seed override BEFORE mount so the auto-open effect fires on the
    // spec().id sample at initial render. This is the canonical "load a
    // customized spec from disk / a share URL" flow.
    setReplicationMode(aes128Spec.id, "key-expansion", "always");
    const { container } = render(() => <GraphView />);
    const toggle = container.querySelector(
      '[data-testid="replication-panel-toggle"]',
    ) as HTMLButtonElement | null;
    expect(toggle?.dataset.open).toBe("true");
    expect(container.querySelector('[data-testid="replication-row-key-expansion"]')).not.toBeNull();
  });

  it("clicking the header chevron toggles the panel open and closed", () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    const toggle = container.querySelector(
      '[data-testid="replication-panel-toggle"]',
    ) as HTMLButtonElement;
    // Starts closed (no overrides) → click → open.
    expect(toggle.dataset.open).toBe("false");
    toggle.click();
    expect(toggle.dataset.open).toBe("true");
    expect(container.querySelector('[data-testid="replication-row-key-expansion"]')).not.toBeNull();
    // Click again → closed → body disappears.
    toggle.click();
    expect(toggle.dataset.open).toBe("false");
    expect(container.querySelector('[data-testid="replication-row-key-expansion"]')).toBeNull();
  });

  it("aria-expanded mirrors the open/closed state for screen-reader users", () => {
    seedAes128Trace();
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    const toggle = container.querySelector(
      '[data-testid="replication-panel-toggle"]',
    ) as HTMLButtonElement;
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    toggle.click();
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
  });
});
