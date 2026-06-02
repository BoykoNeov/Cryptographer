// @vitest-environment jsdom

/**
 * Canvas click-to-arm wiring gesture (universal-port Phase 4d-bis, Slice E —
 * port handles in `GraphView.tsx`).
 *
 * Scope + caveat: these tests exercise the LOGIC path of the gesture —
 * handle renders → click arms the store → legal sources sprout bind handles →
 * click binds the spec. They do NOT prove the handles are actually clickable
 * by a user in a real browser: jsdom `fireEvent.click` dispatches straight to
 * the handler, bypassing the CSS/SVG hit-testing that a real pointer is
 * subject to (memory `jsdom_pointer_events_gap`). The real-browser
 * clickability + visual feedback is covered by the Playwright smoke
 * (`e2e/port-wiring-smoke.spec.ts`). Here we guard against regressions in the
 * render + store + rebind wiring.
 *
 * The default AES-128 spec renders its round bodies expanded, so
 * `round.1.{sub-bytes,shift-rows,mix-columns}` are visible leaves in one
 * scope — ideal for "rewire mix-columns from shift-rows to sub-bytes."
 */

import { findStep } from "@/core/spec-mutations";
import { App } from "@/ui/App";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests, setViewMode } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { __resetWiringForTests } from "@/ui/stores/wiring";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

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
  __resetWiringForTests();
};

const q = (c: HTMLElement, testid: string): Element | null =>
  c.querySelector(`[data-testid="${testid}"]`);

const inputBinding = (stepId: string, port: string) =>
  findStep(useSpec()(), stepId)?.portInputs?.[port];

beforeEach(() => {
  resetAll();
  setViewMode("graph");
});

afterEach(() => {
  cleanup();
  __resetWiringForTests();
});

describe("GraphView port-wiring gesture", () => {
  it("renders an input-port handle on a real leaf", async () => {
    const { container } = render(() => <App />);
    await waitFor(() => expect(q(container, "graph-leaf-round.1.mix-columns")).toBeTruthy());
    expect(q(container, "graph-port-in-round.1.mix-columns-input")).toBeTruthy();
  });

  it("arms an input port, then binds it to a legal source leaf", async () => {
    const { container } = render(() => <App />);
    await waitFor(() => expect(q(container, "graph-leaf-round.1.mix-columns")).toBeTruthy());

    // Baseline: mix-columns reads shift-rows.
    expect(inputBinding("round.1.mix-columns", "input")).toEqual({
      node: "round.1.shift-rows",
      port: "output",
    });

    // Arm mix-columns' input.
    fireEvent.click(q(container, "graph-port-in-round.1.mix-columns-input") as Element);

    // sub-bytes (a preceding sibling it does NOT currently read) becomes a
    // legal bind target — its bind handle appears.
    const bindHandle = await waitFor(() => {
      const h = q(container, "graph-port-bind-round.1.sub-bytes");
      if (!h) throw new Error("bind handle did not appear on the legal source");
      return h;
    });
    fireEvent.click(bindHandle);

    // mix-columns now reads sub-bytes; the wire disarmed (handle gone).
    expect(inputBinding("round.1.mix-columns", "input")).toEqual({
      node: "round.1.sub-bytes",
      port: "output",
    });
    expect(q(container, "graph-port-bind-round.1.sub-bytes")).toBeNull();
  });

  it("re-clicking the armed handle disarms (no bind handles shown)", async () => {
    const { container } = render(() => <App />);
    await waitFor(() => expect(q(container, "graph-leaf-round.1.mix-columns")).toBeTruthy());

    const arm = () =>
      fireEvent.click(q(container, "graph-port-in-round.1.mix-columns-input") as Element);
    arm();
    await waitFor(() => expect(q(container, "graph-port-bind-round.1.sub-bytes")).toBeTruthy());
    // Toggle off.
    arm();
    await waitFor(() => expect(q(container, "graph-port-bind-round.1.sub-bytes")).toBeNull());
  });
});
