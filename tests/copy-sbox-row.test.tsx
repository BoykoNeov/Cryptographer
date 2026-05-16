// @vitest-environment jsdom

/**
 * UI test for the Copy-S-box-to-counterpart button (`CopySboxRow`)
 * rendered inside the AES key-expansion S-box <details> in
 * `ParamEditor`.
 *
 * Properties pinned here (sibling to `sync-inverse-row.test.tsx` for
 * the inverse case):
 *   - The button RENDERS when a key-expansion step is selected.
 *   - Its label names the COPY operation (distinct from the inverse
 *     row's "Sync inverse" verb).
 *   - It carries `data-mirror-class="identity"` so the enumeration
 *     coverage test can find it.
 *   - It is gated on S-box bijection (matches the inverse row's
 *     gating policy for consistency across all S-box mirror rows).
 *   - The disabled state is reactive — repairing the table re-enables
 *     the button without needing a remount.
 *
 * Cross-slot write semantics are exercised at the store boundary in
 * `tests/sync-sbox-copy.test.ts`; here we only verify the UI affordance.
 */

import { App } from "@/ui/App";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, editStepParams, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setSelectedStepId } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render, waitFor } from "@solidjs/testing-library";
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
};

// The canonical AES-128 spec puts key-expansion at a top-level leaf with
// id "key-expansion". Selecting it makes the KeyExpansionBlock render
// (with the CopySboxRow nested inside its <details>).
const selectKeyExpansion = (): void => {
  setSelectedStepId("key-expansion");
};

const findCopyButton = (root: HTMLElement): HTMLButtonElement | null =>
  root.querySelector(".copy-sbox-row button") as HTMLButtonElement | null;

// Walk the live spec to find the key-expansion leaf so the sabotage path
// can read its current S-box without depending on the canonical table
// shape (which differs across AES-128 / 192 / 256 if those ship later).
type Node = { kind: string; id?: string; params?: unknown; children?: readonly Node[] };
const findKeyExpansion = (): Node | null => {
  const spec = useSpec()();
  let found: Node | null = null;
  const visit = (nodes: readonly Node[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.id === "key-expansion") {
        found = n;
      } else if (n.kind === "group" && n.children) {
        visit(n.children);
      }
    }
  };
  visit(spec.steps as readonly Node[]);
  return found;
};

describe("CopySboxRow — gating on bijection + label + mirror class", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the Copy button with the COPY verb on a fresh canonical key-expansion step", async () => {
    const { container } = render(() => <App />);
    selectKeyExpansion();

    await waitFor(() => {
      const btn = findCopyButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findCopyButton(container);
    // The COPY verb (not "Sync inverse") is the architectural hook —
    // FIPS-197 §5.2 says key expansion uses the FORWARD S-box on both
    // sides, so the label names the identity-mirror operation
    // specifically.
    expect(btn?.textContent ?? "").toMatch(/Copy S-box to decrypt/);
    // Canonical AES_SBOX is bijective → button enabled.
    expect(btn?.disabled).toBe(false);
  });

  it('carries data-mirror-class="identity" for the enumeration test', async () => {
    const { container } = render(() => <App />);
    selectKeyExpansion();

    await waitFor(() => {
      const btn = findCopyButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findCopyButton(container);
    expect(btn?.getAttribute("data-mirror-class")).toBe("identity");
  });

  it("tooltip cites FIPS-197 §5.2 (the spec citation is the pedagogical hook)", async () => {
    const { container } = render(() => <App />);
    selectKeyExpansion();

    await waitFor(() => {
      const btn = findCopyButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findCopyButton(container);
    expect(btn?.title ?? "").toMatch(/FIPS-197 §5\.2/);
    expect(btn?.title ?? "").toMatch(/FORWARD S-box/);
  });

  it("is DISABLED after sabotaging the S-box into a non-permutation; re-ENABLES after restore", async () => {
    const { container } = render(() => <App />);
    selectKeyExpansion();

    await waitFor(() => {
      expect(findCopyButton(container)).not.toBeNull();
    });

    const step = findKeyExpansion();
    const canonical = [...((step?.params as { sbox?: readonly number[] }).sbox ?? [])];

    // Phase 1: force a duplicate, expect disabled.
    const sabotaged = [...canonical];
    sabotaged[0x10] = sabotaged[0x00] ?? 0;
    editStepParams("key-expansion", {
      ...(step?.params as Record<string, unknown>),
      sbox: sabotaged,
    });

    await waitFor(() => {
      const btn = findCopyButton(container);
      expect(btn?.disabled).toBe(true);
    });
    expect(findCopyButton(container)?.title ?? "").toMatch(/Repair/);

    // Phase 2: restore canonical, button should re-enable (regression
    // guard: a stuck-disabled state would indicate the bijection memo
    // captured the sabotaged sbox by value rather than reactively).
    editStepParams("key-expansion", {
      ...(step?.params as Record<string, unknown>),
      sbox: canonical,
    });

    await waitFor(() => {
      const btn = findCopyButton(container);
      expect(btn?.disabled).toBe(false);
    });
  });
});
