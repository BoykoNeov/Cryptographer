// @vitest-environment jsdom

/**
 * UI test for the Sync-inverse-to-counterpart button (`SyncInverseRow`)
 * rendered below the S-box editor in `ParamEditor`.
 *
 * Two properties pinned here that the pure store test (`sync-sbox-
 * inverse.test.ts`) doesn't cover:
 *   - The button is DISABLED when the current S-box is not bijective.
 *     This is the "Repair first" interaction contract — Sync without
 *     bijection would write a garbage inverse to the counterpart slot.
 *   - The button is ENABLED after the user repairs the table (no
 *     transient stuck-disabled state).
 *
 * The cross-slot write itself is exercised at the store boundary
 * elsewhere; here we only verify the button's gating logic, which is
 * the UI's contribution to correctness.
 */

import { App } from "@/ui/App";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  editStepParams,
  setCipher,
  setCipherMode,
  useSpec,
} from "@/ui/stores/spec";
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
  // Retarget to AES-128 ECB: every single-block AES is byte-native as of Slice
  // B1.3, so its `round.1.sub-bytes` is `byte-substitute@1` whose editor ALSO
  // renders a SyncInverseRow with the same button text — selecting a byte-native
  // leaf here would mis-target (the assertion would pass against the wrong
  // block, leaving the matrix `generic.byte-substitution@1` SbxBlock path
  // uncovered). The AES-128 ECB/CBC modes keep the matrix `generic.*` round body
  // (`aes-round-builder.ts`) until Slice B1.4, so ECB's `round.1.sub-bytes` is a
  // genuine `generic.byte-substitution@1` leaf rendering the matrix SbxBlock +
  // its Sync-inverse row. (The matrix body lives inside the iterate, but the
  // spec leaf id is still `round.1.sub-bytes`.)
  setCipher("aes-128");
  setCipherMode("ecb");
};

describe("SyncInverseRow — gating on bijection", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("starts ENABLED on a fresh canonical AES-128 spec (forward S-box is bijective)", async () => {
    const { container } = render(() => <App />);

    // Select an `aes.sub-bytes`-typed leaf so SbxBlock + SyncInverseRow render.
    // The canonical encrypt spec has `round.1.sub-bytes` and friends.
    setSelectedStepId("round.1.sub-bytes");

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findSyncButton(container);
    expect(btn?.disabled).toBe(false);
    expect(btn?.textContent ?? "").toMatch(/Sync inverse S-box to decrypt/);
  });

  it("is DISABLED after editing the S-box into a non-permutation", async () => {
    const { container } = render(() => <App />);
    setSelectedStepId("round.1.sub-bytes");

    // Sabotage the live spec via the same boundary the editor uses.
    const sboxFromStep = (): readonly number[] => {
      const step = findRound1SubBytes();
      return (step?.params as { sbox?: readonly number[] }).sbox ?? [];
    };
    const sabotaged = [...sboxFromStep()];
    sabotaged[0x10] = sabotaged[0x00] ?? 0; // force collision
    editStepParams("round.1.sub-bytes", { sbox: sabotaged });

    // The button should be disabled because the table is no longer a
    // permutation — invertSbox would produce a non-inverse.
    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn?.disabled).toBe(true);
    });

    const btn = findSyncButton(container);
    expect(btn?.title ?? "").toMatch(/Repair/);
  });

  it("re-ENABLES after repairing the table (the disabled state is reactive, not sticky)", async () => {
    // Regression guard: if the bijection memo accidentally captured the
    // sabotaged sbox by value rather than reading it reactively from
    // props, the previous two tests still pass but the button would be
    // stuck-disabled after Repair. This test exercises the transition.
    const { container } = render(() => <App />);
    setSelectedStepId("round.1.sub-bytes");

    const sboxFromStep = (): readonly number[] => {
      const step = findRound1SubBytes();
      return (step?.params as { sbox?: readonly number[] }).sbox ?? [];
    };
    const canonical = [...sboxFromStep()];

    // Phase 1: sabotage, observe disabled.
    const sabotaged = [...canonical];
    sabotaged[0x10] = sabotaged[0x00] ?? 0;
    editStepParams("round.1.sub-bytes", { sbox: sabotaged });

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn?.disabled).toBe(true);
    });

    // Phase 2: restore the canonical S-box (simulating a Repair click —
    // we don't need to drive the actual button here; we just need the
    // spec store to flip to a bijective table and assert the UI follows).
    editStepParams("round.1.sub-bytes", { sbox: canonical });

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn?.disabled).toBe(false);
    });
  });
});

// Helpers — kept local to avoid bleeding generic DOM utilities into the
// shared test surface.

const findSyncButton = (root: HTMLElement): HTMLButtonElement | null =>
  root.querySelector(".sync-inverse-row button") as HTMLButtonElement | null;

type Node = { kind: string; id?: string; params?: unknown; children?: readonly Node[] };

const findRound1SubBytes = (): Node | null => {
  // Walk the live spec to find the canonical first SubBytes step. We
  // do this through the public accessor so the test is robust against
  // tree-shape changes.
  const spec = useSpec()();
  let found: Node | null = null;
  const visit = (nodes: readonly Node[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.id === "round.1.sub-bytes") {
        found = n;
      } else if ((n.kind === "group" || n.kind === "iterate") && n.children) {
        // ECB wraps the round body in an `iterate`; recurse into it too so the
        // round.1.sub-bytes leaf inside the per-block body is reachable.
        visit(n.children);
      }
    }
  };
  visit(spec.steps as readonly Node[]);
  return found;
};
