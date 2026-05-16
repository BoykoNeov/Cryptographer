// @vitest-environment jsdom

/**
 * UI tests for the Serpent SubBytes editor's validation + Repair + Sync
 * trio. Mirrors the AES-side `sync-inverse-row.test.tsx` pattern but at
 * N=16 instead of N=256, with two Serpent-specific twists:
 *
 *   - The warning banner uses a tighter padding variant
 *     (`.serpent-sbox-warning-banner`) than the AES version.
 *   - The Sync button names the specific S-box index ("Sync inverse S_3
 *     to decrypt") because Serpent cycles 8 distinct tables across the
 *     rounds. The per-index propagation contract is exercised at the
 *     store boundary in `tests/sync-serpent-sbox-inverse.test.ts`; here
 *     we only check the UI-level affordance (button presence, label,
 *     gating, Repair).
 */

import { SERPENT_SBOXES } from "@/ciphers/serpent-constants";
import { App } from "@/ui/App";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
// `setCipher` MUST come from stores/spec, not stores/cipher — the former
// rebuilds the active+counterpart specs via buildCanonicalPair, the
// latter only flips the signal (matching the real UI's setCipher path).
import { __resetSpecForTests, editStepParams, setCipher, useSpec } from "@/ui/stores/spec";
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

const selectSerpentRound1SubBytes = (): void => {
  setCipher("serpent-128");
  // `round.1.sub-bytes` in serpent uses sboxIndex 0 — `S_{(r-1) mod 8}`
  // for round 1 is `S_0`. See `serpent-round-builder.ts::subBytesLeaf`.
  setSelectedStepId("round.1.sub-bytes");
};

const findSyncButton = (root: HTMLElement): HTMLButtonElement | null =>
  root.querySelector(".sync-inverse-row button") as HTMLButtonElement | null;

const findRepairButton = (root: HTMLElement): HTMLButtonElement | null =>
  root.querySelector(".sbox-warning-repair") as HTMLButtonElement | null;

const findWarningBanner = (root: HTMLElement): HTMLElement | null =>
  root.querySelector(".serpent-sbox-warning-banner") as HTMLElement | null;

// Walk the live spec to find a leaf by id — same pattern the AES
// sync-inverse-row test uses; kept local so the test file is
// self-contained.
type Node = { kind: string; id?: string; params?: unknown; children?: readonly Node[] };
const findStepById = (stepId: string): Node | null => {
  const spec = useSpec()();
  let found: Node | null = null;
  const visit = (nodes: readonly Node[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.id === stepId) {
        found = n;
      } else if ((n.kind === "group" || n.kind === "iterate") && n.children) {
        visit(n.children);
      }
    }
  };
  visit(spec.steps as readonly Node[]);
  return found;
};

describe("Serpent SubBytes — validation banner + Repair + Sync", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the Sync button labelled with the leaf's sboxIndex on a fresh canonical spec", async () => {
    const { container } = render(() => <App />);
    selectSerpentRound1SubBytes();

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findSyncButton(container);
    // S_0 because round 1 uses S_{(1-1) mod 8} = S_0.
    expect(btn?.textContent ?? "").toMatch(/Sync inverse S_0 to decrypt/);
    // Bijective canonical table → button is enabled.
    expect(btn?.disabled).toBe(false);
  });

  it("does NOT render the warning banner when the table is a permutation", async () => {
    const { container } = render(() => <App />);
    selectSerpentRound1SubBytes();

    // Give the editor a render cycle so the banner-absence is meaningful.
    await waitFor(() => {
      expect(findSyncButton(container)).not.toBeNull();
    });

    expect(findWarningBanner(container)).toBeNull();
    expect(findRepairButton(container)).toBeNull();
  });

  it("renders the warning banner + Repair button when the user creates a duplicate value", async () => {
    const { container } = render(() => <App />);
    selectSerpentRound1SubBytes();

    // Wait until the editor has mounted.
    await waitFor(() => {
      expect(findSyncButton(container)).not.toBeNull();
    });

    // Force a duplicate: set entry [1] to whatever entry [0] holds.
    const step = findStepById("round.1.sub-bytes");
    const sbox = [...(((step?.params as { sbox?: readonly number[] }).sbox ?? []) as number[])];
    sbox[1] = sbox[0] ?? 0;
    editStepParams("round.1.sub-bytes", { sbox, sboxIndex: 0 });

    await waitFor(() => {
      const banner = findWarningBanner(container);
      expect(banner).not.toBeNull();
      expect(banner?.textContent ?? "").toMatch(/duplicate/i);
    });

    expect(findRepairButton(container)).not.toBeNull();
  });

  it("disables the Sync button while the table is non-bijective; re-enables after Repair", async () => {
    const { container } = render(() => <App />);
    selectSerpentRound1SubBytes();

    await waitFor(() => {
      expect(findSyncButton(container)).not.toBeNull();
    });

    // Sabotage: duplicate entry.
    const canonical = [...(SERPENT_SBOXES[0] ?? [])];
    const sabotaged = [...canonical];
    sabotaged[3] = sabotaged[0] ?? 0;
    editStepParams("round.1.sub-bytes", { sbox: sabotaged, sboxIndex: 0 });

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn?.disabled).toBe(true);
    });
    const disabledBtn = findSyncButton(container);
    expect(disabledBtn?.title ?? "").toMatch(/Repair/);

    // Restore the canonical table (analog to a successful Repair click —
    // the repair-button-click path is exercised via the ActionButton
    // primitive tests; here we only need the spec to flip back to
    // bijective and check the UI follows).
    editStepParams("round.1.sub-bytes", { sbox: canonical, sboxIndex: 0 });

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn?.disabled).toBe(false);
    });
  });

  it("Sync button tooltip names the per-index semantic ('other 7 S-boxes are independent')", async () => {
    const { container } = render(() => <App />);
    selectSerpentRound1SubBytes();

    await waitFor(() => {
      expect(findSyncButton(container)).not.toBeNull();
    });

    const btn = findSyncButton(container);
    // Pedagogical hook: the tooltip must explicitly state that other
    // S-box indices stay un-mirrored, so users don't think the button is
    // broken when their S_5 edits don't propagate after a sync of S_3.
    expect(btn?.title ?? "").toMatch(/other 7 .* S-boxes? are independent/i);
  });
});
