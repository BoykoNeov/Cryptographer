// @vitest-environment jsdom

/**
 * UI test for the Sync-inverse-MixColumns button (`SyncMixColumnsRow`)
 * rendered inside `MixBlock` in `ParamEditor`.
 *
 * Properties pinned here (sibling to `sync-inverse-row.test.tsx` for the
 * S-box inverse case):
 *   - The button RENDERS when a `generic.mix-columns@1` step is selected.
 *   - Its label names the SYNC INVERSE operation.
 *   - It carries `data-mirror-class="inverse"` so the enumeration coverage
 *     test can find it.
 *   - It is gated on GF(2^8) invertibility via try/catch around
 *     `gfMatInverse4x4` — singular matrix disables the button.
 *   - The disabled state is reactive — repairing the matrix re-enables
 *     the button without needing a remount.
 *   - The disabled-state tooltip cites GF(2^8) singularity explicitly
 *     (NOT "Repair first," because there's no Repair affordance for a
 *     4×4 mixing matrix the way there is for an S-box).
 *
 * Cross-slot write semantics are exercised at the store boundary in
 * `tests/sync-mix-columns-store.test.ts`; here we only verify the UI
 * affordance.
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
  // Retarget to AES-128 CBC: every single-block AES (B1.3) AND ECB (B1.4a) is
  // byte-native, so their `round.1.mix-columns` is `gf-matrix-multiply@1` whose
  // editor ALSO renders a SyncMixColumnsRow (same `.sync-mix-columns-row`
  // class) — selecting a byte-native leaf here would MIS-TARGET (the assertion
  // would pass against the wrong block, leaving the matrix `generic.mix-columns@1`
  // path uncovered — the vacuous-pass trap). The AES-128 **CBC** mode is the
  // last selectable spec keeping the matrix `generic.*` round body
  // (`aes-round-builder.ts`) until Slice B1.4b, so CBC's `round.1.mix-columns`
  // is a genuine `generic.mix-columns@1` leaf rendering the matrix MixColumns
  // editor + its Sync-inverse-MixColumns row. (The matrix body lives inside the
  // iterate, but the spec leaf id is still `round.1.mix-columns`.) When CBC
  // converts in B1.4b this retarget re-breaks and the matrix path retires with
  // Phase C.
  setCipher("aes-128");
  setCipherMode("cbc");
};

// Canonical AES-128 has a MixColumns leaf in every non-final round at
// id `round.N.mix-columns`. Round 1 is always present.
const selectMixColumns = (): void => {
  setSelectedStepId("round.1.mix-columns");
};

const findSyncButton = (root: HTMLElement): HTMLButtonElement | null =>
  root.querySelector(".sync-mix-columns-row button") as HTMLButtonElement | null;

// Walk the live spec to find the round.1.mix-columns leaf so the sabotage
// path can read its current matrix without depending on a hard-coded
// shape (in case the canonical matrix changes or rounds are renumbered
// by another test).
type Node = { kind: string; id?: string; params?: unknown; children?: readonly Node[] };
const findMixLeaf = (): Node | null => {
  const spec = useSpec()();
  let found: Node | null = null;
  const visit = (nodes: readonly Node[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.id === "round.1.mix-columns") {
        found = n;
      } else if ((n.kind === "group" || n.kind === "iterate") && n.children) {
        visit(n.children);
      }
    }
  };
  visit(spec.steps as readonly Node[]);
  return found;
};

describe("SyncMixColumnsRow — gating on GF(2^8) invertibility + label + mirror class", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the Sync button with the SYNC INVERSE verb on a fresh canonical MixColumns step", async () => {
    const { container } = render(() => <App />);
    selectMixColumns();

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findSyncButton(container);
    expect(btn?.textContent ?? "").toMatch(/Sync inverse MixColumns to decrypt/);
    // Canonical AES_MIX_MATRIX is invertible → button enabled.
    expect(btn?.disabled).toBe(false);
  });

  it('carries data-mirror-class="inverse" for the enumeration test', async () => {
    const { container } = render(() => <App />);
    selectMixColumns();

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findSyncButton(container);
    expect(btn?.getAttribute("data-mirror-class")).toBe("inverse");
  });

  it("enabled tooltip cites FIPS-197 §5.3.3 (the spec citation is the pedagogical hook)", async () => {
    const { container } = render(() => <App />);
    selectMixColumns();

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findSyncButton(container);
    expect(btn?.title ?? "").toMatch(/FIPS-197 §5\.3\.3/);
    expect(btn?.title ?? "").toMatch(/Gauss-Jordan/);
  });

  it("is DISABLED after sabotaging the matrix into a singular one (zero row); re-ENABLES after restore", async () => {
    const { container } = render(() => <App />);
    selectMixColumns();

    await waitFor(() => {
      expect(findSyncButton(container)).not.toBeNull();
    });

    const step = findMixLeaf();
    const canonical =
      (step?.params as { matrix?: readonly (readonly number[])[] }).matrix?.map((row) => [
        ...row,
      ]) ?? [];

    // Phase 1: zero out the first row → singular over GF(2^8) → button disabled.
    const sabotaged = canonical.map((row) => [...row]);
    sabotaged[0] = [0, 0, 0, 0];
    editStepParams("round.1.mix-columns", {
      ...(step?.params as Record<string, unknown>),
      matrix: sabotaged,
    });

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn?.disabled).toBe(true);
    });

    // Disabled tooltip must be honest about the gating reason — name the
    // GF(2^8) singularity AND say what the user has to do (edit a cell)
    // rather than copy/paste the S-box "Repair to a permutation first"
    // phrasing (no Repair button exists for a 4×4 mixing matrix; the
    // canonical AES matrix is one specific invertible table — there's no
    // general inverse-table recipe like there is for an arbitrary
    // bijection on 0..255). Asserting both phrases keeps the pedagogical
    // honesty from regressing to the easier S-box copy.
    expect(findSyncButton(container)?.title ?? "").toMatch(/no inverse over GF\(2\^8\)/i);
    expect(findSyncButton(container)?.title ?? "").toMatch(/Edit a cell/i);

    // Phase 2: restore canonical, button should re-enable (regression guard:
    // a stuck-disabled state would indicate the invertibility memo captured
    // the sabotaged matrix by value rather than reactively).
    editStepParams("round.1.mix-columns", {
      ...(step?.params as Record<string, unknown>),
      matrix: canonical,
    });

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn?.disabled).toBe(false);
    });
  });

  it("is DISABLED on a different singular pattern (two identical rows)", async () => {
    // Belt-and-braces: covers a singular pattern that the zero-row test
    // doesn't (rank-deficient but no all-zero row).
    const { container } = render(() => <App />);
    selectMixColumns();

    await waitFor(() => {
      expect(findSyncButton(container)).not.toBeNull();
    });

    const step = findMixLeaf();
    const sabotaged = [
      [1, 2, 3, 4],
      [5, 6, 7, 8],
      [1, 2, 3, 4], // duplicate of row 0
      [9, 0xa, 0xb, 0xc],
    ];
    editStepParams("round.1.mix-columns", {
      ...(step?.params as Record<string, unknown>),
      matrix: sabotaged,
    });

    await waitFor(() => {
      const btn = findSyncButton(container);
      expect(btn?.disabled).toBe(true);
    });
  });
});
