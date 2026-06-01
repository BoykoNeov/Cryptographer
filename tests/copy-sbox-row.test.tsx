// @vitest-environment jsdom

/**
 * UI test for the Copy-S-box-to-counterpart button (`CopySboxRow`)
 * rendered inside the AES key-schedule SubWord `byte-substitute@1` editor
 * (`ByteSubstituteBlock`) in `ParamEditor`.
 *
 * Since the key-schedule decomposition (2026-06-01) the Copy affordance is
 * re-homed from the retired monolithic `aes.key-expansion@1/@2` leaf onto
 * the decomposed SubWord leaf (`key-schedule.g1.subword`, a
 * `byte-substitute@1` step inside the `key-schedule` group). The round-body
 * SubBytes leaves of the SAME type render the *inverse* row instead — so
 * selecting a SubWord leaf is what surfaces the Copy button.
 *
 * Properties pinned here (sibling to `sync-inverse-row.test.tsx` for
 * the inverse case):
 *   - The button RENDERS when a key-schedule SubWord step is selected.
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

// The decomposed AES-128 key schedule puts SubWord on a `byte-substitute@1`
// leaf at `key-schedule.g1.subword` (inside the default-collapsed
// `key-schedule` group). Selecting it makes `ByteSubstituteBlock` render its
// key-schedule branch — the CopySboxRow. (ParamEditor resolves the selected
// leaf regardless of graph collapse state.)
const SUBWORD_LEAF_ID = "key-schedule.g1.subword";
const selectSubWord = (): void => {
  setSelectedStepId(SUBWORD_LEAF_ID);
};

const findCopyButton = (root: HTMLElement): HTMLButtonElement | null =>
  root.querySelector(".copy-sbox-row button") as HTMLButtonElement | null;

// Walk the live spec to find the SubWord leaf so the sabotage path can read
// its current S-box without depending on the canonical table shape.
type Node = { kind: string; id?: string; params?: unknown; children?: readonly Node[] };
const findSubWord = (): Node | null => {
  const spec = useSpec()();
  let found: Node | null = null;
  const visit = (nodes: readonly Node[]): void => {
    for (const n of nodes) {
      if (n.kind === "step" && n.id === SUBWORD_LEAF_ID) {
        found = n;
      } else if ((n.kind === "group" || n.kind === "iterate") && n.children) {
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

  it("renders the Copy button with the COPY verb on a fresh canonical key-schedule SubWord step", async () => {
    const { container } = render(() => <App />);
    selectSubWord();

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
    selectSubWord();

    await waitFor(() => {
      const btn = findCopyButton(container);
      expect(btn).not.toBeNull();
    });

    const btn = findCopyButton(container);
    expect(btn?.getAttribute("data-mirror-class")).toBe("identity");
  });

  it("tooltip cites FIPS-197 §5.2 (the spec citation is the pedagogical hook)", async () => {
    const { container } = render(() => <App />);
    selectSubWord();

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
    selectSubWord();

    await waitFor(() => {
      expect(findCopyButton(container)).not.toBeNull();
    });

    const step = findSubWord();
    const canonical = [...((step?.params as { sbox?: readonly number[] }).sbox ?? [])];

    // Phase 1: force a duplicate, expect disabled.
    const sabotaged = [...canonical];
    sabotaged[0x10] = sabotaged[0x00] ?? 0;
    editStepParams(SUBWORD_LEAF_ID, {
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
    editStepParams(SUBWORD_LEAF_ID, {
      ...(step?.params as Record<string, unknown>),
      sbox: canonical,
    });

    await waitFor(() => {
      const btn = findCopyButton(container);
      expect(btn?.disabled).toBe(false);
    });
  });
});
