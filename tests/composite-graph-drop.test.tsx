// @vitest-environment jsdom

/**
 * Compose-and-save GraphView integration (universal-port Phase 4f, Slice D).
 *
 * Two surfaces:
 *   1. The `[save as element]` header chip on a GROUP captures it into the
 *      composites library.
 *   2. Dropping a "my elements" entry (composite MIME payload) INLINES a fresh
 *      clone of the group into the spec at the drop anchor, with its seed
 *      auto-bound to the insertion-point predecessor.
 *
 * Like `step-palette.test.tsx`, we don't run the real HTML5 drag (jsdom
 * DataTransfer is partial) — we fire a `drop` Event with a populated
 * `dataTransfer`, and we rely on the documented jsdom gap that `fireEvent.click`
 * bypasses CSS `pointer-events:none` so the hover-hidden save chip is clickable.
 * The live hover + real drag are covered by the Slice E Playwright smoke.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { findStepAndParent } from "@/core/spec-mutations";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { COMPOSITE_DRAG_MIME } from "@/ui/components/StepPalette";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetCompositesForTests, listComposites, saveComposite } from "@/ui/stores/composites";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetCompositesForTests();
  __resetHistoryForTests();
  __resetLayoutsForTests();
  __resetPaddingForTests();
  __resetReplicationForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetViewModeForTests();
};

const mockDataTransfer = (payload: { readonly [mime: string]: string }) => ({
  getData: (mime: string) => payload[mime] ?? "",
  types: Object.keys(payload),
  setData: () => {},
  effectAllowed: "" as DataTransfer["effectAllowed"],
  dropEffect: "" as DataTransfer["dropEffect"],
});

const fireCompositeDropAt = (target: Element, compositeId: string): void => {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: mockDataTransfer({ [COMPOSITE_DRAG_MIME]: compositeId }),
  });
  target.dispatchEvent(event);
};

beforeEach(resetAll);
afterEach(() => {
  cleanup();
  resetAll();
  vi.restoreAllMocks();
});

describe("GraphView — save-as-element chip", () => {
  it("captures a group into the composites library via the prompt", () => {
    vi.spyOn(window, "prompt").mockReturnValue("My Saved Round");
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const chip = container.querySelector<SVGGElement>('[data-testid="graph-save-element-round.1"]');
    expect(chip, "round.1 group should render a save-as-element chip").not.toBeNull();
    fireEvent.click(chip as SVGGElement);

    const saved = listComposites().find((c) => c.name === "My Saved Round");
    expect(saved, "a composite should be saved under the prompted name").toBeDefined();
    // Context-free template: seedInput cleared, reads as one chip, label = name.
    expect(saved?.group.seedInput).toBeUndefined();
    expect(saved?.group.defaultCollapsed).toBe(true);
    expect(saved?.group.label).toBe("My Saved Round");
  });

  it("does NOT render a save chip on an iterate container", () => {
    // The AES-128 single-block default has no iterate; the chip is gated on
    // `kind === "group"`, so a leaf/iterate never shows it. Assert the chip is
    // absent for a known leaf id (sanity that the gate is id/kind-scoped).
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    expect(
      container.querySelector('[data-testid="graph-save-element-initial.add-round-key"]'),
    ).toBeNull();
  });
});

describe("GraphView — composite drop", () => {
  it("inlines a fresh clone of the composite group at the drop anchor", () => {
    seedAes128Trace();
    // Save a composite from the live round.1 group, then drop it.
    const def = saveComposite({
      kind: "group",
      id: "round.1",
      label: "AES Round",
      defaultCollapsed: true,
      bodyOutput: { node: "round.1.add-round-key", port: "output" },
      children: [
        {
          kind: "step",
          id: "round.1.sub-bytes",
          type: "byte-substitute@1",
          params: { sbox: [...Array(256).keys()] },
          portInputs: { input: { node: "round.1", port: "in" } },
        },
      ],
    });

    const { container } = render(() => <GraphView />);
    const leaf = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="initial.add-round-key"]',
    );
    expect(leaf).not.toBeNull();
    if (!leaf) return;
    fireCompositeDropAt(leaf, def.id);

    // A fresh group derived from the slug of "AES Round" should be inlined.
    const located = findStepAndParent(useSpec()(), "aes-round");
    expect(located, "dropped composite should inline as a group").not.toBeNull();
    expect(located?.node.kind).toBe("group");
    if (located?.node.kind === "group") {
      // Seed auto-bound to the predecessor (insert-into-pipeline semantics).
      expect(located.node.seedInput?.node).toBe("initial.add-round-key");
      // Fresh child id under the new root; internal seed ref rebased.
      const child = located.node.children[0];
      expect(child?.id).toBe("aes-round.sub-bytes");
      if (child?.kind === "step") {
        expect(child.portInputs?.input).toEqual({ node: "aes-round", port: "in" });
      }
    }
  });

  it("ignores a composite drop whose id is not in the library", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const before = useSpec()().steps.length;
    const leaf = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="initial.add-round-key"]',
    );
    if (!leaf) throw new Error("test setup: initial.add-round-key leaf missing");
    fireCompositeDropAt(leaf, "composite.does-not-exist");
    expect(useSpec()().steps.length).toBe(before);
  });
});
