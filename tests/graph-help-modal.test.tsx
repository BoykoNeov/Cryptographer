// @vitest-environment jsdom

/**
 * Slice 11 — graph view help modal smoke test.
 *
 * Two narrow cases:
 *   1. The toolbar renders a `?` help button.
 *   2. Clicking it doesn't throw, flips the modal's `<dialog>` open state,
 *      and renders the markdown content from `docs/help/graph-view.md`.
 *
 * jsdom note: `HTMLDialogElement.showModal` is undefined in jsdom 22+. Our
 * `GraphHelpModal` guards against the missing API in production code, but
 * the dialog's `open` property won't change unless we stub the methods
 * here. We replace `showModal`/`close` with the minimum that flips the
 * native `open` reflected attribute, matching real-browser behavior for
 * test-assertion purposes only.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

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

beforeAll(() => {
  // jsdom 22+ ships HTMLDialogElement but NOT showModal/close. The shim
  // mirrors the real DOM's effect on the reflected `open` attribute,
  // which is what our component effect reads. Without this, the modal's
  // `<dialog>` would never flip open and we couldn't assert the post-
  // click state. Production code is unaffected — every supported browser
  // ships these methods natively.
  type DialogProto = HTMLDialogElement & {
    showModal: () => void;
    close: () => void;
    open: boolean;
  };
  const proto = HTMLDialogElement.prototype as DialogProto;
  if (typeof proto.showModal !== "function") {
    proto.showModal = function () {
      this.open = true;
    };
  }
  if (typeof proto.close !== "function") {
    proto.close = function () {
      this.open = false;
    };
  }
});

describe("GraphView — help button + modal", () => {
  beforeEach(() => {
    resetAll();
    seedAes128Trace();
  });

  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders a help button in the toolbar", () => {
    const { container } = render(() => <GraphView />);
    const btn = container.querySelector<HTMLButtonElement>(".graph-view-help-button");
    expect(btn, "help button must exist in the graph toolbar").not.toBeNull();
    // Accessible name carries the long-form intent for screen readers.
    expect(btn?.getAttribute("aria-label")).toBe("Show graph view help");
  });

  it("opens a dialog containing rendered help content when clicked", async () => {
    const { container } = render(() => <GraphView />);
    // Pre-click: the help dialog exists in the DOM (Solid renders dialogs
    // unconditionally) but its `open` flag is false.
    const dialog = container.querySelector<HTMLDialogElement>("dialog.graph-help-modal");
    expect(dialog, "help dialog must mount").not.toBeNull();
    expect(dialog?.open).toBe(false);

    fireEvent.click(
      container.querySelector<HTMLButtonElement>(".graph-view-help-button") as HTMLButtonElement,
    );

    await waitFor(() => {
      // The createEffect inside GraphHelpModal calls showModal() on the
      // tick after the signal flips; waitFor handles the microtask gap.
      expect(dialog?.open).toBe(true);
    });

    // Sanity: the markdown rendered into the modal body. We only check
    // for one well-known phrase from the help doc — exact prose is the
    // help doc's job, not this test's.
    const body = dialog?.querySelector(".graph-help-body");
    expect(body?.textContent).toContain("graph view");
  });

  it("closes the dialog when the × button is clicked", async () => {
    const { container } = render(() => <GraphView />);
    fireEvent.click(
      container.querySelector<HTMLButtonElement>(".graph-view-help-button") as HTMLButtonElement,
    );
    const dialog = container.querySelector<HTMLDialogElement>("dialog.graph-help-modal");
    await waitFor(() => expect(dialog?.open).toBe(true));

    // The close button carries class `modal-close` (shared with the run-
    // explorer modal); the help modal renders only one such button.
    fireEvent.click(dialog?.querySelector<HTMLButtonElement>(".modal-close") as HTMLButtonElement);
    await waitFor(() => expect(dialog?.open).toBe(false));
  });
});
