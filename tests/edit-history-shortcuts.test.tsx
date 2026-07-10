// @vitest-environment jsdom
/**
 * C4 jsdom tests for the undo/redo keyboard shortcuts + toolbar depth
 * accessors (Part C of `docs/plans/toasty-zooming-harp.md`).
 *
 * `installEditHistoryShortcuts` attaches a window `keydown` handler:
 *   Ctrl/Cmd+Z → undo, Ctrl/Cmd+Shift+Z / Ctrl/Cmd+Y → redo, and it BAILS
 * first on editable targets so Ctrl+Z inside a text field does native text
 * undo. These drive real synthetic KeyboardEvents through the installed
 * handler and assert the spec reverts (or doesn't, for the editable bail).
 *
 * NOTE: jsdom lets the test pick `e.key` freely, so the "Shift+letter arrives
 * uppercase" normalization can't be caught here — that's on the browser smoke.
 * These tests pin the wiring (handler installed, modifier gate, editable bail,
 * reactive depth accessors), not the real-browser key casing.
 */

import { __resetCipherForTests } from "@/ui/stores/cipher";
import {
  __resetEditHistoryForTests,
  installEditHistoryCapture,
  installEditHistoryShortcuts,
  useCanRedo,
  useCanUndo,
} from "@/ui/stores/edit-history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, editStepParams, useSpecsByMode } from "@/ui/stores/spec";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

let dispose = (): void => {};

const setup = (): void => {
  __resetSpecForTests();
  __resetCipherForTests();
  __resetLayoutsForTests();
  __resetViewDensityForTests();
  __resetEditHistoryForTests();
  createRoot((d) => {
    dispose = d;
    installEditHistoryCapture();
    installEditHistoryShortcuts();
  });
};

const dispatchKey = (target: EventTarget, init: KeyboardEventInit & { key: string }): void => {
  target.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, ...init }));
};

beforeEach(setup);
afterEach(() => {
  dispose();
  dispose = (): void => {};
  document.body.innerHTML = "";
  __resetEditHistoryForTests();
});

describe("edit-history C4 — keyboard shortcuts", () => {
  it("Ctrl+Z undoes the last edit and Ctrl+Shift+Z redoes it", () => {
    const original = useSpecsByMode()();
    editStepParams("round.1.sub-bytes", { __histTweak: 1 });
    const edited = useSpecsByMode()();
    expect(edited).not.toBe(original);

    dispatchKey(window, { key: "z", ctrlKey: true });
    expect(useSpecsByMode()()).toBe(original);

    dispatchKey(window, { key: "z", ctrlKey: true, shiftKey: true });
    expect(useSpecsByMode()()).toBe(edited);
  });

  it("Ctrl+Y also redoes (Windows convention)", () => {
    const original = useSpecsByMode()();
    editStepParams("round.1.sub-bytes", { __histTweak: 2 });
    dispatchKey(window, { key: "z", ctrlKey: true });
    expect(useSpecsByMode()()).toBe(original);

    dispatchKey(window, { key: "y", ctrlKey: true });
    expect(useSpecsByMode()()).not.toBe(original);
  });

  it("Cmd+Z (metaKey) works cross-platform", () => {
    const original = useSpecsByMode()();
    editStepParams("round.1.sub-bytes", { __histTweak: 3 });
    dispatchKey(window, { key: "z", metaKey: true });
    expect(useSpecsByMode()()).toBe(original);
  });

  it("does NOT hijack Ctrl+Z fired from inside an editable input (native text undo)", () => {
    editStepParams("round.1.sub-bytes", { __histTweak: 4 });
    const edited = useSpecsByMode()();

    const input = document.createElement("input");
    document.body.appendChild(input);
    // Event bubbles from the input to the window handler; `isEditableTarget`
    // must see the input as the target and bail, leaving the spec untouched.
    dispatchKey(input, { key: "z", ctrlKey: true });
    expect(useSpecsByMode()()).toBe(edited);
  });

  it("ignores a bare Z with no Ctrl/Cmd modifier", () => {
    editStepParams("round.1.sub-bytes", { __histTweak: 5 });
    const edited = useSpecsByMode()();
    dispatchKey(window, { key: "z" });
    expect(useSpecsByMode()()).toBe(edited);
  });
});

describe("edit-history C4 — reactive depth accessors (toolbar disable logic)", () => {
  it("useCanUndo/useCanRedo track the stacks so the buttons enable/disable", () => {
    // The accessors just read the stack-depth signals point-in-time (the
    // toolbar buttons wrap them in JSX `disabled={!canUndo()}`), so no tracking
    // scope is needed — and edits must stay OUTSIDE a createRoot to flush (the
    // C2 flush model). The observer from `setup()` is already live.
    const canUndo = useCanUndo();
    const canRedo = useCanRedo();

    // Fresh: both empty → both buttons disabled.
    expect(canUndo()).toBe(false);
    expect(canRedo()).toBe(false);

    editStepParams("round.1.sub-bytes", { __histTweak: 9 });
    expect(canUndo()).toBe(true);
    expect(canRedo()).toBe(false);

    dispatchKey(window, { key: "z", ctrlKey: true });
    expect(canUndo()).toBe(false);
    expect(canRedo()).toBe(true);
  });
});
