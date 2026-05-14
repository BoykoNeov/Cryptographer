// @vitest-environment jsdom

/**
 * Custom-spec indicator + reset-to-canonical button.
 *
 * When the user edits the cipher (param tweak via ParamEditor, palette
 * insert, delete) the spec diverges from the canonical default for the
 * selected (cipher, cipherMode, mode, padding). The header label and
 * the cipher dropdown's selected option both switch from the canonical
 * name to "Custom (was <variant>)" so the divergence is visible at a
 * glance, and a small "reset" button appears next to the dropdown that
 * snaps the spec back to canonical.
 *
 * Tests pinned here (each its own regression guard):
 *   1. Fresh AES-128 load shows the canonical name, no reset button,
 *      no .is-custom class on the header span.
 *   2. After editStepParams on any step, both the header and the dropdown
 *      flip to "Custom (was AES-128)", and the reset button is rendered.
 *   3. Clicking reset restores the canonical name + hides the reset
 *      button. (Round-trip property of `resetSpec`.)
 *   4. Switching cipher (AES-128 → AES-192) clears the "Custom" state
 *      because setCipher replaces the spec with the new canonical default.
 *   5. Flipping the padding selector on an UNMODIFIED spec keeps
 *      isCustomSpec() false. This is the edge case the advisor flagged:
 *      `setPadding` rebuilds via `applyPaddingScheme` from the live
 *      spec — if that left residual fields the comparison would flag a
 *      false-positive "custom".
 */

import { App } from "@/ui/App";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, editStepParams, isCustomSpec, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const findSelectByLabel = (container: HTMLElement, labelText: string): HTMLSelectElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) throw new Error(`label starting with "${labelText}" not found`);
  const select = target.querySelector("select");
  if (!select) throw new Error(`select under "${labelText}" label not found`);
  return select;
};

const headerCipherName = (container: HTMLElement): HTMLSpanElement => {
  const span = container.querySelector(".cipher-name");
  if (!span) throw new Error(".cipher-name span not found");
  return span as HTMLSpanElement;
};

const selectedCipherOption = (container: HTMLElement): HTMLOptionElement => {
  const select = findSelectByLabel(container, "cipher");
  const opt = select.options[select.selectedIndex];
  if (!opt) throw new Error("no selected option under cipher select");
  return opt;
};

const resetButton = (container: HTMLElement): HTMLButtonElement | null =>
  container.querySelector(".reset-spec-button");

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetAutoRerunForTests();
};

describe("App — custom-spec indicator", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders canonical name + no reset button on fresh AES-128 load", () => {
    const { container } = render(() => <App />);
    expect(headerCipherName(container).textContent?.trim()).toBe("AES-128");
    expect(headerCipherName(container).classList.contains("is-custom")).toBe(false);
    expect(selectedCipherOption(container).textContent?.trim()).toBe("AES-128");
    expect(resetButton(container)).toBeNull();
    expect(isCustomSpec()).toBe(false);
  });

  it("flips header + dropdown to 'Custom (was AES-128)' after a param edit", () => {
    const { container } = render(() => <App />);

    // Drive the same store mutation the ParamEditor would. Round-key-0 is
    // a leaf that exists in every AES-128 canonical spec; changing its
    // params is the most direct way to force a spec divergence.
    const firstLeaf = findFirstEditableLeafId();
    editStepParams(firstLeaf, { tweak: "yes" });

    expect(isCustomSpec()).toBe(true);
    const header = headerCipherName(container);
    expect(header.textContent?.trim()).toBe("Custom (was AES-128)");
    expect(header.classList.contains("is-custom")).toBe(true);
    expect(selectedCipherOption(container).textContent?.trim()).toBe("Custom (was AES-128)");
    expect(resetButton(container)).not.toBeNull();
  });

  it("clicking reset restores canonical name + hides the reset button", () => {
    const { container } = render(() => <App />);

    const firstLeaf = findFirstEditableLeafId();
    editStepParams(firstLeaf, { tweak: "yes" });
    expect(isCustomSpec()).toBe(true);

    const btn = resetButton(container);
    if (!btn) throw new Error("reset button should be visible while custom");
    fireEvent.click(btn);

    expect(isCustomSpec()).toBe(false);
    expect(headerCipherName(container).textContent?.trim()).toBe("AES-128");
    expect(selectedCipherOption(container).textContent?.trim()).toBe("AES-128");
    expect(resetButton(container)).toBeNull();
  });

  it("switching cipher clears the Custom state (new canonical replaces spec)", () => {
    const { container } = render(() => <App />);

    editStepParams(findFirstEditableLeafId(), { tweak: "yes" });
    expect(isCustomSpec()).toBe(true);

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "aes-192" },
    });

    expect(isCustomSpec()).toBe(false);
    expect(headerCipherName(container).textContent?.trim()).toBe("AES-192");
    expect(resetButton(container)).toBeNull();
  });

  it("flipping padding scheme on unmodified spec does NOT flag Custom", () => {
    const { container } = render(() => <App />);
    expect(isCustomSpec()).toBe(false);

    // none → pkcs7 → zero-pad → pkcs7 → none round-trip. Each setPadding
    // rebuilds the spec via applyPaddingScheme from the live tree; if any
    // step left residual fields that aren't on a freshly-built canonical
    // default for the same (cipher, mode, padding), the deep-equal would
    // flag a false-positive "modified".
    const paddingSelect = findSelectByLabel(container, "padding");
    for (const scheme of ["pkcs7", "zero-pad", "iso7816-4", "pkcs7", "none"]) {
      fireEvent.change(paddingSelect, { target: { value: scheme } });
      expect(isCustomSpec()).toBe(false);
      expect(headerCipherName(container).classList.contains("is-custom")).toBe(false);
    }
  });
});

/**
 * Walk the live spec and return the id of the first non-padding step
 * leaf — that's a stable, always-present mutation target across the AES
 * canonical specs. (Padding-overlay leaves only exist when a padding
 * scheme is active; round-0/round-1 leaves are always there.)
 */
const findFirstEditableLeafId = (): string => {
  const spec = useSpec()();
  const visit = (
    nodes: readonly { kind: string; id: string; type?: string; children?: readonly unknown[] }[],
  ): string | null => {
    for (const n of nodes) {
      if (
        n.kind === "step" &&
        n.type &&
        !n.type.includes("pkcs7") &&
        !n.type.includes("zero-pad") &&
        !n.type.includes("iso7816") &&
        !n.type.includes("load-block") &&
        !n.type.includes("store-block")
      ) {
        return n.id;
      }
      if (n.kind !== "step" && Array.isArray(n.children)) {
        const found = visit(n.children as never);
        if (found) return found;
      }
    }
    return null;
  };
  const id = visit(spec.steps as never);
  if (!id) throw new Error("no editable leaf found in spec");
  return id;
};
