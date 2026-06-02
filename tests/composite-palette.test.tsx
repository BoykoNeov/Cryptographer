// @vitest-environment jsdom

/**
 * Palette "my elements" section (universal-port Phase 4f, Slice C).
 *
 * Renders `<StepPalette />` with saved composites in the store and checks the
 * section appears, lists each composite as a draggable entry, and that the
 * inline delete/rename actions drive the store reactively. We do NOT exercise
 * the real HTML5 drag (jsdom DataTransfer is partial — the Playwright smoke in
 * Slice E covers the live drag); the drop-side integration is tested in the
 * GraphView drop test (Slice D).
 */

import type { StepGroup } from "@/core/types";
import { StepPalette } from "@/ui/components/StepPalette";
import { __resetCompositesForTests, saveComposite } from "@/ui/stores/composites";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const template = (name: string): StepGroup => ({
  kind: "group",
  id: "round.1",
  label: name,
  defaultCollapsed: true,
  bodyOutput: { node: "round.1.x", port: "output" },
  children: [{ kind: "step", id: "round.1.x", type: "permute@1", params: {} }],
});

beforeEach(__resetCompositesForTests);
afterEach(() => {
  cleanup();
  __resetCompositesForTests();
  vi.restoreAllMocks();
});

describe("StepPalette — my elements section", () => {
  it("hides the section entirely when no composites are saved", () => {
    const { container } = render(() => <StepPalette />);
    expect(container.querySelector('[data-testid="step-palette-group-composites"]')).toBeNull();
  });

  it("lists a saved composite as a draggable entry carrying its id + name", () => {
    const def = saveComposite(template("AES Round"));
    const { container } = render(() => <StepPalette />);
    const section = container.querySelector('[data-testid="step-palette-group-composites"]');
    expect(section).not.toBeNull();
    const entry = container.querySelector<HTMLElement>(
      `[data-testid="composite-palette-entry-${def.id}"]`,
    );
    expect(entry).not.toBeNull();
    expect(entry?.getAttribute("data-composite-id")).toBe(def.id);
    expect(entry?.draggable).toBe(true);
    expect(entry?.textContent).toContain("AES Round");
  });

  it("the delete action removes the composite from the section", () => {
    const def = saveComposite(template("Doomed"));
    const { container } = render(() => <StepPalette />);
    const del = container.querySelector<HTMLButtonElement>(
      `[data-testid="composite-delete-${def.id}"]`,
    );
    expect(del).not.toBeNull();
    fireEvent.click(del as HTMLButtonElement);
    // Reactive: the signal change re-renders the For; the entry is gone, and
    // with no composites left the whole section disappears too.
    expect(container.querySelector(`[data-testid="composite-palette-entry-${def.id}"]`)).toBeNull();
    expect(container.querySelector('[data-testid="step-palette-group-composites"]')).toBeNull();
  });

  it("the rename action updates the displayed name via prompt", () => {
    const def = saveComposite(template("Old Name"));
    vi.spyOn(window, "prompt").mockReturnValue("New Name");
    const { container } = render(() => <StepPalette />);
    const rename = container.querySelector<HTMLButtonElement>(
      `[data-testid="composite-rename-${def.id}"]`,
    );
    fireEvent.click(rename as HTMLButtonElement);
    const entry = container.querySelector<HTMLElement>(
      `[data-testid="composite-palette-entry-${def.id}"]`,
    );
    expect(entry?.textContent).toContain("New Name");
  });
});
