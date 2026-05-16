// @vitest-environment jsdom

/**
 * Tests for the `<ActionButton>` flash-on-click primitive. Pins three
 * behaviors that any future change to the primitive (or its CSS hooks)
 * must preserve:
 *
 *   1. `onAction` runs synchronously on click.
 *   2. The button gets a `flashing` class immediately after click; the
 *      class is removed after ~900ms (the visible "click landed"
 *      signal we promised in the plan).
 *   3. An `aria-live="polite"` region carries a meaningful label so
 *      screen-reader users hear what the click did.
 *
 * We deliberately use fake timers so the test runs in ~milliseconds
 * instead of waiting a real 900ms. The wall-clock duration is the
 * primitive's contract; the test pins the *transition*, not the
 * absolute number — adjusting `flashMs` in a future change should
 * update this test in one place.
 */

import { ActionButton } from "@/ui/components/ActionButton";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("ActionButton — flash-on-click feedback", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    cleanup();
  });

  it("calls onAction synchronously on click", () => {
    const onAction = vi.fn();
    const { getByRole } = render(() => <ActionButton onAction={onAction}>Click me</ActionButton>);

    fireEvent.click(getByRole("button"));

    expect(onAction).toHaveBeenCalledTimes(1);
  });

  it("adds the `flashing` class immediately on click and removes it after 900ms", () => {
    const { getByRole } = render(() => <ActionButton onAction={() => {}}>Repair</ActionButton>);

    const button = getByRole("button");

    // Before click: no flashing class.
    expect(button.className).not.toMatch(/\bflashing\b/);

    fireEvent.click(button);

    // Immediately after click: flashing class present.
    expect(button.className).toMatch(/\bflashing\b/);

    // Advance time past the flash window (default 900ms).
    vi.advanceTimersByTime(900);

    // After the flash: class removed.
    expect(button.className).not.toMatch(/\bflashing\b/);
  });

  it("announces the feedbackLabel via the live region and clears it after the flash window", () => {
    // The live region is a <output> element — implicit role="status"
    // + aria-live="polite", which is what screen readers respect.
    // We locate it by tag rather than by an `aria-live` attribute the
    // element no longer needs to spell out.
    const { getByRole, container } = render(() => (
      <ActionButton onAction={() => {}} feedbackLabel="Repaired S-box to a permutation">
        Repair
      </ActionButton>
    ));

    const liveRegion = container.querySelector("output");
    expect(liveRegion).not.toBeNull();
    // Before click: empty announcement.
    expect(liveRegion?.textContent ?? "").toBe("");

    fireEvent.click(getByRole("button"));

    // After click: announcement populated with the supplied label.
    expect(liveRegion?.textContent ?? "").toBe("Repaired S-box to a permutation");

    vi.advanceTimersByTime(900);

    // After the flash: cleared, so a re-click can re-trigger
    // (aria-live only announces *changes* in text content).
    expect(liveRegion?.textContent ?? "").toBe("");
  });

  it("falls back to the button text content when feedbackLabel is omitted", () => {
    const { getByRole, container } = render(() => (
      <ActionButton onAction={() => {}}>Do the thing</ActionButton>
    ));

    fireEvent.click(getByRole("button"));

    const liveRegion = container.querySelector("output");
    expect(liveRegion?.textContent ?? "").toBe("Do the thing");
  });

  it("preserves the caller's class while layering `action-button` and `flashing`", () => {
    const { getByRole } = render(() => (
      <ActionButton onAction={() => {}} class="sbox-warning-repair">
        Repair
      </ActionButton>
    ));

    const button = getByRole("button");
    // Resting state: action-button + caller's class, no flashing.
    expect(button.className).toMatch(/\baction-button\b/);
    expect(button.className).toMatch(/\bsbox-warning-repair\b/);
    expect(button.className).not.toMatch(/\bflashing\b/);

    fireEvent.click(button);

    // Flashing layered on without dropping the others.
    expect(button.className).toMatch(/\baction-button\b/);
    expect(button.className).toMatch(/\bsbox-warning-repair\b/);
    expect(button.className).toMatch(/\bflashing\b/);
  });

  it("forwards `disabled` and `title` to the underlying <button>", () => {
    const { getByRole } = render(() => (
      <ActionButton onAction={() => {}} disabled title="Tooltip text">
        Disabled action
      </ActionButton>
    ));

    const button = getByRole("button") as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.title).toBe("Tooltip text");
  });

  it("defaults `type` to 'button' so it never accidentally submits a form", () => {
    // Bare <button> defaults to type="submit" inside a <form>. Action
    // buttons are never form-submit triggers in this app, so the
    // primitive defaults to type="button". Easy to forget at call
    // sites; pinning here means we can drop `type="button"` from
    // callers without bugs.
    const { getByRole } = render(() => <ActionButton onAction={() => {}}>X</ActionButton>);
    expect((getByRole("button") as HTMLButtonElement).type).toBe("button");
  });

  it("respects a custom flashMs override", () => {
    const { getByRole } = render(() => (
      <ActionButton onAction={() => {}} flashMs={250}>
        Quick flash
      </ActionButton>
    ));

    const button = getByRole("button");
    fireEvent.click(button);
    expect(button.className).toMatch(/\bflashing\b/);

    // Still flashing at 200ms.
    vi.advanceTimersByTime(200);
    expect(button.className).toMatch(/\bflashing\b/);

    // Cleared by 300ms.
    vi.advanceTimersByTime(100);
    expect(button.className).not.toMatch(/\bflashing\b/);
  });
});
