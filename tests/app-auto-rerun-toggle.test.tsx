// @vitest-environment jsdom

/**
 * Integration test for the auto/manual rerun toggle (May 2026).
 *
 * The toggle's whole point is that batched spec edits in manual mode get
 * folded into ONE new run snapshot instead of one-per-edit — which is
 * what protects the prior snapshot from being evicted out of the 5-deep
 * history buffer before the user can compare against it.
 *
 * Two paths matter:
 *   1. Manual mode: edit the spec → no new run, banner appears, history
 *      stays at one snapshot. Click Run → banner clears, a new snapshot
 *      lands.
 *   2. Auto mode (default): edit the spec → a new run happens (via the
 *      200ms debounced effect), banner never appears, history grows.
 *
 * We drive the spec edit via `editStepParams` directly because that's
 * the same store mutator the ParamEditor uses — going through a specific
 * ParamEditor input adds noise unrelated to what we're testing here.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { findStep, updateStepParams } from "@/core/spec-mutations";
import { App } from "@/ui/App";
import { __resetAutoRerunForTests, setAutoRerun } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests, useHistory } from "@/ui/stores/history";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, editStepParams } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const findButton = (container: HTMLElement, text: string): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll("button"));
  const target = buttons.find((b) => b.textContent?.trim().startsWith(text));
  if (!target) throw new Error(`button "${text}" not found`);
  return target as HTMLButtonElement;
};

const findAutoRerunCheckbox = (container: HTMLElement): HTMLInputElement => {
  // The label is `.auto-rerun-toggle`; its checkbox is the only input child.
  const label = container.querySelector(".auto-rerun-toggle");
  if (!label) throw new Error("auto-rerun-toggle not found");
  const input = label.querySelector("input[type='checkbox']");
  if (!input) throw new Error("auto-rerun checkbox not found");
  return input as HTMLInputElement;
};

/** Pull the modified S-box bytes off the (round 1 sub-bytes) leaf. */
const tweakRound1Sbox = (): void => {
  const original = findStep(aes128Spec, "round.1.sub-bytes");
  const originalSbox = (original?.params as { sbox: number[] }).sbox;
  const tweaked = [...originalSbox];
  tweaked[0] = 0x00; // canonical AES sbox[0] is 0x63; force a delta.
  // Re-use updateStepParams on the canonical spec to discover the right
  // params shape (sbox key + any siblings); then push that through the
  // store mutator so the App's `on(spec)` effect fires.
  const next = updateStepParams(aes128Spec, "round.1.sub-bytes", { sbox: tweaked });
  const target = findStep(next, "round.1.sub-bytes");
  editStepParams("round.1.sub-bytes", target?.params ?? {});
};

describe("App — auto/manual rerun toggle", () => {
  beforeEach(() => {
    __resetAutoRerunForTests();
    __resetByteFormatForTests();
    __resetCipherForTests();
    __resetPaddingForTests();
    __resetSpecForTests();
    __resetHistoryForTests();
    __resetTraceForTests();
  });
  afterEach(() => {
    cleanup();
    __resetAutoRerunForTests();
    __resetByteFormatForTests();
    __resetCipherForTests();
    __resetPaddingForTests();
    __resetSpecForTests();
    __resetHistoryForTests();
    __resetTraceForTests();
  });

  it("renders the toggle in the inputs row, checked by default (auto mode)", () => {
    const { container } = render(() => <App />);
    const cb = findAutoRerunCheckbox(container);
    expect(cb.checked).toBe(true);
  });

  it("manual mode: spec edits don't produce new snapshots until Run is clicked", async () => {
    const { container } = render(() => <App />);
    const runBtn = findButton(container, "run");

    // 1. Initial Run → one snapshot in history.
    fireEvent.click(runBtn);
    expect(useHistory()().length).toBe(1);

    // 2. Switch to manual mode via the store (clicking the checkbox would
    //    also work; calling setAutoRerun is more direct and bypasses any
    //    in-DOM change-event quirks).
    setAutoRerun(false);
    expect(findAutoRerunCheckbox(container).checked).toBe(false);

    // 3. Edit the spec → banner should appear; history should NOT grow.
    tweakRound1Sbox();
    // Pending banner is rendered immediately (no debounce on the dirty flag).
    const banner = container.querySelector(".pending-banner");
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain("edits pending");
    // Critical assertion: no new snapshot from the edit.
    expect(useHistory()().length).toBe(1);

    // 4. Click Run → banner clears, a second snapshot lands.
    fireEvent.click(runBtn);
    expect(container.querySelector(".pending-banner")).toBeNull();
    expect(useHistory()().length).toBe(2);
  });

  it("flipping the toggle back ON clears the pending banner immediately", () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "run"));
    setAutoRerun(false);
    tweakRound1Sbox();
    // Banner is up.
    expect(container.querySelector(".pending-banner")).not.toBeNull();
    // Flip back to auto — the setter clears `dirty` to avoid stale visual
    // noise (the createEffect will pick up the next edit on its own).
    setAutoRerun(true);
    expect(container.querySelector(".pending-banner")).toBeNull();
  });

  it("manual mode: dirty banner stays up across multiple edits before a Run", () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "run"));
    setAutoRerun(false);

    tweakRound1Sbox();
    expect(container.querySelector(".pending-banner")).not.toBeNull();

    // Edit again — still one banner, still one snapshot. The user wants
    // to batch this whole flurry into one new run.
    const round1 = findStep(aes128Spec, "round.1.sub-bytes");
    const sbox = [...(round1?.params as { sbox: number[] }).sbox];
    sbox[5] = 0xaa;
    editStepParams("round.1.sub-bytes", { sbox });

    expect(container.querySelector(".pending-banner")).not.toBeNull();
    expect(useHistory()().length).toBe(1);
  });
});
