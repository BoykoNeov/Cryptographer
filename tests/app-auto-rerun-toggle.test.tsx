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
import { __resetCipherModeForTests, setCipherMode } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests, useHistory } from "@/ui/stores/history";
import { __resetIvForTests, setIvBytes } from "@/ui/stores/iv";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, editStepParams } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
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

/**
 * Find the plaintext/ciphertext or key text input. We locate by the label's
 * leading text since both labels include the active byte format suffix
 * (e.g., "plaintext (hex)") that we don't want to hardcode.
 */
const findInputByLabelPrefix = (container: HTMLElement, prefix: string): HTMLInputElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(prefix));
  if (!target) throw new Error(`label starting with "${prefix}" not found`);
  const input = target.querySelector("input");
  if (!input) throw new Error(`input under "${prefix}" label not found`);
  return input as HTMLInputElement;
};

/** Drive a text input the way the user would. fireEvent.input is enough —
 * `onInput` is what the App listens to — but firing change too keeps us
 * symmetric with patterns in the CBC integration test. */
const typeInto = (input: HTMLInputElement, value: string): void => {
  fireEvent.input(input, { target: { value } });
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
    __resetCipherModeForTests();
    __resetIvForTests();
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
    __resetCipherModeForTests();
    __resetIvForTests();
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

  it("auto mode: typing new plaintext triggers a new run after debounce", async () => {
    const { container } = render(() => <App />);
    // The boot-time onMount run produces the first snapshot.
    await waitFor(() => {
      expect(useHistory()().length).toBe(1);
    });
    // Type a fresh plaintext. The default field text is a 16-byte hex
    // sequence; replace it with another valid 16-byte vector so the run
    // succeeds and produces a NEW snapshot (different bytes = different
    // trace = passes pushSnapshot dedup).
    const pt = findInputByLabelPrefix(container, "plaintext");
    typeInto(pt, "aa".repeat(16));
    // Debounce is 200ms — `waitFor` polls up to 1s.
    await waitFor(
      () => {
        expect(
          useHistory()().length,
          "plaintext edit should produce a new snapshot via auto-rerun",
        ).toBe(2);
      },
      { timeout: 1000 },
    );
  });

  it("auto mode: typing a new key triggers a new run after debounce", async () => {
    const { container } = render(() => <App />);
    await waitFor(() => {
      expect(useHistory()().length).toBe(1);
    });
    const key = findInputByLabelPrefix(container, "key");
    typeInto(key, "bb".repeat(16));
    await waitFor(
      () => {
        expect(useHistory()().length, "key edit should produce a new snapshot via auto-rerun").toBe(
          2,
        );
      },
      { timeout: 1000 },
    );
  });

  it("manual mode: typing new plaintext lights the pending banner without growing history", async () => {
    const { container } = render(() => <App />);
    await waitFor(() => {
      expect(useHistory()().length).toBe(1);
    });
    setAutoRerun(false);
    // Flush any debounced setTimeouts left over from previously-rendered
    // App instances in this file (their createEffect tracks the module-scoped
    // `spec` signal and fires on the beforeEach reset). The leaked
    // setTimeout closures fire run() against their own local input/key
    // state, which would otherwise inflate this test's history count.
    await new Promise((r) => setTimeout(r, 250));
    // Take a fresh baseline AFTER draining the leak so the assertion is
    // robust against test ordering.
    const baseline = useHistory()().length;
    const pt = findInputByLabelPrefix(container, "plaintext");
    typeInto(pt, "aa".repeat(16));
    // Dirty flag flips synchronously; the banner is up immediately.
    expect(container.querySelector(".pending-banner")).not.toBeNull();
    // The cipher must NOT have re-run. Wait past the would-be debounce to
    // make sure no late timer sneaks a snapshot in.
    await new Promise((r) => setTimeout(r, 250));
    expect(useHistory()().length).toBe(baseline);
  });

  it("manual mode: typing a new key lights the pending banner without growing history", async () => {
    const { container } = render(() => <App />);
    await waitFor(() => {
      expect(useHistory()().length).toBe(1);
    });
    setAutoRerun(false);
    // Same leaked-timer drain as the plaintext test above.
    await new Promise((r) => setTimeout(r, 250));
    const baseline = useHistory()().length;
    const key = findInputByLabelPrefix(container, "key");
    typeInto(key, "bb".repeat(16));
    expect(container.querySelector(".pending-banner")).not.toBeNull();
    await new Promise((r) => setTimeout(r, 250));
    expect(useHistory()().length).toBe(baseline);
  });

  it("auto mode: editing the IV in CBC produces a new run after debounce", async () => {
    // Switch to CBC BEFORE rendering so the boot run uses the CBC spec.
    setCipherMode("cbc");
    render(() => <App />);
    // Drain CBC boot + any leaked debounced timers from prior tests. After
    // this wait, history may be at MAX_HISTORY (5), which would break a
    // naive `baseline + 1` assertion because the next snapshot evicts the
    // oldest and length stays at 5. Reset to a clean baseline instead.
    await new Promise((r) => setTimeout(r, 500));
    __resetHistoryForTests();
    expect(useHistory()().length).toBe(0);
    // Stand in for the user pressing the 🎲 button. Using an explicit IV
    // (not randomizeIv) keeps the test deterministic.
    setIvBytes(new Uint8Array(16).fill(0xab));
    await waitFor(
      () => {
        expect(
          useHistory()().length,
          "IV edit in auto mode + CBC should produce a new snapshot",
        ).toBeGreaterThanOrEqual(1);
      },
      { timeout: 1000 },
    );
  });

  // Generous timeout because this test renders the full <App />, flips to
  // manual mode, then waits 250 ms × 3 for boot timers / debounce drains —
  // close enough to 5 s under heavy suite parallelism that the default
  // sometimes ticks past. Same pattern as `[[feedback-url-share-flake]]`.
  it(
    "manual mode: editing the IV in CBC lights the pending banner without growing history",
    { timeout: 15000 },
    async () => {
      setCipherMode("cbc");
      const { container } = render(() => <App />);
      // Drain boot + leaked timers, flip to manual, then drain once more so
      // any setTimeouts scheduled before the flip finish before we measure.
      await new Promise((r) => setTimeout(r, 250));
      setAutoRerun(false);
      await new Promise((r) => setTimeout(r, 250));
      __resetHistoryForTests();
      expect(useHistory()().length).toBe(0);
      setIvBytes(new Uint8Array(16).fill(0xcd));
      // Dirty flag is set synchronously in manual mode — banner up immediately.
      expect(container.querySelector(".pending-banner")).not.toBeNull();
      // Wait past the auto-rerun debounce to confirm no late timer sneaks
      // a snapshot in (would indicate the manual-mode branch failed).
      await new Promise((r) => setTimeout(r, 250));
      expect(useHistory()().length).toBe(0);
    },
  );

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
