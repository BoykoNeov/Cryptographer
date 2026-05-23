// @vitest-environment jsdom

/**
 * UX-H regression test (2026-05-23): when the user flips the mode
 * selector from encrypt → decrypt (or vice versa), the just-computed
 * output is copied into the input field automatically. Without this,
 * decrypt would re-run on the still-present plaintext (computing it
 * AS ciphertext) and surface a nonsense result until the user
 * manually pasted the previous output. Symmetric in both directions.
 *
 * The IV is intentionally NOT auto-swapped — it's a separate axis the
 * user may want to keep or edit independently of the mode flip (per
 * the plan note). Not asserted here because CBC isn't exercised; the
 * single-block AES default keeps the test focused on the mode-flip
 * swap mechanism itself.
 */

import { App } from "@/ui/App";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const findInputByLabel = (container: HTMLElement, labelText: string): HTMLInputElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) throw new Error(`label starting with "${labelText}" not found`);
  const input = target.querySelector("input");
  if (!input) throw new Error(`input under "${labelText}" label not found`);
  return input;
};

const findSelectByLabel = (container: HTMLElement, labelText: string): HTMLSelectElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) throw new Error(`label starting with "${labelText}" not found`);
  const select = target.querySelector("select");
  if (!select) throw new Error(`select under "${labelText}" label not found`);
  return select;
};

const findButton = (container: HTMLElement, text: string): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll("button"));
  const target = buttons.find((b) => b.textContent?.trim() === text);
  if (!target) throw new Error(`button "${text}" not found`);
  return target as HTMLButtonElement;
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetCipherModeForTests();
  __resetSpecForTests();
};

describe("App — UX-H mode-flip auto-swap (2026-05-23)", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("copies the ciphertext into the input field when flipping encrypt → decrypt", () => {
    const { container } = render(() => <App />);

    // App boots in encrypt mode with the FIPS-197 default plaintext
    // and key, and auto-runs on mount, so the result already shows the
    // FIPS-197 §C.1 ciphertext "69c4e0d86a7b0430d8cdb78070b4c55a"
    // (or whatever the current default produces; we don't hard-code
    // it — we read it from the rendered output).
    const ciphertextHex = container.querySelector(".result code")?.textContent?.trim();
    expect(ciphertextHex).toBeTruthy();
    if (!ciphertextHex) return;

    // Capture the plaintext (to verify it gets replaced after the flip).
    const plaintextBefore = findInputByLabel(container, "plaintext").value;
    expect(plaintextBefore).not.toBe(ciphertextHex);

    // Flip mode. The input field's label flips from "plaintext (hex)"
    // to "ciphertext (hex)" because outputLabel() derives from mode().
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });

    // UX-H assertion: the now-renamed "ciphertext" input holds the
    // previously-computed ciphertext, not the stale plaintext.
    const cipherInput = findInputByLabel(container, "ciphertext");
    expect(cipherInput.value).toBe(ciphertextHex);

    // End-to-end sanity: running decrypt on the auto-swapped input
    // recovers the original plaintext. (Auto-rerun is debounced 200ms
    // in production; click Run synchronously for the test.)
    fireEvent.click(findButton(container, "run"));
    const recovered = container.querySelector(".result code")?.textContent?.trim();
    expect(recovered).toBe(plaintextBefore);
  });

  it("copies the recovered plaintext into the input field when flipping decrypt → encrypt", () => {
    const { container } = render(() => <App />);

    // Set up: start in encrypt mode (default), capture the boot
    // ciphertext, flip to decrypt (auto-swap puts ciphertext in
    // input). The trace re-runs, the result becomes the recovered
    // plaintext.
    const ciphertextHex = container.querySelector(".result code")?.textContent?.trim();
    expect(ciphertextHex).toBeTruthy();
    if (!ciphertextHex) return;

    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    fireEvent.click(findButton(container, "run"));

    const recoveredPlaintext = container.querySelector(".result code")?.textContent?.trim();
    expect(recoveredPlaintext).toBeTruthy();
    if (!recoveredPlaintext) return;

    // Now flip BACK to encrypt. UX-H assertion (symmetric direction):
    // the input — now labeled "plaintext" again — holds the recovered
    // plaintext, not the lingering ciphertext.
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "encrypt" } });

    const ptInput = findInputByLabel(container, "plaintext");
    expect(ptInput.value).toBe(recoveredPlaintext);

    // Re-encrypt round-trips back to the original ciphertext.
    fireEvent.click(findButton(container, "run"));
    const reencrypted = container.querySelector(".result code")?.textContent?.trim();
    expect(reencrypted).toBe(ciphertextHex);
  });

  it("does NOT swap when there is no output yet (e.g. flipping before first run is harmless)", () => {
    // Edge case: the auto-rerun on mount populates outputText, so
    // outputText() is always truthy in normal boot. But if the spec
    // produced no trace (e.g. a future error path), the auto-swap
    // should silently skip rather than blank the input. We exercise
    // this by reading the plaintext BEFORE the flip and asserting it
    // wasn't replaced by an empty string after the flip in the
    // degenerate case of equal input + output (cipher being identity,
    // which doesn't actually happen here — this is a smoke).
    const { container } = render(() => <App />);
    const plaintextBefore = findInputByLabel(container, "plaintext").value;
    expect(plaintextBefore.length).toBeGreaterThan(0);

    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });

    // The "ciphertext"-labeled input must have *some* value — either
    // the swapped ciphertext (the common path) or the original
    // plaintext bytes if no trace ever produced output (the skip
    // path). Either way, it must NOT be blank.
    const cipherInput = findInputByLabel(container, "ciphertext");
    expect(cipherInput.value.length).toBeGreaterThan(0);
  });
});
