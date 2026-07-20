// @vitest-environment jsdom

/**
 * Headline integration test for the multi-block ECB feature (Phase 1).
 *
 * The whole point: pick cipher-mode = ECB, type a multi-block plaintext,
 * encrypt, decrypt, recover the same plaintext. Catches wiring bugs in
 * the cipher-mode dropdown ↔ spec store ↔ padding overlay ↔ Run handler
 * chain, all of which are non-trivial under multi-block.
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
  const target = buttons.find((b) => b.textContent?.trim().startsWith(text));
  if (!target) throw new Error(`button "${text}" not found`);
  return target as HTMLButtonElement;
};

const findFormatButton = (container: HTMLElement, label: string): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll(".format-toggle button"));
  const target = buttons.find((b) => b.textContent?.trim() === label);
  if (!target) throw new Error(`format button "${label}" not found`);
  return target as HTMLButtonElement;
};

const setInputValue = (input: HTMLInputElement, value: string): void => {
  // Use both input and change events because the App might listen on either.
  fireEvent.input(input, { target: { value } });
  fireEvent.change(input, { target: { value } });
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetCipherModeForTests();
  __resetSpecForTests();
};

describe("App — multi-block ECB round-trip (Phase 1)", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("encrypts a multi-block plaintext under ECB+PKCS#7 then decrypts to recover it", () => {
    const { container } = render(() => <App />);

    // 1. Switch to ECB mode of operation.
    fireEvent.change(findSelectByLabel(container, "mode of operation"), {
      target: { value: "ecb" },
    });
    expect(findSelectByLabel(container, "mode of operation").value).toBe("ecb");

    // 2. Select PKCS#7 padding (so input length can be arbitrary).
    fireEvent.change(findSelectByLabel(container, "padding"), {
      target: { value: "pkcs7" },
    });

    // 3. Switch format to ASCII so we can type a readable plaintext.
    fireEvent.click(findFormatButton(container, "ASCII"));

    // 4. Type a 26-character plaintext spanning 2 blocks (16 + 10 = 26 bytes).
    const PLAINTEXT = "the quick brown fox jumps over";
    expect(PLAINTEXT.length).toBe(30);
    setInputValue(findInputByLabel(container, "plaintext"), PLAINTEXT);

    // 5. Run encrypt.
    fireEvent.click(findButton(container, "run"));
    const errAfterEncrypt = container.querySelector(".error");
    expect(errAfterEncrypt).toBeFalsy();

    // 6. Verify ciphertext rendered (exact characters depend on byte format
    // and printable-byte rendering; we round-trip below to verify correctness).
    expect(container.querySelector(".result code")).toBeTruthy();

    // 7. Switch to decrypt. UX-H (2026-05-23) auto-swap copies the
    // just-computed ciphertext into the input field — no manual paste
    // needed. The format flip + manual paste from the pre-UX-H version
    // is now redundant.
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });

    // 8. Run decrypt on the auto-swapped ciphertext. (The auto-rerun
    // effect is debounced 200ms in production; tests trigger Run
    // synchronously to avoid the wait.)
    fireEvent.click(findButton(container, "run"));
    const errAfterDecrypt = container.querySelector(".error");
    expect(errAfterDecrypt).toBeFalsy();

    // 9. Read recovered plaintext (still in ASCII format from step 3).
    const recovered = container.querySelector(".result code")?.textContent?.trim();
    expect(recovered).toBe(PLAINTEXT);
  });

  it("cipher-mode dropdown enables ECB + CBC + CTR for a cipher with a core", () => {
    const { container } = render(() => <App />);
    const sel = findSelectByLabel(container, "mode of operation");
    const cbcOption = Array.from(sel.options).find((o) => o.value === "cbc");
    const ctrOption = Array.from(sel.options).find((o) => o.value === "ctr");
    // All three multi-block modes now ship. CTR was the last, and it cost one
    // mode file plus one arithmetic step — no change to `BlockCipherCore`.
    expect(cbcOption?.disabled).toBe(false);
    expect(ctrOption?.disabled).toBe(false);
    const ecbOption = Array.from(sel.options).find((o) => o.value === "ecb");
    expect(ecbOption?.disabled).toBe(false);
  });
});
