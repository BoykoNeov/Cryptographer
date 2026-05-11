// @vitest-environment jsdom

/**
 * Integration test for the cipher selector (AES-128 / 192 / 256).
 *
 * The KAT files (`aes-192-vectors.test.ts`, `aes-256-vectors.test.ts`) prove
 * the engine and key-expansion math are correct. This file proves the user
 * can actually REACH those code paths through the UI:
 *
 *   1. The cipher dropdown renders all three options.
 *   2. Selecting AES-192 swaps the key field to the canonical FIPS §A.2
 *      key in the active byte format (auto-swap policy — only fires when
 *      the field still holds the previous cipher's default).
 *   3. Clicking Run after the swap produces the canonical NIST AES Core 192
 *      ciphertext. Verifies that App.run() reads the key length off the
 *      live spec (24 bytes) rather than the hardcoded 16.
 *   4. AES-256 swap + Run produces the canonical AES Core 256 ciphertext.
 *   5. A USER-TYPED key is NEVER clobbered by a cipher change (mirrors the
 *      sacred-input policy from `changePadding`). This is the regression
 *      guard for "Claude tried to be helpful and overwrote my custom key".
 *
 * Driving via the actual <select> change events (not setCipher directly)
 * is intentional — the same trap as the format-toggle pitfall in CLAUDE.md.
 * setCipher only updates the signal; the App's `changeCipher` handler is
 * what swaps the key field text.
 */

import { App } from "@/ui/App";
import { __resetCipherForTests } from "@/ui/stores/cipher";
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

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
};

// FIPS-197 §A.1/§A.2/§A.3 canonical keys. These match what the cipher
// store hands the App, so on a default load the key field should always
// equal one of these for the currently-selected cipher.
const AES_128_KEY_HEX = "000102030405060708090a0b0c0d0e0f";
const AES_192_KEY_HEX = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const AES_256_KEY_HEX = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

describe("App — cipher selector", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders all three AES variants in the cipher dropdown", () => {
    const { container } = render(() => <App />);
    const select = findSelectByLabel(container, "cipher");
    const values = Array.from(select.querySelectorAll("option")).map((o) => o.value);
    expect(values).toEqual(["aes-128", "aes-192", "aes-256"]);
  });

  it("defaults to AES-128 with the FIPS-197 §A.1 key on fresh load", () => {
    const { container } = render(() => <App />);
    const select = findSelectByLabel(container, "cipher");
    expect(select.value).toBe("aes-128");
    const keyInput = findInputByLabel(container, "key");
    expect(keyInput.value).toBe(AES_128_KEY_HEX);
  });

  it("swaps the key field to AES-192 default when cipher changes from AES-128", () => {
    const { container } = render(() => <App />);
    const select = findSelectByLabel(container, "cipher");

    fireEvent.change(select, { target: { value: "aes-192" } });

    expect(select.value).toBe("aes-192");
    const keyInput = findInputByLabel(container, "key");
    expect(keyInput.value).toBe(AES_192_KEY_HEX);
  });

  it("encrypts under AES-192 and produces the NIST AES Core 192 ciphertext end-to-end", () => {
    const { container } = render(() => <App />);

    // Switch cipher first — this auto-swaps the key to §A.2's canonical 24-byte
    // key. The plaintext field still holds the FIPS 16-byte sequential vector
    // (block size is identical across all AES variants), which is what we'll
    // encrypt under AES-192.
    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "aes-192" },
    });

    // Replace the plaintext with the NIST AES Core 192 input. It's the matching
    // half of the (key, plaintext, ciphertext) triple that the KAT tests
    // assert against.
    const ptInput = findInputByLabel(container, "plaintext");
    fireEvent.input(ptInput, { target: { value: "6bc1bee22e409f96e93d7e117393172a" } });

    fireEvent.click(findButton(container, "run"));

    // No error banner.
    expect(container.querySelector(".error")).toBeNull();
    // Result line shows the canonical ciphertext.
    const result = container.querySelector(".result code")?.textContent ?? "";
    expect(result).toBe("bd334f1d6e45f25ff712a214571fa5cc");
  });

  it("encrypts under AES-256 and produces the NIST AES Core 256 ciphertext end-to-end", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "aes-256" },
    });

    const keyInput = findInputByLabel(container, "key");
    expect(keyInput.value).toBe(AES_256_KEY_HEX);

    const ptInput = findInputByLabel(container, "plaintext");
    fireEvent.input(ptInput, { target: { value: "6bc1bee22e409f96e93d7e117393172a" } });

    fireEvent.click(findButton(container, "run"));

    expect(container.querySelector(".error")).toBeNull();
    const result = container.querySelector(".result code")?.textContent ?? "";
    expect(result).toBe("f3eed1bdb5d2a03c064b5a7e3db181f8");
  });

  it("does NOT clobber a user-typed key when the cipher changes", () => {
    const { container } = render(() => <App />);
    const keyInput = findInputByLabel(container, "key");

    // Type a custom 16-byte key (all-zeros) — distinct from any canonical
    // default, so the swap policy should leave it alone.
    fireEvent.input(keyInput, { target: { value: "00000000000000000000000000000000" } });

    // Switch to AES-192. App should NOT swap to the §A.2 default because the
    // current value isn't the AES-128 canonical default.
    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "aes-192" },
    });

    expect(keyInput.value).toBe("00000000000000000000000000000000");
    // Bonus: Run should now produce a friendly error (16 bytes ≠ expected 24).
    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")?.textContent ?? "").toMatch(/key/i);
  });
});
