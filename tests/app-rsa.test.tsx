// @vitest-environment jsdom

/**
 * Integration test for the RSA (public-key / asymmetric) category in the App
 * (Phase 3 of `docs/plans/shimmying-booping-moth.md`).
 *
 * `tests/rsa-vectors.test.ts` proves the math headlessly. This file proves the
 * user can REACH it through the UI:
 *
 *   1. The "kind" selector offers a Public-key category; choosing it swaps in
 *      the RSA algorithm dropdown and HIDES the symmetric-key field + the
 *      cipher-mode / padding selectors (a key field for RSA would miseducate).
 *   2. The mode selector stays (RSA has encrypt/decrypt direction, unlike a
 *      hash) and the default message encrypts to the textbook ciphertext.
 *   3. Encrypt m=65 → c=2790, then decrypt c=2790 → m=65 end-to-end (the
 *      same vector the headless KAT pins, reached through real DOM events).
 *   4. A message m ≥ n is rejected with a friendly value-based error (the
 *      `m < n` guard — without it the ladder silently computes m mod n).
 *
 * Driving via real <select>/<input>/<button> events (not the store setters)
 * is intentional — the same trap as the cipher-selector test: `setAsymmetric`
 * only flips the signal; the App's `changeCategory` handler is what swaps the
 * input field + hides the symmetric surfaces.
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

const findSelectByLabel = (container: HTMLElement, labelText: string): HTMLSelectElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) throw new Error(`label starting with "${labelText}" not found`);
  const select = target.querySelector("select");
  if (!select) throw new Error(`select under "${labelText}" label not found`);
  return select;
};

const findInputByLabel = (container: HTMLElement, labelText: string): HTMLInputElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) throw new Error(`input label starting with "${labelText}" not found`);
  const input = target.querySelector("input");
  if (!input) throw new Error(`input under "${labelText}" not found`);
  return input;
};

const labelExists = (container: HTMLElement, labelText: string): boolean =>
  Array.from(container.querySelectorAll("label")).some((l) =>
    l.textContent?.trim().startsWith(labelText),
  );

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

/** Switch the App into the RSA (asymmetric) category via the kind selector. */
const selectRsa = (container: HTMLElement): void => {
  fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "asymmetric" } });
};

describe("App — RSA (public-key) category", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("offers a Public-key kind that swaps in the RSA dropdown and hides key/mode-of-operation/padding", () => {
    const { container } = render(() => <App />);
    const kind = findSelectByLabel(container, "kind");
    expect(Array.from(kind.querySelectorAll("option")).map((o) => o.value)).toEqual([
      "cipher",
      "hash",
      "asymmetric",
    ]);

    selectRsa(container);

    // RSA algorithm dropdown present + selected.
    const algo = findSelectByLabel(container, "algorithm");
    expect(algo.value).toBe("rsa");
    // Symmetric-only surfaces hidden.
    expect(labelExists(container, "key")).toBe(false);
    expect(labelExists(container, "cipher-mode")).toBe(false);
    expect(labelExists(container, "padding")).toBe(false);
    // Direction stays — RSA encrypts and decrypts.
    expect(labelExists(container, "mode")).toBe(true);
  });

  it("encrypts the default message m=65 to the textbook ciphertext c=2790 (0x0ae6)", () => {
    const { container } = render(() => <App />);
    selectRsa(container);

    // Default message swapped in by changeCategory: 65 as a 2-byte BE hex int.
    expect(findInputByLabel(container, "message").value).toBe("0041");

    fireEvent.click(findButton(container, "run"));

    expect(container.querySelector(".error")).toBeNull();
    expect(container.querySelector(".result code")?.textContent ?? "").toBe("0ae6");
  });

  it("decrypts the ciphertext c=2790 back to the message m=65", () => {
    const { container } = render(() => <App />);
    selectRsa(container);

    // Flip to decrypt (input label becomes "ciphertext"), feed c=2790.
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    fireEvent.input(findInputByLabel(container, "ciphertext"), { target: { value: "0ae6" } });

    fireEvent.click(findButton(container, "run"));

    expect(container.querySelector(".error")).toBeNull();
    expect(container.querySelector(".result code")?.textContent ?? "").toBe("0041");
  });

  it("rejects a message m ≥ n with a friendly value-based error", () => {
    const { container } = render(() => <App />);
    selectRsa(container);

    // 0xffff = 65535 ≥ n = 3233 → must be rejected (else the ladder would
    // silently compute m mod n and the round-trip would not recover m).
    fireEvent.input(findInputByLabel(container, "message"), { target: { value: "ffff" } });
    fireEvent.click(findButton(container, "run"));

    const err = container.querySelector(".error")?.textContent ?? "";
    expect(err).toMatch(/less than the modulus/);
  });
});
