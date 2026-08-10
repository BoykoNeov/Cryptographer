// @vitest-environment jsdom

/**
 * ML-KEM-768 reached through the UI (P4 of
 * `docs/plans/unified-stargazing-quasar.md`).
 *
 * `tests/ml-kem-768-kat.test.ts` proves the cryptography headlessly. This file
 * exists because of a bug that suite could never have seen, and which a browser
 * found on the first click.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE BUG: A VARIANT SWITCH THAT NOTHING SWAPPED
 *
 * RSA was the only member of the public-key family, so switching *variant*
 * within it was unreachable and the dropdown wired straight to `setAsymmetric`
 * — no smart input swap, unlike `changeHash` and `changePrng`. ML-KEM made the
 * switch reachable, and the first click on it left RSA's 2-byte message in the
 * field. The trace died on
 *
 *     zq-vec-add: ports "a" (512 bytes) and "b" (32 bytes) must be the same length
 *
 * — a stale-input problem wearing the costume of a polynomial-arithmetic bug.
 * Nothing in the headless suite touches that handler, and every KAT passed.
 *
 * The second half of the fix is the MODE-AWARENESS: this family's defaults now
 * differ by direction (a 32-byte message vs a 1088-byte ciphertext), so the
 * comparison and the swap both have to be taken at the current mode. Comparing
 * an encapsulation-shaped default while sitting in decapsulation would never
 * match and the field would silently keep the wrong bytes — which is why the
 * decrypt-direction case below is asserted separately rather than assumed.
 *
 * Driving via real <select>/<input> events, not the store setters: the store
 * setter only flips the signal, and the App's handler is the thing under test.
 */

import { ML_KEM_DEFAULT_CIPHERTEXT, ML_KEM_DEFAULT_MESSAGE } from "@/ciphers/ml-kem-768";
import { App } from "@/ui/App";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

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

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
};

/** Public-key category, then the ML-KEM variant — the exact two clicks. */
const selectMlKem = (container: HTMLElement): void => {
  fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "asymmetric" } });
  fireEvent.change(findSelectByLabel(container, "algorithm"), {
    target: { value: "ml-kem-768" },
  });
};

describe("App — ML-KEM-768 in the public-key family", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("offers both public-key variants and keeps the family's surfaces", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "asymmetric" } });

    const algo = findSelectByLabel(container, "algorithm");
    expect(Array.from(algo.querySelectorAll("option")).map((o) => o.value)).toEqual([
      "rsa",
      "ml-kem-768",
    ]);

    fireEvent.change(algo, { target: { value: "ml-kem-768" } });

    // A KEM has a key PAIR but no symmetric key, no mode of operation and no
    // padding — the whole reason it went in this family rather than becoming a
    // cipher. `isAsymmetric` being membership is what keeps this true.
    expect(labelExists(container, "key")).toBe(false);
    expect(labelExists(container, "cipher-mode")).toBe(false);
    expect(labelExists(container, "padding")).toBe(false);
    expect(labelExists(container, "mode")).toBe(true);
  });

  it("swaps RSA's message for ML-KEM's when the variant changes (the bug)", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "asymmetric" } });
    expect(findInputByLabel(container, "message").value).toBe("0041");

    fireEvent.change(findSelectByLabel(container, "algorithm"), {
      target: { value: "ml-kem-768" },
    });

    // Without the swap this stayed "0041" and the run died inside the lattice
    // arithmetic — 32 bytes is what the message decodes to as a polynomial.
    expect(findInputByLabel(container, "message").value).toBe(hex(ML_KEM_DEFAULT_MESSAGE));
  });

  it("swaps the DECRYPT-direction default too, which is a separate branch", () => {
    // The mode-aware half. Sitting in decapsulation, the field holds RSA's
    // canonical CIPHERTEXT, and the value that must replace it is the
    // 1088-byte one — not the 32-byte message. A mode-blind swap compares
    // against the encrypt-side default, never matches, and silently leaves
    // RSA's two bytes in a field that wants 1088.
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "asymmetric" } });
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    // Set RSA's canonical ciphertext explicitly. The mode flip itself copies
    // the previously COMPUTED output across (a separate, deliberate UX rule),
    // and in a freshly rendered App that output is still the boot cipher's —
    // so relying on the flip to seed this would be testing the wrong handler.
    fireEvent.input(findInputByLabel(container, "ciphertext"), { target: { value: "0ae6" } });

    fireEvent.change(findSelectByLabel(container, "algorithm"), {
      target: { value: "ml-kem-768" },
    });

    expect(findInputByLabel(container, "ciphertext").value).toBe(hex(ML_KEM_DEFAULT_CIPHERTEXT));
  });

  it("leaves a user-typed message alone, like every other family's swap", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "asymmetric" } });
    fireEvent.input(findInputByLabel(container, "message"), { target: { value: "0042" } });

    fireEvent.change(findSelectByLabel(container, "algorithm"), {
      target: { value: "ml-kem-768" },
    });

    // Sacred input: only a value equal to the PREVIOUS variant's canonical
    // default is replaced. This one will fail the length check on Run, which is
    // correct — it is the user's value, and silently overwriting it is worse.
    expect(findInputByLabel(container, "message").value).toBe("0042");
  });

  it("names the endpoints as a KEM's, not an encryption scheme's", () => {
    // A KEM does not transport a chosen message and does not return a
    // plaintext. If these read "message"/"message" the labels would teach the
    // wrong model, which is the one thing the UI can get wrong on its own.
    const { container } = render(() => <App />);
    selectMlKem(container);
    expect(labelExists(container, "message m (random)")).toBe(true);

    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    expect(labelExists(container, "ciphertext")).toBe(true);
    expect(container.textContent).toContain("shared secret");
  });
});
