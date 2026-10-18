// @vitest-environment jsdom

/**
 * ML-DSA-44 reached through the UI (P4 of `docs/plans/refactored-petting-tide.md`).
 *
 * `tests/ml-dsa-44-sign.test.ts` proves the cryptography headlessly. This file
 * covers what only the App can get wrong:
 *
 * 1. **The selector entry** — the public-key family gains a third member, and
 *    switching to it swaps the previous variant's default input for ML-DSA's
 *    (the ML-KEM stale-input bug, which a browser found, re-checked here).
 * 2. **The labels** — signing turns a message into a signature and
 *    verification turns a signature into a verdict. Nothing type-checks a
 *    label, so they are read as strings.
 * 3. **The opt-in message copy** (the user's decision, 2026-10-18). Verify
 *    checks its own message step; flipping from Sign carries the SIGNATURE
 *    across but never the message, so a learner who signed something else gets
 *    INVALID until they click "Use the message from Sign". The click must be
 *    what makes it valid — asserted both ways, so a copy that happened on its
 *    own would fail the test.
 *
 * Driven through real <select>/<input> events: the App's handlers are what is
 * under test, not the store setters.
 */

import { ML_DSA_44_DEFAULT_MESSAGE, ML_DSA_44_DEFAULT_SIGNATURE } from "@/ciphers/ml-dsa-44";
import { App } from "@/ui/App";
import { endpointLabelsFor } from "@/ui/stores/cipher";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSignedMessageForTests } from "@/ui/stores/signed-message";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
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

/** The result row's value, once a run has produced one. */
const resultText = (container: HTMLElement): string | null =>
  container.querySelector(".inputs-result code")?.textContent ?? null;

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetSignedMessageForTests();
};

const selectMlDsa = (container: HTMLElement): void => {
  fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "asymmetric" } });
  fireEvent.change(findSelectByLabel(container, "algorithm"), { target: { value: "ml-dsa-44" } });
};

const run = (container: HTMLElement): void => {
  const button = Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent?.trim() === "run",
  );
  if (!button) throw new Error("run button not found");
  fireEvent.click(button);
};

describe("endpointLabelsFor — one source for the sidebar and the graph pills", () => {
  it("names a signature scheme's endpoints for what they are", () => {
    expect(endpointLabelsFor("ml-dsa-44", "encrypt")).toEqual({
      input: "message",
      output: "signature",
    });
    expect(endpointLabelsFor("ml-dsa-44", "decrypt")).toEqual({
      input: "signature",
      output: "verdict",
    });
  });

  it("names ML-KEM's the way the sidebar always did (the graph pills used to disagree)", () => {
    expect(endpointLabelsFor("ml-kem-768", "encrypt")).toEqual({
      input: "message m (random)",
      output: "ciphertext",
    });
    expect(endpointLabelsFor("ml-kem-768", "decrypt")).toEqual({
      input: "ciphertext",
      output: "shared secret",
    });
  });

  it("leaves RSA, the hashes and the ciphers as they were", () => {
    expect(endpointLabelsFor("rsa", "decrypt")).toEqual({ input: "ciphertext", output: "message" });
    expect(endpointLabelsFor("sha-256", "encrypt")).toEqual({ input: "message", output: "digest" });
    expect(endpointLabelsFor("aes-128", "decrypt")).toEqual({
      input: "ciphertext",
      output: "plaintext",
    });
  });
});

describe("App — ML-DSA-44 in the public-key family", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("is the third public-key variant, with no key, mode or padding surface", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "asymmetric" } });
    const algo = findSelectByLabel(container, "algorithm");
    expect(Array.from(algo.querySelectorAll("option")).map((o) => o.value)).toEqual([
      "rsa",
      "ml-kem-768",
      "ml-dsa-44",
    ]);
    fireEvent.change(algo, { target: { value: "ml-dsa-44" } });
    const labels = Array.from(container.querySelectorAll("label")).map((l) =>
      l.textContent?.trim(),
    );
    expect(labels.some((l) => l?.startsWith("key"))).toBe(false);
    expect(labels.some((l) => l?.startsWith("cipher-mode"))).toBe(false);
    expect(labels.some((l) => l?.startsWith("padding"))).toBe(false);
  });

  it("swaps in the default message on the variant switch, and the default signature in Verify", () => {
    const { container } = render(() => <App />);
    selectMlDsa(container);
    expect(findInputByLabel(container, "message").value).toBe(hex(ML_DSA_44_DEFAULT_MESSAGE));

    // The decrypt-direction default is a separate branch of the swap.
    fireEvent.change(findSelectByLabel(container, "algorithm"), { target: { value: "rsa" } });
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    fireEvent.input(findInputByLabel(container, "ciphertext"), { target: { value: "0ae6" } });
    fireEvent.change(findSelectByLabel(container, "algorithm"), { target: { value: "ml-dsa-44" } });
    expect(findInputByLabel(container, "signature").value).toBe(hex(ML_DSA_44_DEFAULT_SIGNATURE));
  });

  it("shows Verify's message, and copies Sign's in only when asked", async () => {
    const { container, getByText, getByTestId } = render(() => <App />);
    selectMlDsa(container);

    // Sign a message other than the default ("Hi" = 48 69).
    fireEvent.input(findInputByLabel(container, "message"), { target: { value: "4869" } });
    run(container);
    await waitFor(() => expect(resultText(container)?.replace(/\s/g, "").length).toBe(4840), {
      timeout: 60_000,
    });

    // Flip to Verify: the signature comes across, the message does not.
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    const row = getByTestId("ml-dsa-verify-message");
    expect(row.textContent).toContain(hex(ML_DSA_44_DEFAULT_MESSAGE));
    run(container);
    await waitFor(() => expect(resultText(container)).toBe("00"), { timeout: 60_000 });

    // The click is what makes it verify.
    fireEvent.click(getByText("Use the message from Sign"));
    expect(getByTestId("ml-dsa-verify-message").textContent).toContain("4869");
    run(container);
    await waitFor(() => expect(resultText(container)).toBe("01"), { timeout: 60_000 });
    expect((getByText("Use the message from Sign") as HTMLButtonElement).disabled).toBe(true);
  }, 180_000);

  it("refuses a signature of the wrong length with a sentence, not a split error", async () => {
    const { container } = render(() => <App />);
    selectMlDsa(container);
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    fireEvent.input(findInputByLabel(container, "signature"), { target: { value: "0102" } });
    run(container);
    await waitFor(() =>
      expect(container.textContent).toContain("an ML-DSA-44 signature is exactly 2420 bytes"),
    );
  });
});
