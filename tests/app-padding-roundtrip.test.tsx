// @vitest-environment jsdom

/**
 * Headline integration test for the PKCS#7 padding feature.
 *
 * The whole point of the feature is: type "apple", encrypt with PKCS#7, see
 * the pad expand to 16 bytes in the trace, get a ciphertext, decrypt that
 * ciphertext, recover exactly "apple". This test drives the App through
 * that full loop with the same flow a user would follow.
 *
 * Why drive at the App level instead of stitching pieces in node-env: the
 * spec store, padding store, format store, and trace store all interact via
 * Solid signals — the only sure way to catch a wiring bug is to render the
 * App and click the actual buttons.
 */

import { App } from "@/ui/App";
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
  // Click the actual format button (not setByteFormat directly) so the App's
  // changeFormat handler re-renders BOTH input and key fields in place. Calling
  // the store directly leaves the key in the old format → the run handler then
  // rejects it as the wrong byte length.
  const buttons = Array.from(container.querySelectorAll(".format-toggle button"));
  const target = buttons.find((b) => b.textContent?.trim() === label);
  if (!target) throw new Error(`format button "${label}" not found`);
  return target as HTMLButtonElement;
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
};

describe("App — PKCS#7 padding round-trip", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("encrypts 'apple' through pkcs7-pad → AES → produces a 16-byte ciphertext", () => {
    const { container } = render(() => <App />);

    // Select PKCS#7 from the padding dropdown. The App's changePadding
    // handler swaps the canonical FIPS vector for the short "apple" bytes
    // automatically since the input field still holds the default.
    fireEvent.change(findSelectByLabel(container, "padding"), { target: { value: "pkcs7" } });

    // Click the ASCII format button — this re-renders BOTH the plaintext
    // and key fields in place (parse-with-hex → re-format-with-ASCII). The
    // input field should now display "apple" as literal chars.
    fireEvent.click(findFormatButton(container, "ASCII"));
    expect(findInputByLabel(container, "plaintext").value).toBe("apple");

    // Run.
    fireEvent.click(findButton(container, "run"));

    // No error block.
    const err = container.querySelector(".error");
    expect(err).toBeFalsy();
    // Result block with ciphertext text.
    const result = container.querySelector(".result code");
    expect(result).toBeTruthy();
  });

  it("the encrypt trace includes a pkcs7-pad frame whose 'after' is 16 bytes ending in 0x0b", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "padding"), { target: { value: "pkcs7" } });
    fireEvent.click(findFormatButton(container, "ASCII"));
    fireEvent.click(findButton(container, "run"));

    // Scrub the timeline to frame 0 (= the pkcs7-pad frame, since it's
    // first in the spec).
    const slider = container.querySelector(
      ".trace-timeline input[type='range']",
    ) as HTMLInputElement | null;
    expect(slider).toBeTruthy();
    if (!slider) return;
    fireEvent.input(slider, { target: { value: "0" } });

    // Frame header should name the pkcs7-pad step.
    const frameStep = container.querySelector(".frame-step")?.textContent ?? "";
    expect(frameStep).toContain("pkcs7-pad");

    // The "after" bytes-row should have 16 cells; the last 11 are 0x0b.
    const rows = container.querySelectorAll(".bytes-row-block");
    expect(rows.length).toBeGreaterThanOrEqual(2);
    const afterCells = rows[1]?.querySelectorAll(".bytes-cell") ?? [];
    expect(afterCells.length).toBe(16);
    for (let i = 5; i < 16; i++) {
      expect(afterCells[i]?.textContent?.trim()).toBe("\\x0b");
    }
  });

  it("displays a friendly error when input exceeds 15 bytes under PKCS#7", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "padding"), { target: { value: "pkcs7" } });
    // Stay in hex format. Write 16 bytes (32 hex chars) — too long for PKCS#7.
    fireEvent.input(findInputByLabel(container, "plaintext"), {
      target: { value: "00112233445566778899aabbccddeeff" },
    });
    fireEvent.click(findButton(container, "run"));

    const err = container.querySelector(".error")?.textContent ?? "";
    expect(err).toContain("PKCS#7");
    expect(err).toContain("0–15 bytes");
    expect(err).toContain("got 16");
  });

  it("preserves the padding selection across mode flips", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "padding"), { target: { value: "pkcs7" } });
    expect(findSelectByLabel(container, "padding").value).toBe("pkcs7");

    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });

    // Mode change re-applies padding to the freshly-loaded decrypt spec —
    // the selector should still say pkcs7.
    expect(findSelectByLabel(container, "padding").value).toBe("pkcs7");
  });

  it("decrypts ciphertext (16 bytes) through pkcs7-unpad to recover 'apple'", () => {
    const { container } = render(() => <App />);

    // Step 1: encrypt "apple" under PKCS#7, capture the resulting ciphertext.
    // Stay in hex (the default format) — easier to grab and paste back as
    // the decrypt input than ASCII would be.
    fireEvent.change(findSelectByLabel(container, "padding"), { target: { value: "pkcs7" } });
    fireEvent.input(findInputByLabel(container, "plaintext"), {
      target: { value: "6170706c65" }, // "apple" in hex
    });
    fireEvent.click(findButton(container, "run"));

    let resultCode = container.querySelector(".result code")?.textContent ?? "";
    // Strip leading whitespace just in case.
    resultCode = resultCode.trim();
    expect(resultCode.length).toBe(32); // 16 bytes = 32 hex chars
    const ciphertextHex = resultCode;

    // Step 2: flip to decrypt mode and paste the ciphertext as input.
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    // Padding selector should still be pkcs7 after mode flip.
    expect(findSelectByLabel(container, "padding").value).toBe("pkcs7");

    fireEvent.input(findInputByLabel(container, "ciphertext"), {
      target: { value: ciphertextHex },
    });
    fireEvent.click(findButton(container, "run"));

    // The recovered plaintext should be 5 bytes: 61 70 70 6c 65 ("apple").
    const decResultCode = (container.querySelector(".result code")?.textContent ?? "").trim();
    expect(decResultCode).toBe("6170706c65");
  });
});

describe("App — ISO 7816-4 padding round-trip", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("encrypts 'apple' under ISO 7816-4 and the pad frame ends in 0x80 + zeros", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "padding"), {
      target: { value: "iso7816-4" },
    });
    fireEvent.click(findFormatButton(container, "ASCII"));
    expect(findInputByLabel(container, "plaintext").value).toBe("apple");

    fireEvent.click(findButton(container, "run"));

    const err = container.querySelector(".error");
    expect(err).toBeFalsy();

    // Scrub to frame 0 (= the iso7816-4-pad frame).
    const slider = container.querySelector(
      ".trace-timeline input[type='range']",
    ) as HTMLInputElement | null;
    expect(slider).toBeTruthy();
    if (!slider) return;
    fireEvent.input(slider, { target: { value: "0" } });

    const frameStep = container.querySelector(".frame-step")?.textContent ?? "";
    expect(frameStep).toContain("iso7816-4-pad");

    // 'after' row: 16 cells, byte 5 is 0x80 sentinel, bytes 6..15 are 0x00.
    const rows = container.querySelectorAll(".bytes-row-block");
    expect(rows.length).toBeGreaterThanOrEqual(2);
    const afterCells = rows[1]?.querySelectorAll(".bytes-cell") ?? [];
    expect(afterCells.length).toBe(16);
    expect(afterCells[5]?.textContent?.trim()).toBe("\\x80");
    for (let i = 6; i < 16; i++) {
      expect(afterCells[i]?.textContent?.trim()).toBe("\\x00");
    }
  });

  it("round-trips 'apple' through encrypt → decrypt under ISO 7816-4", () => {
    const { container } = render(() => <App />);

    // Encrypt path.
    fireEvent.change(findSelectByLabel(container, "padding"), {
      target: { value: "iso7816-4" },
    });
    fireEvent.input(findInputByLabel(container, "plaintext"), {
      target: { value: "6170706c65" }, // "apple" in hex
    });
    fireEvent.click(findButton(container, "run"));

    const cipherHex = (container.querySelector(".result code")?.textContent ?? "").trim();
    expect(cipherHex.length).toBe(32);

    // Decrypt path.
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    expect(findSelectByLabel(container, "padding").value).toBe("iso7816-4");
    fireEvent.input(findInputByLabel(container, "ciphertext"), {
      target: { value: cipherHex },
    });
    fireEvent.click(findButton(container, "run"));

    const decHex = (container.querySelector(".result code")?.textContent ?? "").trim();
    expect(decHex).toBe("6170706c65"); // "apple" recovered intact
  });
});

describe("App — Zero-pad scheme", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("keeps the FIPS 16-byte default when switching to zero-pad (max=16)", () => {
    const { container } = render(() => <App />);

    // Default plaintext is the FIPS vector (16 bytes). Zero-pad accepts up
    // to 16 bytes, so the input doesn't need swapping — verify the App
    // does NOT clobber the user's input on this transition.
    const inputBefore = findInputByLabel(container, "plaintext").value;
    fireEvent.change(findSelectByLabel(container, "padding"), {
      target: { value: "zero-pad" },
    });
    const inputAfter = findInputByLabel(container, "plaintext").value;
    expect(inputAfter).toBe(inputBefore);
  });

  it("encrypts the 16-byte FIPS vector under zero-pad with no padding step output growth", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "padding"), {
      target: { value: "zero-pad" },
    });
    fireEvent.click(findButton(container, "run"));

    // No error, valid ciphertext produced.
    expect(container.querySelector(".error")).toBeFalsy();
    const cipherHex = (container.querySelector(".result code")?.textContent ?? "").trim();
    expect(cipherHex.length).toBe(32);

    // Scrub to frame 0 (the zero-pad frame). Zero-pad on a clean block
    // multiple is a no-op: 'after' bytes should match 'before' length-wise.
    const slider = container.querySelector(
      ".trace-timeline input[type='range']",
    ) as HTMLInputElement | null;
    if (!slider) return;
    fireEvent.input(slider, { target: { value: "0" } });
    const frameStep = container.querySelector(".frame-step")?.textContent ?? "";
    expect(frameStep).toContain("zero-pad");
    const rows = container.querySelectorAll(".bytes-row-block");
    const beforeCells = rows[0]?.querySelectorAll(".bytes-cell") ?? [];
    const afterCells = rows[1]?.querySelectorAll(".bytes-cell") ?? [];
    expect(beforeCells.length).toBe(16);
    expect(afterCells.length).toBe(16);
  });

  it("rejects length-0 input under zero-pad with a friendly error", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "padding"), {
      target: { value: "zero-pad" },
    });
    fireEvent.input(findInputByLabel(container, "plaintext"), { target: { value: "" } });
    fireEvent.click(findButton(container, "run"));

    const err = container.querySelector(".error")?.textContent ?? "";
    expect(err).toContain("Zero-pad");
    expect(err).toContain("1–16 bytes");
  });
});
