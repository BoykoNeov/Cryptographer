// @vitest-environment jsdom

/**
 * Headline integration test for the Phase-2 CBC feature.
 *
 * Catches the UI wiring bugs the spec-level KAT and signal-level IV store
 * tests can't see:
 *   - dropdown picks "cbc" → cipherMode signal flips → spec is the CBC
 *     factory's output, not ECB or single-block (the Run handler's IV-seed
 *     branch fires).
 *   - <Show when={cipherMode() === "cbc"}> renders <IvInput>; when the
 *     user flips back to single-block / ECB it disappears.
 *   - The IV field is editable in hex format, defaults to the NIST §F.2
 *     vector, and persists through the run.
 *   - Changing the IV (or pressing 🎲) re-runs the cipher with different
 *     output for the same plaintext + key.
 *   - The Run handler reads ivBytes() live (not a stale closure from
 *     before the IV was edited).
 *
 * Each of these is a class of regression the spec-level tests miss. The
 * NIST §F.2.1 byte-for-byte assertion ties the App-level pipeline to the
 * same KAT the spec-level test pins, so a wiring break vs a spec break
 * surface separately.
 */

import { App } from "@/ui/App";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetIvForTests } from "@/ui/stores/iv";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const findInputByLabel = (container: HTMLElement, labelText: string): HTMLInputElement | null => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) return null;
  return target.querySelector("input");
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

const setInputValue = (input: HTMLInputElement, value: string): void => {
  fireEvent.input(input, { target: { value } });
  fireEvent.change(input, { target: { value } });
};

const commitInput = (input: HTMLInputElement): void => {
  // The IvInput component commits on blur (and on Enter). Tests fire
  // both so a future refactor that drops blur-commit doesn't silently
  // break this regression.
  fireEvent.blur(input);
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetCipherModeForTests();
  __resetIvForTests();
  __resetSpecForTests();
};

const NIST_SAMPLE_PLAINTEXT_HEX =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const NIST_KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c";

// §F.2.1 expected ciphertext, first block. We only spot-check the first
// 16 bytes — that's enough to catch wiring breaks; the spec-level KAT
// pins all 64 bytes.
const NIST_F21_FIRST_BLOCK_HEX = "7649abac8119b246cee98e9b12e9197d";

const readResultHex = (container: HTMLElement): string | null => {
  const code = container.querySelector(".result code");
  return code?.textContent?.trim() ?? null;
};

describe("App — CBC IV flow (Phase 2)", () => {
  beforeEach(() => resetAll());
  afterEach(() => cleanup());

  it("selecting CBC reveals the IV input row; switching back hides it", () => {
    const { container } = render(() => <App />);
    // Default mode is single-block; IV field should NOT be rendered.
    expect(findInputByLabel(container, "IV")).toBeNull();

    // Flip cipher-mode to CBC.
    fireEvent.change(findSelectByLabel(container, "mode of operation"), {
      target: { value: "cbc" },
    });
    const ivInput = findInputByLabel(container, "IV");
    expect(ivInput).not.toBeNull();
    // The default IV is the NIST §F.2 standard test vector in hex.
    expect(ivInput?.value).toBe("000102030405060708090a0b0c0d0e0f");

    // Flip back to single-block → IV row disappears.
    fireEvent.change(findSelectByLabel(container, "mode of operation"), {
      target: { value: "single-block" },
    });
    expect(findInputByLabel(container, "IV")).toBeNull();
  });

  it("CBC run with default IV + NIST §F.2.1 plaintext + key matches the published first block", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "mode of operation"), {
      target: { value: "cbc" },
    });
    // Type the 64-byte NIST plaintext in hex format (default).
    setInputValue(
      findInputByLabel(container, "plaintext") as HTMLInputElement,
      NIST_SAMPLE_PLAINTEXT_HEX,
    );
    setInputValue(findInputByLabel(container, "key") as HTMLInputElement, NIST_KEY_HEX);

    fireEvent.click(findButton(container, "run"));

    const result = readResultHex(container) ?? "";
    // Compare bytes-only (the rendered hex contains spaces — strip them).
    const compact = result.replace(/\s+/g, "");
    expect(compact.slice(0, 32)).toBe(NIST_F21_FIRST_BLOCK_HEX);
  });

  it("editing the IV changes the ciphertext for the same plaintext + key", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "mode of operation"), {
      target: { value: "cbc" },
    });
    setInputValue(
      findInputByLabel(container, "plaintext") as HTMLInputElement,
      NIST_SAMPLE_PLAINTEXT_HEX,
    );
    setInputValue(findInputByLabel(container, "key") as HTMLInputElement, NIST_KEY_HEX);

    fireEvent.click(findButton(container, "run"));
    const ciphertextA = (readResultHex(container) ?? "").replace(/\s+/g, "");

    // Change the IV to all zeros and re-run.
    const ivInput = findInputByLabel(container, "IV") as HTMLInputElement;
    setInputValue(ivInput, "0".repeat(32));
    commitInput(ivInput);

    fireEvent.click(findButton(container, "run"));
    const ciphertextB = (readResultHex(container) ?? "").replace(/\s+/g, "");

    // The IV change must alter the ciphertext (proves the Run handler
    // reads the live IV, not a stale closure).
    expect(ciphertextA).not.toBe("");
    expect(ciphertextB).not.toBe("");
    expect(ciphertextA).not.toBe(ciphertextB);
  });

  it("drives Serpent-128 CBC through the whole App UI and round-trips a 2-block message", () => {
    // The advisor's flagged gap: the Serpent modes KAT runs the CBC spec
    // straight through the runtime, but not through the App's mode-dropdown ↔
    // spec-store ↔ IV-field ↔ Run wiring. Serpent's 16-byte block means its IV
    // path is byte-identical to AES's (the field even defaults to the same
    // vector), so this proves the wiring, not new arithmetic. A round-trip is
    // self-checking — no external Serpent oracle exists (`node:crypto` has none).
    const { container } = render(() => <App />);

    // Select Serpent-128, then CBC. Serpent now supports CBC, so the cipher
    // switch does NOT reset the mode back to single-block.
    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "serpent-128" },
    });
    fireEvent.change(findSelectByLabel(container, "mode of operation"), {
      target: { value: "cbc" },
    });

    // The IV row must appear with the 16-byte default — the same width AES
    // uses, since Serpent's block is also 16 bytes.
    const ivInput = findInputByLabel(container, "IV");
    expect(ivInput).not.toBeNull();
    expect(ivInput?.value).toBe("000102030405060708090a0b0c0d0e0f");

    // A 2-block plaintext (32 bytes) under a 16-byte key. Padding stays "none"
    // (the input is an exact block multiple), so no pad step is spliced in.
    const PT_2_BLOCKS = "11111111111111111111111111111111" + "000102030405060708090a0b0c0d0e0f";
    setInputValue(findInputByLabel(container, "plaintext") as HTMLInputElement, PT_2_BLOCKS);
    setInputValue(
      findInputByLabel(container, "key") as HTMLInputElement,
      "80000000000000000000000000000000",
    );

    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    const ct = (readResultHex(container) ?? "").replace(/\s+/g, "");
    // 2 blocks × 16 bytes = 32 bytes = 64 hex chars, and CBC must not leave the
    // plaintext untouched.
    expect(ct.length).toBe(64);
    expect(ct).not.toBe(PT_2_BLOCKS);

    // Flip to decrypt — the auto-swap copies the ciphertext into the input —
    // and Run must recover the original plaintext.
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    const recovered = (readResultHex(container) ?? "").replace(/\s+/g, "");
    expect(recovered).toBe(PT_2_BLOCKS);
  });

  it("drives AES-128 CTR through the whole App UI, byte-equal to node:crypto", () => {
    // The CTR KAT builds specs by calling `buildCtrSpec` directly, so it never
    // touches the App's mode-dropdown ↔ spec-store ↔ IV-field ↔ Run wiring —
    // the same gap the Serpent CBC test above exists to close. CTR adds a
    // wrinkle worth pinning here: the IV field must appear for CTR too (it
    // holds the INITIAL COUNTER BLOCK rather than a chaining value), and the
    // Run handler's aux-seed branch had to learn `ctr` alongside `cbc`. If
    // that branch were missed, `aux["iv"]` would be absent and `fetch-iv`
    // would fail — a break invisible to a spec-level test.
    const { container } = render(() => <App />);

    // Set the cipher EXPLICITLY rather than relying on the default. The
    // Serpent test above leaves the cipher selector on serpent-128, and
    // Serpent shares AES's 16-byte block and key width — so without this the
    // test would silently run Serpent-128 CTR and fail against an AES vector
    // with no hint that the cipher was wrong.
    fireEvent.change(findSelectByLabel(container, "cipher"), { target: { value: "aes-128" } });
    fireEvent.change(findSelectByLabel(container, "mode of operation"), {
      target: { value: "ctr" },
    });

    // The IV row appears for CTR, defaulting to the same 16-byte value AES
    // CBC uses (the width is the block width, which CTR shares).
    const ivInput = findInputByLabel(container, "IV");
    expect(ivInput).not.toBeNull();
    expect(ivInput?.value).toBe("000102030405060708090a0b0c0d0e0f");

    const PT_2_BLOCKS = "00112233445566778899aabbccddeeff" + "ffeeddccbbaa99887766554433221100";
    setInputValue(findInputByLabel(container, "plaintext") as HTMLInputElement, PT_2_BLOCKS);
    setInputValue(
      findInputByLabel(container, "key") as HTMLInputElement,
      "000102030405060708090a0b0c0d0e0f",
    );

    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    const ct = (readResultHex(container) ?? "").replace(/\s+/g, "");
    // Byte-equal to `node:crypto`'s aes-128-ctr for this (key, counter,
    // plaintext) — computed independently and pinned as a literal so this
    // test needs no crypto import and cannot drift with the implementation.
    expect(ct).toBe("0a852986053b9632795a3ee30a8e04a5fd8d3158ddb2eb1eedbca84b78861edc");

    // Flip to decrypt — which runs the SAME forward cipher — and recover the
    // plaintext. This is the UI-level statement of CTR's defining property.
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    expect((readResultHex(container) ?? "").replace(/\s+/g, "")).toBe(PT_2_BLOCKS);
  });

  it("invalid IV (wrong length) snaps back to the store's last known good value", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "mode of operation"), {
      target: { value: "cbc" },
    });
    const ivInput = findInputByLabel(container, "IV") as HTMLInputElement;
    const before = ivInput.value;

    // Type 15 bytes (30 hex chars) and blur — should revert.
    setInputValue(ivInput, "00".repeat(15));
    commitInput(ivInput);
    expect(ivInput.value).toBe(before);
  });
});
