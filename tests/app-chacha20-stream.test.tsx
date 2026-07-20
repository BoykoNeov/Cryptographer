// @vitest-environment jsdom

/**
 * App-level wiring for ChaCha20 — the first stream cipher.
 *
 * The spec-level KAT (`tests/chacha20-kat.test.ts`) proves the cipher is
 * correct when handed a key and an IV. It cannot prove the App hands it the
 * RIGHT ones, and that gap is not hypothetical: the headline bug this file
 * exists to pin was found by opening the app in a browser, not by any test.
 *
 * **The bug.** `reconcileIvWidth` short-circuits when the IV's width is already
 * correct. AES and ChaCha20 both want a 16-byte IV, so switching AES → ChaCha20
 * kept AES's `00 01 02 03 …`. Every unit test still passed, because they all
 * pass the IV explicitly. But ChaCha20's first four IV bytes are a
 * little-endian block counter, so the app silently ran with counter
 * `0x03020100` instead of 1 — producing a perfectly plausible ciphertext that
 * matches no published vector and decrypts nowhere else. That is the whole
 * category of ChaCha bug the RFC warns about, reached through a UI seam.
 *
 * So the assertions below are deliberately about the SEAM, not the cipher:
 * which mode a newly-selected cipher lands in, which IV bytes it inherits,
 * which controls are live, and whether the default view still reproduces
 * RFC 8439 §2.4.2 end to end.
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

const selectValue = (select: HTMLSelectElement, value: string): void => {
  fireEvent.change(select, { target: { value } });
};

/** The ciphertext is rendered as text in the `.result` row, not as an input. */
const readResultHex = (container: HTMLElement): string =>
  (container.querySelector(".result code")?.textContent ?? "").replace(/\s+/g, "");

const findButton = (container: HTMLElement, text: string): HTMLButtonElement => {
  const target = Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent?.trim() === text,
  );
  if (!target) throw new Error(`button "${text}" not found`);
  return target as HTMLButtonElement;
};

/**
 * Select a cipher, going via AES-128 first.
 *
 * `__resetSpecForTests` does NOT reset the cipher selector, so it leaks across
 * tests in this file's `describe`. That matters because `changeCipher`
 * early-returns when the cipher is unchanged — so a test that "selects
 * ChaCha20" while a previous test already left it selected would fire no
 * change at all, the mode would stay wherever the reset left it, and the
 * assertions would read a half-configured app. Routing through a known cipher
 * makes every test's starting point explicit.
 */
const useCipher = (container: HTMLElement, value: string): void => {
  const select = findSelectByLabel(container, "cipher");
  if (value !== "aes-128") selectValue(select, "aes-128");
  selectValue(select, value);
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

/** RFC 8439 §2.4.2: counter = 1 (little-endian) then the 96-bit nonce. */
const RFC_IV_HEX = "01000000000000000000004a00000000";
/** The first 16 bytes of RFC 8439 §2.4.2's published ciphertext. */
const RFC_CT_PREFIX = "6e2e359a2568f98041ba0728dd0d6981";

describe("ChaCha20 — App wiring for a cipher with no BlockCipherCore", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("selecting ChaCha20 lands the mode in 'stream', not the single-block default", () => {
    // The fallback used to be a hardcoded "single-block". ChaCha20 has no such
    // mode, so that resolved to a spec which does not exist and threw.
    const { container } = render(() => <App />);
    useCipher(container, "chacha20");
    expect(findSelectByLabel(container, "mode of operation").value).toBe("stream");
  });

  it("offers 'stream' as the only mode, and disables the selector since there is no choice", () => {
    const { container } = render(() => <App />);
    useCipher(container, "chacha20");
    const modeSelect = findSelectByLabel(container, "mode of operation");
    expect(Array.from(modeSelect.options).map((o) => o.value)).toEqual(["stream"]);
    expect(modeSelect.disabled).toBe(true);
  });

  it("never offers 'stream' to a block cipher", () => {
    // The other half of the filter: "stream" is not a mode of operation that a
    // block cipher could be put into, so it must not appear at all.
    const { container } = render(() => <App />);
    useCipher(container, "aes-128");
    const values = Array.from(findSelectByLabel(container, "mode of operation").options).map(
      (o) => o.value,
    );
    expect(values).not.toContain("stream");
    expect(values).toContain("single-block");
  });

  it("disables padding — a stream cipher never pads", () => {
    const { container } = render(() => <App />);
    useCipher(container, "chacha20");
    expect(findSelectByLabel(container, "padding").disabled).toBe(true);
  });

  it("shows the IV field with the counter/nonce split named", () => {
    // A single opaque "IV" field would hide the one part of these 16 bytes
    // whose value silently changes the answer.
    const { container } = render(() => <App />);
    useCipher(container, "chacha20");
    expect(findInputByLabel(container, "IV")).not.toBeNull();
    expect(container.textContent).toContain("block counter");
    expect(container.textContent).toContain("96-bit nonce");
  });

  // ── The regression the browser found ────────────────────────────────────
  it("REGRESSION: replaces AES's 16-byte IV with ChaCha20's own, despite equal widths", () => {
    // AES's IV and ChaCha20's are both 16 bytes, so width reconciliation alone
    // is a no-op and the old bytes survived. Harmless for an opaque CBC IV;
    // for ChaCha20 it set the block counter to 0x03020100 instead of 1.
    const { container } = render(() => <App />);
    useCipher(container, "aes-128");
    selectValue(findSelectByLabel(container, "mode of operation"), "cbc");
    const aesIv = findInputByLabel(container, "IV")?.value;

    useCipher(container, "chacha20");
    const chachaIv = findInputByLabel(container, "IV")?.value;

    expect(chachaIv).not.toBe(aesIv);
    expect(chachaIv).toBe(RFC_IV_HEX);
    // Stated directly, because this is the byte that matters: the counter is 1.
    expect(chachaIv?.slice(0, 8)).toBe("01000000");
  });

  it("does NOT clobber a user-typed IV when switching cipher", () => {
    // The other side of the same policy — the key and plaintext fields already
    // treat a user-typed value as sacred, and the IV must match them.
    const { container } = render(() => <App />);
    useCipher(container, "aes-128");
    selectValue(findSelectByLabel(container, "mode of operation"), "cbc");
    const ivInput = findInputByLabel(container, "IV");
    if (!ivInput) throw new Error("IV input not found");
    const typed = "ffeeddccbbaa99887766554433221100";
    fireEvent.input(ivInput, { target: { value: typed } });
    fireEvent.blur(ivInput);

    useCipher(container, "chacha20");
    expect(findInputByLabel(container, "IV")?.value).toBe(typed);
  });

  it("reproduces RFC 8439 §2.4.2 end-to-end from the app's own defaults", () => {
    // The payoff of choosing the RFC's key, nonce, counter and message as the
    // defaults: the first thing a user sees when they pick ChaCha20 is a
    // published test vector, exactly as AES-128 shows FIPS-197 §C.1.
    const { container } = render(() => <App />);
    useCipher(container, "chacha20");
    fireEvent.click(findButton(container, "run"));
    const ciphertext = readResultHex(container);
    expect(ciphertext.slice(0, 32)).toBe(RFC_CT_PREFIX);
    // 114 bytes in, 114 bytes out — no padding, and a short final block.
    expect(ciphertext.length).toBe(114 * 2);
  });

  it("switching back to a block cipher restores single-block and re-enables the controls", () => {
    // The reverse direction of the mode fallback, which a one-way fix misses.
    const { container } = render(() => <App />);
    useCipher(container, "chacha20");
    useCipher(container, "aes-128");
    expect(findSelectByLabel(container, "mode of operation").value).toBe("single-block");
    expect(findSelectByLabel(container, "mode of operation").disabled).toBe(false);
    expect(findSelectByLabel(container, "padding").disabled).toBe(false);
  });
});
