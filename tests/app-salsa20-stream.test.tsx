// @vitest-environment jsdom

/**
 * App-level wiring for Salsa20 — the second stream cipher.
 *
 * The spec-level KAT (`tests/salsa20-kat.test.ts`) proves the cipher is correct
 * when handed a key and an IV. It cannot prove the App hands it the RIGHT ones.
 * That gap is not hypothetical for this cipher family — it is where ChaCha20's
 * headline bug lived, and Salsa20 walks into the identical trap:
 *
 * **The IV-width trap.** `reconcileIvWidth` short-circuits when the IV's width
 * is already correct. AES, ChaCha20 and Salsa20 ALL want a 16-byte IV, so
 * switching between any two of them is a no-op as far as width is concerned and
 * the previous cipher's bytes survive. Harmless for an opaque CBC IV; for a
 * stream cipher the leading bytes are a little-endian block counter, so the app
 * silently runs at the wrong counter and produces plausible ciphertext that
 * decrypts nowhere else. ChaCha20's instance of this was found by opening a
 * browser, not by any test. Both directions are pinned below.
 *
 * **The caption trap, found while writing this file.** The IV caption naming
 * the counter/nonce split was a ChaCha20-specific string behind a *generic*
 * `isStreamCipher` gate. The two stream ciphers do not agree on the split —
 * ChaCha20 is 4/12 starting at 1, Salsa20 is 8/8 starting at 0 — so Salsa20
 * would have displayed a caption wrong in every particular, pointing the user
 * at the wrong bytes for exactly the field where that matters most. It is now
 * per-cipher (`IV_LAYOUT_CAPTION_BY_CIPHER`) and asserted here.
 *
 * So the assertions below are deliberately about the SEAM, not the cipher.
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
 * tests in this file's `describe`, and `changeCipher` early-returns when the
 * cipher is unchanged. Routing through a known cipher makes every test's
 * starting point explicit. (See `feedback_app_test_cipher_selector_leak`.)
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

/** Salsa20's default IV: a 64-bit little-endian counter of 0, then the nonce. */
const SALSA_IV_HEX = "00000000000000000d74db42a91077de";
/** ChaCha20's default IV, for the cross-stream-cipher regression. */
const CHACHA_IV_HEX = "01000000000000000000004a00000000";
/** First 16 bytes of the app's default Salsa20 ciphertext (pinned in the KAT). */
const SALSA_CT_PREFIX = "a69bb94c18cbef78a6dbc9bc89e9b660";

describe("Salsa20 — App wiring for the second stream cipher", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  // ── The "stream" abstraction holds ──────────────────────────────────────

  it("selecting Salsa20 lands the mode in 'stream', not the single-block default", () => {
    // Salsa20 has no "single-block" mode, so a hardcoded fallback would resolve
    // to a spec that does not exist and throw. This passing without any new
    // per-cipher branch is the plan's thesis: `defaultCipherModeFor` derives
    // from the mode table, so the one row added there was the entire cost.
    const { container } = render(() => <App />);
    useCipher(container, "salsa20");
    expect(findSelectByLabel(container, "mode of operation").value).toBe("stream");
  });

  it("offers 'stream' as the only mode, and disables the selector since there is no choice", () => {
    const { container } = render(() => <App />);
    useCipher(container, "salsa20");
    const modeSelect = findSelectByLabel(container, "mode of operation");
    expect(Array.from(modeSelect.options).map((o) => o.value)).toEqual(["stream"]);
    expect(modeSelect.disabled).toBe(true);
  });

  it("disables padding — a stream cipher never pads", () => {
    const { container } = render(() => <App />);
    useCipher(container, "salsa20");
    expect(findSelectByLabel(container, "padding").disabled).toBe(true);
  });

  // ── The IV field ────────────────────────────────────────────────────────

  it("names Salsa20's OWN counter/nonce split, not ChaCha20's", () => {
    // The caption regression. Salsa20 splits 8/8 from 0; ChaCha20 splits 4/12
    // from 1. Showing the latter for the former points the user at the wrong
    // bytes for the one field where a wrong value looks entirely plausible.
    const { container } = render(() => <App />);
    useCipher(container, "salsa20");
    expect(findInputByLabel(container, "IV")).not.toBeNull();
    expect(container.textContent).toContain("bytes 0–7 = block counter");
    expect(container.textContent).toContain("64-bit nonce");
    // And explicitly NOT ChaCha20's caption.
    expect(container.textContent).not.toContain("96-bit nonce");
    expect(container.textContent).not.toContain("bytes 0–3 = block counter");
  });

  // ── The regressions that width reconciliation cannot catch ──────────────

  it("REGRESSION: replaces AES's 16-byte IV with Salsa20's own, despite equal widths", () => {
    const { container } = render(() => <App />);
    useCipher(container, "aes-128");
    selectValue(findSelectByLabel(container, "mode of operation"), "cbc");
    const aesIv = findInputByLabel(container, "IV")?.value;

    useCipher(container, "salsa20");
    const salsaIv = findInputByLabel(container, "IV")?.value;

    expect(salsaIv).not.toBe(aesIv);
    expect(salsaIv).toBe(SALSA_IV_HEX);
    // Stated directly, because these are the bytes that matter: counter = 0,
    // across all EIGHT bytes. A 4-byte counter would leave nonce bytes here.
    expect(salsaIv?.slice(0, 16)).toBe("0000000000000000");
  });

  it("REGRESSION: swapping between the two stream ciphers replaces the IV both ways", () => {
    // The sharper version of the same trap, and one ChaCha20's own test file
    // could not express: both ciphers are stream ciphers with a 16-byte IV
    // whose leading bytes are a counter. Width reconciliation is a no-op, and
    // `isStreamCipher` is true on both sides, so any guard written in terms of
    // "is this a stream cipher?" rather than "is this the SAME cipher?" would
    // let the wrong counter through in both directions.
    const { container } = render(() => <App />);

    useCipher(container, "chacha20");
    expect(findInputByLabel(container, "IV")?.value).toBe(CHACHA_IV_HEX);

    useCipher(container, "salsa20");
    expect(findInputByLabel(container, "IV")?.value).toBe(SALSA_IV_HEX);

    useCipher(container, "chacha20");
    expect(findInputByLabel(container, "IV")?.value).toBe(CHACHA_IV_HEX);
  });

  it("does NOT clobber a user-typed IV when switching cipher", () => {
    // The other side of the policy: the key and plaintext fields treat a
    // user-typed value as sacred, and the IV must match them.
    const { container } = render(() => <App />);
    useCipher(container, "salsa20");
    const ivInput = findInputByLabel(container, "IV");
    expect(ivInput).not.toBeNull();

    const typed = "ff".repeat(16);
    fireEvent.input(ivInput as HTMLInputElement, { target: { value: typed } });
    expect((ivInput as HTMLInputElement).value).toBe(typed);
  });

  // ── End to end ──────────────────────────────────────────────────────────

  it("the default view encrypts to the pinned Salsa20 ciphertext end to end", () => {
    // Everything the seam is responsible for, in one assertion: the right spec,
    // the right key, the right IV, the right plaintext, and no padding spliced
    // in. The expected bytes are the ones `tests/salsa20-kat.test.ts` pins
    // against pycryptodome and the independent reference implementation.
    const { container } = render(() => <App />);
    useCipher(container, "salsa20");
    fireEvent.click(findButton(container, "run"));
    expect(readResultHex(container).slice(0, 32)).toBe(SALSA_CT_PREFIX);
  });

  it("produces ciphertext exactly as long as the plaintext (no padding, ragged tail)", () => {
    // The app's default Salsa20 plaintext is 108 bytes — not a multiple of the
    // 64-byte block. A padding overlay silently engaging would round this up.
    const { container } = render(() => <App />);
    useCipher(container, "salsa20");
    fireEvent.click(findButton(container, "run"));
    expect(readResultHex(container).length).toBe(108 * 2);
  });
});
