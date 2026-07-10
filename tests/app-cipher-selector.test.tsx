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

  it("renders every cipher variant in the dropdown (3 AES + 2 Speck + 3 Serpent + 1 DES)", () => {
    const { container } = render(() => <App />);
    const select = findSelectByLabel(container, "cipher");
    const values = Array.from(select.querySelectorAll("option")).map((o) => o.value);
    expect(values).toEqual([
      "aes-128",
      "aes-192",
      "aes-256",
      "speck-32-64-be",
      "speck-32-64-le",
      "serpent-128",
      "serpent-192",
      "serpent-256",
      // DES added in Phase 4 of `docs/plans/des-feistel.md`. First Feistel
      // cipher; single-block only.
      "des",
      // Blowfish (`docs/plans/blowfish.md`) — second Feistel cipher, single-block.
      "blowfish",
    ]);
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

  it("encrypts under Speck32/64 (BE-paper) end-to-end through the selector", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "speck-32-64-be" },
    });

    // Auto-swap should have replaced both fields with the Speck KAT defaults.
    // Verify before clicking Run so a regression in changeCipher's plaintext-
    // swap policy is caught here, not silently via the wrong ciphertext.
    expect(findInputByLabel(container, "key").value).toBe("1918111009080100");
    expect(findInputByLabel(container, "plaintext").value).toBe("6574694c");

    // Padding selector must be disabled — overlay assumes a 16-byte matrix.
    const paddingSelect = findSelectByLabel(container, "padding");
    expect(paddingSelect.disabled).toBe(true);

    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    const result = container.querySelector(".result code")?.textContent ?? "";
    expect(result).toBe("a86842f2");

    // Regression guard: ParamEditor must dispatch to the Speck-specific
    // Match arms, NOT fall back to the raw-JSON view (`.param-raw`). The
    // raw fallback would silently ship a stringified params blob — the
    // exact failure src/steps/CLAUDE.md flags as the most common new-
    // step-type pitfall.
    expect(container.querySelector(".param-raw")).toBeNull();
    expect(container.querySelector(".param-scalars")).not.toBeNull();
  });

  it("encrypts under Speck32/64 (LE-NSA) and produces the LE-encoded ciphertext", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "speck-32-64-le" },
    });

    // The LE-NSA key is the same KAT word-wise, low-byte-first in memory.
    expect(findInputByLabel(container, "key").value).toBe("0001080910111819");
    expect(findInputByLabel(container, "plaintext").value).toBe("4c697465");

    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    const result = container.querySelector(".result code")?.textContent ?? "";
    expect(result).toBe("f24268a8");
  });

  it("flipping AES-128 → Speck → AES-128 round-trips the canonical inputs back", () => {
    // Regression guard for the changeCipher plaintext-swap policy. Going
    // AES → Speck should swap a 16-byte FIPS vector to a 4-byte KAT
    // plaintext; coming back should restore the FIPS vector. A user-typed
    // value in between would break this expectation — but here we never type.
    const { container } = render(() => <App />);

    const ptInput = findInputByLabel(container, "plaintext");
    expect(ptInput.value).toBe("00112233445566778899aabbccddeeff");

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "speck-32-64-be" },
    });
    expect(ptInput.value).toBe("6574694c");

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "aes-128" },
    });
    expect(ptInput.value).toBe("00112233445566778899aabbccddeeff");
  });

  it("encrypts under Serpent-128 end-to-end through the selector", () => {
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "serpent-128" },
    });

    // Auto-swap should leave the FIPS-style sequential bytes in both fields
    // (Serpent defaults reuse them — same block size, no AES vs Serpent
    // ambiguity for a 16-byte plaintext).
    expect(findInputByLabel(container, "key").value).toBe("000102030405060708090a0b0c0d0e0f");
    expect(findInputByLabel(container, "plaintext").value).toBe("00112233445566778899aabbccddeeff");

    // Padding is AES-only today; Serpent uses BytesState so the overlay's
    // applyPaddingScheme early-returns and the dropdown disables.
    const paddingSelect = findSelectByLabel(container, "padding");
    expect(paddingSelect.disabled).toBe(true);

    // Use a verified KAT vector from the Python reference. Replace the
    // plaintext field with all-zeros and the key with the single-bit key
    // so we can match against the headline reference value.
    fireEvent.input(findInputByLabel(container, "plaintext"), {
      target: { value: "00000000000000000000000000000000" },
    });
    fireEvent.input(findInputByLabel(container, "key"), {
      target: { value: "80000000000000000000000000000000" },
    });

    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    const result = container.querySelector(".result code")?.textContent ?? "";
    expect(result).toBe("264e5481eff42a4606abda06c0bfda3d");

    // Regression guard: the Serpent ParamEditor blocks must dispatch (no
    // raw-JSON fallback).
    expect(container.querySelector(".param-raw")).toBeNull();
  });

  it("encrypts under DES end-to-end through the selector (FIPS 46-3 Appendix B)", () => {
    // Phase 4 of `docs/plans/des-feistel.md`. The DES default key + plaintext
    // are the FIPS 46-3 Appendix B test vector
    //   PT=0123456789abcdef, K=133457799bbcdff1 → CT=85e813540f0ab405
    // so a fresh selector swap + Run should land on the canonical ciphertext
    // without any per-field edits. Verifies the full path: cipher swap →
    // store defaults swap → spec swap → input/key text swap → Run produces
    // a clean trace → result rendered in hex.
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "des" },
    });

    // Auto-swap policy: the previous (AES-128) defaults sit in the fields
    // on first load, so the swap should replace them with DES's canonical
    // 8-byte values.
    expect(findInputByLabel(container, "key").value).toBe("133457799bbcdff1");
    expect(findInputByLabel(container, "plaintext").value).toBe("0123456789abcdef");

    // Padding is AES-only today (load-block hardcoded to 16 bytes). DES uses
    // BytesState, so the overlay's applyPaddingScheme early-returns and the
    // dropdown disables — matching Speck and Serpent.
    const paddingSelect = findSelectByLabel(container, "padding");
    expect(paddingSelect.disabled).toBe(true);

    // Cipher-mode is AES-only for the same reason.
    const cipherModeSelect = findSelectByLabel(container, "mode of operation");
    expect(cipherModeSelect.disabled).toBe(true);

    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    const result = container.querySelector(".result code")?.textContent ?? "";
    expect(result).toBe("85e813540f0ab405");

    // Regression guard: the DES ParamEditor blocks must dispatch (no
    // raw-JSON fallback for any DES step type).
    expect(container.querySelector(".param-raw")).toBeNull();
  });

  it("encrypts under Blowfish end-to-end through the selector (Eric-Young vector)", () => {
    // `docs/plans/blowfish.md`. The Blowfish default key + plaintext are the
    // Eric-Young Blowfish-ECB vector
    //   PT=1111111111111111, K=0123456789abcdef → CT=61f9c3802281b096
    // so a fresh selector swap + Run lands on the published ciphertext with no
    // per-field edits. This is the only end-to-end UI path Blowfish lacked (the
    // pinned option-list assertion above proves it's IN the dropdown; this
    // proves the whole select → defaults → spec → Run → CT pipeline works,
    // exercising the 521-loop monolith + 16 port-native Feistel rounds through
    // the real App).
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "blowfish" },
    });

    // Auto-swap replaces the AES-128 defaults with Blowfish's canonical 8-byte
    // key + plaintext.
    expect(findInputByLabel(container, "key").value).toBe("0123456789abcdef");
    expect(findInputByLabel(container, "plaintext").value).toBe("1111111111111111");

    // Padding + cipher-mode are AES-only (Blowfish is single-block, BytesState).
    expect(findSelectByLabel(container, "padding").disabled).toBe(true);
    expect(findSelectByLabel(container, "mode of operation").disabled).toBe(true);

    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    expect(container.querySelector(".result code")?.textContent ?? "").toBe("61f9c3802281b096");

    // No raw-JSON fallback for any Blowfish step type.
    expect(container.querySelector(".param-raw")).toBeNull();
  });

  it("swapping from AES-128 + PKCS7 to DES does not throw on the padding overlay", () => {
    // Regression guard surfaced during Phase 4 advisor review:
    // `setCipher("des")` rebuilds both spec slots via
    // `buildCanonicalPair("des", "single-block", padding())`. If the user
    // was on AES-128 + PKCS7 just before the swap, that call invokes
    // `applyPaddingScheme(desSpec, "encrypt", "pkcs7")`. The overlay
    // expects matrix4x4-bytes state; DES is BytesState. The early-return
    // guard at `spec.stateShape !== "matrix4x4-bytes"` in
    // `applyPaddingScheme` is what makes this safe — without it, the
    // pad/load-block leaves would be prepended onto a non-matrix spec
    // and `load-block` would throw at runtime.
    //
    // The plaintext field text doesn't necessarily auto-swap to DES's
    // canonical 8-byte value here — App.tsx's swap heuristic checks the
    // current field against DEFAULT_PT_BYTES_BY_CIPHER for the OLD
    // cipher, and PKCS7-on-AES seeds a different (5-byte "apple")
    // default. So the user might need to retype the plaintext after
    // the swap; we type DES's canonical value explicitly and verify
    // Run produces the published KAT, which proves the overlay routed
    // around DES correctly.
    const { container } = render(() => <App />);

    // Pick PKCS7 while still on AES-128.
    fireEvent.change(findSelectByLabel(container, "padding"), {
      target: { value: "pkcs7" },
    });

    // Now swap to DES. No throw, no error banner.
    fireEvent.change(findSelectByLabel(container, "cipher"), {
      target: { value: "des" },
    });
    expect(container.querySelector(".error")).toBeNull();

    // Explicitly retype the FIPS canonical plaintext to bypass the
    // PKCS7-default-short residue, then Run.
    fireEvent.input(findInputByLabel(container, "plaintext"), {
      target: { value: "0123456789abcdef" },
    });
    fireEvent.input(findInputByLabel(container, "key"), {
      target: { value: "133457799bbcdff1" },
    });

    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    const result = container.querySelector(".result code")?.textContent ?? "";
    expect(result).toBe("85e813540f0ab405");
  });

  it("switching cipher in DECRYPT mode swaps the ciphertext + key to the new cipher's canonical defaults and round-trips", () => {
    // Regression guard for the decrypt-mode input swap (the "DES decrypt
    // default ciphertext is 16 bytes → must be exactly 8 bytes" bug). The
    // encrypt-mode plaintext swap policy didn't fire in decrypt mode because
    // the field holds a CIPHERTEXT, which never equals the plaintext default —
    // so a stale 16-byte AES block survived a switch to DES and tripped the
    // 8-byte block-size banner. `changeCipher` now compares against the
    // per-mode default table (DEFAULT_CT in decrypt) so the swap works.
    const { container } = render(() => <App />);

    // Boot is AES-128 encrypt; auto-run leaves the §C.1 ciphertext in the
    // result line. Flip to decrypt — the mode-flip auto-swap copies that
    // ciphertext into the (now "ciphertext"-labeled) input field, which is
    // exactly DEFAULT_CT["aes-128"].
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    expect(findInputByLabel(container, "ciphertext").value).toBe(
      "69c4e0d86a7b0430d8cdb78070b4c55a",
    );

    // Now switch cipher to DES while still in decrypt mode. The 16-byte AES
    // ciphertext must be replaced by DES's canonical 8-byte ciphertext, and
    // the key by DES's canonical key (the key swap is mode-independent and
    // already worked — assert it here so the round-trip below is meaningful).
    fireEvent.change(findSelectByLabel(container, "cipher"), { target: { value: "des" } });
    expect(findInputByLabel(container, "ciphertext").value).toBe("85e813540f0ab405");
    expect(findInputByLabel(container, "key").value).toBe("133457799bbcdff1");

    // Decrypting that canonical ciphertext recovers the FIPS 46-3 Appendix B
    // plaintext with no length banner — the whole point of the swap.
    fireEvent.click(findButton(container, "run"));
    expect(container.querySelector(".error")).toBeNull();
    expect(container.querySelector(".result code")?.textContent ?? "").toBe("0123456789abcdef");
  });

  it("does NOT clobber a user-typed ciphertext when the cipher changes in decrypt mode", () => {
    // Sacred-input policy in decrypt mode, mirroring the user-typed-key guard
    // below. A custom ciphertext (not any cipher's canonical default) must
    // survive a cipher switch — the user will see a friendly length banner on
    // Run if it doesn't fit the new block, but we never silently overwrite it.
    const { container } = render(() => <App />);

    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });

    // Type a custom 16-byte ciphertext distinct from every canonical default.
    const custom = "112233445566778899aabbccddeeff00";
    fireEvent.input(findInputByLabel(container, "ciphertext"), { target: { value: custom } });

    // Switch to DES. The custom value is preserved (no swap to DES's default).
    fireEvent.change(findSelectByLabel(container, "cipher"), { target: { value: "des" } });
    expect(findInputByLabel(container, "ciphertext").value).toBe(custom);
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
