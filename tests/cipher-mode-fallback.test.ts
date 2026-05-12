/**
 * Regression: picking a cipher-mode that isn't registered for the
 * current cipher must not silently fall back to single-block while the
 * UI still claims the requested mode.
 *
 * Background: in Phase 1, only AES-128 has the ECB factory. AES-192 /
 * AES-256 / Speck fall back to single-block via `resolveDefault` in
 * `stores/spec.ts`. Without the fix in this commit, the cipher-mode
 * signal would still say "ecb" after the fallback, `paddingLimits`
 * would return the multi-block range (0..255), and a 16-byte input
 * would pass the length check, run the single-block AES spec with the
 * padding overlay, and trip `load-block: expected 16 got 32` deep in
 * the runtime.
 *
 * The fix: `setCipher` resets `cipherMode` to "single-block" if the
 * new cipher doesn't support the active mode. The cipher-mode store's
 * `loadInitial` performs the same check at load time so a persisted
 * mismatch (cipher=aes-192, cipherMode=ecb in localStorage) gets
 * corrected on next reload.
 */

import { isCipherModeSupported } from "@/ui/stores/cipher-mode";
import { describe, expect, it } from "vitest";

describe("cipher-mode × cipher support matrix", () => {
  it("Phase 1: AES-128 supports single-block + ecb; others single-block only", () => {
    expect(isCipherModeSupported("aes-128", "single-block")).toBe(true);
    expect(isCipherModeSupported("aes-128", "ecb")).toBe(true);
    expect(isCipherModeSupported("aes-128", "cbc")).toBe(false);
    expect(isCipherModeSupported("aes-128", "ctr")).toBe(false);

    for (const cipher of ["aes-192", "aes-256", "speck-32-64-be", "speck-32-64-le"] as const) {
      expect(isCipherModeSupported(cipher, "single-block")).toBe(true);
      expect(isCipherModeSupported(cipher, "ecb")).toBe(false);
      expect(isCipherModeSupported(cipher, "cbc")).toBe(false);
      expect(isCipherModeSupported(cipher, "ctr")).toBe(false);
    }
  });
});
