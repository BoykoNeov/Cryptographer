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
  it("Phase 2: AES-128 supports single-block + ecb + cbc; others single-block only", () => {
    expect(isCipherModeSupported("aes-128", "single-block")).toBe(true);
    expect(isCipherModeSupported("aes-128", "ecb")).toBe(true);
    expect(isCipherModeSupported("aes-128", "cbc")).toBe(true);
    // CTR ships in Phase 3.
    expect(isCipherModeSupported("aes-128", "ctr")).toBe(false);

    for (const cipher of ["aes-192", "aes-256", "speck-32-64-be", "speck-32-64-le"] as const) {
      expect(isCipherModeSupported(cipher, "single-block")).toBe(true);
      expect(isCipherModeSupported(cipher, "ecb")).toBe(false);
      expect(isCipherModeSupported(cipher, "cbc")).toBe(false);
      expect(isCipherModeSupported(cipher, "ctr")).toBe(false);
    }
  });

  it("Serpent ships single-block only at first (all variants); ecb/cbc/ctr unsupported", () => {
    // Canary: when a future phase adds multi-block Serpent (which would
    // reuse the iterate primitive the same way AES-128-ECB does), this
    // test fires and forces the SUPPORTED_CIPHER_MODES_BY_CIPHER matrix
    // to be updated alongside the new spec factory.
    for (const cipher of ["serpent-128", "serpent-192", "serpent-256"] as const) {
      expect(isCipherModeSupported(cipher, "single-block")).toBe(true);
      expect(isCipherModeSupported(cipher, "ecb")).toBe(false);
      expect(isCipherModeSupported(cipher, "cbc")).toBe(false);
      expect(isCipherModeSupported(cipher, "ctr")).toBe(false);
    }
  });

  it("DES ships single-block only (Phase 4 of des-feistel.md); ecb/cbc/ctr unsupported", () => {
    // Canary: multi-block DES would need block-size-aware
    // `load-block`/`store-block` (currently 16-byte-only) — same blocker
    // as Serpent/Speck multi-block. When that lands, this test fires
    // and the matrix gets updated.
    expect(isCipherModeSupported("des", "single-block")).toBe(true);
    expect(isCipherModeSupported("des", "ecb")).toBe(false);
    expect(isCipherModeSupported("des", "cbc")).toBe(false);
    expect(isCipherModeSupported("des", "ctr")).toBe(false);
  });

  it("Blowfish ships single-block only (docs/plans/blowfish.md); ecb/cbc/ctr unsupported", () => {
    // Canary: multi-block Blowfish would need block-size-aware
    // load-block/store-block (currently 16-byte-only) — same blocker as
    // Speck/Serpent/DES. When that lands, this test fires and the matrix
    // gets updated alongside the new spec factory.
    expect(isCipherModeSupported("blowfish", "single-block")).toBe(true);
    expect(isCipherModeSupported("blowfish", "ecb")).toBe(false);
    expect(isCipherModeSupported("blowfish", "cbc")).toBe(false);
    expect(isCipherModeSupported("blowfish", "ctr")).toBe(false);
  });
});
