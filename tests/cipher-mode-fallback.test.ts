/**
 * Regression: picking a cipher-mode that isn't registered for the
 * current cipher must not silently fall back to single-block while the
 * UI still claims the requested mode.
 *
 * Background: a cipher can only run a mode of operation if it has a
 * `BlockCipherCore` (`src/ui/stores/block-cipher-cores.ts`) — a core is what
 * lets a mode builder hand the cipher's body its block from the iterate loop
 * instead of `$input`. Ciphers without one fall back to single-block via
 * `resolveDefault` in `stores/spec.ts`. Without the fix this file guards, the
 * cipher-mode signal would still say "ecb" after the fallback, `paddingLimits`
 * would return the multi-block range, and a 2-block input would pass the
 * length check and then blow up deep in the runtime running a single-block spec.
 *
 * The fix: `setCipher` resets `cipherMode` to "single-block" if the
 * new cipher doesn't support the active mode. The cipher-mode store's
 * `loadInitial` performs the same check at load time so a persisted
 * mismatch (cipher=speck, cipherMode=ecb in localStorage) gets
 * corrected on next reload.
 *
 * ## This file is the two-table canary
 *
 * `SUPPORTED_CIPHER_MODES_BY_CIPHER` and the `defaults` table in `spec.ts` are
 * separate and must agree. These assertions are deliberately written as exact
 * equality against the CURRENT truth, so registering a core without updating
 * both tables fails here rather than lying in the dropdown. When a cipher below
 * gains ECB/CBC, flip its row in the same commit as the core.
 */

import { hasBlockCipherCore } from "@/ui/stores/block-cipher-cores";
import { type Cipher, isAesCipher } from "@/ui/stores/cipher";
import { isCipherModeSupported } from "@/ui/stores/cipher-mode";
import { describe, expect, it } from "vitest";

/** Every cipher that has no `BlockCipherCore` yet ⇒ single-block only. */
const CORELESS_CIPHERS = [
  "speck-32-64-be",
  "speck-32-64-le",
  "serpent-128",
  "serpent-192",
  "serpent-256",
  "des",
  "blowfish",
  "twofish",
] as const satisfies readonly Cipher[];

const AES_CIPHERS = ["aes-128", "aes-192", "aes-256"] as const satisfies readonly Cipher[];

describe("cipher-mode × cipher support matrix", () => {
  it("every AES variant supports single-block + ecb + cbc", () => {
    // Phase B of `docs/plans/foamy-prancing-wren.md` extended ECB/CBC from
    // AES-128 to all three variants: they were always variant-parameterized,
    // and once the mode builders took a core the other two cost a table row.
    for (const cipher of AES_CIPHERS) {
      expect(isCipherModeSupported(cipher, "single-block")).toBe(true);
      expect(isCipherModeSupported(cipher, "ecb")).toBe(true);
      expect(isCipherModeSupported(cipher, "cbc")).toBe(true);
      // CTR is designed for but not built — the contract exposes the forward
      // body + a no-padding flag so it lands as a `modes/ctr.ts` alone.
      expect(isCipherModeSupported(cipher, "ctr")).toBe(false);
    }
  });

  it("a cipher with no BlockCipherCore is single-block only", () => {
    // Canary: adding a core for any of these (Phase C templates it on
    // Blowfish) fires this test and forces the mode matrix + the `defaults`
    // table to be updated in the same commit as the core.
    for (const cipher of CORELESS_CIPHERS) {
      expect(isCipherModeSupported(cipher, "single-block")).toBe(true);
      expect(isCipherModeSupported(cipher, "ecb")).toBe(false);
      expect(isCipherModeSupported(cipher, "cbc")).toBe(false);
      expect(isCipherModeSupported(cipher, "ctr")).toBe(false);
    }
  });

  it("core presence is what decides multi-block support, for every cipher", () => {
    // The load-bearing invariant, stated directly: the two facts must agree.
    // A cipher with a core but no `defaults` entry would show an enabled
    // dropdown option that silently falls back to single-block; a cipher with
    // a `defaults` entry but no core cannot have been built at all.
    for (const cipher of [...AES_CIPHERS, ...CORELESS_CIPHERS]) {
      expect(isCipherModeSupported(cipher, "ecb")).toBe(hasBlockCipherCore(cipher));
      expect(isCipherModeSupported(cipher, "cbc")).toBe(hasBlockCipherCore(cipher));
    }
  });

  it("AES is exactly the set of ciphers with a core today", () => {
    // Pins the CURRENT rollout state. Deliberately not written as "AES has a
    // core" — this fires when Blowfish's core lands (Phase C), which is the
    // moment `isAesCipher` stops being a usable stand-in for "can do modes"
    // anywhere it still survives.
    for (const cipher of [...AES_CIPHERS, ...CORELESS_CIPHERS]) {
      expect(hasBlockCipherCore(cipher)).toBe(isAesCipher(cipher));
    }
  });
});
