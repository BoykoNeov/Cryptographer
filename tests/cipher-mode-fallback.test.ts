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
const CORELESS_CIPHERS = ["twofish"] as const satisfies readonly Cipher[];

/** Every cipher that HAS a core ⇒ single-block + ecb + cbc. */
const CORED_CIPHERS = [
  "aes-128",
  "aes-192",
  "aes-256",
  "speck-32-64-be",
  "speck-32-64-le",
  "blowfish",
  "serpent-128",
  "serpent-192",
  "serpent-256",
  "des",
] as const satisfies readonly Cipher[];

describe("cipher-mode × cipher support matrix", () => {
  it("every cipher with a core supports single-block + ecb + cbc + ctr", () => {
    // Phase B extended ECB/CBC from AES-128 to all three AES variants; Phase C
    // added Blowfish, the first non-AES member and the first whose block is not
    // 16 bytes; Serpent followed as an AES-shaped family (three more cores); and
    // Speck32/64 joined as the first core whose block is smaller than 8 bytes
    // (a byte-order pair). All arrive the same way: a core plus two table rows.
    for (const cipher of CORED_CIPHERS) {
      expect(isCipherModeSupported(cipher, "single-block")).toBe(true);
      expect(isCipherModeSupported(cipher, "ecb")).toBe(true);
      expect(isCipherModeSupported(cipher, "cbc")).toBe(true);
      // CTR landed exactly as `block-cipher-core.ts` predicted it would: a
      // single `modes/ctr.ts` plus one new arithmetic step, with ZERO changes
      // to the core contract. Every core gained it at once — which is the
      // N+M-not-N×M claim paying out for the third time.
      expect(isCipherModeSupported(cipher, "ctr")).toBe(true);
    }
  });

  it("a cipher with no BlockCipherCore is single-block only", () => {
    // Canary: adding a core for any of these fires this test and forces the
    // mode matrix + the `defaults` table to be updated in the same commit as
    // the core. `src/ciphers/blowfish-core.ts` is the template to follow.
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
    for (const cipher of [...CORED_CIPHERS, ...CORELESS_CIPHERS]) {
      expect(isCipherModeSupported(cipher, "ecb")).toBe(hasBlockCipherCore(cipher));
      expect(isCipherModeSupported(cipher, "cbc")).toBe(hasBlockCipherCore(cipher));
      expect(isCipherModeSupported(cipher, "ctr")).toBe(hasBlockCipherCore(cipher));
    }
  });

  it("a core is no longer the same thing as being AES", () => {
    // Retires the old "AES is exactly the set of ciphers with a core" pin,
    // which existed to fire the moment `isAesCipher` stopped standing in for
    // "can do modes". Phase C is that moment, so the pin is inverted rather
    // than deleted: Blowfish must have a core while NOT being AES, which is
    // what makes any surviving `isAesCipher` mode gate a bug.
    expect(hasBlockCipherCore("blowfish")).toBe(true);
    expect(isAesCipher("blowfish")).toBe(false);
  });
});
