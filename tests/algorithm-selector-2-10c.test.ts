/**
 * Tests for the algorithm-selector signal flow — Slice 2.10c of
 * `docs/plans/universal-port-dataflow.md` (2026-05-25).
 *
 * Slice 2.10c reaches the hash branch from the live UI by:
 *   - Splitting the algorithm signal into three: `cipher` (existing,
 *     always holds a Cipher), `hash` (new, always holds a Hash),
 *     `category` (new, "cipher" | "hash" discriminant).
 *   - Exposing `useAlgorithm()` as the derived accessor — returns
 *     `category === "cipher" ? cipher() : hash()`.
 *   - Adding `setAlgorithm(a: Algorithm)` to `stores/spec.ts` that routes
 *     to `setCipher` or `setHash` (both flip category and rebuild specs).
 *   - Updating `setSpecFromDocument`'s hash branch to also write the
 *     category + hash signals so the dropdown UI lands on the right
 *     family after a load. The cipher branch defensively writes
 *     category="cipher" so a hash → cipher load lands correctly too.
 *
 * The "Remember last cipher" semantic (user pick at slice start): the
 * cipher and hash signals are independent and preserve their last value
 * across category flips, so a cipher → hash → cipher detour returns
 * the user to the same cipher they were on.
 *
 * This file pins the store-level contract. The JSX-side tests live
 * alongside the existing jsdom App tests; today we don't add a dedicated
 * jsdom test for the algorithm-selector dropdown because the existing
 * cipher-selector tests still cover the dropdown shape end-to-end (the
 * cipher dropdown is the same control today's tests already exercise).
 */

import { buildSha256Spec } from "@/ciphers/sha-256";
import { CURRENT_SCHEMA_VERSION, type CipherDocument } from "@/core/document";
import {
  __resetCipherForTests,
  setCategory,
  setCipher as setCipherRawSignal,
  setHash as setHashRawSignal,
  useAlgorithm,
  useCategory,
  useCipher,
  useHash,
} from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  setAlgorithm,
  setCipher,
  setHash,
  setSpecFromDocument,
  useSpec,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetPaddingForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetLayoutsForTests();
  __resetSpecForTests();
};

describe("algorithm-selector (Slice 2.10c)", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  // ─── useAlgorithm accessor ─────────────────────────────────────────────

  describe("useAlgorithm", () => {
    it("returns the cipher signal when category is 'cipher'", () => {
      // Default boot state: category="cipher", cipher="aes-128".
      expect(useCategory()()).toBe("cipher");
      expect(useCipher()()).toBe("aes-128");
      expect(useAlgorithm()()).toBe("aes-128");
    });

    it("returns the hash signal when category is 'hash'", () => {
      // Flip the category WITHOUT going through setAlgorithm so we exercise
      // the accessor's branching directly. `setCategory` is the raw signal
      // setter from stores/cipher.ts; the spec store isn't touched here.
      setCategory("hash");
      expect(useAlgorithm()()).toBe("sha-256");
    });

    it("re-resolves when the underlying cipher or hash signal flips", () => {
      // category=cipher; flip cipher to des, algorithm should follow.
      setCipher("des");
      expect(useAlgorithm()()).toBe("des");
      // Now category=hash via the spec-store boundary; algorithm flips to
      // the current hash signal value.
      setHash("sha-256");
      expect(useAlgorithm()()).toBe("sha-256");
    });
  });

  // ─── Remember-last-cipher semantic ─────────────────────────────────────

  describe('"Remember last cipher" — independent cipher + hash signals', () => {
    it("cipher signal survives a cipher → hash → cipher detour", () => {
      // Pick an arbitrary non-default cipher to make the survival visible.
      setCipher("aes-256");
      expect(useCipher()()).toBe("aes-256");
      expect(useCategory()()).toBe("cipher");

      // Flip to hash. The cipher signal stays at aes-256.
      setHash("sha-256");
      expect(useCategory()()).toBe("hash");
      expect(useCipher()()).toBe("aes-256"); // ← the load-bearing assertion

      // Flip back. Without explicit cipher set, we just flip category;
      // the cipher signal is still aes-256 from before.
      setCategory("cipher");
      expect(useAlgorithm()()).toBe("aes-256");
    });

    it("hash signal survives a hash → cipher → hash detour", () => {
      // Today's hash union has one member, so this test is somewhat
      // structural — but it pins the contract that the hash signal is
      // INDEPENDENT of the category flag, so SHA-3 / SHA-512 additions
      // ride the same shape.
      setHash("sha-256");
      expect(useHash()()).toBe("sha-256");
      setCipher("aes-128");
      expect(useHash()()).toBe("sha-256"); // still remembered
      setCategory("hash");
      expect(useAlgorithm()()).toBe("sha-256");
    });
  });

  // ─── setAlgorithm dispatch ─────────────────────────────────────────────

  describe("setAlgorithm — routes to setCipher or setHash by category", () => {
    it("dispatches a Cipher value through the cipher branch", () => {
      setAlgorithm("des");
      expect(useCategory()()).toBe("cipher");
      expect(useCipher()()).toBe("des");
      const s = useSpecsByMode()();
      expect(s.kind).toBe("cipher");
      // Spec is the canonical DES single-block spec — id carries a
      // version-suffix `@1` per project convention.
      expect(useSpec()().id.startsWith("des")).toBe(true);
    });

    it("dispatches a Hash value through the hash branch", () => {
      setAlgorithm("sha-256");
      expect(useCategory()()).toBe("hash");
      expect(useHash()()).toBe("sha-256");
      const s = useSpecsByMode()();
      expect(s.kind).toBe("hash");
      if (s.kind !== "hash") return;
      expect(s.hash).toBe("sha-256");
      // Spec is the canonical SHA-256 spec from hashDefaults.
      expect(useSpec()()).toEqual(buildSha256Spec());
    });

    it("crossing cipher → hash → cipher returns the prior cipher's spec", () => {
      setAlgorithm("aes-256");
      const aes256Spec = useSpec()();
      setAlgorithm("sha-256");
      expect(useSpec()()).not.toBe(aes256Spec);
      // Flip back via the LOW-LEVEL category setter — semantically:
      // "the user clicked the Cipher radio without re-picking from the
      // cipher dropdown". The category-only flip relies on the cipher
      // signal having remembered "aes-256".
      setCategory("cipher");
      // useSpecsByMode still holds the hash-kind because setCategory
      // doesn't touch the spec store. This is intentional: setCategory
      // is the raw signal setter; the App's `changeCategory` wrapper
      // composes it with the spec-side setAlgorithm.
      // What we CAN check at this layer: useAlgorithm() resolves
      // correctly to aes-256.
      expect(useAlgorithm()()).toBe("aes-256");
    });
  });

  // ─── setCipher + setHash side-effect: category flip ────────────────────

  describe("setCipher / setHash also flip category", () => {
    it("setCipher flips category to 'cipher' even if it was 'hash'", () => {
      setAlgorithm("sha-256"); // category becomes "hash"
      expect(useCategory()()).toBe("hash");
      setCipher("aes-192");
      expect(useCategory()()).toBe("cipher");
      expect(useCipher()()).toBe("aes-192");
    });

    it("setHash flips category to 'hash' even if it was 'cipher'", () => {
      // Default: category="cipher".
      setHash("sha-256");
      expect(useCategory()()).toBe("hash");
      expect(useHash()()).toBe("sha-256");
    });
  });

  // ─── setSpecFromDocument category sync ─────────────────────────────────

  describe("setSpecFromDocument syncs category + hash signals", () => {
    it("hash document loaded into a cipher recipient flips category to hash", () => {
      // Recipient starts in default cipher category.
      expect(useCategory()()).toBe("cipher");

      const doc: CipherDocument = {
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: buildSha256Spec(),
        algorithm: "sha-256",
      };
      setSpecFromDocument(doc);

      // Category + hash signals tracked the load.
      expect(useCategory()()).toBe("hash");
      expect(useHash()()).toBe("sha-256");
      expect(useAlgorithm()()).toBe("sha-256");
    });

    it("cipher document loaded into a hash recipient flips category back to cipher", () => {
      // Set up: recipient in hash category.
      setAlgorithm("sha-256");
      expect(useCategory()()).toBe("hash");

      // A spec-only cipher document with the algorithm hint.
      const doc: CipherDocument = {
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: { ...buildSha256Spec(), id: "fake-cipher" }, // any non-hash spec; algorithm hint is what drives the branch
        algorithm: "aes-128",
      };
      setSpecFromDocument(doc);

      // Category flipped back to "cipher" defensively.
      expect(useCategory()()).toBe("cipher");
      expect(useCipher()()).toBe("aes-128");
    });
  });

  // ─── Direct signal access for unused-import paranoia ────────────────────
  // Keep the raw-signal imports referenced so a future refactor that
  // removes them shows up in tests. The signal setters MUST exist on
  // the cipher store for the spec store's wrappers to compose against.

  it("raw signal setters are exported from stores/cipher", () => {
    // Just call each and re-read; the assertion is structural (no throw).
    setCipherRawSignal("aes-128");
    setHashRawSignal("sha-256");
    setCategory("cipher");
    expect(useCipher()()).toBe("aes-128");
    expect(useHash()()).toBe("sha-256");
    expect(useCategory()()).toBe("cipher");
  });
});
