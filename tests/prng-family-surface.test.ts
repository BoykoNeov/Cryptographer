/**
 * PRNG family surface — the store-level contract for the app's fourth algorithm
 * family (`docs/plans/iterative-dancing-ocean.md`, Phase P1).
 *
 * `tests/lcg-kat.test.ts` proves the generator is CORRECT. This file proves it
 * is correctly *installed*: that the four families partition `Algorithm`, that a
 * PRNG spec lands in a single direction-less slot, that the output length
 * survives a save/load round-trip, and that "custom" means what it says.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ONE TEST THAT MATTERS MOST is `isCipher` in group 1.
 *
 * Every other coupling in this feature is enforced by the compiler. Adding a
 * `kind: "prng"` variant to the `SpecsByMode` union makes `activeSpec`'s
 * `s[mode()]` a type error, so `tsc` walks the author through every branch.
 *
 * `isCipher` gets none of that protection. It is a hand-written type predicate
 * (`a is Cipher`), so `!isHash(p) && !isAsymmetric(p)` returns `true` for a PRNG
 * and **the compiler believes it** — routing generators into `setCipher`, the
 * `DEFAULT_*_BY_CIPHER` lookups and the padding overlay, all of which would be
 * `undefined` at runtime rather than a type error at build time. The store file
 * carries a comment saying every new non-cipher family must be subtracted there;
 * this is the test that makes the comment enforceable. RSA shipped this exact
 * bug once already.
 */

import { LCG_ITERATE_ID, LCG_WORD_BYTES, buildLcgSpec } from "@/ciphers/lcg";
import {
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
import { ALGORITHM_IDS, PRNG_IDS } from "@/core/document-schema";
import {
  ASYMMETRIC_OPTIONS,
  type Algorithm,
  CIPHER_OPTIONS,
  DEFAULT_KEY_BYTES_BY_PRNG,
  DEFAULT_PT_BYTES_BY_PRNG,
  HASH_OPTIONS,
  PRNG_LABELS,
  PRNG_OPTIONS,
  __resetCipherForTests,
  isAsymmetric,
  isCipher,
  isHash,
  isPrng,
  useAlgorithm,
  useCategory,
  usePrng,
} from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  DEFAULT_PRNG_OUTPUT,
  MAX_PRNG_OUTPUT,
  __resetSpecForTests,
  isCustomSpec,
  resetSpec,
  setAlgorithm,
  setCipher,
  setMode,
  setPrng,
  setPrngOutputLength,
  setSpecFromDocument,
  useMode,
  usePrngOutputLength,
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
  setPrngOutputLength(DEFAULT_PRNG_OUTPUT);
};

const ALL_ALGORITHMS: readonly Algorithm[] = [
  ...CIPHER_OPTIONS,
  ...HASH_OPTIONS,
  ...ASYMMETRIC_OPTIONS,
  ...PRNG_OPTIONS,
];

describe("PRNG family surface", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  // ─── 1. The family predicates partition Algorithm ───────────────────────

  describe("family predicates", () => {
    it("isCipher does NOT claim a generator", () => {
      // THE landmine. See the file header: this is the one coupling `tsc`
      // cannot check, because `isCipher` is a hand-written type predicate and
      // the compiler trusts whatever it returns.
      for (const p of PRNG_OPTIONS) {
        expect(isCipher(p), `isCipher("${p}") must be false`).toBe(false);
      }
    });

    it("every algorithm belongs to exactly one family", () => {
      // Catches both directions of failure: a family that forgets to claim its
      // own members, and one that over-claims another's.
      for (const a of ALL_ALGORITHMS) {
        const claims = [isCipher(a), isHash(a), isAsymmetric(a), isPrng(a)].filter(Boolean);
        expect(
          claims,
          `"${a}" is claimed by ${claims.length} families, expected exactly 1`,
        ).toEqual([true]);
      }
    });

    it("isPrng claims every generator and nothing else", () => {
      for (const p of PRNG_OPTIONS) expect(isPrng(p)).toBe(true);
      for (const c of CIPHER_OPTIONS) expect(isPrng(c)).toBe(false);
      for (const h of HASH_OPTIONS) expect(isPrng(h)).toBe(false);
      for (const a of ASYMMETRIC_OPTIONS) expect(isPrng(a)).toBe(false);
    });

    it("the persisted algorithm enum covers every generator", () => {
      // `PRNG_IDS` is pinned to the `Prng` union at compile time by
      // `assertPrngCoverage`; this checks the runtime tuple actually reaches
      // ALGORITHM_IDS, which is what `z.enum` validates a loaded document
      // against. Miss it and saving works while loading rejects the file.
      for (const p of PRNG_OPTIONS) {
        expect(PRNG_IDS as readonly string[]).toContain(p);
        expect(ALGORITHM_IDS as readonly string[]).toContain(p);
      }
    });

    it("every generator has a label and a default seed", () => {
      for (const p of PRNG_OPTIONS) {
        expect(PRNG_LABELS[p]).toBeTruthy();
        // The seed is one word wide; the key is empty (generators are keyless
        // in the symmetric sense, and the UI hides the field on that basis).
        expect(DEFAULT_PT_BYTES_BY_PRNG[p]).toHaveLength(LCG_WORD_BYTES);
        expect(DEFAULT_KEY_BYTES_BY_PRNG[p]).toHaveLength(0);
      }
    });
  });

  // ─── 2. Selecting a generator ──────────────────────────────────────────

  describe("selection", () => {
    it("setPrng lands a single direction-less slot and flips the category", () => {
      setPrng("minstd-rand0");
      expect(useCategory()()).toBe("prng");
      expect(useAlgorithm()()).toBe("minstd-rand0");
      const specs = useSpecsByMode()();
      expect(specs.kind).toBe("prng");
      if (specs.kind !== "prng") throw new Error("expected a prng SpecsByMode");
      expect(specs.prng).toBe("minstd-rand0");
    });

    it("setAlgorithm routes a generator to the PRNG branch", () => {
      // The single boundary the selector UI calls. If `isCipher` were wrong,
      // this would land in `setCipher` and the assertion below would fail with
      // kind "cipher" — a second, independent net under the same landmine.
      setAlgorithm("minstd-rand");
      expect(useSpecsByMode()().kind).toBe("prng");
      expect(usePrng()()).toBe("minstd-rand");
    });

    it("the active spec ignores the mode signal", () => {
      // A generator has no inverse, so `mode()` is inert. The UI hides the
      // toggle; this pins the store half of that contract.
      setPrng("minstd-rand0");
      const encryptSpec = useSpec()();
      setMode("decrypt");
      expect(useMode()()).toBe("decrypt");
      expect(useSpec()()).toBe(encryptSpec);
    });

    it("remembers the generator across a detour through another family", () => {
      setPrng("minstd-rand");
      setCipher("aes-128");
      expect(useCategory()()).toBe("cipher");
      setAlgorithm("minstd-rand");
      expect(usePrng()()).toBe("minstd-rand");
    });
  });

  // ─── 3. Output length ──────────────────────────────────────────────────

  describe("output length", () => {
    it("the default is deliberately not a multiple of the word size", () => {
      // So the app's FIRST PAINT exercises the partial-final-block path. A
      // regression in the trim would otherwise be invisible until someone typed
      // an awkward number. Same reasoning as ChaCha20's 114-byte default.
      expect(DEFAULT_PRNG_OUTPUT % LCG_WORD_BYTES).not.toBe(0);
    });

    it("changing it rebuilds the spec structurally", () => {
      setPrng("minstd-rand0");
      const before = useSpec()();
      setPrngOutputLength(64);
      const after = useSpec()();
      expect(after).not.toBe(before);
      expect(usePrngOutputLength()()).toBe(64);
      // 64 bytes ⇒ 16 whole words. The count lives in the `zero-fill@1` width.
      const request = after.steps.find((n) => n.id === "request");
      if (request === undefined || request.kind !== "step") throw new Error("no request leaf");
      expect((request.params as { byteLength?: number }).byteLength).toBe(64);
    });

    it("clamps to [1, MAX_PRNG_OUTPUT]", () => {
      setPrng("minstd-rand0");
      setPrngOutputLength(0);
      expect(usePrngOutputLength()()).toBe(1);
      setPrngOutputLength(MAX_PRNG_OUTPUT + 5000);
      expect(usePrngOutputLength()()).toBe(MAX_PRNG_OUTPUT);
    });

    it("a pure length change does NOT read as a custom spec", () => {
      // The contract that makes the length a first-class selector rather than an
      // edit: the signal and the active spec move together through the
      // structural rebuild, so `isCustomSpec` compares against a canonical built
      // at the SAME length. Break the lockstep and the app shows
      // "Custom (was …)" plus a reset button after touching a spinner.
      setPrng("minstd-rand0");
      expect(isCustomSpec()).toBe(false);
      setPrngOutputLength(100);
      expect(isCustomSpec()).toBe(false);
    });

    it("still updates while a non-PRNG algorithm is active", () => {
      // So switching to a generator later picks up the chosen length rather
      // than snapping back to the default.
      setCipher("aes-128");
      setPrngOutputLength(77);
      setPrng("minstd-rand0");
      expect(usePrngOutputLength()()).toBe(77);
    });
  });

  // ─── 4. Custom / reset ─────────────────────────────────────────────────

  describe("custom and reset", () => {
    it("a leaf edit reads as custom, and reset restores the canonical", () => {
      setPrng("minstd-rand0");
      expect(isCustomSpec()).toBe(false);

      // Rewrite the multiplier constant — the edit a learner actually makes.
      const specs = useSpecsByMode()();
      if (specs.kind !== "prng") throw new Error("expected a prng SpecsByMode");
      const iterate = specs.single.steps.find((n) => n.id === LCG_ITERATE_ID);
      if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
      const edited = {
        ...specs.single,
        steps: specs.single.steps.map((n) =>
          n.id === LCG_ITERATE_ID
            ? {
                ...iterate,
                children: iterate.children.map((c) =>
                  c.kind === "step" && c.id === "mult"
                    ? { ...c, params: { bytes: [0, 0, 0, 3] } }
                    : c,
                ),
              }
            : n,
        ),
      };
      setSpecFromDocument({
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: edited,
        algorithm: "minstd-rand0",
      });
      expect(isCustomSpec()).toBe(true);

      resetSpec();
      expect(isCustomSpec()).toBe(false);
    });
  });

  // ─── 5. Document round-trip ────────────────────────────────────────────

  describe("save / load", () => {
    it("round-trips a generator document including its output length", () => {
      // The length is the piece most likely to be silently dropped: it lives in
      // the spec (so it survives serialization for free) but ALSO in a signal
      // the UI reads. Without `readLcgOutputLength` in the load path the two
      // disagree — the trace shows 137 bytes while the control reads 42.
      setPrng("minstd-rand");
      setPrngOutputLength(137);

      const doc: CipherDocument = {
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: useSpec()(),
        algorithm: "minstd-rand",
      };
      const text = serializeDocument(doc);

      // Land somewhere else entirely, then load.
      setCipher("aes-128");
      setPrngOutputLength(DEFAULT_PRNG_OUTPUT);
      expect(useCategory()()).toBe("cipher");

      const parsed = parseDocument(text);
      expect(parsed.ok, parsed.ok ? "" : parsed.error).toBe(true);
      if (!parsed.ok) return;
      setSpecFromDocument(parsed.doc);

      expect(useCategory()()).toBe("prng");
      expect(usePrng()()).toBe("minstd-rand");
      expect(usePrngOutputLength()()).toBe(137);
      expect(useSpecsByMode()().kind).toBe("prng");
      // And the loaded spec is the canonical one for that length — so it reads
      // "not custom" rather than showing a spurious reset button.
      expect(isCustomSpec()).toBe(false);
    });

    it("a generator document validates against the persisted algorithm enum", () => {
      // Guards the `ALGORITHM_IDS` widening end-to-end: `z.enum` rejects an
      // algorithm string it does not know, so a missing PRNG_IDS spread would
      // make every saved generator document unloadable.
      const text = serializeDocument({
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: buildLcgSpec("minstd-rand0", 42),
        algorithm: "minstd-rand0",
      });
      const parsed = parseDocument(text);
      expect(parsed.ok, parsed.ok ? "" : parsed.error).toBe(true);
    });
  });
});
