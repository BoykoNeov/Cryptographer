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

import { buildChaCha20CsprngSpec } from "@/ciphers/chacha20-csprng";
import { LCG_ITERATE_ID, LCG_WORD_BYTES, buildLcgSpec } from "@/ciphers/lcg";
import { MT_MAX_OUTPUT_BYTES, buildMt19937Spec } from "@/ciphers/mt19937";
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
  type Prng,
  SEED_BYTES_BY_PRNG,
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
  MAX_CSPRNG_OUTPUT,
  MAX_PRNG_OUTPUT,
  __resetSpecForTests,
  isCustomSpec,
  maxPrngOutputFor,
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

/**
 * Build a canonical spec for any generator, without going through the store.
 * Routes on the variant because the family now spans THREE builders — the
 * shared LCG template, the ChaCha20 CSPRNG and MT19937 — and a test that called
 * only the first would silently stop covering the newest variant.
 *
 * This dispatcher earned its keep when MT19937 landed: adding the variant to
 * the `Prng` union broke this line at compile time, which is precisely the
 * coverage-erosion this shape exists to prevent.
 */
const buildPrngSpecFor = (p: Prng, length: number) =>
  p === "chacha20-csprng"
    ? buildChaCha20CsprngSpec(length)
    : p === "mt19937"
      ? buildMt19937Spec(length)
      : buildLcgSpec(p, length);

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

    it("PRNG_OPTIONS lists EVERY member of the Prng union", () => {
      // Found by perturbation while adding MT19937, and worth the extra test:
      // every assertion in this file iterates `PRNG_OPTIONS`, so a variant
      // missing from `ALL_PRNGS` does not fail anything — it silently shrinks
      // the loops and the whole file passes VACUOUSLY. Deleting MT19937 from
      // `ALL_PRNGS` took this suite from 28 tests to 26, all green.
      //
      // `PRNG_LABELS` is a `Record<Prng, string>`, so the COMPILER already
      // forces it to carry every variant. Comparing the runtime list against
      // its keys is what converts that compile-time exhaustiveness into a
      // check on the list every other test here trusts.
      expect([...PRNG_OPTIONS].sort()).toEqual(Object.keys(PRNG_LABELS).sort());
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

    it("every generator has a label and a default seed of its own width", () => {
      for (const p of PRNG_OPTIONS) {
        expect(PRNG_LABELS[p]).toBeTruthy();
        // Per-variant, NOT one constant. The LCGs take a 32-bit word; the
        // CSPRNG takes 32 bytes, because its seed occupies ChaCha20's key
        // region. A default that disagreed with `SEED_BYTES_BY_PRNG` would make
        // the app throw its own seed-width error on first Run — and the same
        // table is what `App.tsx` validates against, so this pins both halves.
        expect(DEFAULT_PT_BYTES_BY_PRNG[p]).toHaveLength(SEED_BYTES_BY_PRNG[p]);
        // The key is empty for every generator (they are keyless in the
        // symmetric sense, and the UI hides the field on that basis) — the
        // CSPRNG included, whose seed rides the plaintext field like the rest.
        expect(DEFAULT_KEY_BYTES_BY_PRNG[p]).toHaveLength(0);
      }
    });

    it("the LCGs share the one-word seed the family shipped with", () => {
      // Keeps the generalization above honest: widening to a per-variant table
      // must not have quietly changed what the three LCGs accept.
      for (const p of ["minstd-rand0", "minstd-rand", "ansi-c-lcg"] as const) {
        expect(SEED_BYTES_BY_PRNG[p]).toBe(LCG_WORD_BYTES);
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

    it("keeps MAX_PRNG_OUTPUT inside what ONE MT19937 twist can supply", () => {
      // MT19937 is the only variant whose `resolvePrngDefault` arm does not
      // clamp: it does not need to, because 1024 < 2496 and the builder's
      // refusal above 2496 is therefore unreachable from the UI. That is an
      // INEQUALITY between two constants in different files, and
      // `MAX_PRNG_OUTPUT`'s own docblock invites raising it ("Raise this only
      // with a fresh measurement") — so the next person to do that would get an
      // uncaught throw in the spec-rebuild path rather than a clamped value.
      //
      // Pin the relationship here so raising the ceiling fails loudly and names
      // the reason. If MT19937 ever needs to exceed one twist, it needs a
      // refill in the spec, not a bigger number here.
      expect(MAX_PRNG_OUTPUT).toBeLessThanOrEqual(MT_MAX_OUTPUT_BYTES);
      // And the builder really does refuse past its own limit.
      expect(() => buildMt19937Spec(MT_MAX_OUTPUT_BYTES + 1)).toThrow(/second twist/);
      // The UI ceiling is reachable and legal.
      setPrng("mt19937");
      setPrngOutputLength(MAX_PRNG_OUTPUT);
      expect(usePrngOutputLength()()).toBe(MAX_PRNG_OUTPUT);
      expect(() => buildMt19937Spec(usePrngOutputLength()())).not.toThrow();
    });

    it("clamps the CSPRNG to its own, much lower ceiling", () => {
      // The generators differ in frame cost by three orders of magnitude: an
      // LCG spends ~4 frames per 4-byte word, the CSPRNG ~990 per 64-byte
      // block. One shared ceiling cannot serve both — at 1024 bytes the CSPRNG
      // would build ~16,000 frames and take tens of seconds per edit.
      setPrng("chacha20-csprng");
      setPrngOutputLength(MAX_PRNG_OUTPUT);
      expect(usePrngOutputLength()()).toBe(MAX_CSPRNG_OUTPUT);
      expect(maxPrngOutputFor("chacha20-csprng")).toBe(MAX_CSPRNG_OUTPUT);
      expect(maxPrngOutputFor("minstd-rand0")).toBe(MAX_PRNG_OUTPUT);
    });

    it("re-clamps a too-long length when SWITCHING to the CSPRNG", () => {
      // The length signal is shared across variants, so a length legal under an
      // LCG can be far above what the CSPRNG can render. Clamping only inside
      // `setPrngOutputLength` would miss this path entirely — the user never
      // touches the stepper, they just change the dropdown.
      setPrng("minstd-rand0");
      setPrngOutputLength(MAX_PRNG_OUTPUT);
      expect(usePrngOutputLength()()).toBe(MAX_PRNG_OUTPUT);

      setPrng("chacha20-csprng");
      expect(usePrngOutputLength()()).toBe(MAX_CSPRNG_OUTPUT);
      // And the spec that landed was built at the clamped length, not the
      // original — otherwise the control and the trace would disagree.
      const request = useSpec()().steps.find((n) => n.id === "request");
      if (request === undefined || request.kind !== "step") throw new Error("no request leaf");
      expect((request.params as { byteLength?: number }).byteLength).toBe(MAX_CSPRNG_OUTPUT);
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
    // Looped over the option list rather than written once per variant: this is
    // the ONE path where the persisted `PRNG_IDS` enum, `setSpecFromDocument`'s
    // prng branch and `readLcgOutputLength` all meet, so a new variant that is
    // only added to two of the three would round-trip wrong. Written per-variant
    // it silently covers whichever ones happened to be named when it was
    // authored — which is exactly what happened between P1 and P2.
    for (const prng of PRNG_OPTIONS) {
      it(`round-trips a ${prng} document including its output length`, () => {
        // The length is the piece most likely to be silently dropped: it lives
        // in the spec (so it survives serialization for free) but ALSO in a
        // signal the UI reads. Without `readLcgOutputLength` in the load path
        // the two disagree — the trace shows 137 bytes while the control reads
        // the default.
        setPrng(prng);
        setPrngOutputLength(137);

        const doc: CipherDocument = {
          schemaVersion: CURRENT_SCHEMA_VERSION,
          spec: useSpec()(),
          algorithm: prng,
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
        expect(usePrng()()).toBe(prng);
        expect(usePrngOutputLength()()).toBe(137);
        expect(useSpecsByMode()().kind).toBe("prng");
        // And the loaded spec is the canonical one for that length — so it
        // reads "not custom" rather than showing a spurious reset button.
        expect(isCustomSpec()).toBe(false);
      });

      it(`a ${prng} document validates against the persisted algorithm enum`, () => {
        // `PRNG_IDS` is pinned to the `Prng` union in BOTH directions at
        // compile time (`satisfies readonly Prng[]` one way, `assertPrngCoverage`
        // the other), so a missing variant is a type error rather than a
        // runtime surprise. What is NOT compile-checked is that the ids reach
        // Zod: `ALGORITHM_IDS` spreads four lists, and dropping the spread
        // leaves every assertion above green while `z.enum` rejects the string
        // and makes every saved generator document unloadable.
        const text = serializeDocument({
          schemaVersion: CURRENT_SCHEMA_VERSION,
          spec: buildPrngSpecFor(prng, 42),
          algorithm: prng,
        });
        const parsed = parseDocument(text);
        expect(parsed.ok, parsed.ok ? "" : parsed.error).toBe(true);
      });
    }
  });
});
