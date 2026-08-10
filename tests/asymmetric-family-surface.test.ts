/**
 * The public-key family's surface, as a set of couplings the compiler cannot
 * check (P4 of `docs/plans/unified-stargazing-quasar.md`).
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY THIS FILE DID NOT EXIST UNTIL THE FAMILY HAD TWO MEMBERS
 *
 * `tests/prng-family-surface.test.ts` and `tests/lattice-family-surface.test.ts`
 * both exist for one reason: `isCipher` is a HAND-WRITTEN type predicate, so a
 * family it forgets to subtract silently becomes a cipher and the compiler
 * believes it — acquiring a symmetric key field, a mode-of-operation selector
 * and a padding scheme. RSA shipped exactly that bug once.
 *
 * The public-key family never got the same treatment, because with one member
 * there was nothing a list could get wrong. ML-KEM changed that, and the
 * landmine is re-armed by every new *variant*, not just every new family:
 *
 *   - `ALL_ASYMMETRICS` is typed `readonly Asymmetric[]`, so **deleting an entry
 *     is not a compile error**. `isAsymmetric` then returns false, `isCipher`
 *     returns true, and `tsc` is satisfied.
 *   - The `Record<Asymmetric, string>` tables stay green throughout, because
 *     their keys are enforced and the missing name is still there.
 *
 * Perturbation-verified while writing this: removing `"ml-kem-768"` from
 * `ALL_ASYMMETRICS` passes `tsc` cleanly and, before this file, was caught only
 * incidentally — by a UI test noticing the dropdown had lost an option. Nothing
 * asserted the consequence that actually matters.
 *
 * The other half of the vacuity hazard, learned from MT19937: every assertion
 * below iterates `ASYMMETRIC_OPTIONS`, so a variant missing from the list would
 * simply shrink the loops and the whole file would pass. That is why the first
 * test pins the list against the compiler-enforced keys of a `Record`.
 */

import { CURRENT_SCHEMA_VERSION, type CipherDocument } from "@/core/document";
import { parseDocument, serializeDocument } from "@/core/document";
import {
  ALGORITHM_IDS,
  ASYMMETRIC_IDS,
  CIPHER_IDS,
  HASH_IDS,
  LATTICE_IDS,
  PRNG_IDS,
} from "@/core/document-schema";
import {
  ASYMMETRIC_DESCRIPTIONS,
  ASYMMETRIC_HISTORY,
  ASYMMETRIC_LABELS,
  ASYMMETRIC_OPTIONS,
  type Algorithm,
  CIPHER_OPTIONS,
  DEFAULT_CT_BYTES_BY_ASYMMETRIC,
  DEFAULT_KEY_BYTES_BY_ASYMMETRIC,
  DEFAULT_PT_BYTES_BY_ASYMMETRIC,
  HASH_OPTIONS,
  LATTICE_OPTIONS,
  PRNG_OPTIONS,
  describeAlgorithm,
  historyOfAlgorithm,
  isAsymmetric,
  isCipher,
  isHash,
  isLattice,
  isPrng,
} from "@/ui/stores/cipher";
import { useAsymmetric, useCategory } from "@/ui/stores/cipher";
import {
  setAsymmetric,
  setCipher,
  setSpecFromDocument,
  useSpec,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { describe, expect, it } from "vitest";

const ALL_ALGORITHMS: readonly Algorithm[] = [
  ...CIPHER_OPTIONS,
  ...HASH_OPTIONS,
  ...ASYMMETRIC_OPTIONS,
  ...PRNG_OPTIONS,
  ...LATTICE_OPTIONS,
];

describe("public-key family surface", () => {
  it("ASYMMETRIC_OPTIONS lists EVERY member of the Asymmetric union", () => {
    // The anti-vacuity pin, and the reason it comes first: every other
    // assertion here iterates this list. `ASYMMETRIC_LABELS` is a
    // `Record<Asymmetric, string>`, so the COMPILER already forces it to carry
    // every variant — comparing the runtime list against its keys is what turns
    // that compile-time exhaustiveness into a check on the list itself.
    expect([...ASYMMETRIC_OPTIONS].sort()).toEqual(Object.keys(ASYMMETRIC_LABELS).sort());
  });

  it("isCipher does NOT claim a public-key algorithm", () => {
    // THE landmine. `isCipher` is a hand-written type predicate; the compiler
    // trusts whatever it returns, so this coupling has no other guard.
    for (const a of ASYMMETRIC_OPTIONS) {
      expect(isCipher(a), `isCipher("${a}") must be false`).toBe(false);
    }
  });

  it("isAsymmetric claims every public-key algorithm and nothing else", () => {
    for (const a of ASYMMETRIC_OPTIONS) expect(isAsymmetric(a)).toBe(true);
    for (const c of CIPHER_OPTIONS) expect(isAsymmetric(c)).toBe(false);
    for (const h of HASH_OPTIONS) expect(isAsymmetric(h)).toBe(false);
    for (const p of PRNG_OPTIONS) expect(isAsymmetric(p)).toBe(false);
    for (const l of LATTICE_OPTIONS) expect(isAsymmetric(l)).toBe(false);
  });

  it("every algorithm belongs to exactly one family", () => {
    // Catches both directions: a family that forgets its own members, and one
    // that over-claims another's. ML-KEM is the interesting case — it is built
    // entirely out of lattice arithmetic and must still be claimed by exactly
    // one family, the public-key one.
    for (const a of ALL_ALGORITHMS) {
      const claims = [isCipher(a), isHash(a), isAsymmetric(a), isPrng(a), isLattice(a)].filter(
        Boolean,
      );
      expect(claims, `"${a}" is claimed by ${claims.length} families, expected 1`).toEqual([true]);
    }
  });

  it("the persisted algorithm enum covers every public-key variant", () => {
    // `ASYMMETRIC_IDS` is pinned to the union at compile time by
    // `assertAsymmetricCoverage`; this checks the runtime tuple actually
    // reaches `ALGORITHM_IDS`, which is what `z.enum` validates a loaded
    // document against. Miss it and saving works while loading rejects the file.
    for (const a of ASYMMETRIC_OPTIONS) {
      expect(ASYMMETRIC_IDS as readonly string[]).toContain(a);
      expect(ALGORITHM_IDS as readonly string[]).toContain(a);
    }
    // And it must not have leaked into another family's id tuple.
    for (const a of ASYMMETRIC_OPTIONS) {
      for (const [name, ids] of [
        ["CIPHER_IDS", CIPHER_IDS],
        ["HASH_IDS", HASH_IDS],
        ["PRNG_IDS", PRNG_IDS],
        ["LATTICE_IDS", LATTICE_IDS],
      ] as const) {
        expect(ids as readonly string[], `${a} should not be in ${name}`).not.toContain(a);
      }
    }
  });

  it("every variant has a label, a description and a history line", () => {
    // `describeAlgorithm` and `historyOfAlgorithm` route by family and fall
    // through to the CIPHER table, so a missing arm is a silent `undefined`
    // rather than a type error — the failure mode CLAUDE.md records.
    for (const a of ASYMMETRIC_OPTIONS) {
      expect(ASYMMETRIC_LABELS[a], `${a} label`).toBeTruthy();
      expect(ASYMMETRIC_DESCRIPTIONS[a], `${a} description`).toBeTruthy();
      expect(ASYMMETRIC_HISTORY[a], `${a} history`).toBeTruthy();
      expect(describeAlgorithm(a)).toBe(ASYMMETRIC_DESCRIPTIONS[a]);
      expect(historyOfAlgorithm(a)).toBe(ASYMMETRIC_HISTORY[a]);
    }
  });

  it("no variant has a symmetric key, and both direction defaults exist", () => {
    for (const a of ASYMMETRIC_OPTIONS) {
      // A key PAIR is not a symmetric key: both variants derive theirs inside
      // the spec from editable constants, and the UI hides the key field on
      // exactly this basis.
      expect(DEFAULT_KEY_BYTES_BY_ASYMMETRIC[a], `${a} key`).toHaveLength(0);
      // Both directions, because this family's defaults became MODE-AWARE in
      // P4. A variant with an encrypt default and no decrypt default leaves the
      // field holding the previous algorithm's bytes on a direction landing.
      expect(DEFAULT_PT_BYTES_BY_ASYMMETRIC[a]?.length, `${a} message default`).toBeGreaterThan(0);
      expect(DEFAULT_CT_BYTES_BY_ASYMMETRIC[a]?.length, `${a} ciphertext default`).toBeGreaterThan(
        0,
      );
    }
  });

  // ─── Save / load, per variant ───────────────────────────────────────────
  //
  // Looped over the option list rather than written once: this is the one path
  // where the persisted `ASYMMETRIC_IDS` enum, `setSpecFromDocument`'s
  // asymmetric branch and `buildCanonicalAsymmetric` all meet, so a variant
  // added to two of the three round-trips wrong. `document-roundtrip.test.ts`
  // does NOT enumerate algorithms, so it passed throughout P4 without ever
  // touching an ML-KEM document — the same vacuity this file's first test
  // guards against, one layer down.
  for (const variant of ASYMMETRIC_OPTIONS) {
    it(`round-trips a ${variant} document through save and load`, () => {
      setAsymmetric(variant);
      const doc: CipherDocument = {
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: useSpec()(),
        algorithm: variant,
      };
      const text = serializeDocument(doc);

      // Land somewhere else entirely, then load.
      setCipher("aes-128");
      expect(useCategory()()).toBe("cipher");

      const parsed = parseDocument(text);
      expect(parsed.ok, parsed.ok ? "" : parsed.error).toBe(true);
      if (!parsed.ok) return;
      setSpecFromDocument(parsed.doc);

      expect(useCategory()()).toBe("asymmetric");
      expect(useAsymmetric()()).toBe(variant);
      // Two slots, not one: this family is direction-FUL, so a load that
      // dropped the other direction would leave the mode toggle pointing at a
      // spec that no longer exists.
      expect(useSpecsByMode()().kind).toBe("asymmetric");
    });
  }
});
