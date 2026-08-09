/**
 * Lattice family surface — the store-level contract for the app's FIFTH
 * algorithm family (`docs/plans/unified-stargazing-quasar.md`, P1).
 *
 * `tests/ntt-3329-256-kat.test.ts` proves the transform is CORRECT. This file
 * proves it is correctly *installed*: that the five families partition
 * `Algorithm`, that a lattice spec lands in TWO direction slots (unlike hash and
 * PRNG), that a save/load round-trip keeps it in its own family, and that
 * "custom" means what it says.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ONE TEST THAT MATTERS MOST is `isCipher` in group 1.
 *
 * Every other coupling here is enforced by the compiler — adding
 * `kind: "lattice"` to the `SpecsByMode` union made `tsc` walk every branch, and
 * the two `DEFAULT_*_BY_CIPHER` fall-throughs in `App.tsx` surfaced as type
 * errors the moment the union widened.
 *
 * `isCipher` gets none of that protection. It is a hand-written type predicate
 * (`a is Cipher`), so an un-subtracted family returns `true` and **the compiler
 * believes it** — routing the transform into `setCipher`, the
 * `DEFAULT_*_BY_CIPHER` lookups, the padding overlay and the cipher-mode
 * selector, every one of which is `undefined` at runtime rather than a type
 * error at build time. RSA shipped this exact bug once; the PRNG family
 * re-armed it by variant. The assertion below was verified by PERTURBING the
 * predicate (dropping `&& !isLattice(a)` from `isCipher`), not by assuming.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE SECOND-MOST IMPORTANT is the `Record<Lattice, …>` pin in group 1.
 *
 * `validated-growing-dongarra.md` records the vacuous-suite hole: MT19937 was
 * deleted from `ALL_PRNGS` and the whole family suite stayed green, because
 * every assertion iterated the options list. Anything derived from
 * `LATTICE_OPTIONS` can go quietly empty. The label/description/history tables
 * are `Record<Lattice, string>`, whose keys the compiler enforces, so walking
 * THEM is what makes a missing variant fail.
 */

import { POLY_BYTES } from "@/ciphers/mlkem-constants";
import { DEFAULT_NTT_INPUT, DEFAULT_NTT_OUTPUT } from "@/ciphers/ntt-3329-256";
import {
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
import { ALGORITHM_IDS, LATTICE_IDS } from "@/core/document-schema";
import {
  ASYMMETRIC_OPTIONS,
  type Algorithm,
  CIPHER_OPTIONS,
  DEFAULT_CT_BYTES_BY_LATTICE,
  DEFAULT_KEY_BYTES_BY_LATTICE,
  DEFAULT_PT_BYTES_BY_LATTICE,
  HASH_OPTIONS,
  INPUT_BYTES_BY_LATTICE,
  LATTICE_DESCRIPTIONS,
  LATTICE_HISTORY,
  LATTICE_LABELS,
  LATTICE_OPTIONS,
  type Lattice,
  PRNG_OPTIONS,
  __resetCipherForTests,
  describeAlgorithm,
  historyOfAlgorithm,
  isAsymmetric,
  isCipher,
  isHash,
  isLattice,
  isPrng,
  latticeDefaultInput,
  useAlgorithm,
  useCategory,
  useLattice,
} from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  isCustomSpec,
  resetSpec,
  setAlgorithm,
  setCipher,
  setMode,
  setSpecFromDocument,
  useMode,
  useSpec,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { beforeEach, describe, expect, it } from "vitest";

/**
 * Every lattice variant, taken from a table whose keys the COMPILER enforces —
 * not from `LATTICE_OPTIONS`, which can silently go empty. See the file header.
 */
const ALL: readonly Lattice[] = Object.keys(LATTICE_LABELS) as Lattice[];

beforeEach(() => {
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
  __resetLayoutsForTests();
  __resetSpecForTests();
});

// ─── 1. The families partition Algorithm ──────────────────────────────────

describe("the five families partition Algorithm", () => {
  it("isCipher is FALSE for every lattice variant (the landmine)", () => {
    // Perturbation-verified: removing `&& !isLattice(a)` from `isCipher` makes
    // this fail. It is a hand-written predicate, so nothing else would.
    for (const l of ALL) {
      expect(isCipher(l), `isCipher(${l}) must be false`).toBe(false);
      expect(isLattice(l)).toBe(true);
      expect(isHash(l)).toBe(false);
      expect(isAsymmetric(l)).toBe(false);
      expect(isPrng(l)).toBe(false);
    }
  });

  it("no OTHER family's member is mistaken for a lattice variant", () => {
    const others: readonly Algorithm[] = [
      ...CIPHER_OPTIONS,
      ...HASH_OPTIONS,
      ...ASYMMETRIC_OPTIONS,
      ...PRNG_OPTIONS,
    ];
    for (const a of others) expect(isLattice(a), `isLattice(${a})`).toBe(false);
  });

  it("the variant list, the labels, the schema ids and the tables all agree", () => {
    // The vacuous-suite guard. `ALL` comes from the compiler-enforced Record
    // keys; everything else must match it, so a variant dropped from any one
    // list fails here rather than shrinking the suite silently.
    expect(ALL.length).toBeGreaterThan(0);
    expect([...LATTICE_OPTIONS].sort()).toEqual([...ALL].sort());
    expect([...LATTICE_IDS].sort()).toEqual([...ALL].sort());
    for (const l of ALL) {
      expect(LATTICE_LABELS[l]).toBeTruthy();
      expect(LATTICE_DESCRIPTIONS[l]).toBeTruthy();
      expect(LATTICE_HISTORY[l]).toBeTruthy();
      expect(DEFAULT_KEY_BYTES_BY_LATTICE[l]).toBeInstanceOf(Uint8Array);
      expect(DEFAULT_PT_BYTES_BY_LATTICE[l]).toBeInstanceOf(Uint8Array);
      expect(DEFAULT_CT_BYTES_BY_LATTICE[l]).toBeInstanceOf(Uint8Array);
      expect(INPUT_BYTES_BY_LATTICE[l]).toBeGreaterThan(0);
      // The two family-routing dispatchers both fall through to
      // CIPHER_DESCRIPTIONS / CIPHER_HISTORY; a missing arm returns undefined
      // rather than failing to compile.
      expect(describeAlgorithm(l)).toBe(LATTICE_DESCRIPTIONS[l]);
      expect(historyOfAlgorithm(l)).toBe(LATTICE_HISTORY[l]);
      // And the document schema accepts the id.
      expect(ALGORITHM_IDS).toContain(l);
    }
  });

  it("the transform is keyless and takes a fixed-width polynomial", () => {
    for (const l of ALL) {
      expect(DEFAULT_KEY_BYTES_BY_LATTICE[l].length).toBe(0);
      expect(INPUT_BYTES_BY_LATTICE[l]).toBe(POLY_BYTES);
      expect(DEFAULT_PT_BYTES_BY_LATTICE[l].length).toBe(POLY_BYTES);
      expect(DEFAULT_CT_BYTES_BY_LATTICE[l].length).toBe(POLY_BYTES);
    }
  });
});

// ─── 2. It lands in TWO slots, not one ────────────────────────────────────

describe("selecting a lattice variant", () => {
  it("flips the category and lands a two-slot kind: 'lattice'", () => {
    setAlgorithm("ntt-3329-256");
    expect(useCategory()()).toBe("lattice");
    expect(useLattice()()).toBe("ntt-3329-256");
    expect(useAlgorithm()()).toBe("ntt-3329-256");
    const s = useSpecsByMode()();
    expect(s.kind).toBe("lattice");
    if (s.kind !== "lattice") throw new Error("expected the lattice kind");
    expect(s.encrypt).toBeDefined();
    expect(s.decrypt).toBeDefined();
    expect(s.encrypt).not.toBe(s.decrypt);
  });

  it("is direction-FUL — the mode toggle selects between the two specs", () => {
    // The point of templating on RSA rather than on the hash/PRNG single slot.
    setAlgorithm("ntt-3329-256");
    setMode("encrypt");
    const fwd = useSpec()();
    setMode("decrypt");
    const inv = useSpec()();
    expect(fwd).not.toBe(inv);
    expect(fwd.id).toContain("ntt-3329-256");
    expect(inv.id).toContain("inverse");
  });

  it("round-trips through a cipher detour, remembering the variant", () => {
    setAlgorithm("ntt-3329-256");
    setCipher("aes-192");
    expect(useCategory()()).toBe("cipher");
    // The lattice signal survives — the "Remember last selection" semantic.
    expect(useLattice()()).toBe("ntt-3329-256");
    setAlgorithm("ntt-3329-256");
    expect(useCategory()()).toBe("lattice");
    expect(useSpecsByMode()().kind).toBe("lattice");
  });

  it("is not 'custom' until something is edited, and resets back", () => {
    setAlgorithm("ntt-3329-256");
    expect(isCustomSpec()).toBe(false);
    setMode("decrypt");
    expect(isCustomSpec()).toBe(false);
    setMode("encrypt");
    resetSpec();
    expect(isCustomSpec()).toBe(false);
  });
});

// ─── 3. Save / load keeps it in its own family ────────────────────────────

describe("document round-trip", () => {
  it("a saved lattice document loads back as a lattice, not as a cipher", () => {
    // The branch this pins is easy to omit: without a lattice arm in
    // `setSpecFromDocument`, the doc falls through to the CIPHER branch and
    // lands a lattice spec under `kind: "cipher"`, where the next `resetSpec`
    // reaches `resolveDefault(useCipher()(), …)` and returns undefined.
    setAlgorithm("ntt-3329-256");
    const doc: CipherDocument = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      spec: useSpec()(),
      algorithm: "ntt-3329-256",
    };
    const parsed = parseDocument(serializeDocument(doc));
    if (!parsed.ok) throw new Error(parsed.error);
    setCipher("aes-128"); // wander off
    expect(useCategory()()).toBe("cipher");
    setSpecFromDocument(parsed.doc);
    expect(useCategory()()).toBe("lattice");
    expect(useSpecsByMode()().kind).toBe("lattice");
    // And the counterpart slot is the canonical inverse, not a copy.
    const s = useSpecsByMode()();
    if (s.kind !== "lattice") throw new Error("expected the lattice kind");
    expect(s.decrypt.id).toContain("inverse");
    // Reset must resolve through the lattice table, not the cipher one.
    resetSpec();
    expect(useSpec()()).toBeDefined();
    expect(isCustomSpec()).toBe(false);
  });

  it("a document saved in the inverse direction loads into the decrypt slot", () => {
    setAlgorithm("ntt-3329-256");
    setMode("decrypt");
    const doc: CipherDocument = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      spec: useSpec()(),
      algorithm: "ntt-3329-256",
      session: {
        mode: "decrypt",
        cipher: "aes-128",
        cipherMode: "single-block",
        padding: "none",
        byteFormat: "hex",
      },
    };
    const parsed = parseDocument(serializeDocument(doc));
    if (!parsed.ok) throw new Error(parsed.error);
    __resetSpecForTests();
    setSpecFromDocument(parsed.doc);
    expect(useMode()()).toBe("decrypt");
    const s = useSpecsByMode()();
    if (s.kind !== "lattice") throw new Error("expected the lattice kind");
    expect(s.decrypt.id).toContain("inverse");
    expect(s.encrypt.id).not.toContain("inverse");
  });
});

// ─── 4. The default pair round-trips ──────────────────────────────────────

describe("the shipped defaults", () => {
  it("the inverse direction's default is the forward transform of the forward one", () => {
    // Makes `DEFAULT_NTT_OUTPUT` load-bearing rather than decorative: it is
    // derived from FIPS 203's definition (see its own doc comment) and the KAT
    // pins it against a real run of the shipped spec, so the two cannot drift.
    expect(DEFAULT_CT_BYTES_BY_LATTICE["ntt-3329-256"]).toEqual(DEFAULT_NTT_OUTPUT);
    expect(DEFAULT_PT_BYTES_BY_LATTICE["ntt-3329-256"]).toEqual(DEFAULT_NTT_INPUT);
  });
});

// ─── 5. The inverse direction's default is actually REACHABLE ──────────────

describe("landing in the inverse direction", () => {
  it("puts the TRANSFORMED polynomial in the input field, not the untransformed one", () => {
    // The gap this closes: `DEFAULT_CT_BYTES_BY_LATTICE` existed with no reader,
    // so switching to Lattice while the mode was already `decrypt` seeded the
    // field with the FORWARD default and the first run transformed an
    // untransformed polynomial — 512 bytes of silent garbage. A test asserting
    // only the table's CONTENTS cannot see that; this asserts a code path reads
    // it, by driving the same App-level helper the category flip uses.
    //
    // Kept in this file rather than a jsdom App test because the helper is pure
    // and the coupling under test is "which table does the lattice arm pick".
    expect(latticeDefaultInput("ntt-3329-256", "decrypt")).toEqual(
      DEFAULT_CT_BYTES_BY_LATTICE["ntt-3329-256"],
    );
    expect(latticeDefaultInput("ntt-3329-256", "encrypt")).toEqual(
      DEFAULT_PT_BYTES_BY_LATTICE["ntt-3329-256"],
    );
    // And the two are genuinely different values, so the assertion above is not
    // satisfiable by a single table.
    expect(DEFAULT_CT_BYTES_BY_LATTICE["ntt-3329-256"]).not.toEqual(
      DEFAULT_PT_BYTES_BY_LATTICE["ntt-3329-256"],
    );
  });
});
