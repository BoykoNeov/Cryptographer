/**
 * `tests/fixtures/ml-kem-768-seed-vectors.json` — the external oracle P3 and P4
 * are pinned against (`docs/plans/unified-stargazing-quasar.md`).
 *
 * ## Where the fixture comes from, and why it is bytes
 *
 * Node 24's OpenSSL ships ML-KEM. CI runs Node 22, which has none at all, so the
 * vectors are committed rather than generated — the same call P2 made for its
 * encapsulation key.
 *
 * The plan originally assumed `crypto.generateKeyPairSync("ml-kem-768", { seed })`
 * was deterministic. It is **not**: on v24.14.1 the `seed` option is accepted and
 * silently ignored, and three successive calls give three different keys. What
 * does work — probed and then used here — is importing a hand-assembled PKCS#8
 * carrying the `seed` arm of the ML-KEM `PrivateKey` CHOICE:
 *
 *     SEQUENCE {
 *       INTEGER 0,
 *       SEQUENCE { OID 2.16.840.1.101.3.4.4.2 },   -- id-alg-ml-kem-768
 *       OCTET STRING { [0] IMPLICIT OCTET STRING (64 bytes) }
 *     }
 *
 * The `[0]` tag must be **IMPLICIT** (`0x80`): the EXPLICIT spelling (`0xa0`) and
 * a bare OCTET STRING are both rejected with `DECODER routines::unsupported`.
 * That import is deterministic, and a key generated normally exports the *both*
 * arm — seed ‖ expandedKey — so the embedded seed re-imports to the same key,
 * which is how the two halves were cross-checked.
 *
 * To regenerate (needs Node ≥ 24), the harvest script is reproduced in
 * `docs/plans/unified-stargazing-quasar.md`'s P3 section; every seed here is
 * derived from its own label, so the fixture is rebuildable from scratch.
 *
 * ## What this file asserts
 *
 * The fixture is inert data until something reads it, and a corrupt fixture
 * would take P3's KATs down with it in a way that looked like a bug in our
 * cipher. So the vectors are checked for the properties FIPS 203 says they must
 * have, using only shipped code:
 *
 *  - **§7.1's `d ‖ z` split.** The two `shared-d/*` seeds agree on bytes 0..32
 *    and differ on 32..64. They must produce the same `ek` and the same `dk_PKE`
 *    — `z` takes no part in key generation — while decapsulating a *corrupted*
 *    ciphertext to different secrets, because that path returns `J(z ‖ c)`.
 *    That is P4's implicit-rejection branch, pinned before P4 starts.
 *  - **The packed coefficients are in range.** Every `ek` and `dk_PKE` reads as
 *    12-bit words all below `q` — which roughly a fifth of arbitrary 12-bit
 *    values would not be. Read RAW rather than through `zq-byte-decode@1`,
 *    because that step ends in FIPS 203's `mod min(2^d, q)` and so can never
 *    return an out-of-range value; the assertion has to bite on the bytes, not
 *    on the reduction. (The same vacuous shape was found and fixed in P2's
 *    `tests/zq-byte-encode-decode.test.ts` while writing this file.) The shipped
 *    step is then required to agree with the raw read, which ties the fixture to
 *    real code without re-introducing the hole.
 *  - **`H(ek)` matches our own sponge.** `keccak-compute`'s SHA3-256 against
 *    Node's, over real ML-KEM key bytes rather than test strings.
 */

import { sha3_256 } from "@/ciphers/keccak-compute";
import type { Json, StepContext } from "@/core/types";
import { zqByteDecode } from "@/steps/zq-byte-decode";
import { describe, expect, it } from "vitest";
import fixture from "./fixtures/ml-kem-768-seed-vectors.json";

const Q = 3329;
const Q_BYTES = new Uint8Array([0x0d, 0x01]);
const ctx: StepContext = { stepId: "fixture", path: [], aux: new Map() };
const DECODE_12: Json = { coeffBytes: 2, littleEndian: false, d: 12 };

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** Unpack a 12-bit-packed byte string into coefficients, via the shipped step. */
const decode12 = (packed: Uint8Array): number[] => {
  const out = zqByteDecode(
    new Map([
      ["a", packed],
      ["modulus", Q_BYTES],
    ]),
    DECODE_12,
    ctx,
  ).get("output") as Uint8Array;
  return Array.from(
    { length: out.length / 2 },
    (_, i) => (out[i * 2] as number) * 256 + (out[i * 2 + 1] as number),
  );
};

/**
 * The same 12-bit LSB-first read, WITHOUT the reduction — because the range
 * check below is otherwise vacuous.
 *
 * FIPS 203's `ByteDecode_d` finishes with `mod m`, where `m = min(2^d, q)`, and
 * the shipped `zq-byte-decode@1` faithfully does the same. So every coefficient
 * it returns is below `q` no matter what bytes went in, and "the key decodes
 * into range" asserted through it can never fail. Reading the raw 12-bit words
 * is what makes the claim mean something: ~19% of arbitrary 12-bit values
 * exceed `q`, so 27,648 consecutive words landing under it is evidence about
 * the bytes rather than about the reduction.
 */
const rawWords12 = (packed: Uint8Array, reverseBitInByte = false): number[] => {
  const n = (packed.length * 8) / 12;
  return Array.from({ length: n }, (_, i) => {
    let v = 0;
    for (let j = 0; j < 12; j++) {
      const bit = i * 12 + j;
      const shift = reverseBitInByte ? 7 - (bit % 8) : bit % 8;
      if ((((packed[bit >> 3] as number) >> shift) & 1) === 1) v |= 1 << j;
    }
    return v;
  });
};

const vectorNamed = (label: string) => {
  const v = fixture.vectors.find((x) => x.label === label);
  if (!v) throw new Error(`fixture has no vector labelled ${label}`);
  return v;
};

describe("the ML-KEM-768 oracle fixture is structurally what P3/P4 expect", () => {
  it("carries enough vectors, at the sizes FIPS 203 specifies", () => {
    // 16+ seeds because the plan's bar for P3 is "enough fixed random seeds that
    // at least one matrix polynomial demonstrably needs an extra squeeze block",
    // and which seeds those are cannot be known until SampleNTT exists.
    expect(fixture.vectors.length).toBeGreaterThanOrEqual(16);
    expect(fixture.algorithm).toBe("ml-kem-768");
    for (const v of fixture.vectors) {
      expect(v.seed.length / 2, `${v.label} seed`).toBe(64); // d ‖ z
      expect(v.ek.length / 2, `${v.label} ek`).toBe(1184); // 384·k + 32
      expect(v.dkPke.length / 2, `${v.label} dkPke`).toBe(1152); // 384·k
      expect(v.hEk.length / 2, `${v.label} hEk`).toBe(32);
    }
    // Distinct seeds, and distinct keys — a fixture that had accidentally
    // captured one key eighteen times would pass every other test here.
    expect(new Set(fixture.vectors.map((v) => v.seed)).size).toBe(fixture.vectors.length);
    expect(new Set(fixture.vectors.map((v) => v.ek)).size).toBe(fixture.vectors.length - 1);
  });

  it("holds encapsulation vectors whose rejected secret differs from the real one", () => {
    expect(fixture.encaps.length).toBeGreaterThanOrEqual(4);
    for (const e of fixture.encaps) {
      expect(e.ciphertext.length / 2).toBe(1088); // 32·(du·k + dv) = 960 + 128
      expect(e.sharedSecret.length / 2).toBe(32);
      expect(e.rejectedSharedSecret).not.toBe(e.sharedSecret);
    }
  });
});

describe("FIPS 203 §7.1's seed split — d generates the key, z only rejects", () => {
  const zeroZ = vectorNamed("shared-d/zero-z");
  const ffZ = vectorNamed("shared-d/ff-z");

  it("two seeds sharing d but differing in z produce the same key", () => {
    expect(zeroZ.seed).not.toBe(ffZ.seed);
    expect(zeroZ.seed.slice(0, 64)).toBe(ffZ.seed.slice(0, 64)); // same d
    expect(zeroZ.seed.slice(64)).not.toBe(ffZ.seed.slice(64)); // different z
    expect(zeroZ.ek).toBe(ffZ.ek);
    expect(zeroZ.dkPke).toBe(ffZ.dkPke);
  });

  it("and decapsulate a VALID ciphertext identically", () => {
    // Same dk_PKE, so the FO re-encryption check passes for both and the shared
    // secret comes from the same K̄ — z never enters.
    expect(fixture.sharedDCross.validUnderZeroZ).toBe(fixture.sharedDCross.validUnderFfZ);
  });

  it("but decapsulate a CORRUPTED ciphertext to different secrets, because that path returns J(z ‖ c)", () => {
    // The whole IND-CPA/IND-CCA difference, and the branch every round-trip test
    // is blind to: it returns a secret rather than an error, and the secret is
    // the only thing these two keys disagree about.
    expect(fixture.sharedDCross.rejectedUnderZeroZ).not.toBe(fixture.sharedDCross.rejectedUnderFfZ);
    expect(fixture.sharedDCross.rejectedUnderZeroZ).not.toBe(fixture.sharedDCross.validUnderZeroZ);
    expect(fixture.sharedDCross.rejectedUnderFfZ).not.toBe(fixture.sharedDCross.validUnderFfZ);
  });
});

describe("the captured keys really are ring elements", () => {
  it("every ek's t̂ and every dk_PKE's ŝ reads as 768 raw 12-bit words below q", () => {
    for (const v of fixture.vectors) {
      // ek = ByteEncode_12(t̂) ‖ ρ — the trailing 32 bytes are the seed ρ, not
      // coefficients, so only the first 1152 bytes are read.
      const tHat = rawWords12(hexToBytes(v.ek).subarray(0, 1152));
      const sHat = rawWords12(hexToBytes(v.dkPke));
      expect(tHat.length, v.label).toBe(768);
      expect(sHat.length, v.label).toBe(768);
      expect(tHat.filter((c) => c >= Q).length, `${v.label} t̂ out of range`).toBe(0);
      expect(sHat.filter((c) => c >= Q).length, `${v.label} ŝ out of range`).toBe(0);
    }
  });

  it("which is not a free pass — reading the same bytes bit-reversed goes out of range", () => {
    // Run rather than argued, because the whole value of the assertion above is
    // that a wrong reading of these bytes would fail it.
    for (const v of fixture.vectors) {
      const wrong = rawWords12(hexToBytes(v.ek).subarray(0, 1152), true);
      expect(wrong.filter((c) => c >= Q).length, `${v.label} reversed`).toBeGreaterThan(20);
    }
  });

  it("and the shipped zq-byte-decode@1 agrees with the raw read, its reduction never firing", () => {
    // Ties the fixture to shipped code: when every packed word is already below
    // q, FIPS 203's trailing `mod m` is the identity, so the step's output must
    // equal the raw words exactly. A disagreement would mean the step is reading
    // a different bit order from the one that just proved itself in range.
    for (const v of fixture.vectors) {
      const packed = hexToBytes(v.ek).subarray(0, 1152);
      expect(decode12(packed), v.label).toEqual(rawWords12(packed));
    }
  });
});

describe("H(ek) — our sponge against Node's, on real ML-KEM bytes", () => {
  it("reproduces every captured SHA3-256 digest", () => {
    for (const v of fixture.vectors) {
      expect(bytesToHex(sha3_256(hexToBytes(v.ek))), v.label).toBe(v.hEk);
    }
  });
});
