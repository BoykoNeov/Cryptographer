import { aes128Spec } from "@/ciphers/aes-128";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes256Spec } from "@/ciphers/aes-256";
import { AES_RCON, AES_SBOX } from "@/ciphers/aes-constants";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepContext } from "@/core/types";
import { keyExpansion } from "@/steps/key-expansion";
import { describe, expect, it } from "vitest";

/**
 * Decomposed AES key schedule (key-schedule-decomposition plan, Slice K1a).
 *
 * The producer-only ("B-minimal") decomposition replaces the monolithic
 * `aes.key-expansion@1` leaf with `buildAesKeyScheduleNative(rounds, Nk)` — a
 * tree of VISIBLE port-native primitives (RotWord / SubWord / Rcon / word-XOR →
 * concat → byte-slice → publish). The contract that makes this safe is that the
 * decomposed schedule publishes BYTE-IDENTICAL `aux["roundKey.0..N"]` to what
 * the monolith wrote, so the untouched round-body AddRoundKey consumers see the
 * same round keys.
 *
 * This test pins that contract directly: run each shipped AES spec (which now
 * carries the decomposed schedule) and compare every published round key,
 * byte-for-byte, against the FIPS-197-validated monolithic `keyExpansion`
 * executor used as the oracle. Covers all three key sizes — crucially AES-256,
 * whose Nk=8 path exercises the mid-word SubWord (i % Nk == 4) and the
 * group-vs-round-key misalignment repack.
 */

// The monolith executor ignores ctx; a minimal one satisfies the type.
const CTX: StepContext = { stepId: "ref", path: [], aux: new Map() };

/** FIPS-197-validated reference round keys, via the monolithic executor. */
const monolithRoundKeys = (key: Uint8Array, rounds: number): Map<string, Uint8Array> => {
  const outputs = keyExpansion(
    new Map([["masterKey", key]]),
    {
      keyAuxName: "key",
      outputPrefix: "roundKey",
      sbox: [...AES_SBOX],
      rcon: [...AES_RCON],
      rounds,
    },
    CTX,
  );
  return new Map(outputs);
};

const cases: ReadonlyArray<{
  readonly name: string;
  readonly spec: CipherSpec;
  readonly keyHex: string; // FIPS-197 appendix key
  readonly rounds: number;
}> = [
  // FIPS-197 §A.1
  { name: "AES-128", spec: aes128Spec, keyHex: "2b7e151628aed2a6abf7158809cf4f3c", rounds: 10 },
  // FIPS-197 §A.2
  {
    name: "AES-192",
    spec: aes192Spec,
    keyHex: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    rounds: 12,
  },
  // FIPS-197 §A.3 — exercises the Nk=8 mid-word SubWord branch.
  {
    name: "AES-256",
    spec: aes256Spec,
    keyHex: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    rounds: 14,
  },
];

describe("AES key-schedule decomposition (K1a) — published round keys match the monolith", () => {
  for (const { name, spec, keyHex, rounds } of cases) {
    it(`${name}: decomposed roundKey.0..${rounds} are byte-identical to the monolith`, () => {
      const key = bytesFromHex(keyHex);
      const reference = monolithRoundKeys(key, rounds);

      // The schedule is aux-only; the plaintext is irrelevant to the round keys.
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(16)),
        initialAux: new Map<string, AuxValue>([["key", key]]),
      });

      for (let r = 0; r <= rounds; r++) {
        const got = trace.finalAux.get(`roundKey.${r}`);
        expect(got, `roundKey.${r} present`).toBeInstanceOf(Uint8Array);
        expect((got as Uint8Array).length).toBe(16);
        const want = reference.get(`key${r}`) as Uint8Array;
        expect(
          hexFromBytes(got as Uint8Array),
          `roundKey.${r} matches the FIPS-197 reference`,
        ).toBe(hexFromBytes(want));
      }

      // Sanity: roundKey.0 is always the first 16 bytes of the master key.
      expect(hexFromBytes(trace.finalAux.get("roundKey.0") as Uint8Array)).toBe(
        keyHex.slice(0, 32),
      );
    });
  }

  it("publishes exactly rounds+1 round keys (no extra aux entries from over-generation)", () => {
    // AES-192/256 over-cover Nk-word groups internally, but the repack must
    // emit EXACTLY the canonical round-key count — the partial final group and
    // byte-slice range guarantee no roundKey.{>Nr} leaks into aux.
    for (const { spec, rounds } of cases) {
      const key = bytesFromHex(cases.find((c) => c.spec === spec)?.keyHex ?? "");
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(16)),
        initialAux: new Map<string, AuxValue>([["key", key]]),
      });
      expect(trace.finalAux.has(`roundKey.${rounds}`)).toBe(true);
      expect(trace.finalAux.has(`roundKey.${rounds + 1}`)).toBe(false);
    }
  });
});
