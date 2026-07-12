/**
 * Twofish known-answer tests (128-bit key, k=2).
 *
 * The gate the plan + advisor mandate: assert the INTERMEDIATE values (S-vector,
 * all 40 subkeys, a g-function output) BEFORE the endpoint ciphertext — an
 * endpoint KAT after a swapped subkey index or wrong rotation just says "wrong
 * ciphertext" and localizes nothing in a 16-round cipher.
 *
 * Every literal here was produced by a Python reference built from the PUBLISHED
 * SPEC constants (paper MDS/RS matrices + q0/q1 t-table construction) and
 * cross-checked byte-for-byte against Niels Ferguson's reference C library — the
 * S-boxes, all 40 subkeys, and the endpoint CT agreed at all three levels. See
 * `docs/plans/twofish.md`. The canonical all-zero vector
 * (`9f589f5cf6122c32b6bfec2f2ae8c35a`) is the published Twofish 128-bit test
 * vector.
 */

import { describe, expect, it } from "vitest";
import { buildDefaultRegistry } from "../src/ciphers/default-registry";
import { twofishSpec } from "../src/ciphers/twofish";
import {
  bytesBEToU32,
  twofishEncryptBlock,
  twofishKeySchedule,
  u32ToBytesBE,
} from "../src/ciphers/twofish-constants";
import { runSpec } from "../src/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "../src/core/state/bytes";
import type { AuxValue, CipherSpec } from "../src/core/types";

const hexToBytes = (h: string): Uint8Array =>
  new Uint8Array((h.match(/../g) ?? []).map((b) => Number.parseInt(b, 16)));
const bytesToHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
/** Format a possibly-undefined u32 as 8 hex digits (avoids non-null assertions). */
const hx8 = (v: number | undefined): string => (v ?? 0).toString(16).padStart(8, "0");
const headHex = (b: Uint8Array | undefined, n: number): string =>
  bytesToHex((b ?? new Uint8Array()).slice(0, n));

// The default UI vector: sequential key, AES-style plaintext.
const DEFAULT_KEY = hexToBytes("000102030405060708090a0b0c0d0e0f");
const DEFAULT_PT = hexToBytes("00112233445566778899aabbccddeeff");
const DEFAULT_CT = "df8451d26e0504bc19b0a93b049e3203";

describe("Twofish key schedule — intermediate values (vs. reference)", () => {
  const ks = twofishKeySchedule(DEFAULT_KEY);

  it("computes the S-vector words S_0, S_1", () => {
    // S_0 = RS(key[0..7]), S_1 = RS(key[8..15]); big-endian-packed u32.
    expect(hx8(ks.Svec[0])).toBe("d72a062f");
    expect(hx8(ks.Svec[1])).toBe("1a7904f2");
  });

  it("computes all 40 subkeys K[0..39]", () => {
    const expected = [
      "4a3f345a",
      "f7aedde9",
      "e8b9e40f",
      "d8794bcf",
      "e1429065",
      "b67e9807",
      "704d77b4",
      "edd067b7",
      "20f25ac7",
      "16250e5e",
      "61e55dfe",
      "f5552de6",
      "3d67a27d",
      "21ecb038",
      "5f6cc911",
      "3623beba",
    ];
    for (let i = 0; i < expected.length; i++) {
      expect(hx8(ks.K[i])).toBe(expected[i]);
    }
    // Spot-check the tail (output-side subkeys).
    expect(hx8(ks.K[36])).toBe("12226c87");
    expect(hx8(ks.K[39])).toBe("819edbac");
    expect(ks.K).toHaveLength(40);
  });

  it("produces four 256-byte key-dependent S-boxes", () => {
    expect(ks.S).toHaveLength(4);
    for (const box of ks.S) expect(box.length).toBe(256);
    // Heads pinned against the reference.
    expect(headHex(ks.S[0], 8)).toBe("c4a0b4972b9d36d9");
    expect(headHex(ks.S[1], 8)).toBe("69334f6e77efa73b");
  });
});

describe("Twofish endpoint known-answer tests (vs. Ferguson reference)", () => {
  it("encrypts the default sequential vector", () => {
    expect(bytesToHex(twofishEncryptBlock(DEFAULT_KEY, DEFAULT_PT))).toBe(DEFAULT_CT);
  });

  it("encrypts the canonical all-zero 128-bit vector", () => {
    const z = new Uint8Array(16);
    expect(bytesToHex(twofishEncryptBlock(z, z))).toBe("9f589f5cf6122c32b6bfec2f2ae8c35a");
  });

  it("matches additional reference vectors", () => {
    const cases: [string, string, string][] = [
      [
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b1c1d1e1f",
        "de05a6de0290d44c57c44314086b4463",
      ],
      [
        "0123456789abcdeffedcba9876543210",
        "00112233445566778899aabbccddeeff",
        "568124261c4164dcb4dcbeeb440cf19b",
      ],
      [
        "ffffffffffffffffffffffffffffffff",
        "000102030405060708090a0b0c0d0e0f",
        "d252166643a1006bb4c0e541ff096172",
      ],
    ];
    for (const [key, pt, ct] of cases) {
      expect(bytesToHex(twofishEncryptBlock(hexToBytes(key), hexToBytes(pt)))).toBe(ct);
    }
  });
});

/** Encrypt one block via the full spec through the runtime. */
const runCipher = (spec: CipherSpec, keyHex: string, inputHex: string): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
  return hexFromBytes(trace.finalState.bytes);
};

describe("Twofish full spec through the runtime (port-native round body)", () => {
  // A spec-layer green here (with the oracle green above) proves the port-native
  // g-chain / MDS / PHT / whitening wiring matches the verified oracle.
  const cases: [string, string, string][] = [
    ["000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", DEFAULT_CT],
    [
      "00000000000000000000000000000000",
      "00000000000000000000000000000000",
      "9f589f5cf6122c32b6bfec2f2ae8c35a",
    ],
    [
      "0123456789abcdeffedcba9876543210",
      "00112233445566778899aabbccddeeff",
      "568124261c4164dcb4dcbeeb440cf19b",
    ],
  ];
  for (const [key, pt, ct] of cases) {
    it(`key=${key} pt=${pt} → ${ct}`, () => {
      expect(runCipher(twofishSpec, key, pt)).toBe(ct);
    });
  }
});

describe("Twofish BE word codec round-trips", () => {
  it("u32 ↔ big-endian bytes", () => {
    expect(bytesToHex(u32ToBytesBE(0x0c9ff2f2))).toBe("0c9ff2f2");
    expect(bytesBEToU32(hexToBytes("0c9ff2f2"))).toBe(0x0c9ff2f2);
  });
});
