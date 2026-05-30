/**
 * Serpent encrypt/decrypt round-trip tests for all three key sizes.
 *
 * The KAT test (tests/serpent-vectors.test.ts) is the primary
 * cryptographic-correctness check: it pins specific ciphertext outputs
 * against external test vectors. THIS file's job is different — it pins
 * the *invertibility* of the cipher across all three variants:
 *
 *   encrypt(decrypt(c)) === c     and     decrypt(encrypt(p)) === p
 *
 * for arbitrary plaintexts and keys. If a future change to the round
 * builder, key schedule, or any step breaks invertibility, this test
 * fires before the KAT does, because the cipher might still produce
 * SOMETHING for a given input — it just won't round-trip.
 *
 * Also pins structural facts about the trace: frame counts, the 33
 * round-key aux entries, and that each entry is a 16-byte Uint8Array.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// Helper: encrypt a 16-byte plaintext under the given spec and key, return
// the 16-byte ciphertext as a hex string.
const encrypt = (spec: CipherSpec, keyHex: string, plaintextHex: string): string => {
  // Serpent's round body is port-native since Slice B3 → ported dispatch
  // required (the native rounds throw under the legacy path).
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(plaintextHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
    portedDispatchEnabled: true,
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
  return hexFromBytes(trace.finalState.bytes);
};

const variants: Array<{
  name: string;
  encryptSpec: CipherSpec;
  decryptSpec: CipherSpec;
  keyHex: string;
}> = [
  {
    name: "Serpent-128",
    encryptSpec: serpent128Spec,
    decryptSpec: serpent128DecryptSpec,
    keyHex: "000102030405060708090a0b0c0d0e0f",
  },
  {
    name: "Serpent-192",
    encryptSpec: serpent192Spec,
    decryptSpec: serpent192DecryptSpec,
    keyHex: "000102030405060708090a0b0c0d0e0f1011121314151617",
  },
  {
    name: "Serpent-256",
    encryptSpec: serpent256Spec,
    decryptSpec: serpent256DecryptSpec,
    keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
];

describe.each(variants)("$name encrypt/decrypt round-trip", (v) => {
  const plaintexts = [
    "00000000000000000000000000000000",
    "00112233445566778899aabbccddeeff",
    "deadbeefdeadbeefdeadbeefdeadbeef",
    "ffffffffffffffffffffffffffffffff",
  ];

  for (const pt of plaintexts) {
    it(`encrypt → decrypt round-trips for plaintext ${pt}`, () => {
      const ct = encrypt(v.encryptSpec, v.keyHex, pt);
      // Sanity: ciphertext must differ from plaintext for a non-degenerate
      // cipher and key. A round-trip that succeeds because ct === pt would
      // hide a stuck cipher (e.g., key expansion outputting all zeros).
      expect(ct).not.toBe(pt);
      const recovered = encrypt(v.decryptSpec, v.keyHex, ct);
      expect(recovered).toBe(pt);
    });
  }
});

describe.each(variants)("$name trace structure", (v) => {
  it("emits the expected frame count (1 key-expansion + 98 body = 99)", () => {
    // Body = IP + 31 normal rounds (3 leaves each) + 1 final round (3 leaves)
    //        + FP = 1 + 93 + 3 + 1 = 98. Plus key-expansion → 99 leaf frames.
    // Group nodes don't emit their own frames — only the leaves inside them do.
    const trace = runSpec(v.encryptSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("00000000000000000000000000000000")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(v.keyHex)]]),
      portedDispatchEnabled: true,
    });
    expect(trace.frames.length).toBe(99);
  });

  it("produces 33 round keys in aux, each 16 bytes", () => {
    const trace = runSpec(v.encryptSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("00000000000000000000000000000000")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(v.keyHex)]]),
      portedDispatchEnabled: true,
    });
    for (let i = 0; i <= 32; i++) {
      const rk = trace.finalAux.get(`roundKey.${i}`);
      expect(rk).toBeInstanceOf(Uint8Array);
      expect((rk as Uint8Array).length).toBe(16);
    }
  });

  it("round keys are non-trivially distinct (not stuck-zero or duplicated)", () => {
    const trace = runSpec(v.encryptSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("00000000000000000000000000000000")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(v.keyHex)]]),
      portedDispatchEnabled: true,
    });
    const uniqueRoundKeys = new Set<string>();
    for (let i = 0; i <= 32; i++) {
      const rk = trace.finalAux.get(`roundKey.${i}`) as Uint8Array;
      uniqueRoundKeys.add(hexFromBytes(rk));
    }
    // With a non-degenerate input key, all 33 round keys should be
    // distinct. (For an exactly-zero input key after padding, the prekey
    // recurrence still differentiates them via phi and the round counter.)
    expect(uniqueRoundKeys.size).toBe(33);
  });
});

describe("Serpent rejects malformed inputs", () => {
  it("Serpent-128 rejects a 15-byte key", () => {
    expect(() =>
      runSpec(serpent128Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex("00000000000000000000000000000000")),
        initialAux: new Map<string, AuxValue>([
          ["key", bytesFromHex("000102030405060708090a0b0c0d0e")],
        ]),
      }),
    ).toThrow(/keyByteLength=16 but aux key is 15 bytes|key must be 16, 24, or 32 bytes/);
  });

  it("Serpent-256 rejects a 16-byte key (spec declares 32)", () => {
    expect(() =>
      runSpec(serpent256Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex("00000000000000000000000000000000")),
        initialAux: new Map<string, AuxValue>([
          ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
        ]),
      }),
    ).toThrow(/keyByteLength=32 but aux key is 16 bytes/);
  });
});
