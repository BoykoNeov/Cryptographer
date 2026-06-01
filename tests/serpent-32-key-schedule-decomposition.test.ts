import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSerpentKeyScheduleNative } from "@/ciphers/serpent-key-schedule-builder-native";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { serpentKeyExpansion } from "@/steps/serpent-key-expansion";
import { describe, expect, it } from "vitest";

/**
 * Decomposed Serpent key schedule (key-schedule-decomposition plan, K3a).
 *
 * Mirrors `speck-32-64-key-schedule-decomposition.test.ts` (K2a) and
 * `aes-key-schedule-decomposition.test.ts` (K1a) — the parity oracle gate.
 *
 * The producer-only ("B-minimal") decomposition replaces the monolithic
 * `serpent.key-expansion@1` leaf with `buildSerpentKeyScheduleNative(keyByteLength)`
 * — a tree of VISIBLE port-native primitives (load → pad → input-codec (LE→BE)
 * → master-split → 132 ARX recurrence iterations → 33 key-sbox (S-box + IP)
 * groups → publish). The contract that makes this safe is that the decomposed
 * schedule publishes BYTE-IDENTICAL `aux["roundKey.0..32"]` to what the
 * monolithic ABK 1998 §2 executor prescribes, so the round-body
 * `serpent.add-round-key@1` consumers see canonical round keys.
 *
 * THE ORACLE is the monolithic `serpentKeyExpansion` executor itself — the
 * decomposition must reproduce its 33 round-key outputs exactly. We invoke the
 * monolith directly (port-native PortedExecutor: `masterKey` in, `key0..key32`
 * out) and compare against the decomposed schedule's published aux entries.
 *
 * Critically: covers all three key sizes (16/24/32), since the pad branch is
 * size-specific and the byte-order codec is the K3 load-bearing design — the
 * recurrence body math is byte-order-invariant, but the rotation reads
 * big-endian while Serpent prekeys are little-endian, so the input codec is
 * what makes the published bytes match the monolith.
 */

// ─── Oracle: the monolithic serpent.key-expansion executor ────────────────────

const SERPENT_ROUND_KEYS = 33;

/** Run the monolith and collect roundKey.0..32 as a name→bytes map. */
const oracleRoundKeys = (keyBytes: Uint8Array): Map<string, Uint8Array> => {
  const inputs = new Map<string, Uint8Array>([["masterKey", keyBytes]]);
  const params = {
    keyAuxName: "key",
    outputPrefix: "roundKey",
    keyByteLength: keyBytes.length,
  };
  // The monolith's PortedExecutor returns key0..key32 on output ports. The
  // ctx arg is unused by the executor (verified by reading the source).
  const outputs = serpentKeyExpansion(inputs, params, {} as never);
  const out = new Map<string, Uint8Array>();
  for (let r = 0; r < SERPENT_ROUND_KEYS; r++) {
    const v = outputs.get(`key${r}`);
    if (!(v instanceof Uint8Array)) throw new Error(`oracle missing key${r}`);
    out.set(`roundKey.${r}`, v);
  }
  return out;
};

// ─── A minimal aux-only spec wrapping just the decomposed schedule ────────────
// We don't need the round body to validate the schedule — running just the
// key-schedule group publishes roundKey.0..32 into the aux map, which is what
// we compare. A 16-byte zero state seeds the carried block (passthrough).

const scheduleOnlySpec = (keyByteLength: 16 | 24 | 32): CipherSpec => ({
  id: `serpent-key-schedule-only-${keyByteLength}`,
  name: `Serpent key schedule (${keyByteLength}B) — decomposition test`,
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: keyByteLength },
  },
  steps: [buildSerpentKeyScheduleNative(keyByteLength)],
});

type Case = {
  readonly keyByteLength: 16 | 24 | 32;
  readonly keyHex: string;
};

// Real, distinct master keys per size (arbitrary but fixed — the oracle is the
// authority, so any key exercises the parity).
const cases: ReadonlyArray<Case> = [
  { keyByteLength: 16, keyHex: "000102030405060708090a0b0c0d0e0f" },
  { keyByteLength: 24, keyHex: "000102030405060708090a0b0c0d0e0f1011121314151617" },
  {
    keyByteLength: 32,
    keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
];

describe("Serpent — decomposed key schedule (K3a) publishes byte-identical round keys", () => {
  for (const c of cases) {
    it(`Serpent-${c.keyByteLength * 8}: roundKey.0..32 byte-equal to the monolithic oracle`, () => {
      const keyBytes = bytesFromHex(c.keyHex);
      expect(keyBytes.length).toBe(c.keyByteLength);

      const trace = runSpec(scheduleOnlySpec(c.keyByteLength), buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(16)),
        initialAux: new Map<string, AuxValue>([["key", keyBytes]]),
      });
      const oracle = oracleRoundKeys(keyBytes);
      expect(oracle.size).toBe(33);

      for (let r = 0; r < SERPENT_ROUND_KEYS; r++) {
        const name = `roundKey.${r}`;
        const expected = oracle.get(name);
        if (!(expected instanceof Uint8Array)) throw new Error(`oracle missing ${name}`);
        const actual = trace.finalAux.get(name);
        expect(actual).toBeInstanceOf(Uint8Array);
        expect(actual instanceof Uint8Array ? hexFromBytes(actual) : null).toBe(
          hexFromBytes(expected),
        );
      }
    });
  }

  it("publishes the 33-key fan-out from `key-schedule.publish` (the surviving meta-bearing leaf)", () => {
    const trace = runSpec(scheduleOnlySpec(16), buildDefaultRegistry(), {
      initialState: makeBytesState(new Uint8Array(16)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(cases[0]?.keyHex ?? "")]]),
    });
    const publish = trace.frames.find((f) => f.stepId === "key-schedule.publish");
    expect(publish).toBeDefined();
    if (!publish) return;
    expect(publish.stepType).toBe("serpent.publish-round-keys@1");
    expect(publish.auxWritten.size).toBe(33);
    for (let r = 0; r < SERPENT_ROUND_KEYS; r++) {
      expect(publish.auxWritten.has(`roundKey.${r}`)).toBe(true);
    }
  });
});
