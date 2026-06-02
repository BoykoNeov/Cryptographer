import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { DES_PC1, DES_PC2, DES_SHIFTS } from "@/ciphers/des-constants";
import { buildDesKeyScheduleNative } from "@/ciphers/des-key-schedule-builder-native";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { desKeySchedule } from "@/steps/des-key-schedule";
import { describe, expect, it } from "vitest";

/**
 * Decomposed DES key schedule (key-schedule-decomposition plan, K4a).
 *
 * Mirrors `serpent-32-key-schedule-decomposition.test.ts` (K3a),
 * `speck-32-64-key-schedule-decomposition.test.ts` (K2a), and
 * `aes-key-schedule-decomposition.test.ts` (K1a) — the parity oracle gate.
 *
 * The producer-only ("B-minimal") decomposition replaces the monolithic
 * `des.key-schedule@1` leaf with `buildDesKeyScheduleNative()` — a tree of
 * VISIBLE port-native primitives (load → PC-1 → 16× rotate-halves → PC-2 →
 * publish). The contract that makes this safe is that the decomposed schedule
 * publishes BYTE-IDENTICAL `aux["roundKey.0..15"]` to what the monolithic
 * FIPS 46-3 §5 executor prescribes, so the round-body `des.xor-with-K@1`
 * consumers see canonical round keys.
 *
 * THE ORACLE is the monolithic `desKeySchedule` executor itself — the
 * decomposition must reproduce its 16 round-key outputs exactly. We invoke the
 * monolith directly (port-native PortedExecutor: `masterKey` in, `key0..key15`
 * out) and compare against the decomposed schedule's published aux entries.
 *
 * DES has NO key-size variant (the 64-bit master key always reduces to 56
 * effective bits via PC-1), so — unlike Serpent's 3-size matrix — a couple of
 * fixed keys exercise the whole schedule: the FIPS 46-3 Appendix B key plus
 * one more.
 */

const DES_ROUND_KEYS = 16;

/** Run the monolith and collect roundKey.0..15 as a name→bytes map. */
const oracleRoundKeys = (keyBytes: Uint8Array): Map<string, Uint8Array> => {
  const inputs = new Map<string, Uint8Array>([["masterKey", keyBytes]]);
  const params = {
    keyAuxName: "key",
    outputPrefix: "roundKey",
    pc1: [...DES_PC1],
    pc2: [...DES_PC2],
    shifts: [...DES_SHIFTS],
  };
  // The monolith's PortedExecutor returns key0..key15 on output ports. The
  // ctx arg is unused by the executor (verified by reading the source).
  const outputs = desKeySchedule(inputs, params, {} as never);
  const out = new Map<string, Uint8Array>();
  for (let r = 0; r < DES_ROUND_KEYS; r++) {
    const v = outputs.get(`key${r}`);
    if (!(v instanceof Uint8Array)) throw new Error(`oracle missing key${r}`);
    out.set(`roundKey.${r}`, v);
  }
  return out;
};

// ─── A minimal aux-only spec wrapping just the decomposed schedule ────────────
// We don't need the round body to validate the schedule — running just the
// key-schedule group publishes roundKey.0..15 into the aux map, which is what
// we compare. An 8-byte zero state seeds the carried block (passthrough).

const scheduleOnlySpec = (): CipherSpec => ({
  id: "des-key-schedule-only",
  name: "DES key schedule — decomposition test",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 8 },
  },
  steps: [buildDesKeyScheduleNative()],
});

// FIPS 46-3 Appendix B key + one arbitrary-but-fixed second key. The oracle is
// the authority, so any key exercises the parity; the App-B key also keeps the
// test anchored to the standard's published vector.
const keys: readonly string[] = ["133457799bbcdff1", "0123456789abcdef"];

describe("DES — decomposed key schedule (K4a) publishes byte-identical round keys", () => {
  for (const keyHex of keys) {
    it(`key ${keyHex}: roundKey.0..15 byte-equal to the monolithic oracle`, () => {
      const keyBytes = bytesFromHex(keyHex);
      expect(keyBytes.length).toBe(8);

      const trace = runSpec(scheduleOnlySpec(), buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(8)),
        initialAux: new Map<string, AuxValue>([["key", keyBytes]]),
      });
      const oracle = oracleRoundKeys(keyBytes);
      expect(oracle.size).toBe(16);

      for (let r = 0; r < DES_ROUND_KEYS; r++) {
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

  it("publishes the 16-key fan-out from `key-schedule.publish` (the surviving meta-bearing leaf)", () => {
    const trace = runSpec(scheduleOnlySpec(), buildDefaultRegistry(), {
      initialState: makeBytesState(new Uint8Array(8)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keys[0] ?? "")]]),
    });
    const publish = trace.frames.find((f) => f.stepId === "key-schedule.publish");
    expect(publish).toBeDefined();
    if (!publish) return;
    expect(publish.stepType).toBe("des.publish-round-keys@1");
    expect(publish.auxWritten.size).toBe(16);
    for (let r = 0; r < DES_ROUND_KEYS; r++) {
      expect(publish.auxWritten.has(`roundKey.${r}`)).toBe(true);
    }
  });
});
