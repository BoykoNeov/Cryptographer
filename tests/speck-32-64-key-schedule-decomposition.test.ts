import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepContext } from "@/core/types";
import { speckKeySchedule } from "@/steps/speck-key-schedule";
import { describe, expect, it } from "vitest";

/**
 * Decomposed Speck32/64 key schedule (key-schedule-decomposition plan, K2a).
 *
 * Mirrors `aes-key-schedule-decomposition.test.ts` — the K1a parity oracle.
 *
 * The producer-only ("B-minimal") decomposition replaces the monolithic
 * `speck.key-schedule@1` leaf with `buildSpeck32_64KeyScheduleNative(rounds, m,
 * wordBits, alpha, beta, byteOrder)` — a tree of VISIBLE port-native primitives
 * (input-codec → master-split → (m-1) lag-chained ARX iterations → asymmetric
 * output codec → publish). The contract that makes this safe is that the
 * decomposed schedule publishes BYTE-IDENTICAL `aux["roundKey.0..21"]` to what
 * the monolith wrote, so the untouched round-body `speck.round@1` consumers see
 * the same round keys.
 *
 * This test pins that contract directly: run each shipped Speck32/64 spec
 * (which now carries the decomposed schedule) and compare every published
 * round key, byte-for-byte, against the Beaulieu et al. 2013 §3-validated
 * monolithic `speckKeySchedule` executor used as the oracle. Critically: it
 * covers BOTH byte-order conventions (BE-paper and LE-NSA), since the codec
 * boundary handling is the K2-specific load-bearing design — the body math is
 * byte-order-invariant, but the published bytes ARE byte-order-dependent.
 *
 * Speck32/64 constants (`m=4, wordBits=16, rounds=22, alpha=7, beta=2`) are
 * baked into the shipped specs. The legacy `speck.key-schedule@1` executor
 * stays registered for back-compat (per the K1 pattern), so this test can
 * use it directly as the parity oracle without reaching into a builder.
 */

// The monolith executor ignores ctx; a minimal one satisfies the type.
const CTX: StepContext = { stepId: "ref", path: [], aux: new Map() };

/** Beaulieu Table 4.1 validated reference round keys via the monolithic
 *  executor. The schedule is identical for both byte orders at the
 *  word-value level; only the byte encoding of the master key + each round
 *  key changes per `byteOrder`. */
const monolithRoundKeys = (
  keyBytes: Uint8Array,
  byteOrder: "be-paper" | "le-nsa",
): Map<string, Uint8Array> => {
  const outputs = speckKeySchedule(
    new Map([["masterKey", keyBytes]]),
    {
      keyAuxName: "key",
      outputPrefix: "roundKey",
      rounds: 22,
      wordBits: 16,
      m: 4,
      alpha: 7,
      beta: 2,
      byteOrder,
    },
    CTX,
  );
  // The monolith emits `key0`..`key21` ports; turn that into roundKey.N for
  // a direct compare against the decomposed schedule's aux publication.
  const renamed = new Map<string, Uint8Array>();
  for (const [k, v] of outputs) {
    const m = /^key(\d+)$/.exec(k);
    if (!m) throw new Error(`monolith oracle: unexpected port name ${k}`);
    renamed.set(`roundKey.${m[1]}`, v);
  }
  return renamed;
};

type Case = {
  readonly label: string;
  readonly spec: CipherSpec;
  readonly byteOrder: "be-paper" | "le-nsa";
  readonly keyHex: string;
  readonly plaintextHex: string;
};

// Beaulieu Table 4.1 — the canonical Speck32/64 test vector under each
// byteOrder convention. Both conventions produce the IDENTICAL word-level
// schedule; the published bytes per round key differ ONLY in byte order.
const cases: ReadonlyArray<Case> = [
  {
    label: "BE-paper",
    spec: speck32_64BeSpec,
    byteOrder: "be-paper",
    keyHex: "1918111009080100",
    plaintextHex: "6574694c",
  },
  {
    label: "LE-NSA",
    spec: speck32_64LeSpec,
    byteOrder: "le-nsa",
    keyHex: "0001080910111819",
    plaintextHex: "4c697465",
  },
];

describe("Speck32/64 — decomposed key schedule (K2a) publishes byte-identical round keys", () => {
  for (const c of cases) {
    it(`${c.label}: roundKey.0..21 byte-equal to the monolithic oracle`, () => {
      const keyBytes = bytesFromHex(c.keyHex);
      const trace = runSpec(c.spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(c.plaintextHex)),
        initialAux: new Map<string, AuxValue>([["key", keyBytes]]),
      });
      const oracle = monolithRoundKeys(keyBytes, c.byteOrder);

      // Sanity: the oracle produces exactly 22 round-key entries.
      expect(oracle.size).toBe(22);

      // Byte-equality on every published roundKey.N. Use hex for readable
      // diffs when a mismatch surfaces (a one-byte-off in the codec
      // indices would point at the exact round).
      for (let r = 0; r < 22; r++) {
        const name = `roundKey.${r}`;
        const expected = oracle.get(name);
        if (!(expected instanceof Uint8Array)) {
          throw new Error(`oracle missing ${name}`);
        }
        const actual = trace.finalAux.get(name);
        expect(actual).toBeInstanceOf(Uint8Array);
        expect(actual instanceof Uint8Array ? hexFromBytes(actual) : null).toBe(
          hexFromBytes(expected),
        );
      }
    });
  }

  it("roundKey.0 = master-key first logical word k_0 regardless of byteOrder", () => {
    // The schedule's roundKey.0 is the master key's FIRST LOGICAL word k_0.
    // Under BE-paper the master-key bytes are (l_2, l_1, l_0, k_0) BE per word
    // → k_0 = 0x0100 → BE bytes [0x01, 0x00]. Under LE-NSA the bytes are
    // (k_0, l_0, l_1, l_2) LE per word → k_0 = 0x0100 → LE bytes [0x00, 0x01].
    // Same word value 0x0100, different byte serialization. Pins both the
    // input-codec correctness AND the publish encoding.
    const beTrace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("6574694c")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("1918111009080100")]]),
    });
    expect(hexFromBytes(beTrace.finalAux.get("roundKey.0") as Uint8Array)).toBe("0100");

    const leTrace = runSpec(speck32_64LeSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("4c697465")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("0001080910111819")]]),
    });
    expect(hexFromBytes(leTrace.finalAux.get("roundKey.0") as Uint8Array)).toBe("0001");
  });

  it("publishes the round-key fan-out from `key-schedule.publish` (the surviving meta-bearing leaf)", () => {
    // The aux fan-out is the one surviving meta in the K2 decomposition.
    // K1's blast-radius lesson: ensure the producer leaf id is what the
    // graph derivation expects (the collapsed view remaps onto the container,
    // but the raw publish-leaf id is the load-bearing thing the producer
    // discovery in deriveAuxGraph and the cross-mode mirror routing target).
    const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("6574694c")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("1918111009080100")]]),
    });
    const publish = trace.frames.find((f) => f.stepId === "key-schedule.publish");
    expect(publish).toBeDefined();
    if (!publish) return;
    expect(publish.stepType).toBe("speck.publish-round-keys@1");
    // The publish frame is what carries the 22-key auxWritten fan-out.
    expect(publish.auxWritten.size).toBe(22);
    // Verified above is byte-equal; here just pin the structural names.
    for (let r = 0; r < 22; r++) {
      expect(publish.auxWritten.has(`roundKey.${r}`)).toBe(true);
    }
  });
});
