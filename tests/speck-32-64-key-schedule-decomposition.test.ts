import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
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
 * the original Beaulieu et al. 2013 §3 recurrence prescribes, so the
 * round-body `speck.round@1` consumers see canonical round keys.
 *
 * This test pins that contract directly: run each shipped Speck32/64 spec
 * (which now carries the decomposed schedule) and compare every published
 * round key, byte-for-byte, against an **inline reference implementation**
 * of the Beaulieu §3 recurrence (formerly compared against the monolithic
 * `speckKeySchedule` executor; that step type was fully retired at the K2c
 * follow-up). The two recurrence implementations are independent: the
 * decomposed schedule expresses the recurrence as a tree of port-native
 * primitive frames; this oracle expresses it as straight-line TS. A
 * mismatch would mean either the builder's primitive wiring is wrong or
 * this oracle is wrong — both run in this file's tests, so a divergence
 * surfaces before any cipher KAT fails. Critically: covers BOTH byte-order
 * conventions (BE-paper and LE-NSA), since the codec boundary is the K2
 * load-bearing design — the body math is byte-order-invariant, but the
 * published bytes ARE byte-order-dependent.
 *
 * Speck32/64 constants (`m=4, wordBits=16, rounds=22, alpha=7, beta=2`) are
 * baked into the shipped specs and into this oracle.
 */

// ─── Inline Beaulieu §3 reference (replaces the retired monolith oracle) ──
//
// The recurrence (Beaulieu et al. 2013 §3, with `i` the iteration index):
//   l_{i+m-1} = (k_i + ROR(l_i, alpha)) ⊕ i
//   k_{i+1}   = ROL(k_i, beta) ⊕ l_{i+m-1}
// for i = 0..rounds-2. The cipher's round keys are k_0, k_1, …, k_{rounds-1}.
//
// Speck32/64 specifics: wordBits=16, m=4, alpha=7, beta=2, rounds=22 → 22
// round keys, k_0 plus 21 iterations.
//
// Byte-order codec (matches `speck-word-codec.ts`):
//   BE-paper memory layout = (l_{m-2}, …, l_0, k_0) BE-encoded per word
//     → byte indices [6,7, 4,5, 2,3, 0,1] for m=4 (word reverse, no in-word swap)
//   LE-NSA  memory layout = (k_0, l_0, …, l_{m-2}) LE-encoded per word
//     → byte indices [1,0, 3,2, 5,4, 7,6] for m=4 (in-word byte-swap, no reverse)
// Round-key output encoding matches the spec's byteOrder: BE-encoded for
// BE-paper, LE-encoded for LE-NSA.

const WORD_BITS = 16;
const WORD_MASK = (1 << WORD_BITS) - 1;
const M = 4;
const ALPHA = 7;
const BETA = 2;
const ROUNDS = 22;

const ror = (x: number, n: number): number => ((x >>> n) | (x << (WORD_BITS - n))) & WORD_MASK;
const rol = (x: number, n: number): number => ((x << n) | (x >>> (WORD_BITS - n))) & WORD_MASK;

/** Decode the 8-byte master key into [k_0, l_0, l_1, l_2] (logical word
 *  order, plain 16-bit number values), accounting for the byteOrder
 *  memory layout. */
const decodeMasterKey = (
  keyBytes: Uint8Array,
  byteOrder: "be-paper" | "le-nsa",
): readonly number[] => {
  if (keyBytes.length !== M * 2) {
    throw new Error(`expected ${M * 2} master-key bytes, got ${keyBytes.length}`);
  }
  // BE-paper: memory = (l_2, l_1, l_0, k_0) BE per word — so the LAST 2 bytes
  // are k_0, the previous 2 are l_0, etc. Word indices reverse vs memory.
  // LE-NSA: memory = (k_0, l_0, l_1, l_2) LE per word — so the FIRST 2 bytes
  // are k_0 (low byte first), the next 2 are l_0, etc.
  const words: number[] = [];
  for (let i = 0; i < M; i++) {
    if (byteOrder === "be-paper") {
      const offset = (M - 1 - i) * 2;
      const hi = keyBytes[offset];
      const lo = keyBytes[offset + 1];
      if (hi === undefined || lo === undefined) throw new Error("oob");
      words.push(((hi << 8) | lo) & WORD_MASK);
    } else {
      const offset = i * 2;
      const lo = keyBytes[offset];
      const hi = keyBytes[offset + 1];
      if (hi === undefined || lo === undefined) throw new Error("oob");
      words.push(((hi << 8) | lo) & WORD_MASK);
    }
  }
  return words; // [k_0, l_0, l_1, l_2]
};

/** Encode a 16-bit word value to 2 bytes per the spec's byteOrder. */
const encodeRoundKeyWord = (w: number, byteOrder: "be-paper" | "le-nsa"): Uint8Array => {
  const hi = (w >>> 8) & 0xff;
  const lo = w & 0xff;
  return byteOrder === "be-paper" ? new Uint8Array([hi, lo]) : new Uint8Array([lo, hi]);
};

/** Inline reference: run the Beaulieu §3 recurrence on the decoded master
 *  key and emit `roundKey.0..roundKey.21` as byte-encoded round-key words. */
const referenceRoundKeys = (
  keyBytes: Uint8Array,
  byteOrder: "be-paper" | "le-nsa",
): Map<string, Uint8Array> => {
  const decoded = decodeMasterKey(keyBytes, byteOrder);
  // l[0..m-2] are the (m-1) cross-iteration carries; k is the round-key
  // accumulator. Pre-allocate `l` long enough for the (i + m - 1) writes
  // that happen for i = 0 .. rounds-2.
  const k: number[] = [decoded[0] as number];
  const l: number[] = [];
  for (let j = 0; j < M - 1; j++) l.push(decoded[j + 1] as number);

  for (let i = 0; i < ROUNDS - 1; i++) {
    const ki = k[i] as number;
    const li = l[i] as number;
    const lNext = ((ki + ror(li, ALPHA)) & WORD_MASK) ^ (i & WORD_MASK);
    const kNext = rol(ki, BETA) ^ lNext;
    l.push(lNext);
    k.push(kNext);
  }

  const out = new Map<string, Uint8Array>();
  for (let r = 0; r < ROUNDS; r++) {
    out.set(`roundKey.${r}`, encodeRoundKeyWord(k[r] as number, byteOrder));
  }
  return out;
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
    it(`${c.label}: roundKey.0..21 byte-equal to the inline Beaulieu §3 reference`, () => {
      const keyBytes = bytesFromHex(c.keyHex);
      const trace = runSpec(c.spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(c.plaintextHex)),
        initialAux: new Map<string, AuxValue>([["key", keyBytes]]),
      });
      const oracle = referenceRoundKeys(keyBytes, c.byteOrder);

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
