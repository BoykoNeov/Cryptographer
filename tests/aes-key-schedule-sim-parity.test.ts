/**
 * Parity test: AES key-schedule simulator (`src/ui/key-schedule-sim/aes.ts`)
 * vs the runtime executor (`src/steps/key-expansion.ts`).
 *
 * The plan deliberately chose to re-simulate AES key expansion in viz
 * rather than refactor the executor to yield intermediates (the runtime
 * contract is `(state, params, ctx) → state`, and growing `StepResult` to
 * carry sub-frames would force a registry-wide schema change). The cost
 * is code duplication; the safety is THIS test — for every shipped key
 * size and both executor variants, the simulator's final `roundKeys`
 * must match the executor's `auxWrites` byte-for-byte.
 *
 * Coverage:
 *   - AES-128 (Nk=4, rounds=10) — canonical FIPS-197 Appendix A.1 key
 *   - AES-192 (Nk=6, rounds=12) — Appendix A.2 key
 *   - AES-256 (Nk=8, rounds=14) — Appendix A.3 key (exercises the
 *     Nk>6 mid-word SubWord branch)
 *   - All-zero keys for each size (regression guard — a buggy
 *     simulator could pass on a structured key and fail on zeros)
 *   - `aes.key-expansion@2` with non-canonical `rounds = Nk + 7`
 *     (duplicate-round scenario) — exercises the on-the-fly Rcon
 *     extension via xtime
 *   - Truncated Rcon seed (only index 0 + 1 present) — proves the
 *     simulator and executor's xtime fallbacks agree
 */

import { AES_RCON, AES_SBOX } from "@/ciphers/aes-constants";
import { StepRegistry } from "@/core/registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import {
  keyExpansion,
  keyExpansionMeta,
  keyExpansionPortContract,
  keyExpansionV2,
} from "@/steps/key-expansion";
import { simulateAesKeySchedule } from "@/ui/key-schedule-sim/aes";
import { describe, expect, it } from "vitest";

// FIPS-197 Appendix A canonical keys.
const FIPS_KEY_128 = "000102030405060708090a0b0c0d0e0f";
const FIPS_KEY_192 = "000102030405060708090a0b0c0d0e0f1011121314151617";
const FIPS_KEY_256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const ZERO_KEY_16 = "00".repeat(16);
const ZERO_KEY_24 = "00".repeat(24);
const ZERO_KEY_32 = "00".repeat(32);

/**
 * Run the executor against a one-step spec and pull the round-key
 * sequence out of `finalAux`. Bypasses the spec builders since we want
 * to exercise the key-expansion step in isolation against arbitrary
 * `rounds` values (including the `@2`-only relaxed cases).
 */
const runKeyExpansionExecutor = (
  variant: "v1" | "v2",
  masterKeyHex: string,
  rounds: number,
  rconSeed: readonly number[],
): readonly Uint8Array[] => {
  const registry = new StepRegistry();
  const executor = variant === "v1" ? keyExpansion : keyExpansionV2;
  // Slice 5.2 — the executors are now `PortedExecutor`s, so register the
  // probe type as `kind: "ported"` with the shared meta + contract. @1 and
  // @2 use the same `keyExpansionMeta` / `keyExpansionPortContract` (the @2
  // exports are aliases). Doc block satisfied by a minimal stub — `runSpec`
  // doesn't inspect it; only the executor + meta projection matter. With no
  // `legacy` fallback this is pure port-native, so the run below sets
  // `portedDispatchEnabled: true`.
  registry.register("test.key-expansion", {
    kind: "ported",
    executor,
    shape: keyExpansionPortContract,
    meta: keyExpansionMeta,
    doc: {
      name: "test",
      summary: "test",
      detail: "test",
    },
  });

  const spec: CipherSpec = {
    id: "test-aes-keyexp",
    name: "test",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: masterKeyHex.length / 2 },
    },
    steps: [
      {
        kind: "step",
        id: "key-expansion",
        type: "test.key-expansion",
        params: {
          keyAuxName: "key",
          outputPrefix: "roundKey",
          sbox: [...AES_SBOX],
          rcon: [...rconSeed],
          rounds,
        },
      },
    ],
  };

  const trace = runSpec(spec, registry, {
    // State is irrelevant — key-expansion has no state port — but runSpec
    // needs SOME initial state to seed the walk. The round keys still land
    // in finalAux: the ported runtime maps each `key${r}` output port →
    // `aux[roundKey.${r}]` via `keyExpansionMeta.auxWritePorts`.
    initialState: makeBytesState(new Uint8Array(16)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(masterKeyHex)]]),
  });

  // Pull every `roundKey.N` (N = 0..rounds) out of finalAux in order.
  const roundKeys: Uint8Array[] = [];
  for (let r = 0; r <= rounds; r++) {
    const v = trace.finalAux.get(`roundKey.${r}`);
    if (!(v instanceof Uint8Array)) {
      throw new Error(`executor did not emit roundKey.${r} (got: ${typeof v})`);
    }
    roundKeys.push(v);
  }
  return roundKeys;
};

const assertParity = (
  variant: "v1" | "v2",
  masterKeyHex: string,
  rounds: number,
  rconSeed: readonly number[] = AES_RCON,
): void => {
  const executorRoundKeys = runKeyExpansionExecutor(variant, masterKeyHex, rounds, rconSeed);
  const simulation = simulateAesKeySchedule(bytesFromHex(masterKeyHex), AES_SBOX, rconSeed, rounds);
  expect(simulation.roundKeys.length).toBe(executorRoundKeys.length);
  for (let r = 0; r < executorRoundKeys.length; r++) {
    expect(Array.from(simulation.roundKeys[r] ?? new Uint8Array())).toEqual(
      Array.from(executorRoundKeys[r] ?? new Uint8Array()),
    );
  }
};

describe("AES key-schedule simulator — parity vs aes.key-expansion@1 (canonical rounds)", () => {
  it("matches the executor on AES-128 with the FIPS-197 Appendix A.1 key", () => {
    assertParity("v1", FIPS_KEY_128, 10);
  });

  it("matches the executor on AES-192 with the FIPS-197 Appendix A.2 key", () => {
    assertParity("v1", FIPS_KEY_192, 12);
  });

  it("matches the executor on AES-256 with the FIPS-197 Appendix A.3 key (Nk>6 branch fires)", () => {
    // AES-256 exercises the `Nk > 6 && i % Nk === 4` extra-SubWord
    // branch that AES-128 and AES-192 never reach. If the simulator's
    // `isNk8Mid` predicate has the wrong threshold, this test fails.
    assertParity("v1", FIPS_KEY_256, 14);
  });

  it("matches the executor on all-zero AES-128 key (structural-key regression guard)", () => {
    // A buggy simulator could pass on a structured key (where SubWord
    // visibly perturbs bytes) and fail on zeros (where it doesn't —
    // S[0x00] = 0x63 but every word starts at 0). Pin both.
    assertParity("v1", ZERO_KEY_16, 10);
  });

  it("matches the executor on all-zero AES-192 key", () => {
    assertParity("v1", ZERO_KEY_24, 12);
  });

  it("matches the executor on all-zero AES-256 key", () => {
    assertParity("v1", ZERO_KEY_32, 14);
  });
});

describe("AES key-schedule simulator — parity vs aes.key-expansion@2 (relaxed rounds + xtime Rcon)", () => {
  it("matches the executor on AES-128 with `rounds = 11` (one extra round, no Rcon extension needed)", () => {
    // Canonical AES_RCON has 11 entries (indices 0..10). Adding one
    // extra round needs Rcon[1..floor(47/4)=11] — index 11 missing. The
    // executor and simulator must agree on extending via xtime from
    // Rcon[10] = 0x36 → Rcon[11] = xtime(0x36) = 0x6c.
    assertParity("v2", FIPS_KEY_128, 11);
  });

  it("matches the executor on AES-128 with `rounds = 15` (heavy Rcon extension)", () => {
    // Needs Rcon[1..15]; only 1..10 in the canonical seed. 5 new
    // entries via xtime: 0x6c, 0xd8, 0xab, 0x4d, 0x9a. If either
    // simulator OR executor has a wrong reduction polynomial (e.g.
    // missing the ^ 0x1b on overflow), they'd disagree past 0x80.
    assertParity("v2", FIPS_KEY_128, 15);
  });

  it("matches the executor on AES-128 with a TRUNCATED Rcon seed (extension fallback)", () => {
    // Only Rcon[0]=0 and Rcon[1]=0x01 seeded; the rest must be derived
    // by both the executor and simulator from the recurrence
    // Rcon[i] = xtime(Rcon[i-1]). At canonical rounds=10 this stresses
    // 8 levels of the recurrence on both sides.
    const truncated = [0x00, 0x01] as const;
    assertParity("v2", FIPS_KEY_128, 10, truncated);
  });

  it("matches the executor on AES-192 with `rounds = 13`", () => {
    // Nk=6, totalWords=4*14=56, maxRconIdx=floor(55/6)=9 — fits in
    // canonical seed; verifies the @2 path doesn't accidentally do
    // something different when extension ISN'T needed.
    assertParity("v2", FIPS_KEY_192, 13);
  });

  it("matches the executor on AES-256 with `rounds = 15` (extends Rcon AND fires Nk>6 branch)", () => {
    // Nk=8, maxRconIdx=floor(63/8)=7 — canonical seed covers it. The
    // simulator's `isNk8Mid` flag must still fire correctly under @2's
    // relaxed bound.
    assertParity("v2", FIPS_KEY_256, 15);
  });
});

describe("AES key-schedule simulator — yielded stages structural invariants", () => {
  it("emits Nk init words + (totalWords - Nk) derived words", () => {
    const sim = simulateAesKeySchedule(bytesFromHex(FIPS_KEY_128), AES_SBOX, AES_RCON, 10);
    // Nk=4, totalWords=44.
    expect(sim.words.length).toBe(44);
    // Init words are the first Nk.
    for (let i = 0; i < 4; i++) {
      expect(sim.words[i]?.stages.length).toBe(1);
      expect(sim.words[i]?.stages[0]?.kind).toBe("init");
    }
  });

  it("flags chain-start words (i % Nk === 0) with 4 stages: rotword, subword, rcon-xor, xor-prev", () => {
    const sim = simulateAesKeySchedule(bytesFromHex(FIPS_KEY_128), AES_SBOX, AES_RCON, 10);
    // For AES-128, every Nk-th word from 4 onward is chain-start:
    // i = 4, 8, 12, ..., 40.
    for (let i = 4; i <= 40; i += 4) {
      const w = sim.words[i];
      expect(w?.isChainStart).toBe(true);
      expect(w?.stages.length).toBe(4);
      expect(w?.stages.map((s) => s.kind)).toEqual(["rotword", "subword", "rcon-xor", "xor-prev"]);
    }
  });

  it("flags AES-256 mid-Nk words (i % Nk === 4) with 2 stages: extra-subword, xor-prev", () => {
    const sim = simulateAesKeySchedule(bytesFromHex(FIPS_KEY_256), AES_SBOX, AES_RCON, 14);
    // For AES-256, i = 12, 20, 28, 36, 44, 52 are the mid-Nk words
    // (12 = 8+4, 20 = 16+4, ..., 52 = 48+4). Less than totalWords=60.
    for (let i = 12; i <= 52; i += 8) {
      const w = sim.words[i];
      expect(w?.isNk8Mid).toBe(true);
      expect(w?.isChainStart).toBe(false);
      expect(w?.stages.length).toBe(2);
      expect(w?.stages.map((s) => s.kind)).toEqual(["extra-subword", "xor-prev"]);
    }
  });

  it("plain derived words have exactly one stage: xor-prev", () => {
    const sim = simulateAesKeySchedule(bytesFromHex(FIPS_KEY_128), AES_SBOX, AES_RCON, 10);
    // For AES-128, i in [5,6,7], [9,10,11], etc. — any i >= Nk that's
    // not a chain-start. Sample a few.
    for (const i of [5, 6, 7, 9, 10, 11, 43]) {
      const w = sim.words[i];
      expect(w?.isChainStart).toBe(false);
      expect(w?.isNk8Mid).toBe(false);
      expect(w?.stages.length).toBe(1);
      expect(w?.stages[0]?.kind).toBe("xor-prev");
    }
  });

  it("throws on invalid masterKey length", () => {
    expect(() => simulateAesKeySchedule(new Uint8Array(15), AES_SBOX, AES_RCON, 10)).toThrow();
    expect(() => simulateAesKeySchedule(new Uint8Array(17), AES_SBOX, AES_RCON, 10)).toThrow();
  });

  it("throws on rounds < 1", () => {
    expect(() => simulateAesKeySchedule(new Uint8Array(16), AES_SBOX, AES_RCON, 0)).toThrow();
  });

  it("throws on sbox != 256 entries", () => {
    expect(() => simulateAesKeySchedule(new Uint8Array(16), [0, 1, 2], AES_RCON, 10)).toThrow();
  });
});
