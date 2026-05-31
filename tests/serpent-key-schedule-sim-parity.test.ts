/**
 * Parity test: Serpent key-schedule simulator
 * (`src/ui/key-schedule-sim/serpent.ts`) vs the runtime executor
 * (`src/steps/serpent-key-expansion.ts`).
 *
 * Same Option-B trade-off as the AES sim — re-simulate in viz, pin
 * byte-equality against the executor. Plan in
 * ~/.claude/plans/immutable-doodling-quokka.md.
 *
 * Coverage:
 *   - Serpent-128 / 192 / 256 with canonical Serpent NIST submission
 *     test keys.
 *   - Zero keys for each size (regression guard — a buggy padding step
 *     could pass on structured keys and fail on zeros where the 0x01
 *     pad byte is the only non-zero byte in the padded buffer).
 *   - Structural-invariant tests on the yielded stages list.
 */

import { StepRegistry } from "@/core/registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import {
  serpentKeyExpansion,
  serpentKeyExpansionMeta,
  serpentKeyExpansionPortContract,
} from "@/steps/serpent-key-expansion";
import { simulateSerpentKeySchedule } from "@/ui/key-schedule-sim/serpent";
import { describe, expect, it } from "vitest";

const ZERO_16 = "00".repeat(16);
const ZERO_24 = "00".repeat(24);
const ZERO_32 = "00".repeat(32);

// Serpent submission test keys (Anderson/Biham/Knudsen reference vectors).
const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const SERPENT192_KEY = "00112233445566778899aabbccddeeff0011223344556677";
const SERPENT256_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/**
 * Run the Serpent key-expansion executor in isolation against a chosen
 * master key, returning the 33 round keys in index order.
 */
const runSerpentExecutor = (masterKeyHex: string): readonly Uint8Array[] => {
  const registry = new StepRegistry();
  // Slice 5.2 — `serpentKeyExpansion` is now a `PortedExecutor`, so register
  // the probe type as `kind: "ported"` with its shared meta + contract and
  // run flag-on. The runtime projects `aux[key] → masterKey` and
  // `key${i} → aux[roundKey.${i}]` via the meta, so the 33 round keys still
  // land in `trace.finalAux` exactly as under the former lifted path.
  registry.register("test.serpent-key-expansion", {
    kind: "ported",
    executor: serpentKeyExpansion,
    shape: serpentKeyExpansionPortContract,
    meta: serpentKeyExpansionMeta,
    doc: { name: "t", summary: "t", detail: "t" },
  });

  const keyByteLength = masterKeyHex.length / 2;
  const spec: CipherSpec = {
    id: "test-serpent-keyexp",
    name: "test",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: keyByteLength },
    },
    steps: [
      {
        kind: "step",
        id: "key-expansion",
        type: "test.serpent-key-expansion",
        params: {
          keyAuxName: "key",
          outputPrefix: "roundKey",
          keyByteLength,
        },
      },
    ],
  };

  const trace = runSpec(spec, registry, {
    // State is unused by key-expansion; an empty bytes value satisfies
    // the runtime's shape check.
    initialState: makeBytesState(new Uint8Array(0)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(masterKeyHex)]]),
  });

  const roundKeys: Uint8Array[] = [];
  for (let r = 0; r <= 32; r++) {
    const v = trace.finalAux.get(`roundKey.${r}`);
    if (!(v instanceof Uint8Array)) {
      throw new Error(`executor did not emit roundKey.${r}`);
    }
    roundKeys.push(v);
  }
  return roundKeys;
};

const assertSerpentParity = (masterKeyHex: string): void => {
  const executorKeys = runSerpentExecutor(masterKeyHex);
  const sim = simulateSerpentKeySchedule(bytesFromHex(masterKeyHex));
  expect(sim.roundKeys.length).toBe(33);
  expect(sim.roundKeys.length).toBe(executorKeys.length);
  for (let r = 0; r < executorKeys.length; r++) {
    expect(Array.from(sim.roundKeys[r] ?? new Uint8Array())).toEqual(
      Array.from(executorKeys[r] ?? new Uint8Array()),
    );
  }
};

describe("Serpent key-schedule simulator — parity vs serpent.key-expansion@1", () => {
  it("matches the executor on Serpent-128 with the canonical test key", () => {
    assertSerpentParity(SERPENT128_KEY);
  });

  it("matches the executor on Serpent-192", () => {
    assertSerpentParity(SERPENT192_KEY);
  });

  it("matches the executor on Serpent-256 (256-bit padded path is a no-op)", () => {
    // For 256-bit keys the padding step doesn't fire (no 0x01 marker
    // byte). Verifies the simulator's `if (masterKey.length < 32)`
    // gate agrees with the executor.
    assertSerpentParity(SERPENT256_KEY);
  });

  it("matches the executor on all-zero Serpent-128 key (regression guard for padding step)", () => {
    // After padding, the 32-byte buffer is `[0,0,...,0,0x01,0,...,0]`
    // with the 0x01 at index 16. If the sim's padding mishandles the
    // marker byte (wrong index, wrong value, no-op when it should fire)
    // the prekey[4] = readWordLE32(padded, 16) read would be 0 instead
    // of 0x00000001 and every downstream prekey diverges. Pin both.
    assertSerpentParity(ZERO_16);
  });

  it("matches the executor on all-zero Serpent-192 key", () => {
    assertSerpentParity(ZERO_24);
  });

  it("matches the executor on all-zero Serpent-256 key", () => {
    // 256-bit zero key has no pad byte; verifies the sim emits identical
    // bytes when the padding-stage is a no-op AND every prekey starts
    // at zero. The phi XOR + counter XOR is the only non-zero input
    // to the recurrence here — exercises that path cleanly.
    assertSerpentParity(ZERO_32);
  });
});

describe("Serpent key-schedule simulator — yielded stages structural invariants", () => {
  it("emits the expected stage count and order on Serpent-128", () => {
    // Stage breakdown:
    //   1 × pad
    //   1 × prekey-init
    //   132 × prekey-recurrence (j = 0..131)
    //   33 × sbox-group (i = 0..32)
    //   33 × ip (one after each sbox-group)
    // Total: 1 + 1 + 132 + 33 + 33 = 200.
    const sim = simulateSerpentKeySchedule(bytesFromHex(SERPENT128_KEY));
    expect(sim.stages.length).toBe(200);
    expect(sim.stages[0]?.kind).toBe("pad");
    expect(sim.stages[1]?.kind).toBe("prekey-init");
    // First recurrence at index 2; last at index 2+131=133.
    expect(sim.stages[2]?.kind).toBe("prekey-recurrence");
    expect(sim.stages[133]?.kind).toBe("prekey-recurrence");
    // First sbox-group at 134, first ip at 135. Then they alternate.
    expect(sim.stages[134]?.kind).toBe("sbox-group");
    expect(sim.stages[135]?.kind).toBe("ip");
    // Last ip at index 199.
    expect(sim.stages[199]?.kind).toBe("ip");
  });

  it("pad stage marks padByteIndex correctly for 128/192/256-bit keys", () => {
    const sim128 = simulateSerpentKeySchedule(bytesFromHex(SERPENT128_KEY));
    const pad128 = sim128.stages[0];
    if (pad128?.kind !== "pad") throw new Error("expected pad stage");
    expect(pad128.padByteIndex).toBe(16);
    expect(pad128.padded[16]).toBe(0x01);

    const sim192 = simulateSerpentKeySchedule(bytesFromHex(SERPENT192_KEY));
    const pad192 = sim192.stages[0];
    if (pad192?.kind !== "pad") throw new Error("expected pad stage");
    expect(pad192.padByteIndex).toBe(24);
    expect(pad192.padded[24]).toBe(0x01);

    const sim256 = simulateSerpentKeySchedule(bytesFromHex(SERPENT256_KEY));
    const pad256 = sim256.stages[0];
    if (pad256?.kind !== "pad") throw new Error("expected pad stage");
    // 256-bit keys: no padding byte fires.
    expect(pad256.padByteIndex).toBe(-1);
  });

  it("sbox-group stages reference the correct walks-down-with-wraparound index", () => {
    const sim = simulateSerpentKeySchedule(bytesFromHex(SERPENT128_KEY));
    // Filter to sbox-group stages and check the indexing pattern.
    const groups = sim.stages.filter(
      (s): s is Extract<typeof s, { kind: "sbox-group" }> => s.kind === "sbox-group",
    );
    expect(groups.length).toBe(33);
    // Spot-check the classic off-by-one trap: group 0 uses S_3, group 4
    // uses S_7, group 5 uses S_6.
    expect(groups[0]?.sboxIndex).toBe(3);
    expect(groups[1]?.sboxIndex).toBe(2);
    expect(groups[2]?.sboxIndex).toBe(1);
    expect(groups[3]?.sboxIndex).toBe(0);
    expect(groups[4]?.sboxIndex).toBe(7);
    expect(groups[5]?.sboxIndex).toBe(6);
    // Last group i=32: (35-32) mod 8 = 3.
    expect(groups[32]?.sboxIndex).toBe(3);
  });

  it("throws on invalid master-key length", () => {
    expect(() => simulateSerpentKeySchedule(new Uint8Array(15))).toThrow();
    expect(() => simulateSerpentKeySchedule(new Uint8Array(17))).toThrow();
    expect(() => simulateSerpentKeySchedule(new Uint8Array(33))).toThrow();
  });
});
