/**
 * Parity test for the DES key-schedule simulator (Phase 5e of
 * `docs/plans/des-feistel.md`).
 *
 * The simulator (`src/ui/key-schedule-sim/des.ts`) re-runs the algorithm
 * to *yield* the per-round C_i / D_i halves the executor never exposes.
 * Drift between simulator and executor would silently mislabel the
 * derived intermediates while still passing the end-to-end DES KAT.
 *
 * This test runs the executor and the simulator on the same input and
 * asserts byte-for-byte equality on every K_i for i = 0..15. The 16
 * checked values are the entire output of the schedule — any divergence
 * in PC-1, the shift rule, the rotate-left direction, the bit packing,
 * or PC-2 will be caught immediately.
 *
 * Fixtures:
 *   - FIPS 46-3 Appendix B (the canonical (PT, K, CT) triple).
 *   - A second random-feeling key to catch a single-fixture coincidence.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { DES_PC1, DES_PC2, DES_SHIFTS } from "@/ciphers/des-constants";
import { runSpec } from "@/core/runtime";
import { simulateDesKeySchedule } from "@/ui/key-schedule-sim/des";
import { describe, expect, it } from "vitest";

const runDesExecutorAndExtractKeys = (key: Uint8Array): Uint8Array[] => {
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array(8) },
    initialAux: new Map([["key", key]]),
    portedDispatchEnabled: true,
  });
  const out: Uint8Array[] = [];
  for (let i = 0; i < 16; i++) {
    const v = trace.finalAux.get(`roundKey.${i}`);
    if (!(v instanceof Uint8Array)) {
      throw new Error(`executor did not emit roundKey.${i} as Uint8Array`);
    }
    out.push(v);
  }
  return out;
};

const expectByteEqual = (sim: Uint8Array, exec: Uint8Array, label: string): void => {
  expect(sim.length, `${label}: simulator length`).toBe(exec.length);
  for (let i = 0; i < sim.length; i++) {
    expect(sim[i], `${label}: byte ${i}`).toBe(exec[i]);
  }
};

describe("DES key-schedule simulator parity with executor", () => {
  it("matches executor byte-for-byte on FIPS 46-3 Appendix B key", () => {
    const key = new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]);
    const execKeys = runDesExecutorAndExtractKeys(key);
    const sim = simulateDesKeySchedule(key, {
      pc1: DES_PC1,
      pc2: DES_PC2,
      shifts: DES_SHIFTS,
    });
    expect(sim.roundKeys.length).toBe(16);
    for (let r = 0; r < 16; r++) {
      const simK = sim.roundKeys[r];
      const execK = execKeys[r];
      if (!simK || !execK) throw new Error(`round ${r + 1} missing`);
      expectByteEqual(simK, execK, `K_${r + 1}`);
    }
  });

  it("matches executor byte-for-byte on a second arbitrary 8-byte key", () => {
    // Distinct from Appendix B to catch a coincidence on the canonical
    // vector. Bytes picked to exercise high-bit positions across PC-1.
    const key = new Uint8Array([0xff, 0x00, 0xaa, 0x55, 0x12, 0xed, 0x80, 0x01]);
    const execKeys = runDesExecutorAndExtractKeys(key);
    const sim = simulateDesKeySchedule(key, {
      pc1: DES_PC1,
      pc2: DES_PC2,
      shifts: DES_SHIFTS,
    });
    for (let r = 0; r < 16; r++) {
      const simK = sim.roundKeys[r];
      const execK = execKeys[r];
      if (!simK || !execK) throw new Error(`round ${r + 1} missing`);
      expectByteEqual(simK, execK, `K_${r + 1}`);
    }
  });

  it("yields per-round intermediate C_i and D_i bit arrays (28 bits each)", () => {
    const key = new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]);
    const sim = simulateDesKeySchedule(key, {
      pc1: DES_PC1,
      pc2: DES_PC2,
      shifts: DES_SHIFTS,
    });
    expect(sim.C0bits.length).toBe(28);
    expect(sim.D0bits.length).toBe(28);
    for (let r = 0; r < 16; r++) {
      const round = sim.rounds[r];
      if (!round) throw new Error(`round ${r + 1} missing`);
      expect(round.Cbits.length).toBe(28);
      expect(round.Dbits.length).toBe(28);
      expect(round.round).toBe(r + 1);
      expect(round.shift).toBe(DES_SHIFTS[r]);
    }
    // Cumulative shifts: 1+1+2+2+2+2+2+2+1+2+2+2+2+2+2+1 = 28. After 16
    // rounds the C / D halves have rotated by a full 28-bit cycle, so
    // C_16 = C_0 and D_16 = D_0. Pinning this property pins the rotation
    // direction (left) without depending on a specific cipher key.
    const last = sim.rounds[15];
    if (!last) throw new Error("round 16 missing");
    expect(last.cumulativeShift).toBe(28);
    expect(last.Cbits).toEqual(sim.C0bits);
    expect(last.Dbits).toEqual(sim.D0bits);
  });

  it("throws on master keys whose length is not 8", () => {
    expect(() =>
      simulateDesKeySchedule(new Uint8Array(7), {
        pc1: DES_PC1,
        pc2: DES_PC2,
        shifts: DES_SHIFTS,
      }),
    ).toThrow(/8 bytes/);
  });

  it("throws on a shifts array that is not exactly 16 entries", () => {
    expect(() =>
      simulateDesKeySchedule(new Uint8Array(8), {
        pc1: DES_PC1,
        pc2: DES_PC2,
        shifts: [1, 1, 2],
      }),
    ).toThrow(/16 entries/);
  });
});
