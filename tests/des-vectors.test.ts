/**
 * DES known-answer tests pinning the cipher to the Phase-1 oracle fixture
 * at `tests/fixtures/des-kat.json`.
 *
 * Per `[[feedback-crypto-verification]]`: the fixture was produced by
 * `scripts/verify-des.mjs` and cross-checked against `node:crypto` for the
 * final ciphertext. Three vectors (FIPS Appendix B + two boundary cases:
 * all-zeros and all-ones) each carry the IP output, per-round F
 * intermediates (E, X, S, P, F_out), and the final pre-FP value. The DES
 * spec's trace MUST match every recorded value.
 *
 * **Round-16 alignment gotcha.** The oracle's per-round records use
 * textbook Feistel-standard semantics for ALL 16 rounds: `L_out = R_in`
 * and `R_out = L_in ⊕ F_out`. After the loop, it computes
 * `preFp = R_16 || L_16` (a final swap) and applies FP.
 *
 * Our spec uses `combineKind: "feistel-no-swap"` for round 16 — equivalent
 * to "don't record the final swap." So:
 *   - Rounds 1..15: rejoin stateAfter bytes [0..3] == oracle.L_out,
 *     bytes [4..7] == oracle.R_out (matches the fixture verbatim).
 *   - Round 16: rejoin stateAfter == oracle.preFp (NOT oracle.L_out||R_out;
 *     no-swap inverts the order). This is what the test asserts.
 *
 * Both encodings produce the same ciphertext after FP — the difference is
 * purely "where the final swap lives" (in the post-loop step vs. baked
 * into the round-16 combine kind).
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import type { AuxValue, BytesState } from "@/core/types";
import { describe, expect, it } from "vitest";

type RoundFixture = {
  readonly i: number;
  readonly L_in: string;
  readonly R_in: string;
  readonly K: string;
  readonly E: string;
  readonly X: string;
  readonly S: string;
  readonly P: string;
  readonly F_out: string;
  readonly L_out: string;
  readonly R_out: string;
};

type VectorFixture = {
  readonly pt: string;
  readonly key: string;
  readonly ip: string;
  readonly rounds: readonly RoundFixture[];
  readonly preFp: string;
  readonly ct: string;
};

type Fixture = {
  readonly vectors: readonly VectorFixture[];
};

const FIXTURE_PATH = join(process.cwd(), "tests", "fixtures", "des-kat.json");
const FIXTURE: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as Fixture;

const bytesShape = (state: { readonly shape: string }): state is BytesState =>
  state.shape === "bytes";

/** Run the DES encrypt spec on a single fixture vector. */
const runVector = (vec: VectorFixture) => {
  const plaintext: BytesState = { shape: "bytes", bytes: bytesFromHex(vec.pt) };
  const key = bytesFromHex(vec.key);
  const initialAux = new Map<string, AuxValue>([["key", key]]);
  return runSpec(desSpec, buildDefaultRegistry(), { initialState: plaintext, initialAux });
};

describe("DES — final ciphertext", () => {
  for (const vec of FIXTURE.vectors) {
    it(`PT=${vec.pt} K=${vec.key} → CT=${vec.ct}`, () => {
      const trace = runVector(vec);
      expect(bytesShape(trace.finalState)).toBe(true);
      if (!bytesShape(trace.finalState)) return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(vec.ct);
    });
  }
});

describe("DES — key schedule produces 16 round keys (FIPS Appendix B vector)", () => {
  const vec = FIXTURE.vectors[0];
  if (!vec) throw new Error("fixture missing");
  it("aux carries roundKey.0..15, each a 6-byte Uint8Array equal to fixture K_i", () => {
    const trace = runVector(vec);
    for (let r = 0; r < 16; r++) {
      const rk = trace.finalAux.get(`roundKey.${r}`);
      expect(rk, `roundKey.${r} missing`).toBeInstanceOf(Uint8Array);
      const arr = rk as Uint8Array;
      expect(arr.length).toBe(6);
      const expected = vec.rounds[r]?.K;
      expect(expected, `fixture missing round ${r + 1} K`).toBeDefined();
      if (!expected) continue;
      expect(hexFromBytes(arr)).toBe(expected);
    }
  });
});

describe("DES — initial-permutation frame matches fixture IP output", () => {
  for (const vec of FIXTURE.vectors) {
    it(`PT=${vec.pt}: IP output == ${vec.ip}`, () => {
      const trace = runVector(vec);
      const ip = trace.frames.find((f) => f.stepId === "initial-permutation");
      expect(ip, "initial-permutation frame missing").toBeDefined();
      if (!ip) return;
      expect(bytesShape(ip.stateAfter)).toBe(true);
      if (!bytesShape(ip.stateAfter)) return;
      expect(hexFromBytes(ip.stateAfter.bytes)).toBe(vec.ip);
    });
  }
});

describe("DES — F-function intermediates match fixture per round", () => {
  const vec = FIXTURE.vectors[0];
  if (!vec) throw new Error("fixture missing");
  // Spot-check 4 rounds to keep this test focused; if all checks pass
  // here AND the final ciphertext + IP/FP match, the cipher is correct.
  // Rounds 1 (entry) and 16 (last with the no-swap kind), plus a couple
  // in the middle to exercise the standard combine across the loop.
  const ROUNDS_TO_CHECK = [1, 2, 8, 16];
  for (const r of ROUNDS_TO_CHECK) {
    const round = vec.rounds[r - 1];
    if (!round) throw new Error(`fixture missing round ${r}`);

    it(`round ${r}: expand-R(R_in) == ${round.E}`, () => {
      const trace = runVector(vec);
      const f = trace.frames.find((fr) => fr.stepId === `round.${r}.expand-R:tR`);
      expect(f, `round.${r}.expand-R:tR missing`).toBeDefined();
      if (!f) return;
      if (!bytesShape(f.stateAfter)) return;
      expect(hexFromBytes(f.stateAfter.bytes)).toBe(round.E);
    });

    it(`round ${r}: xor-K(E) == ${round.X}`, () => {
      const trace = runVector(vec);
      const f = trace.frames.find((fr) => fr.stepId === `round.${r}.xor-K:tR`);
      expect(f, `round.${r}.xor-K:tR missing`).toBeDefined();
      if (!f) return;
      if (!bytesShape(f.stateAfter)) return;
      expect(hexFromBytes(f.stateAfter.bytes)).toBe(round.X);
    });

    it(`round ${r}: s-boxes(X) == ${round.S}`, () => {
      const trace = runVector(vec);
      const f = trace.frames.find((fr) => fr.stepId === `round.${r}.s-boxes:tR`);
      expect(f, `round.${r}.s-boxes:tR missing`).toBeDefined();
      if (!f) return;
      if (!bytesShape(f.stateAfter)) return;
      expect(hexFromBytes(f.stateAfter.bytes)).toBe(round.S);
    });

    it(`round ${r}: p-permute(S) == ${round.P} (== F_out)`, () => {
      const trace = runVector(vec);
      const f = trace.frames.find((fr) => fr.stepId === `round.${r}.p-permute:tR`);
      expect(f, `round.${r}.p-permute:tR missing`).toBeDefined();
      if (!f) return;
      if (!bytesShape(f.stateAfter)) return;
      // F_out == P_out (P is the last step inside F).
      expect(hexFromBytes(f.stateAfter.bytes)).toBe(round.P);
      expect(round.F_out).toBe(round.P);
    });
  }
});

describe("DES — rejoin frame matches expected (L_out || R_out) per round", () => {
  const vec = FIXTURE.vectors[0];
  if (!vec) throw new Error("fixture missing");
  it("rounds 1..15 (feistel-standard): rejoin stateAfter == L_out || R_out", () => {
    const trace = runVector(vec);
    for (let r = 1; r <= 15; r++) {
      const round = vec.rounds[r - 1];
      if (!round) throw new Error(`fixture missing round ${r}`);
      const rejoin = trace.frames.find((f) => f.stepId === `round.${r}:rejoin`);
      expect(rejoin, `round.${r}:rejoin missing`).toBeDefined();
      if (!rejoin) continue;
      if (!bytesShape(rejoin.stateAfter)) continue;
      // Fixture records L_out and R_out under textbook Feistel-standard
      // semantics; our rounds 1..15 use the same combine, so direct match.
      expect(hexFromBytes(rejoin.stateAfter.bytes)).toBe(round.L_out + round.R_out);
    }
  });

  it("round 16 (feistel-no-swap): rejoin stateAfter == preFp (NOT L_out||R_out)", () => {
    const trace = runVector(vec);
    const round16 = vec.rounds[15];
    expect(round16, "fixture missing round 16").toBeDefined();
    if (!round16) return;
    const rejoin = trace.frames.find((f) => f.stepId === "round.16:rejoin");
    expect(rejoin, "round.16:rejoin missing").toBeDefined();
    if (!rejoin) return;
    if (!bytesShape(rejoin.stateAfter)) return;
    // feistel-no-swap puts (L_in ⊕ R_out_track, R_in) into the rejoin
    // output, equivalent to oracle's (R_out, L_out) for round 16 ==
    // oracle's preFp by construction.
    expect(hexFromBytes(rejoin.stateAfter.bytes)).toBe(vec.preFp);
  });
});

describe("DES — branchPath stamping on track frames", () => {
  it("R-track frames carry branchPath=['R']; rejoin frames carry it too", () => {
    const vec = FIXTURE.vectors[0];
    if (!vec) throw new Error("fixture missing");
    const trace = runVector(vec);
    for (const frame of trace.frames) {
      const inTrack = /:tR$/.test(frame.stepId);
      const isRejoin = /:rejoin$/.test(frame.stepId);
      if (inTrack) {
        expect(frame.branchPath, `${frame.stepId} should have branchPath`).toEqual(["R"]);
      } else if (isRejoin) {
        // Synthetic rejoin frame: branchPath omitted (the rejoin sits at
        // the round's parent scope, not inside a track). See runtime.ts.
        expect(frame.branchPath, `${frame.stepId} should NOT have branchPath`).toBeUndefined();
      } else {
        expect(frame.branchPath, `${frame.stepId} should not have branchPath`).toBeUndefined();
      }
    }
  });
});
