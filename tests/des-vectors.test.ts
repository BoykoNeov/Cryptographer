/**
 * DES encrypt known-answer + per-leaf parity tests, pinning the port-native
 * DES rebuild (B4 — universal-port Phase 4d) to the Phase-1 oracle fixture
 * at `tests/fixtures/des-kat.json`.
 *
 * Per `[[feedback-crypto-verification]]`: the fixture was produced by
 * `scripts/verify-des.mjs` and cross-checked against `node:crypto` for the
 * final ciphertext. Three vectors (FIPS Appendix B + all-zeros + all-ones)
 * each carry the IP output, per-round F intermediates (E, X, S, P, F_out),
 * L_out/R_out, and the final pre-FP value.
 *
 * **Per-leaf parity net (the B2/B3 golden-frame-stream analog).** The
 * port-native rebuild changed the trace TOPOLOGY (no `feistel-round`, no
 * `:rejoin` frames, new split/xor/concat leaves), so a B2/B3-style whole
 * frame-stream equality no longer applies. Instead each fixture intermediate
 * is asserted against the matching native leaf's OUTPUT PORT
 * (`frame.portOutputs`, NOT `stateAfter` — port-native leaves don't thread
 * `state`):
 *   - `ip`    → `initial-permutation.state`
 *   - `E`     → `round.r.expand-R.state`
 *   - `X`     → `round.r.xor-K.state`
 *   - `S`     → `round.r.s-boxes.state`
 *   - `P/F_out` → `round.r.p-permute.state`
 *   - `L_in/R_in` → `round.r.split.output0/output1`
 *   - `R_out` (= L_in ⊕ F) → `round.r.fxor.output`
 *   - `preFp` → `round.16.recombine.output`
 *
 * **The swap-order trap (advisor done-check).** The Feistel swap is nothing
 * but the `concat@1` argument order. Rounds 1..15 emit `R_in || (L_in⊕F)`
 * (= `L_out || R_out`); round 16 (the no-swap exception) emits
 * `(L_in⊕F) || R_in` (= `preFp`). `round.16.recombine.output == preFp` is the
 * single place a standard/no-swap order slip would hide — pinned explicitly.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import type { AuxValue, BytesState, TraceFrame } from "@/core/types";
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

/**
 * Run the port-native DES encrypt spec on a single fixture vector. The spec
 * has port-native leaves, so `portedDispatchEnabled: true` is required (the
 * runtime throws otherwise).
 */
const runVector = (vec: VectorFixture) => {
  const plaintext: BytesState = { shape: "bytes", bytes: bytesFromHex(vec.pt) };
  const key = bytesFromHex(vec.key);
  const initialAux = new Map<string, AuxValue>([["key", key]]);
  return runSpec(desSpec, buildDefaultRegistry(), {
    initialState: plaintext,
    initialAux,
    portedDispatchEnabled: true,
  });
};

/** Map every frame by its stepId for direct lookup. */
const byId = (frames: readonly TraceFrame[]): Map<string, TraceFrame> => {
  const m = new Map<string, TraceFrame>();
  for (const f of frames) m.set(f.stepId, f);
  return m;
};

/** Hex of a leaf's named OUTPUT port (port-native leaves publish here). */
const portHex = (
  frames: Map<string, TraceFrame>,
  stepId: string,
  portName: string,
): string | undefined => {
  const bytes = frames.get(stepId)?.portOutputs?.get(portName);
  return bytes === undefined ? undefined : hexFromBytes(bytes);
};

describe("DES (port-native) — final ciphertext", () => {
  for (const vec of FIXTURE.vectors) {
    it(`PT=${vec.pt} K=${vec.key} → CT=${vec.ct}`, () => {
      const trace = runVector(vec);
      expect(bytesShape(trace.finalState)).toBe(true);
      if (!bytesShape(trace.finalState)) return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(vec.ct);
    });
  }
});

describe("DES (port-native) — key schedule produces 16 round keys (FIPS Appendix B)", () => {
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

describe("DES (port-native) — initial-permutation output port matches fixture IP", () => {
  for (const vec of FIXTURE.vectors) {
    it(`PT=${vec.pt}: IP.state == ${vec.ip}`, () => {
      const frames = byId(runVector(vec).frames);
      expect(portHex(frames, "initial-permutation", "state")).toBe(vec.ip);
    });
  }
});

describe("DES (port-native) — per-leaf parity vs fixture, ALL 16 rounds", () => {
  const vec = FIXTURE.vectors[0];
  if (!vec) throw new Error("fixture missing");

  it("split.output0/output1 == L_in/R_in for every round", () => {
    const frames = byId(runVector(vec).frames);
    for (let r = 1; r <= 16; r++) {
      const round = vec.rounds[r - 1];
      if (!round) throw new Error(`fixture missing round ${r}`);
      expect(portHex(frames, `round.${r}.split`, "output0"), `round ${r} L_in`).toBe(round.L_in);
      expect(portHex(frames, `round.${r}.split`, "output1"), `round ${r} R_in`).toBe(round.R_in);
    }
  });

  it("expand-R.state == E for every round", () => {
    const frames = byId(runVector(vec).frames);
    for (let r = 1; r <= 16; r++) {
      const round = vec.rounds[r - 1];
      if (!round) throw new Error(`fixture missing round ${r}`);
      expect(portHex(frames, `round.${r}.expand-R`, "state"), `round ${r} E`).toBe(round.E);
    }
  });

  it("xor-K.state == X (E ⊕ K_i) for every round", () => {
    const frames = byId(runVector(vec).frames);
    for (let r = 1; r <= 16; r++) {
      const round = vec.rounds[r - 1];
      if (!round) throw new Error(`fixture missing round ${r}`);
      expect(portHex(frames, `round.${r}.xor-K`, "state"), `round ${r} X`).toBe(round.X);
    }
  });

  it("s-boxes.state == S for every round", () => {
    const frames = byId(runVector(vec).frames);
    for (let r = 1; r <= 16; r++) {
      const round = vec.rounds[r - 1];
      if (!round) throw new Error(`fixture missing round ${r}`);
      expect(portHex(frames, `round.${r}.s-boxes`, "state"), `round ${r} S`).toBe(round.S);
    }
  });

  it("p-permute.state == P (== F_out) for every round", () => {
    const frames = byId(runVector(vec).frames);
    for (let r = 1; r <= 16; r++) {
      const round = vec.rounds[r - 1];
      if (!round) throw new Error(`fixture missing round ${r}`);
      expect(portHex(frames, `round.${r}.p-permute`, "state"), `round ${r} P`).toBe(round.P);
      expect(round.F_out, `round ${r} F_out==P`).toBe(round.P);
    }
  });

  it("fxor.output == R_out (= L_in ⊕ F) for every round", () => {
    const frames = byId(runVector(vec).frames);
    for (let r = 1; r <= 16; r++) {
      const round = vec.rounds[r - 1];
      if (!round) throw new Error(`fixture missing round ${r}`);
      expect(portHex(frames, `round.${r}.fxor`, "output"), `round ${r} R_out`).toBe(round.R_out);
    }
  });

  it("xor-K records the per-round roundKey aux read", () => {
    const frames = byId(runVector(vec).frames);
    for (let r = 1; r <= 16; r++) {
      const f = frames.get(`round.${r}.xor-K`);
      expect(f, `round.${r}.xor-K frame missing`).toBeDefined();
      expect(
        f?.auxRead?.has(`roundKey.${r - 1}`),
        `round ${r} should record auxRead roundKey.${r - 1}`,
      ).toBe(true);
    }
  });
});

describe("DES (port-native) — the swap IS the concat argument order", () => {
  const vec = FIXTURE.vectors[0];
  if (!vec) throw new Error("fixture missing");

  it("rounds 1..15 recombine == R_in || (L_in⊕F) == L_out || R_out (textbook swap)", () => {
    const frames = byId(runVector(vec).frames);
    for (let r = 1; r <= 15; r++) {
      const round = vec.rounds[r - 1];
      if (!round) throw new Error(`fixture missing round ${r}`);
      expect(portHex(frames, `round.${r}.recombine`, "output"), `round ${r} recombine`).toBe(
        round.L_out + round.R_out,
      );
    }
  });

  it("round 16 recombine == (L_in⊕F) || R_in == preFp (NO swap) — the swap-order trap", () => {
    const frames = byId(runVector(vec).frames);
    expect(portHex(frames, "round.16.recombine", "output")).toBe(vec.preFp);
  });
});
