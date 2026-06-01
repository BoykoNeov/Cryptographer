/**
 * Per-cipher dispatch + correctness pins for the three Speck step types.
 *
 * History: lifted in Slice 1.6 of the universal-port-dataflow plan, then
 * taken **byte-native in Slice B2** (scaffolding-suppression Phase B,
 * 2026-05-30). The two ARX rounds (`speck.round@1`, `speck.round-inverse@1`)
 * are now true `PortedExecutor`s — Uint8Array in/out, no legacy fallback —
 * so every shipped Speck spec requires `portedDispatchEnabled: true`. The
 * **key-schedule went port-native too in Slice 5.2** (2026-05-31,
 * hybrid-ported: `speck.key-schedule@1` dropped its `legacy` fallback but
 * KEEPS `meta`), mirroring `aes.key-expansion@1`; the runtime projects
 * `aux[key] → masterKey` and `key${i} → aux[roundKey.${i}]`, so it still
 * writes the 22 round keys to aux byte-identically.
 *
 * Because there is no longer a legacy single-thread path for the rounds,
 * the old "ported == legacy frame parity" surface is gone (it was vacuous
 * for a genuinely port-native step). The B2 rewrite was validated
 * byte-for-byte against a golden frame stream captured from the lifted
 * implementation before conversion; that golden is pinned permanently in
 * suite (b) below.
 *
 * Four surfaces:
 *
 *   (a) **Beaulieu et al. 2013 Table 4.1 KAT under ported dispatch** for
 *       both byte conventions (BE-paper + LE-NSA), encrypt + decrypt — the
 *       correctness floor.
 *
 *   (b) **Golden frame-stream pin** — the full per-frame `stateAfter` stream
 *       for all four specs, byte-equal to the pre-B2 lifted implementation.
 *       A frame-level regression (a wrong intermediate round, a dropped
 *       frame) shows here even when the final KAT still happens to match.
 *
 *   (c) **Round-key port ordering** — the key-schedule (port-native since
 *       Slice 5.2) emits its 22 round keys in `roundKey.0 … roundKey.21`
 *       insertion order, projected from `key0 … key21` via meta.
 *
 *   (d) **Isolated native round** — a minimal schedule + one round spec,
 *       pinning the port-native round in isolation from the 22-round algebra.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import { framePrimaryOutBytes } from "@/core/frame-state";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import { INPUT_SOURCE_ID } from "@/core/types";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Beaulieu et al. 2013, Table 4.1 — Speck32/64 KATs ─────────────────

const BE_KEY = "1918111009080100";
const BE_PLAINTEXT = "6574694c";
const BE_CIPHERTEXT = "a86842f2";

const LE_KEY = "0001080910111819";
const LE_PLAINTEXT = "4c697465";
const LE_CIPHERTEXT = "f24268a8";

// ─── Frame-stream helper ───────────────────────────────────────────────

/** Run a Speck spec under ported dispatch and render the per-ROUND `"state"`
 *  output port as a `stepId=hex|…` stream for golden comparison.
 *
 *  K2a (2026-06-01): the key schedule decomposed from one monolithic frame
 *  into ~130 port-native primitive frames, so the original "1 schedule frame +
 *  22 round frames" stream is no longer well-defined for the schedule
 *  portion. The schedule's byte-equality is pinned separately by the K2a
 *  decomposition parity test — here we restrict the golden to the round
 *  frames, which carry the cipher's round-by-round algebra that's the
 *  load-bearing pedagogy regression check. */
const roundFrameStream = (spec: CipherSpec, stateHex: string, keyHex: string): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(stateHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
  });
  return trace.frames
    .filter((f) => f.stepType === "speck.round@1" || f.stepType === "speck.round-inverse@1")
    .map((f) => {
      const out = framePrimaryOutBytes(f);
      return `${f.stepId}=${out ? hexFromBytes(out) : "(no-state)"}`;
    })
    .join("|");
};

// ─── Suites ─────────────────────────────────────────────────────────────

describe("runtime — ported dispatch, byte-native Speck (Slice B2)", () => {
  // ─── (a) KAT sanity floor under flag-on ──────────────────────────────

  describe("(a) Beaulieu et al. 2013 KATs under portedDispatchEnabled: true", () => {
    it("BE-paper encrypt — published ciphertext under ported", () => {
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(BE_CIPHERTEXT);
    });

    it("LE-NSA encrypt — published ciphertext under ported", () => {
      const trace = runSpec(speck32_64LeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(LE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(LE_KEY)]]),
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(LE_CIPHERTEXT);
    });

    it("BE-paper decrypt — recovers the plaintext under ported", () => {
      const trace = runSpec(speck32_64BeDecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_CIPHERTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(BE_PLAINTEXT);
    });

    it("LE-NSA decrypt — recovers the plaintext under ported", () => {
      const trace = runSpec(speck32_64LeDecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(LE_CIPHERTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(LE_KEY)]]),
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(LE_PLAINTEXT);
    });
  });

  // ─── (b) Golden round-frame stream (byte-equal to the pre-B2 lifted impl) ─

  describe("(b) per-round stateAfter stream matches the lifted golden", () => {
    // Captured from the lifted (pre-B2) Speck and confirmed byte-identical
    // through B2's port-native round rewrite. K2a (2026-06-01) decomposed the
    // schedule into ~130 port-native frames, so the original "1 schedule
    // frame at index 0" entry in the stream went away — but the 22 ROUND
    // frames stay byte-equal because the published round-key aux entries
    // are byte-equal (separately pinned by the K2a decomposition parity
    // test). The encrypt/decrypt symmetry holds: round-inverse.k recovers
    // round.(22-k).
    const GOLDEN: ReadonlyArray<{
      label: string;
      spec: CipherSpec;
      stateHex: string;
      keyHex: string;
      stream: string;
    }> = [
      {
        label: "BE-paper encrypt",
        spec: speck32_64BeSpec,
        stateHex: BE_PLAINTEXT,
        keyHex: BE_KEY,
        stream:
          "round.1=5316f627|round.2=37dfef40|round.3=ccd271d1|round.4=0332c477|round.5=416450bb|round.6=6edf2c32|round.7=e786574e|round.8=a9c6f4ff|round.9=6db8be47|round.10=6111980f|round.11=cc25ac1b|round.12=aec51eab|round.13=44833e2f|round.14=9fbc6700|round.15=a6283a29|round.16=780b90af|round.17=202b6295|round.18=361fbc4a|round.19=172de607|round.20=7a67e278|round.21=3345baa6|round.22=a86842f2",
      },
      {
        label: "BE-paper decrypt",
        spec: speck32_64BeDecryptSpec,
        stateHex: BE_CIPHERTEXT,
        keyHex: BE_KEY,
        stream:
          "round-inverse.1=3345baa6|round-inverse.2=7a67e278|round-inverse.3=172de607|round-inverse.4=361fbc4a|round-inverse.5=202b6295|round-inverse.6=780b90af|round-inverse.7=a6283a29|round-inverse.8=9fbc6700|round-inverse.9=44833e2f|round-inverse.10=aec51eab|round-inverse.11=cc25ac1b|round-inverse.12=6111980f|round-inverse.13=6db8be47|round-inverse.14=a9c6f4ff|round-inverse.15=e786574e|round-inverse.16=6edf2c32|round-inverse.17=416450bb|round-inverse.18=0332c477|round-inverse.19=ccd271d1|round-inverse.20=37dfef40|round-inverse.21=5316f627|round-inverse.22=6574694c",
      },
      {
        label: "LE-NSA encrypt",
        spec: speck32_64LeSpec,
        stateHex: LE_PLAINTEXT,
        keyHex: LE_KEY,
        stream:
          "round.1=27f61653|round.2=40efdf37|round.3=d171d2cc|round.4=77c43203|round.5=bb506441|round.6=322cdf6e|round.7=4e5786e7|round.8=fff4c6a9|round.9=47beb86d|round.10=0f981161|round.11=1bac25cc|round.12=ab1ec5ae|round.13=2f3e8344|round.14=0067bc9f|round.15=293a28a6|round.16=af900b78|round.17=95622b20|round.18=4abc1f36|round.19=07e62d17|round.20=78e2677a|round.21=a6ba4533|round.22=f24268a8",
      },
      {
        label: "LE-NSA decrypt",
        spec: speck32_64LeDecryptSpec,
        stateHex: LE_CIPHERTEXT,
        keyHex: LE_KEY,
        stream:
          "round-inverse.1=a6ba4533|round-inverse.2=78e2677a|round-inverse.3=07e62d17|round-inverse.4=4abc1f36|round-inverse.5=95622b20|round-inverse.6=af900b78|round-inverse.7=293a28a6|round-inverse.8=0067bc9f|round-inverse.9=2f3e8344|round-inverse.10=ab1ec5ae|round-inverse.11=1bac25cc|round-inverse.12=0f981161|round-inverse.13=47beb86d|round-inverse.14=fff4c6a9|round-inverse.15=4e5786e7|round-inverse.16=322cdf6e|round-inverse.17=bb506441|round-inverse.18=77c43203|round-inverse.19=d171d2cc|round-inverse.20=40efdf37|round-inverse.21=27f61653|round-inverse.22=4c697465",
      },
    ];

    for (const g of GOLDEN) {
      it(`${g.label} — 22 round frames byte-equal to golden`, () => {
        const stream = roundFrameStream(g.spec, g.stateHex, g.keyHex);
        expect(stream.split("|").length).toBe(22);
        expect(stream).toBe(g.stream);
      });
    }
  });

  // ─── (c) Round-key publish insertion order ───────────────────────────

  describe("(c) speck.publish-round-keys@1 emits 22 round keys in insertion order", () => {
    it("the publish tail's auxWritten preserves roundKey.0 → roundKey.21 ordering under ported", () => {
      // K2a (2026-06-01): the round-key fan-out moved from the monolithic
      // `speck.key-schedule@1` frame (which used to be frame 0) to the
      // decomposed schedule's `key-schedule.publish` tail leaf. Same aux
      // bindings, same insertion order, just emitted by a different leaf —
      // and surrounded by ~130 sibling schedule frames that didn't exist
      // pre-K2a.
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
      });

      const publishFrame = trace.frames.find((f) => f.stepId === "key-schedule.publish");
      if (!publishFrame) throw new Error("expected key-schedule.publish frame");
      expect(publishFrame.stepType).toBe("speck.publish-round-keys@1");

      const keys = [...publishFrame.auxWritten.keys()];
      expect(keys.length).toBe(22);
      const expected: string[] = [];
      for (let i = 0; i < 22; i++) expected.push(`roundKey.${i}`);
      expect(keys).toEqual(expected);

      // Cross-check: each round-key value is the expected 2-byte
      // Uint8Array (Speck32/64 wordBits=16). Pins that the decomposed
      // schedule didn't accidentally widen a single Speck round key.
      for (const k of keys) {
        const v = publishFrame.auxWritten.get(k);
        expect(v).toBeInstanceOf(Uint8Array);
        expect((v as Uint8Array).length).toBe(2);
      }
    });
  });

  // ─── (d) Isolated native round ───────────────────────────────────────

  describe("(d) per-primitive synthetic — key-schedule + one native round", () => {
    // Two-step spec: the (port-native) schedule expands the master key, then a
    // single port-native round consumes roundKey.0. Pins the native round
    // in isolation — the cipher-level KAT (a) and full frame stream (b)
    // layer 21 more rounds on top.
    const spec: CipherSpec = {
      id: "test-speck-one-round@1",
      name: "Slice B2 — speck schedule + one native round synthetic",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 8 } },
      steps: [
        {
          kind: "step",
          id: "schedule",
          type: "speck.key-schedule@1",
          params: {
            keyAuxName: "key",
            outputPrefix: "roundKey",
            rounds: 22,
            wordBits: 16,
            m: 4,
            alpha: 7,
            beta: 2,
            byteOrder: "be-paper",
          },
        },
        {
          kind: "step",
          id: "round.0",
          type: "speck.round@1",
          params: {
            roundKeyAux: "roundKey.0",
            alpha: 7,
            beta: 2,
            wordBits: 16,
            byteOrder: "be-paper",
          },
        },
      ],
    };

    it("runs under ported dispatch and applies one ARX round to the plaintext", () => {
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
      });
      // schedule frame + one round frame.
      expect(trace.frames.length).toBe(2);
      const roundFrame = trace.frames[1];
      if (!roundFrame) throw new Error("expected round frame at index 1");
      expect(roundFrame.stepId).toBe("round.0");
      expect(roundFrame.stepType).toBe("speck.round@1");
      // round.0 here consumes roundKey.0 — identical math to round.1 of the
      // full BE-paper encrypt, whose golden `"state"` output is 0x5316f627.
      const roundOut = framePrimaryOutBytes(roundFrame);
      expect(roundOut).not.toBeNull();
      expect(hexFromBytes(roundOut ?? new Uint8Array())).toBe("5316f627");
      // The aux read of roundKey.0 is recorded on the native round's frame.
      expect([...roundFrame.auxRead.keys()]).toContain("roundKey.0");
    });
  });

  // ─── (e) Slice 5.3b — explicit state-spine wiring on the SHIPPED spec ───
  describe("(e) port-wired `state` spine preserves the roundKey aux reads", () => {
    // The (d) synthetic spec wires no `portInputs`; the shipped spec does
    // (Slice 5.3b: round.1 ← `$input`, round.N ← round.{N-1}.state). This
    // pins that declaring `portInputs.state` did NOT disturb the `roundKey`
    // aux projection — `state` flows from the port, `roundKey` still flows
    // from `aux[roundKeyAux]` via Step C — so the graph's key-schedule→round
    // fan-out edges (built from `frame.auxRead`) survive.
    it("round frames keep `roundKey.{i-1}` in auxRead while `state` is port-wired", () => {
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
      });
      // Every round.i (1..22) reads roundKey.{i-1} from aux, byte-for-byte
      // as before the port-wiring.
      for (let i = 1; i <= 22; i++) {
        const f = trace.frames.find((fr) => fr.stepId === `round.${i}`);
        if (!f) throw new Error(`missing frame round.${i}`);
        expect([...f.auxRead.keys()]).toContain(`roundKey.${i - 1}`);
      }
    });

    it("the captured frame ports carry `state` + `roundKey`; round.1's `state` is `$input`", () => {
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(BE_PLAINTEXT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(BE_KEY)]]),
      });
      const r2 = trace.frames.find((f) => f.stepId === "round.2");
      if (!r2) throw new Error("missing frame round.2");
      // Hybrid-ported leaf (legacy === undefined) → ports captured. `state`
      // arrives via the declared portInputs; `roundKey` via the meta aux
      // projection — both surface on the frame's portInputs.
      expect(r2.portInputs).toBeDefined();
      expect([...(r2.portInputs?.keys() ?? [])].sort()).toEqual(["roundKey", "state"]);

      // The spec head: round.1 declares its `state` source as `$input`.
      const round1 = speck32_64BeSpec.steps.find((s) => s.id === "round.1");
      if (!round1 || round1.kind !== "step") throw new Error("missing round.1 leaf");
      expect(round1.portInputs?.state).toEqual({ node: INPUT_SOURCE_ID, port: "out" });
    });
  });
});
