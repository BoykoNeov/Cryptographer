/**
 * Per-cipher dispatch + correctness pins for the six Serpent step types.
 *
 * History: lifted in Slice 1.7 of the universal-port-dataflow plan, then
 * the five round-body executors taken **byte-native in Slice B3**
 * (scaffolding-suppression Phase B, 2026-05-30). `serpent.bit-permutation@1`,
 * `serpent.sub-bytes@1`, `serpent.linear-transform@1`,
 * `serpent.inv-linear-transform@1`, and `serpent.add-round-key@1` are now
 * true `PortedExecutor`s — Uint8Array in/out, no legacy fallback — so every
 * shipped Serpent spec requires `portedDispatchEnabled: true`. The
 * **key-schedule stays lifted** (`serpent.key-expansion@1` keeps its `legacy`
 * fallback), mirroring B1/B2's decision to leave `aes.key-expansion@1` /
 * `speck.key-schedule@1` lifted; under ported dispatch it runs its lift
 * adapter and writes the 33 round keys to aux unchanged.
 *
 * Because there is no longer a legacy single-thread path for the round body,
 * the old "ported == legacy frame parity" surface is gone (it was vacuous for
 * a genuinely port-native step). The B3 rewrite was validated against a
 * **golden frame-stream checksum** captured from the lifted implementation
 * before conversion — and that capture cross-checked flag-off (true legacy)
 * == flag-on (lift adapter) so the digest is proven dispatch-independent on
 * lifted code. The native rewrite reproduces it byte-for-byte; the digests
 * are pinned permanently in suite (b) below.
 *
 * Four surfaces (mirror the Slice B2 byte-native Speck test structure):
 *
 *   (a) **Reference KATs under flag-on** for all three Serpent variants
 *       (encrypt + decrypt) — the correctness floor.
 *
 *   (b) **Golden frame-stream checksum** — a per-spec SHA-256 over the ordered
 *       `(stepId, hex(stateAfter), sorted(auxRead))` of every frame, for all 6
 *       specs. Folding `auxRead` into the hash makes the parity net itself
 *       guard the highest-risk change in the B3 conversion: that
 *       `serpent.add-round-key@1`'s `roundKey.N` aux read is still recorded on
 *       the frame from `meta.auxReadPorts` after the executor dropped its
 *       manual `auxReads` return. A frame-structure regression (wrong
 *       intermediate, dropped/relabelled frame, lost aux read) shows here even
 *       when the final KAT still matches. The frame-count prefix surfaces a
 *       count change immediately.
 *
 *   (c) **Round-key port ordering** — the still-lifted key-schedule emits its
 *       33 round keys in `roundKey.0 … roundKey.32` insertion order.
 *
 *   (d) **Isolated native AddRoundKey** — a minimal schedule + one
 *       AddRoundKey spec, pinning the port-native AddRoundKey (and its
 *       meta-driven aux read) in isolation from the 32-round algebra.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Serpent reference KATs (pyserpent.py / Anderson-Biham-Knudsen reference) ─

const KEY_128 = "80000000000000000000000000000000";
const KEY_192 = "800000000000000000000000000000000000000000000000";
const KEY_256 = "8000000000000000000000000000000000000000000000000000000000000000";
const PLAINTEXT_ZERO = "00000000000000000000000000000000";
const CIPHERTEXT_128 = "264e5481eff42a4606abda06c0bfda3d";
const CIPHERTEXT_192 = "9e274ead9b737bb21efcfca548602689";
const CIPHERTEXT_256 = "a223aa1288463c0e2be38ebd825616c0";

// ─── Frame-stream checksum helper ──────────────────────────────────────────

const auxValueToString = (v: AuxValue): string => {
  if (v instanceof Uint8Array) return hexFromBytes(v);
  if (typeof v === "number" || typeof v === "bigint") return String(v);
  // State / readonly State[] — not present in any Serpent auxRead (round keys
  // are Uint8Array), but keep the function total.
  return JSON.stringify(v);
};

/** Run a Serpent spec under ported dispatch and reduce its frame stream to a
 *  `${count}:${sha256}` digest over each frame's
 *  `(stepId, hex(stateAfter), sorted(auxRead))`. */
const frameDigest = (spec: CipherSpec, stateHex: string, keyHex: string): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(stateHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
    portedDispatchEnabled: true,
  });
  const h = createHash("sha256");
  for (const f of trace.frames) {
    const after =
      f.stateAfter.shape === "bytes" ? hexFromBytes(f.stateAfter.bytes) : `?${f.stateAfter.shape}`;
    const aux = [...f.auxRead.entries()]
      .map(([k, v]) => `${k}=${auxValueToString(v)}`)
      .sort()
      .join(",");
    h.update(`${f.stepId} ${after} ${aux}\n`);
  }
  return `${trace.frames.length}:${h.digest("hex")}`;
};

// ─── Suites ─────────────────────────────────────────────────────────────

describe("runtime — ported dispatch, byte-native Serpent (Slice B3)", () => {
  // ─── (a) KAT sanity floor under flag-on ──────────────────────────────

  describe("(a) Reference KATs under portedDispatchEnabled: true", () => {
    it("Serpent-128 encrypt — published ciphertext under ported", () => {
      const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_128);
    });

    it("Serpent-192 encrypt — published ciphertext under ported", () => {
      const trace = runSpec(serpent192Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_192)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_192);
    });

    it("Serpent-256 encrypt — published ciphertext under ported", () => {
      const trace = runSpec(serpent256Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_256)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_256);
    });

    it("Serpent-128 decrypt — recovers plaintext under ported", () => {
      const trace = runSpec(serpent128DecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(CIPHERTEXT_128)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_ZERO);
    });

    it("Serpent-192 decrypt — recovers plaintext under ported", () => {
      const trace = runSpec(serpent192DecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(CIPHERTEXT_192)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_192)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_ZERO);
    });

    it("Serpent-256 decrypt — recovers plaintext under ported", () => {
      const trace = runSpec(serpent256DecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(CIPHERTEXT_256)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_256)]]),
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_ZERO);
    });
  });

  // ─── (b) Golden frame-stream checksum (byte-equal to the pre-B3 lifted impl) ─

  describe("(b) per-spec frame-stream checksum matches the lifted golden", () => {
    // Captured from the lifted (pre-B3) Serpent and confirmed byte-identical
    // to the native rewrite. 99 frames each: 1 key-expansion + IP + 32 rounds
    // (rounds 0..30 = AddRoundKey + SubBytes + LT = 96 frames; round 31 =
    // AddRoundKey + SubBytes + AddRoundKey) + FP. The capture cross-checked
    // that lifted flag-off == flag-on, so the digest is proven
    // dispatch-independent on lifted code — the native impl must reproduce it.
    const GOLDEN: ReadonlyArray<{
      label: string;
      spec: CipherSpec;
      stateHex: string;
      keyHex: string;
      digest: string;
    }> = [
      {
        label: "Serpent-128 encrypt",
        spec: serpent128Spec,
        stateHex: PLAINTEXT_ZERO,
        keyHex: KEY_128,
        digest: "99:824f3e1258fabbcb15784297dff9250d221a7421769396739f2bf9d167e03519",
      },
      {
        label: "Serpent-128 decrypt",
        spec: serpent128DecryptSpec,
        stateHex: CIPHERTEXT_128,
        keyHex: KEY_128,
        digest: "99:5a027a702bc03c18090a83cc638ebf9e95d4866a265bb29ce59dd39d7904cced",
      },
      {
        label: "Serpent-192 encrypt",
        spec: serpent192Spec,
        stateHex: PLAINTEXT_ZERO,
        keyHex: KEY_192,
        digest: "99:d8e7420f7c8296088f46fd622d50fe64de5678f00680456942bdee834dac8285",
      },
      {
        label: "Serpent-192 decrypt",
        spec: serpent192DecryptSpec,
        stateHex: CIPHERTEXT_192,
        keyHex: KEY_192,
        digest: "99:77c9244fec54b1be946775aeb3a797f55c0b426732f0eba1c9c5e172388442d3",
      },
      {
        label: "Serpent-256 encrypt",
        spec: serpent256Spec,
        stateHex: PLAINTEXT_ZERO,
        keyHex: KEY_256,
        digest: "99:1c8d557ec6201e2343ccb0619dfc358d5b7515be20ef5a9307de856a823c451f",
      },
      {
        label: "Serpent-256 decrypt",
        spec: serpent256DecryptSpec,
        stateHex: CIPHERTEXT_256,
        keyHex: KEY_256,
        digest: "99:c48a1074226d679aeecbda73aa84dd4cd7526478c306736ef91cec273c391132",
      },
    ];

    for (const g of GOLDEN) {
      it(`${g.label} — 99-frame stream digest byte-equal to golden`, () => {
        expect(frameDigest(g.spec, g.stateHex, g.keyHex)).toBe(g.digest);
      });
    }
  });

  // ─── (c) Round-key port insertion order ──────────────────────────────

  describe("(c) serpent.key-expansion@1 emits 33 round keys in insertion order", () => {
    it("aux Map iteration preserves roundKey.0 → roundKey.32 ordering under ported", () => {
      const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
        portedDispatchEnabled: true,
      });

      // Find the key-expansion frame (typically frame 0 — the schedule runs
      // once at the start of every Serpent spec). Locating by stepType keeps
      // the test robust to any future leading aux-load additions.
      const ksFrame = trace.frames.find((f) => f.stepType === "serpent.key-expansion@1");
      if (!ksFrame) throw new Error("expected one serpent.key-expansion@1 frame");

      const keys = [...ksFrame.auxWritten.keys()];
      expect(keys.length).toBe(33);
      const expected: string[] = [];
      for (let i = 0; i < 33; i++) expected.push(`roundKey.${i}`);
      expect(keys).toEqual(expected);

      // Cross-check: each round-key value is a 16-byte Uint8Array (Serpent
      // round keys are always 128 bits). Pins that the still-lifted
      // key-schedule didn't accidentally widen a round key into a MatrixState
      // or other variant under ported dispatch.
      for (const k of keys) {
        const v = ksFrame.auxWritten.get(k);
        expect(v).toBeInstanceOf(Uint8Array);
        expect((v as Uint8Array).length).toBe(16);
      }
    });
  });

  // ─── (d) Isolated native AddRoundKey ─────────────────────────────────

  describe("(d) per-primitive synthetic — key-expansion + one native AddRoundKey", () => {
    // Two-step spec: the lifted schedule expands the master key, then a single
    // port-native AddRoundKey consumes roundKey.0 against the all-zero
    // plaintext. Pins the native AddRoundKey in isolation — the cipher-level
    // KAT (a) and full frame digest (b) layer 31 more rounds + IP/FP/LT/SubBytes
    // on top; this fixture is the smallest one that exercises both the lifted
    // schedule and the native AddRoundKey end-to-end.
    const spec: CipherSpec = {
      id: "test-serpent-add-round-key@1",
      name: "Slice B3 — serpent schedule + one native AddRoundKey synthetic",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 16 } },
      steps: [
        {
          kind: "step",
          id: "schedule",
          type: "serpent.key-expansion@1",
          params: {
            keyAuxName: "key",
            outputPrefix: "roundKey",
            keyByteLength: 16,
          },
        },
        {
          kind: "step",
          id: "round.0.add-round-key",
          type: "serpent.add-round-key@1",
          params: { roundKeyAux: "roundKey.0" },
        },
      ],
    };

    it("native AddRoundKey reads roundKey.0 from aux via meta and XORs it into the state", () => {
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PLAINTEXT_ZERO)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_128)]]),
        portedDispatchEnabled: true,
      });

      // schedule frame + one AddRoundKey frame.
      expect(trace.frames.length).toBe(2);
      const ksFrame = trace.frames[0];
      const arkFrame = trace.frames[1];
      if (!ksFrame || !arkFrame) throw new Error("expected schedule + AddRoundKey frames");
      expect(arkFrame.stepId).toBe("round.0.add-round-key");
      expect(arkFrame.stepType).toBe("serpent.add-round-key@1");

      // THE highest-value B3 check: the roundKey.0 aux read is still recorded
      // on the native frame — sourced from `meta.auxReadPorts`, NOT from a
      // manual `auxReads` return (the conversion dropped that + the ctx.aux
      // access). This is what preserves the key-expansion → AddRoundKey
      // fan-out edge in the graph.
      expect([...arkFrame.auxRead.keys()]).toContain("roundKey.0");

      // All-zero plaintext ⇒ AddRoundKey output == roundKey.0 byte-for-byte.
      const rk0 = ksFrame.auxWritten.get("roundKey.0");
      expect(rk0).toBeInstanceOf(Uint8Array);
      expect(arkFrame.stateAfter.shape).toBe("bytes");
      if (arkFrame.stateAfter.shape !== "bytes") return;
      expect(Array.from(arkFrame.stateAfter.bytes)).toEqual(Array.from(rk0 as Uint8Array));
    });
  });
});
