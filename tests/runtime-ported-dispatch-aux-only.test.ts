/**
 * Slice 1.2 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`), updated for Slice 5.2.
 *
 * The three byte-typed aux-only step types went **port-native in Slice 5.2**
 * (2026-05-31): they dropped their `legacy:` lift for true `PortedExecutor`s
 * (the fourth, the matrix `generic.iv-load@1`, retired in Slice 5.1 with the
 * MatrixState shape):
 *
 *   - `generic.aux-load@1`  — pure source (no state, no aux read).
 *   - `generic.aux-copy@1`  — aux read + aux write, Uint8Array shape.
 *   - `generic.aux-xor@1`   — two aux reads + one aux write; the
 *                              load-bearing case for the Map-iteration-
 *                              order invariant called out in
 *                              `ProjectionMetadata`'s contract comment.
 *
 * Because they no longer carry a legacy executor, a flag-OFF run throws
 * "requires portedDispatchEnabled" — there is no legacy frame stream left to
 * compare against. The original flag-off-vs-flag-on frame parity was therefore
 * reduced to flag-ON assertions (the same reduction B2/B3/B4 applied to the
 * cipher dispatch tests). The byte-level executor behavior is pinned
 * independently by `tests/aux-primitives.test.ts`.
 *
 * Two surviving surfaces (all flag-ON):
 *
 *   (a) **Synthetic CBC-head spec** — load an IV literal, copy it into the
 *       chain accumulator, XOR a per-block value in; assert the chain bytes
 *       equal IV ⊕ plaintext end-to-end.
 *
 *   (c) **Targeted invariant pins** for the two hazards the advisor flagged
 *       before Slice 1.2 work began, now asserted on the ported path alone:
 *         - Map iteration order: `auxXor`'s meta returns the binding in
 *           `[from, into]` order, so a fresh-drop frame's `auxReadMissing`
 *           array is `["", ""]` (order matters — it's an ARRAY).
 *         - Empty-name/target sentinel: an unset `auxName` (aux-load) or `to`
 *           (aux-copy) yields an EMPTY meta write binding, so the runtime
 *           never does `aux.set("", ...)` — no auxWrites, no "" key pollution.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── (a) Synthetic CBC-head spec ────────────────────────────────────────

/**
 * Hand-built spec exercising all three port-native aux step types. The data
 * flow is the head of a CBC composition: load an IV literal, copy it into the
 * chain accumulator, XOR a per-block value into it. State is passthrough
 * throughout (no state ports — each step's `shapeContract` is
 * `{ input: "any", output: "preserveInput" }`).
 */
const auxOnlySpec: CipherSpec = {
  id: "test-aux-only@1",
  name: "Slice 1.2 aux-only smoke",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "step",
      id: "load-iv",
      type: "generic.aux-load@1",
      params: {
        auxName: "iv-literal",
        // 16 bytes — matches AES block size.
        value: [
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
          0x0f,
        ],
      },
    },
    {
      kind: "step",
      id: "copy-iv-to-chain",
      type: "generic.aux-copy@1",
      params: { from: "iv-literal", to: "chain-bytes" },
    },
    {
      kind: "step",
      id: "xor-plaintext-into-chain",
      type: "generic.aux-xor@1",
      params: { from: "plaintext-block", into: "chain-bytes" },
    },
  ],
};

const auxOnlyInitialState = () => makeBytesState(new Uint8Array(0));
const auxOnlyInitialAux = (): Map<string, AuxValue> =>
  new Map<string, AuxValue>([
    [
      // A 16-byte "plaintext block" that the aux-xor mixes into the chain.
      "plaintext-block",
      new Uint8Array([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
      ]),
    ],
  ]);

describe("runtime — ported dispatch, aux-only primitives (port-native since Slice 5.2)", () => {
  describe("(a) synthetic CBC-head spec under ported dispatch", () => {
    it("end-to-end aux state matches: chain-bytes is iv XOR plaintext", () => {
      const ported = runSpec(auxOnlySpec, buildDefaultRegistry(), {
        initialState: auxOnlyInitialState(),
        initialAux: auxOnlyInitialAux(),
        portedDispatchEnabled: true,
      });

      // Expected XOR: IV (00..0f) ⊕ plaintext (6b..2a)
      const expectedChain = new Uint8Array([
        0x6b ^ 0x00,
        0xc1 ^ 0x01,
        0xbe ^ 0x02,
        0xe2 ^ 0x03,
        0x2e ^ 0x04,
        0x40 ^ 0x05,
        0x9f ^ 0x06,
        0x96 ^ 0x07,
        0xe9 ^ 0x08,
        0x3d ^ 0x09,
        0x7e ^ 0x0a,
        0x11 ^ 0x0b,
        0x73 ^ 0x0c,
        0x93 ^ 0x0d,
        0x17 ^ 0x0e,
        0x2a ^ 0x0f,
      ]);
      const chainBytes = ported.finalAux.get("chain-bytes");
      expect(chainBytes).toBeInstanceOf(Uint8Array);
      expect(Array.from(chainBytes as Uint8Array)).toEqual(Array.from(expectedChain));
    });
  });

  // ─── (c) Targeted invariants for the two pre-Slice-1.2 hazards ──────────

  describe("(c) hazard pins (flag-on)", () => {
    it("a fresh-drop aux-xor frame has auxReadMissing ['', ''] in [from, into] order", () => {
      // params has neither `from` nor `into`, so meta.auxReadPorts returns
      // [["from", ""], ["into", ""]] and both miss → auxReadMissing ["", ""].
      // A Map-iteration drift in `auxXorMeta.auxReadPorts` would surface here
      // even though Vitest's Map .toEqual is order-insensitive (the field is
      // an ARRAY).
      const spec: CipherSpec = {
        id: "test-aux-xor-unset@1",
        name: "Aux-xor unset params",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "xor-unwired",
            type: "generic.aux-xor@1",
            params: {}, // no from, no into — fresh palette drop
          },
        ],
      };

      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
        portedDispatchEnabled: true,
      });

      expect(ported.frames.length).toBe(1);
      const frame = ported.frames[0];
      if (!frame) throw new Error("frame missing");
      expect(frame.auxReadMissing).toEqual(["", ""]);
    });

    it("aux-load with empty auxName produces NO auxWrites and no '' aux key", () => {
      // Fresh palette drop: `auxName === ""`. meta.auxWritePorts({auxName:""})
      // returns an empty map; the runtime's auxWritten stays empty. If the
      // meta bound an empty-string aux key, the runtime would aux.set("", ...)
      // and the live aux map would gain a "" key.
      const spec: CipherSpec = {
        id: "test-aux-load-unset@1",
        name: "Aux-load unset params",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "load-unwired",
            type: "generic.aux-load@1",
            params: {}, // no auxName
          },
        ],
      };

      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
        portedDispatchEnabled: true,
      });

      const frame = ported.frames[0];
      if (!frame) throw new Error("frame missing");
      expect(frame.auxWritten.size).toBe(0);
      expect(ported.finalAux.has("")).toBe(false);
    });

    it("aux-copy with empty target produces NO auxWrites and doesn't pollute aux", () => {
      // Seed a value the copy reads (so the read side succeeds), then copy it
      // to an empty target. meta.auxWritePorts gates on `to === ""` → empty
      // binding → no auxWrites, no "" key.
      const spec: CipherSpec = {
        id: "test-copy-unset@1",
        name: "Aux-copy unset writer",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "seed",
            type: "generic.aux-load@1",
            params: { auxName: "seed", value: [0xaa, 0xbb, 0xcc, 0xdd] },
          },
          {
            kind: "step",
            id: "copy-unset-target",
            type: "generic.aux-copy@1",
            params: { from: "seed", to: "" }, // empty target
          },
        ],
      };

      const ported = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(new Uint8Array(0)),
        portedDispatchEnabled: true,
      });

      // The copy frame (index 1) writes nothing because its target is unset.
      const copyFrame = ported.frames[1];
      if (!copyFrame) throw new Error("copy frame missing");
      expect(copyFrame.auxWritten.size).toBe(0);
      expect(ported.finalAux.has("")).toBe(false);
    });
  });
});
