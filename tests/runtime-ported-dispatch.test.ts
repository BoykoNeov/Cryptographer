/**
 * Phase-0 task 6 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-dataflow.md`).
 *
 * Two assertions, both load-bearing:
 *
 *   (a) **KAT parity** — under `portedDispatchEnabled: true`, AES-128 (FIPS-197
 *       Appendix C.1) and AES-128 ECB (NIST SP 800-38A §F.1.1, 4-block) produce
 *       the published ciphertext byte-for-byte. This validates that the
 *       ported execution path (input-build → lift adapter → output-reconstruct,
 *       running once per matching leaf) preserves the cipher's algebra.
 *
 *   (b) **Frame-by-frame parity vs legacy** — for the same two cipher specs
 *       and inputs, every emitted TraceFrame is byte-equal between
 *       `portedDispatchEnabled: true` and `portedDispatchEnabled: false`.
 *       This is the inexpensive lever that earns most of the 8 non-Q-gate-9
 *       gate items: linear view, MatrixView highlights, narration, provenance
 *       overlay, mirror buttons, and graph derivation all read TraceFrame; if
 *       the frames are byte-equal, every layer above the runtime works
 *       without change.
 *
 * Phase-0 originally lifted only `generic.byte-substitution@1` +
 * `generic.add-round-key@1` via the side-map (`PROJECTION_METADATA` in
 * `core/port-projection.ts`). Slice 1.4 (2026-05-23) MOVED both step
 * types — plus `aes.key-expansion@1`, `generic.shift-rows@1`, and
 * `generic.mix-columns@1` — to `kind: "ported"` registrations with
 * colocated metadata, so the AES forward path now runs ENTIRELY through
 * the ported path under `portedDispatchEnabled: true`; only the ECB
 * boundary primitives (split-blocks / concat-blocks / compute-block-
 * count / load-block / store-block) remain on the legacy path inside
 * the ECB spec. Slice 1.9 (2026-05-24) DELETED the side-map outright —
 * the previously-pinned side-map keys are gone; the test that asserted
 * its scope was removed in the same commit.
 *
 * The iterate-runtime's `aux[outBlocksAux]` publication is verified here at
 * integration boundary (the 4-block ECB ciphertext bytes match SP 800-38A
 * §F.1.1) — NOT at frame round-trip. Q-gate-9 cannot test outBlocksAux
 * because the runtime writes it as a side-effect, not via leaf `auxWritten`.
 * Findings doc (task 7) calls this out in its own subsection.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, State, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── KAT fixtures ───────────────────────────────────────────────────────

// FIPS-197 Appendix C.1.
const FIPS_PLAINTEXT = "00112233445566778899aabbccddeeff";
const FIPS_KEY = "000102030405060708090a0b0c0d0e0f";
const FIPS_CIPHERTEXT = "69c4e0d86a7b0430d8cdb78070b4c55a";

// NIST SP 800-38A §F.1.1 — ECB-AES128.Encrypt, 4 blocks (no padding).
const ECB_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const ECB_PLAINTEXT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";
const ECB_CIPHERTEXT_4_BLOCKS =
  "3ad77bb40d7a3660a89ecaf32466ef97" +
  "f5d3d58503b9699de785895a96fdbaaf" +
  "43b1cd7f598ece23881b00e3ed030688" +
  "7b0c785e27e8ad3f8223207104725dd4";

// ─── Frame-parity helpers ───────────────────────────────────────────────

const expectStatesEqual = (a: State, b: State, label: string): void => {
  expect(a.shape, `${label}: shape`).toBe(b.shape);
  switch (a.shape) {
    case "bytes":
    case "matrix4x4-bytes": {
      if (b.shape !== a.shape) return;
      expect(Array.from(a.bytes), `${label}: bytes`).toEqual(Array.from(b.bytes));
      return;
    }
    case "bitvec":
      // Not exercised by the AES-128 + AES-128 ECB specs.
      throw new Error(`${label}: bitvec not expected in AES parity test`);
    case "bigint":
      throw new Error(`${label}: bigint not expected in AES parity test`);
  }
};

const expectAuxMapsEqual = (
  a: ReadonlyMap<string, AuxValue>,
  b: ReadonlyMap<string, AuxValue>,
  label: string,
): void => {
  expect([...a.keys()].sort(), `${label}: keys`).toEqual([...b.keys()].sort());
  // Vitest's `toEqual` handles `Map` + nested `Uint8Array`/`State[]`/`number`
  // recursively, which covers all of `AuxValue`'s variants. The boundary
  // primitives (`split-blocks` → `input-blocks: State[]`, `compute-block-
  // count` → `block-count: number`) write non-Uint8Array values that the
  // ported path's auxWritten passes through untouched — so a structural
  // compare here is correct.
  expect(a, `${label}: aux value`).toEqual(b);
};

const expectFramesEqual = (a: TraceFrame, b: TraceFrame, index: number): void => {
  const label = `frame ${index} (${a.stepType} @ ${a.stepId})`;
  expect(a.index, `${label}: index`).toBe(b.index);
  expect(a.path, `${label}: path`).toEqual(b.path);
  expect(a.stepId, `${label}: stepId`).toBe(b.stepId);
  expect(a.stepType, `${label}: stepType`).toBe(b.stepType);
  expect(a.params, `${label}: params`).toEqual(b.params);
  expect(a.blockIndex, `${label}: blockIndex`).toBe(b.blockIndex);
  expect(a.branchPath, `${label}: branchPath`).toEqual(b.branchPath);
  expect(a.auxReadMissing, `${label}: auxReadMissing`).toEqual(b.auxReadMissing);
  expectStatesEqual(a.stateBefore, b.stateBefore, `${label}: stateBefore`);
  expectStatesEqual(a.stateAfter, b.stateAfter, `${label}: stateAfter`);
  expectAuxMapsEqual(a.auxRead, b.auxRead, `${label}: auxRead`);
  expectAuxMapsEqual(a.auxWritten, b.auxWritten, `${label}: auxWritten`);
};

// ─── Test suites ────────────────────────────────────────────────────────

describe("runtime — ported dispatch (Phase 0 task 6)", () => {
  describe("FIPS-197 Appendix C.1 — AES-128 single block", () => {
    const plaintext = matrixFromBytes(bytesFromHex(FIPS_PLAINTEXT));
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(FIPS_KEY)]]);

    it("produces the published ciphertext under portedDispatchEnabled: true", () => {
      const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("matrix4x4-bytes");
      if (trace.finalState.shape !== "matrix4x4-bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(FIPS_CIPHERTEXT);
    });

    it("emits frame-by-frame byte-equal traces vs legacy dispatch", () => {
      const legacy = runSpec(aes128Spec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
      });
      const ported = runSpec(aes128Spec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
        portedDispatchEnabled: true,
      });

      expect(ported.frames.length).toBe(legacy.frames.length);
      for (let i = 0; i < legacy.frames.length; i++) {
        const a = ported.frames[i];
        const b = legacy.frames[i];
        if (!a || !b) throw new Error(`fixture missing frame at index ${i}`);
        expectFramesEqual(a, b, i);
      }

      // finalAux parity: round-key bytes (the ones produced by
      // key-expansion, NOT a ported step) must survive untouched by the
      // ported path running through other steps.
      for (let r = 0; r <= 10; r++) {
        const portedRk = ported.finalAux.get(`roundKey.${r}`);
        const legacyRk = legacy.finalAux.get(`roundKey.${r}`);
        if (!(portedRk instanceof Uint8Array) || !(legacyRk instanceof Uint8Array)) {
          throw new Error(`finalAux roundKey.${r} not Uint8Array`);
        }
        expect(Array.from(portedRk)).toEqual(Array.from(legacyRk));
      }
    });
  });

  describe("NIST SP 800-38A §F.1.1 — AES-128 ECB, 4 blocks", () => {
    // The ECB iterate runs 4 times; each iteration's body contains 10 +
    // 13 = MANY byte-substitution + add-round-key frames, each emitted
    // with `blockIndex: i` (0..3) and `:b{i}` stepId suffix. This is the
    // iterate-body case Q-gate-9 validated at the frame level — task 6
    // validates it at the cipher boundary.
    const plaintext = makeBytesState(bytesFromHex(ECB_PLAINTEXT_4_BLOCKS));
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(ECB_KEY)]]);

    it("produces the published 4-block ciphertext under portedDispatchEnabled: true", () => {
      const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
        portedDispatchEnabled: true,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(ECB_CIPHERTEXT_4_BLOCKS);
    });

    it("emits frame-by-frame byte-equal traces vs legacy dispatch (iterate body)", () => {
      const legacy = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
      });
      const ported = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
        portedDispatchEnabled: true,
      });

      expect(ported.frames.length).toBe(legacy.frames.length);
      for (let i = 0; i < legacy.frames.length; i++) {
        const a = ported.frames[i];
        const b = legacy.frames[i];
        if (!a || !b) throw new Error(`fixture missing frame at index ${i}`);
        expectFramesEqual(a, b, i);
      }
    });

    it("preserves :b{i} stepId suffix + blockIndex on ported iterate-body frames", () => {
      const ported = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
        portedDispatchEnabled: true,
      });

      // Pick a sample byte-substitution frame from each block; confirm
      // the suffix + stamp survived the ported execution path.
      for (let blockIdx = 0; blockIdx < 4; blockIdx++) {
        const sample = ported.frames.find(
          (f) => f.stepType === "generic.byte-substitution@1" && f.blockIndex === blockIdx,
        );
        if (!sample) throw new Error(`no byte-substitution frame found for block ${blockIdx}`);
        expect(sample.stepId.endsWith(`:b${blockIdx}`)).toBe(true);
      }
    });
  });
});
