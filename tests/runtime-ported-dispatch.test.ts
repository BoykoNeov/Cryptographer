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
 *   (b) **Frame-by-frame parity vs legacy** — every emitted TraceFrame is
 *       byte-equal between `portedDispatchEnabled: true` and `false`. This is
 *       the inexpensive lever that earns most of the 8 non-Q-gate-9 gate
 *       items: linear view, MatrixView highlights, narration, provenance
 *       overlay, mirror buttons, and graph derivation all read TraceFrame; if
 *       the frames are byte-equal, every layer above the runtime works
 *       without change.
 *
 *       Slice B1 (2026-05-29): this parity test was REMOVED for the AES-128
 *       single-block spec, which is now byte-native — built from port-native
 *       primitives with no legacy executor, so it cannot run under
 *       `portedDispatchEnabled: false`. The property only ever applied to
 *       lifted-legacy steps (matrix executors with a port contract). It still
 *       holds — and is still pinned here — for the AES-128 ECB spec below,
 *       which stays matrix/lifted-legacy until Slice B1.4.
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
import type { AuxValue } from "@/core/types";
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

// ─── Test suites ────────────────────────────────────────────────────────
//
// Frame-parity-vs-legacy helpers were removed in B1.4: every AES spec
// (single-block + ECB) is now byte-native with NO legacy path, so the
// ported-vs-legacy frame comparison is vacuous here. The surviving
// ported-vs-legacy parity coverage (lifted-legacy steps) lives in
// `runtime-ported-dispatch-frame-parity.test.ts` (Speck/Serpent/DES rows).

describe("runtime — ported dispatch (Phase 0 task 6)", () => {
  describe("FIPS-197 Appendix C.1 — AES-128 single block (byte-native, Slice B1)", () => {
    // Byte-native AES-128 (Slice B1) is built from port-native primitives
    // with NO legacy executor — so `portedDispatchEnabled: true` is now the
    // ONLY way it runs (flag-off throws). The KAT under ported is the
    // correctness anchor; it now produces a `bytes` finalState.
    const plaintext = makeBytesState(bytesFromHex(FIPS_PLAINTEXT));
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(FIPS_KEY)]]);

    it("produces the published ciphertext under portedDispatchEnabled: true", () => {
      const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(FIPS_CIPHERTEXT);
    });

    // The original "frame-by-frame byte-equal vs legacy dispatch" test is
    // GONE by design. That property only made sense for the matrix AES, whose
    // lifted-legacy steps (`kind: "ported"` WITH a legacy executor) ran under
    // both dispatch paths — the test pinned that lifting didn't change frames.
    // Byte-native AES has genuinely port-native steps with no legacy path, so
    // there is nothing to be "faithful to" — the parity is vacuous. The
    // ported-vs-legacy parity infrastructure stays covered by the Speck/
    // Serpent/DES rows in `runtime-ported-dispatch-frame-parity.test.ts` (the
    // AES ECB rows were removed in B1.4 when ECB also went byte-native). The
    // byte-native AES-128 FRAME STREAM (52 frames, 11 round keys, intermediate
    // after initial AddRoundKey) is pinned in `aes-vectors.test.ts`.
  });

  describe("NIST SP 800-38A §F.1.1 — AES-128 ECB, 4 blocks", () => {
    // Byte-native (Slice B1.4): the ECB iterate runs 4 times; each iteration's
    // body is the port-native AES body (byte-substitute / permute /
    // gf-matrix-multiply / xor), each frame emitted with `blockIndex: i` (0..3)
    // and `:b{i}` stepId suffix. Like single-block byte-native AES there is NO
    // legacy path (the body throws under legacy dispatch — `aux-load-bytes@1`
    // requires portedDispatchEnabled), so the ported-vs-legacy parity row that
    // matrix ECB carried is gone; the cipher-boundary KAT + the :b{i} stamp
    // are the surviving assertions.
    const plaintext = makeBytesState(bytesFromHex(ECB_PLAINTEXT_4_BLOCKS));
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(ECB_KEY)]]);

    it("produces the published 4-block ciphertext under portedDispatchEnabled: true", () => {
      const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(ECB_CIPHERTEXT_4_BLOCKS);
    });

    it("preserves :b{i} stepId suffix + blockIndex on ported iterate-body frames", () => {
      const ported = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux: aux,
      });

      // Pick a sample SubBytes frame from each block; confirm the suffix +
      // stamp survived the ported execution path. (Byte-native: the SubBytes
      // step type is `byte-substitute@1`, not the matrix `generic.*`.)
      for (let blockIdx = 0; blockIdx < 4; blockIdx++) {
        const sample = ported.frames.find(
          (f) => f.stepType === "byte-substitute@1" && f.blockIndex === blockIdx,
        );
        if (!sample) throw new Error(`no byte-substitute frame found for block ${blockIdx}`);
        expect(sample.stepId.endsWith(`:b${blockIdx}`)).toBe(true);
      }
    });
  });
});
