/**
 * Toy Feistel cipher spec used by Phase 2 of the DES + branching primitive
 * plan. Exercises the `feistel-round` primitive end-to-end with a minimal,
 * asymmetric F. NOT registered in the cipher selector — the toy is loaded
 * directly by `tests/feistel-primitive.test.ts` and `tests/feistel-graph.test.ts`.
 *
 * Shape:
 *   - 4-byte block (L = bytes [0, 1], R = bytes [2, 3]).
 *   - 2 rounds. Round 1 uses `feistel-standard` (textbook swap); round 2
 *     uses `feistel-no-swap` (textbook "last round, no swap"), so a single
 *     spec exercises BOTH combine variants AND mirrors DES's round-16
 *     exception in miniature.
 *   - F = (R + k) mod 256 per byte. The k values for rounds 1 and 2 are
 *     `0x11` and `0x22` so manual hand-verification stays straightforward.
 *
 * The 2-round toy is the minimum that proves:
 *   - per-track branchPath stamping (each track's leaves carry
 *     `branchPath: ["L"]` or `["R"]`);
 *   - combine ordering for `feistel-standard` AND `feistel-no-swap`;
 *   - empty-track passthrough (L track has `children: []`, so the runtime
 *     emits ZERO frames for L per round — KAT-pinned);
 *   - rejoin synthetic frame stepId convention (`round.N:rejoin`).
 */

import type { CipherSpec, FeistelRoundGroup } from "../core/types";

const round = (
  id: string,
  k: number,
  combineKind: FeistelRoundGroup["combineKind"],
): FeistelRoundGroup => ({
  kind: "feistel-round",
  id,
  label: id,
  tracks: [
    // L track: passthrough (zero frames emitted; the runtime passes L_in
    // through to the combine as L_out unchanged).
    { name: "L", inputBytes: [0, 1], children: [] },
    // R track: applies F = (R + k) mod 256 per byte.
    {
      name: "R",
      inputBytes: [2, 3],
      children: [
        {
          kind: "step",
          id: `${id}.add-k`,
          type: "feistel.toy-add-k@1",
          params: { k },
        },
      ],
    },
  ],
  combineKind,
});

export const FEISTEL_TOY_SPEC: CipherSpec = {
  id: "feistel-toy@1",
  name: "Toy Feistel (test fixture)",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 2 },
  },
  steps: [
    round("round.1", 0x11, "feistel-standard"),
    // Round 2 = "last round, no swap" — matches DES round-16 convention.
    round("round.2", 0x22, "feistel-no-swap"),
  ],
};

/**
 * Hand-computed KAT for the toy spec. Plaintext = [0x01, 0x02, 0x03, 0x04].
 * Trace:
 *   Round 1 (k=0x11, feistel-standard = swap):
 *     L_in  = [0x01, 0x02]
 *     R_in  = [0x03, 0x04]
 *     R_out = R_in + k = [0x14, 0x15]
 *     new_L = R_in    = [0x03, 0x04]
 *     new_R = L_in XOR R_out = [0x01^0x14, 0x02^0x15] = [0x15, 0x17]
 *   Round 2 (k=0x22, feistel-no-swap):
 *     L_in  = [0x03, 0x04]
 *     R_in  = [0x15, 0x17]
 *     R_out = R_in + k = [0x37, 0x39]
 *     new_L = L_in XOR R_out = [0x03^0x37, 0x04^0x39] = [0x34, 0x3D]
 *     new_R = R_in    = [0x15, 0x17]
 *   Final state bytes: [0x34, 0x3D, 0x15, 0x17].
 */
export const FEISTEL_TOY_KAT = {
  plaintext: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
  ciphertext: new Uint8Array([0x34, 0x3d, 0x15, 0x17]),
};
