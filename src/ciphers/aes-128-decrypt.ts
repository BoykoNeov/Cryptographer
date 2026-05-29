/**
 * AES-128 decryption (inverse cipher), FIPS-197 §5.3 (single-block).
 *
 * **Byte-native (scaffolding-suppression Phase B Slice B1.2, 2026-05-29).**
 * The inverse round body now composes from the same port-native primitives
 * the forward cipher uses — `byte-substitute@1` (InvSubBytes, inverse S-box),
 * `permute@1` (InvShiftRows, inverse indices), `gf-matrix-multiply@1`
 * (InvMixColumns, inverse matrix), `aux-load-bytes@1` + `xor@1` (AddRoundKey)
 * — instead of threading a `MatrixState` through the legacy `generic.*` lifts.
 * The 16-byte working state carries port-to-port between inverse round groups
 * via the A3b `StepGroup` `seedInput`/`bodyOutput` contract; the ciphertext
 * arrives on the reserved `$input` source (A3a) and the cipher exit is named
 * by `outputFrom`. Body construction lives in `aes-round-builder-native.ts`.
 *
 * Load-bearing test of the modularity claim: the inverse cipher uses the
 * EXACT SAME step-type registry as the forward cipher — no new executors,
 * no special cases. Key differences:
 *   1. Round structure runs "outward": initial AddRoundKey reads the LAST
 *      round key (roundKey.10), then inverse rounds 9..1, then a final
 *      inverse round at 0.
 *   2. Inside each round, the order is InvShiftRows → InvSubBytes →
 *      AddRoundKey → InvMixColumns (note: AddRoundKey BEFORE InvMixColumns,
 *      unlike forward). The final round drops InvMixColumns.
 *   3. Step params use the inverse S-box, inverse MixColumns matrix, and
 *      the inverse shift schedule (right shift by [0,1,2,3]).
 *   4. Key expansion is identical to forward — same round keys, just read
 *      back in reverse order via the per-round `aux-load-bytes@1` fetch.
 *      It uses the FORWARD S-box (key expansion's SubWord applies the
 *      forward S-box even when decrypting, FIPS-197 §5.2).
 *
 * The ECB/CBC decrypt modes and AES-192/256 decrypt remain matrix-shaped
 * until Slices B1.3 / B1.4 — `main` never holds a half-converted cipher, but
 * this feature branch carries a mixed window mid-rebuild.
 */

import type { CipherSpec } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import { aesNativeDecryptOutputFrom, buildAesDecryptBodyNative } from "./aes-round-builder-native";

const ROUNDS = 10;

export const aes128DecryptSpec: CipherSpec = {
  id: "aes-128-decrypt@1",
  name: "AES-128 (decrypt)",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 16 },
  },
  steps: [
    // Step 1: derive round keys. Identical to forward — uses the FORWARD
    // S-box (key expansion's SubWord applies forward S-box even when
    // decrypting, FIPS-197 §5.2). Writes roundKey.0..10 into aux.
    {
      kind: "step",
      id: "key-expansion",
      type: "aes.key-expansion@1",
      params: {
        keyAuxName: "key",
        outputPrefix: "roundKey",
        sbox: [...AES_SBOX],
        rcon: [...AES_RCON],
        rounds: ROUNDS,
      },
    },
    ...buildAesDecryptBodyNative(ROUNDS),
  ],
  outputFrom: aesNativeDecryptOutputFrom(),
};
