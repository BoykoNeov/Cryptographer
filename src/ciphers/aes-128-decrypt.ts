/**
 * AES-128 decryption (inverse cipher), FIPS-197 §5.3 (single-block).
 *
 * Load-bearing test of the modularity claim: the inverse cipher uses the
 * EXACT SAME step-type registry as the forward cipher. No new executors,
 * no special cases. Key differences:
 *   1. Round structure runs "outward": initial AddRoundKey at round 10,
 *      then rounds 9..1, then a final round at round 0.
 *   2. Inside each round, the order is InvShiftRows → InvSubBytes →
 *      AddRoundKey → InvMixColumns (note: AddRoundKey BEFORE InvMixColumns,
 *      unlike forward). Final round drops InvMixColumns.
 *   3. Step params use the inverse S-box, inverse MixColumns matrix, and
 *      shifts = [0, 3, 2, 1] (= shifting RIGHT by [0, 1, 2, 3]).
 *   4. Key expansion is identical to forward — same round keys, just read
 *      back in reverse order via the AddRoundKey aux references.
 *
 * The inverse body lives in `aes-round-builder.ts` so the upcoming
 * ECB-decrypt / CBC-decrypt factories can reuse it.
 */

import type { CipherSpec } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import { buildAesDecryptBody } from "./aes-round-builder";

const ROUNDS = 10;

export const aes128DecryptSpec: CipherSpec = {
  id: "aes-128-decrypt@1",
  name: "AES-128 (decrypt)",
  stateShape: "matrix4x4-bytes",
  inputs: {
    plaintext: { shape: "matrix4x4-bytes" },
    key: { byteLength: 16 },
  },
  steps: [
    // Step 1: derive round keys. Identical to forward — uses the FORWARD
    // S-box (key expansion's SubWord applies forward S-box even when
    // decrypting).
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
    ...buildAesDecryptBody(ROUNDS),
  ],
};
