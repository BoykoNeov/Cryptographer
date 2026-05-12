/**
 * AES-128 forward cipher, FIPS-197 §5.1 (single-block).
 *
 * The per-block body (initial AddRoundKey + 9 rounds + final round) lives
 * in `aes-round-builder.ts` so the upcoming ECB / CBC / CTR multi-block
 * factories can reuse it verbatim. Key expansion stays here because it runs
 * once total — never inside the per-block loop regardless of mode.
 */

import type { CipherSpec } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import { buildAesEncryptBody } from "./aes-round-builder";

const ROUNDS = 10;

export const aes128Spec: CipherSpec = {
  id: "aes-128@1",
  name: "AES-128",
  stateShape: "matrix4x4-bytes",
  inputs: {
    plaintext: { shape: "matrix4x4-bytes" },
    key: { byteLength: 16 },
  },
  steps: [
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
    ...buildAesEncryptBody(ROUNDS),
  ],
};
