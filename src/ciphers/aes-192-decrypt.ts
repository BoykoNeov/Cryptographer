/**
 * AES-192 decryption (inverse cipher), FIPS-197 §5.3 (single-block).
 *
 * **Byte-native (scaffolding-suppression Phase B Slice B1.3, 2026-05-29).**
 * Mirror of byte-native `aes-128-decrypt.ts`: the inverse round body composes
 * from the same port-native primitives the forward cipher uses —
 * `byte-substitute@1` (InvSubBytes, inverse S-box), `permute@1` (InvShiftRows,
 * inverse indices), `gf-matrix-multiply@1` (InvMixColumns, inverse matrix),
 * `aux-load-bytes@1` + `xor@1` (AddRoundKey) — built by the variant-agnostic
 * `buildAesDecryptBodyNative`. The differences from AES-128-decrypt are
 * ROUNDS=12 and a 24-byte key declared in `inputs`.
 *
 * The 16-byte working state carries port-to-port between inverse round groups
 * via the A3b `StepGroup` `seedInput`/`bodyOutput` contract; the ciphertext
 * arrives on the reserved `$input` source and the cipher exit is named by
 * `outputFrom`. The inverse cipher consumes the round keys in reverse: the
 * initial AddRoundKey reads `roundKey.12`, then inverse rounds 11..1, then a
 * final inverse round at 0 (no InvMixColumns). Inside each round the order is
 * InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns (AddRoundKey BEFORE
 * InvMixColumns, intrinsic to §5.3).
 *
 * Key expansion is shared with the forward AES-192 spec — identical round
 * keys, just read back in reverse. It uses the FORWARD S-box even when
 * decrypting (key expansion's SubWord applies the forward S-box, FIPS-197 §5.2).
 */

import type { CipherSpec } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import { aesNativeDecryptOutputFrom, buildAesDecryptBodyNative } from "./aes-round-builder-native";

const ROUNDS = 12;

export const aes192DecryptSpec: CipherSpec = {
  id: "aes-192-decrypt@1",
  name: "AES-192 (decrypt)",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 24 },
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
    ...buildAesDecryptBodyNative(ROUNDS),
  ],
  outputFrom: aesNativeDecryptOutputFrom(),
};
