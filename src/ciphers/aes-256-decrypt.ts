/**
 * AES-256 decryption (inverse cipher), FIPS-197 §5.3 (single-block).
 *
 * **Byte-native (scaffolding-suppression Phase B Slice B1.3, 2026-05-29).**
 * Mirror of byte-native `aes-128-decrypt.ts` / `aes-192-decrypt.ts`: the
 * inverse round body composes from the same port-native primitives the forward
 * cipher uses (`byte-substitute@1` / `permute@1` / `gf-matrix-multiply@1` with
 * the inverse tables, `aux-load-bytes@1` + `xor@1`), built by the
 * variant-agnostic `buildAesDecryptBodyNative`. ROUNDS=14, 32-byte key.
 *
 * The 16-byte working state carries port-to-port between inverse round groups
 * via the A3b `StepGroup` `seedInput`/`bodyOutput` contract; the ciphertext
 * arrives on the reserved `$input` source and the cipher exit is named by
 * `outputFrom`. The initial AddRoundKey reads `roundKey.14`, then inverse
 * rounds 13..1, then a final inverse round at 0 (no InvMixColumns).
 *
 * Key expansion is shared with the forward AES-256 spec — uses the FORWARD
 * S-box and the AES-256-only `i%Nk==4` SubWord branch even when decrypting (the
 * inverse cipher consumes the same round keys in reverse, never re-derives
 * them).
 */

import type { CipherSpec } from "../core/types";
import { buildAesKeyScheduleNative } from "./aes-key-schedule-builder-native";
import { aesNativeDecryptOutputFrom, buildAesDecryptBodyNative } from "./aes-round-builder-native";

const ROUNDS = 14;
const NK = 8; // 32-byte key / 4 bytes per word

export const aes256DecryptSpec: CipherSpec = {
  id: "aes-256-decrypt@1",
  name: "AES-256 (decrypt)",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 32 },
  },
  steps: [buildAesKeyScheduleNative(ROUNDS, NK), ...buildAesDecryptBodyNative(ROUNDS)],
  outputFrom: aesNativeDecryptOutputFrom(),
};
