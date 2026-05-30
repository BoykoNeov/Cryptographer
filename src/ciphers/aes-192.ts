/**
 * AES-192 forward cipher, FIPS-197 §5.1 (single-block).
 *
 * **Byte-native (scaffolding-suppression Phase B Slice B1.3, 2026-05-29).**
 * Structurally identical to byte-native AES-128 (`aes-128.ts`): the per-block
 * body composes from port-native primitives whose ports are all `layout:"raw"`
 * — `byte-substitute@1` (SubBytes), `permute@1` (ShiftRows),
 * `gf-matrix-multiply@1` (MixColumns), `aux-load-bytes@1` + `xor@1`
 * (AddRoundKey) — built by the variant-agnostic `buildAesEncryptBodyNative`.
 * The ONLY differences from AES-128 are Nk=6 (24-byte cipher key) and
 * ROUNDS=12 (vs 10). The 16-byte working state carries port-to-port between
 * round groups via the A3b `StepGroup` `seedInput`/`bodyOutput` contract; the
 * plaintext arrives on the reserved `$input` source and the cipher exit is
 * named by `outputFrom`.
 *
 * Key expansion stays the monolithic `aes.key-expansion@1` (already A4-clean).
 * The shared executor derives Nk from the actual key length at runtime; this
 * file just tells the runtime to expect a 24-byte key and to assemble 12
 * rounds. It runs once total, writing `roundKey.0..12` into the aux map.
 *
 * Kept as a separate file (rather than parameterizing aes-128) so each variant
 * has a discoverable, named CipherSpec the UI/registry can pick by id.
 */

import type { CipherSpec } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import { aesNativeOutputFrom, buildAesEncryptBodyNative } from "./aes-round-builder-native";

const ROUNDS = 12;

export const aes192Spec: CipherSpec = {
  id: "aes-192@1",
  name: "AES-192",
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
    ...buildAesEncryptBodyNative(ROUNDS),
  ],
  outputFrom: aesNativeOutputFrom(ROUNDS),
};
